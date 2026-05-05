"""Job dispatch + per-type handlers.

Every job runs in an ephemeral Kali container spawned via the Docker SDK.
Container is hardened: rootless, dropped caps, no host volume mounts,
read-only rootfs, tmpfs workdir, network bridge (OSINT requires egress),
short TTL, output collected via stdout JSON or specific output paths.
"""

from __future__ import annotations

import json
import os
import time
import uuid
from pathlib import Path
from typing import Any

import structlog

from kali_factory.models import JobResult, JobStatus
from kali_factory.policy.allowlist import (
    is_image_allowed,
    is_template_blocked,
    is_tool_blocked,
)

log = structlog.get_logger()


# Image used for every Kali job. Built locally from runtimes/kali/Dockerfile.
RUNTIME_IMAGE = os.environ.get("KALI_FACTORY_RUNTIME_IMAGE", "kali-factory/recon:latest")


def dispatch(job_id: str, payload: dict[str, Any]) -> dict[str, Any]:
    """RQ entrypoint. Routes typed payloads to per-type handlers."""
    job_type = payload.get("type")
    log.info("job.started", job_id=job_id, type=job_type)
    started_at = time.time()

    handler = _HANDLERS.get(job_type)
    if handler is None:
        return JobResult(
            job_id=job_id,
            status=JobStatus.rejected,
            job_type=job_type or "unknown",
            submitted_at=started_at,
            finished_at=time.time(),
            error=f"no handler for job type {job_type!r}",
        ).model_dump(mode="json")

    if not is_image_allowed(RUNTIME_IMAGE):
        return JobResult(
            job_id=job_id,
            status=JobStatus.rejected,
            job_type=job_type,
            submitted_at=started_at,
            finished_at=time.time(),
            error=f"runtime image {RUNTIME_IMAGE!r} not in allowlist",
        ).model_dump(mode="json")

    try:
        result = handler(job_id, payload)
        result["finished_at"] = time.time()
        result["duration_sec"] = result["finished_at"] - started_at
        log.info("job.finished", job_id=job_id, type=job_type,
                 duration_sec=result["duration_sec"])
        return result
    except Exception as exc:
        log.exception("job.failed", job_id=job_id, type=job_type, error=str(exc))
        return JobResult(
            job_id=job_id,
            status=JobStatus.failed,
            job_type=job_type,
            submitted_at=started_at,
            finished_at=time.time(),
            error=str(exc),
        ).model_dump(mode="json")


# ─── Per-type handlers ──────────────────────────────────────────────────────


def _run_in_kali(cmd: list[str], *, timeout_sec: int,
                 mem_limit_mb: int = 1024,
                 network_mode: str = "bridge") -> tuple[int, bytes, bytes]:
    """Spawn an ephemeral Kali container, exec the command, reap.

    Hardening:
      - rootless (user 65534)
      - drop ALL caps
      - read-only rootfs
      - tmpfs /tmp + /work
      - no host volumes
      - mem + cpu limits
      - explicit timeout via SIGTERM watchdog (TODO)
    """
    import docker
    client = docker.from_env()

    container = client.containers.run(
        image=RUNTIME_IMAGE,
        command=cmd,
        detach=True,
        user="65534:65534",
        working_dir="/work",
        cap_drop=["ALL"],
        network_mode=network_mode,
        mem_limit=f"{mem_limit_mb}m",
        nano_cpus=1_500_000_000,
        read_only=True,
        tmpfs={"/tmp": "rw,size=256m", "/work": "rw,size=512m"},
        security_opt=["no-new-privileges:true"],
        remove=False,
        labels={"kali-factory.job": "true"},
    )
    try:
        result = container.wait(timeout=timeout_sec)
        exit_code = result.get("StatusCode", -1)
        out = container.logs(stdout=True, stderr=False)
        err = container.logs(stdout=False, stderr=True)
        return exit_code, out or b"", err or b""
    finally:
        try:
            container.remove(force=True)
        except Exception as exc:
            log.warning("container.cleanup_failed", error=str(exc))


def _kali_probe(job_id: str, payload: dict[str, Any]) -> dict[str, Any]:
    """Validate the runtime container starts and the manifest is intact."""
    exit_code, out, err = _run_in_kali(
        cmd=["python3", "-c",
             "import json; m=json.load(open('/etc/parallel-os/tools.json'));"
             "print(json.dumps({'runtime':m['runtime'],"
             "'image_version':m['image_version'],"
             "'tool_count':len(m.get('tools',{}))}))"],
        timeout_sec=30,
        network_mode="none",
    )
    summary = {}
    try:
        summary = json.loads(out.decode())
    except Exception:
        pass
    return JobResult(
        job_id=job_id,
        status=JobStatus.finished if exit_code == 0 else JobStatus.failed,
        job_type=payload["type"],
        submitted_at=time.time(),
        exit_code=exit_code,
        output_summary=summary,
        error=err.decode()[:500] if exit_code != 0 else None,
    ).model_dump(mode="json")


def _subdomain_enum(job_id: str, payload: dict[str, Any]) -> dict[str, Any]:
    """amass enum -d <domain> -passive (when passive_only=True)"""
    domain = payload["domain"]
    passive = payload.get("passive_only", True)
    cmd = ["amass", "enum", "-d", domain]
    if passive:
        cmd.append("-passive")
    exit_code, out, err = _run_in_kali(
        cmd=cmd,
        timeout_sec=payload.get("max_runtime_sec", 300),
    )
    subdomains = [line.strip() for line in out.decode().splitlines() if line.strip()]
    return JobResult(
        job_id=job_id,
        status=JobStatus.finished,
        job_type=payload["type"],
        submitted_at=time.time(),
        exit_code=exit_code,
        output_summary={"domain": domain, "count": len(subdomains), "subdomains": subdomains[:500]},
        error=err.decode()[:500] if exit_code != 0 else None,
    ).model_dump(mode="json")


def _web_fingerprint(job_id: str, payload: dict[str, Any]) -> dict[str, Any]:
    """whatweb --no-errors --log-json=- <url>"""
    url = str(payload["url"])
    exit_code, out, err = _run_in_kali(
        cmd=["whatweb", "--no-errors", "--log-json=/dev/stdout", url],
        timeout_sec=payload.get("max_runtime_sec", 60),
    )
    fingerprint: dict[str, Any] = {}
    for line in out.decode().splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            parsed = json.loads(line)
            fingerprint = parsed
            break
        except Exception:
            continue
    return JobResult(
        job_id=job_id,
        status=JobStatus.finished,
        job_type=payload["type"],
        submitted_at=time.time(),
        exit_code=exit_code,
        output_summary={"url": url, "fingerprint": fingerprint},
        error=err.decode()[:500] if exit_code != 0 else None,
    ).model_dump(mode="json")


def _leak_scan(job_id: str, payload: dict[str, Any]) -> dict[str, Any]:
    """trufflehog github --org=<org> --json"""
    org = payload["github_org"]
    exit_code, out, err = _run_in_kali(
        cmd=["trufflehog", "github", f"--org={org}", "--json"],
        timeout_sec=payload.get("max_runtime_sec", 1800),
        mem_limit_mb=2048,
    )
    findings: list[dict[str, Any]] = []
    for line in out.decode().splitlines():
        try:
            findings.append(json.loads(line))
        except Exception:
            continue
    return JobResult(
        job_id=job_id,
        status=JobStatus.finished,
        job_type=payload["type"],
        submitted_at=time.time(),
        exit_code=exit_code,
        output_summary={"org": org, "finding_count": len(findings),
                        "findings": findings[:200]},
        error=err.decode()[:500] if exit_code != 0 else None,
    ).model_dump(mode="json")


def _nuclei_exposures(job_id: str, payload: dict[str, Any]) -> dict[str, Any]:
    """nuclei -u <url> -t <subset>/ -jsonl  — subset must NOT be in BLOCKED_TEMPLATE_DIRS"""
    subset = payload.get("template_subset", "exposures")
    if is_template_blocked(subset):
        return JobResult(
            job_id=job_id,
            status=JobStatus.rejected,
            job_type=payload["type"],
            submitted_at=time.time(),
            finished_at=time.time(),
            error=f"template subset {subset!r} is blocked",
        ).model_dump(mode="json")

    url = str(payload["url"])
    exit_code, out, err = _run_in_kali(
        cmd=["nuclei", "-u", url, "-t", f"{subset}/", "-jsonl", "-silent"],
        timeout_sec=payload.get("max_runtime_sec", 300),
    )
    findings = []
    for line in out.decode().splitlines():
        try:
            findings.append(json.loads(line))
        except Exception:
            continue
    return JobResult(
        job_id=job_id,
        status=JobStatus.finished,
        job_type=payload["type"],
        submitted_at=time.time(),
        exit_code=exit_code,
        output_summary={"url": url, "subset": subset, "findings": findings[:100]},
        error=err.decode()[:500] if exit_code != 0 else None,
    ).model_dump(mode="json")


def _osint_run(job_id: str, payload: dict[str, Any]) -> dict[str, Any]:
    """Generic dispatch — caller picks a tool from the manifest."""
    tool = payload["tool"]
    if is_tool_blocked(tool):
        return JobResult(
            job_id=job_id,
            status=JobStatus.rejected,
            job_type=payload["type"],
            submitted_at=time.time(),
            finished_at=time.time(),
            error=f"tool {tool!r} is in BLOCKED_TOOLS",
        ).model_dump(mode="json")

    # TODO: render arg template from runtimes/kali/tools.json against payload['args']
    # For now, only the first-class job types are wired end-to-end.
    return JobResult(
        job_id=job_id,
        status=JobStatus.failed,
        job_type=payload["type"],
        submitted_at=time.time(),
        finished_at=time.time(),
        error="generic osint_run not yet implemented; use a typed job",
    ).model_dump(mode="json")


def _traffic_capture(job_id: str, payload: dict[str, Any]) -> dict[str, Any]:
    """mitmdump capture for a bounded duration. Returns capture file path."""
    # TODO: needs persistent storage path, not tmpfs, and probably a side-channel
    # for the agent to feed traffic through the proxy. v0.0.2 work.
    return JobResult(
        job_id=job_id,
        status=JobStatus.failed,
        job_type=payload["type"],
        submitted_at=time.time(),
        finished_at=time.time(),
        error="traffic_capture not yet implemented (needs persistent capture path)",
    ).model_dump(mode="json")


_HANDLERS = {
    "kali_probe":         _kali_probe,
    "subdomain_enum":     _subdomain_enum,
    "web_fingerprint":    _web_fingerprint,
    "leak_scan":          _leak_scan,
    "nuclei_exposures":   _nuclei_exposures,
    "osint_run":          _osint_run,
    "traffic_capture":    _traffic_capture,
}
