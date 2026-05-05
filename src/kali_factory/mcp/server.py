"""Stdio MCP adapter over the local Kali Factory API.

Agents that speak MCP can spawn this server and call its tools, which proxy
to the local Kali Factory API at http://127.0.0.1:8081 with the local bearer
token. Saves the agent from having to know about the HTTP API directly.

Status: skeleton. Wire to the official `mcp` Python package once stable; for
now this is the shape we'll fill in.
"""

from __future__ import annotations

import json
import os
import sys
import time
from pathlib import Path
from typing import Any
from urllib.request import Request, urlopen


def _api_base() -> str:
    return os.environ.get("KALI_FACTORY_API_BASE", "http://127.0.0.1:8081")


def _bearer() -> str:
    token_file = os.environ.get("KALI_FACTORY_API_TOKEN_FILE")
    if not token_file:
        raise RuntimeError("KALI_FACTORY_API_TOKEN_FILE not set")
    return Path(token_file).read_text().strip()


def _api_post(path: str, body: dict[str, Any], timeout_sec: int = 60) -> dict[str, Any]:
    req = Request(
        url=f"{_api_base()}{path}",
        data=json.dumps(body).encode(),
        headers={
            "Authorization": f"Bearer {_bearer()}",
            "Content-Type": "application/json",
        },
        method="POST",
    )
    with urlopen(req, timeout=timeout_sec) as resp:
        return json.loads(resp.read().decode())


def _api_get(path: str, timeout_sec: int = 30) -> dict[str, Any]:
    req = Request(
        url=f"{_api_base()}{path}",
        headers={"Authorization": f"Bearer {_bearer()}"},
    )
    with urlopen(req, timeout=timeout_sec) as resp:
        return json.loads(resp.read().decode())


def _wait_for_job(job_id: str, *, max_wait_sec: int) -> dict[str, Any]:
    deadline = time.time() + max_wait_sec
    while time.time() < deadline:
        result = _api_get(f"/jobs/{job_id}")
        if result.get("status") in ("finished", "failed", "timed_out", "rejected"):
            return result
        time.sleep(2)
    return {"status": "timed_out", "job_id": job_id, "error": f"polled {max_wait_sec}s"}


# ─── MCP tool surface (each maps to a Kali Factory job type) ────────────────


def tool_subdomain_enum(domain: str, passive_only: bool = True,
                        max_runtime_sec: int = 300) -> dict[str, Any]:
    submitted = _api_post("/jobs", {
        "type": "subdomain_enum",
        "domain": domain,
        "passive_only": passive_only,
        "max_runtime_sec": max_runtime_sec,
    })
    return _wait_for_job(submitted["job_id"], max_wait_sec=max_runtime_sec + 30)


def tool_web_fingerprint(url: str, max_runtime_sec: int = 60) -> dict[str, Any]:
    submitted = _api_post("/jobs", {
        "type": "web_fingerprint",
        "url": url,
        "max_runtime_sec": max_runtime_sec,
    })
    return _wait_for_job(submitted["job_id"], max_wait_sec=max_runtime_sec + 30)


def tool_leak_scan(github_org: str, max_runtime_sec: int = 1800) -> dict[str, Any]:
    submitted = _api_post("/jobs", {
        "type": "leak_scan",
        "github_org": github_org,
        "max_runtime_sec": max_runtime_sec,
    })
    return _wait_for_job(submitted["job_id"], max_wait_sec=max_runtime_sec + 60)


def tool_nuclei_exposures(url: str, template_subset: str = "exposures",
                          max_runtime_sec: int = 300) -> dict[str, Any]:
    submitted = _api_post("/jobs", {
        "type": "nuclei_exposures",
        "url": url,
        "template_subset": template_subset,
        "max_runtime_sec": max_runtime_sec,
    })
    return _wait_for_job(submitted["job_id"], max_wait_sec=max_runtime_sec + 30)


def run() -> None:
    """Stdio JSON-RPC loop. Replace with `mcp` package once we adopt it."""
    print(json.dumps({
        "type": "ready",
        "tools": [
            "subdomain_enum",
            "web_fingerprint",
            "leak_scan",
            "nuclei_exposures",
        ],
    }), flush=True)
    for line in sys.stdin:
        line = line.strip()
        if not line:
            continue
        try:
            req = json.loads(line)
            tool = req.get("tool")
            args = req.get("args") or {}
            if tool == "subdomain_enum":
                result = tool_subdomain_enum(**args)
            elif tool == "web_fingerprint":
                result = tool_web_fingerprint(**args)
            elif tool == "leak_scan":
                result = tool_leak_scan(**args)
            elif tool == "nuclei_exposures":
                result = tool_nuclei_exposures(**args)
            else:
                result = {"error": f"unknown tool {tool!r}"}
            print(json.dumps({"id": req.get("id"), "result": result}), flush=True)
        except Exception as exc:
            print(json.dumps({"error": str(exc)}), flush=True)


if __name__ == "__main__":
    run()
