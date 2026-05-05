"""Kali Factory FastAPI server.

Mirrors GPU Factory's API shape:
  GET  /health          → liveness + version
  POST /jobs            → submit a typed job (bearer auth required)
  GET  /jobs/{job_id}   → poll status / fetch result (bearer auth required)
  GET  /tools           → list allowlisted tools from the manifest
  GET  /audit/recent    → last 50 audit-log entries (bearer auth required)
"""

from __future__ import annotations

import os
import time
import uuid
from typing import Any

import structlog
from fastapi import Depends, FastAPI, HTTPException, status
from pydantic import BaseModel
from redis import Redis
from rq import Queue

from kali_factory import __version__
from kali_factory.models import JobRequest, JobResult, JobStatus
from kali_factory.policy import load_tools_manifest, verify_bearer_token

log = structlog.get_logger()

app = FastAPI(
    title="Kali Factory API",
    version=__version__,
    description="Typed Kali OSINT job execution. Bearer-auth required on all mutating endpoints.",
)

# Redis + RQ
_REDIS_URL = os.environ.get("KALI_FACTORY_REDIS_URL", "redis://localhost:6379/0")
_redis = Redis.from_url(_REDIS_URL)
_queue = Queue("kali-factory", connection=_redis)


class HealthResponse(BaseModel):
    status: str
    version: str
    redis_ok: bool
    tools_manifest_loaded: bool
    runtime_image_allowed: bool


class JobSubmittedResponse(BaseModel):
    job_id: str
    status: JobStatus
    submitted_at: float


@app.get("/health", response_model=HealthResponse)
def health() -> HealthResponse:
    redis_ok = False
    try:
        _redis.ping()
        redis_ok = True
    except Exception:
        pass

    tools_loaded = False
    try:
        manifest = load_tools_manifest()
        tools_loaded = bool(manifest.get("tools"))
    except Exception:
        pass

    return HealthResponse(
        status="ok" if redis_ok and tools_loaded else "degraded",
        version=__version__,
        redis_ok=redis_ok,
        tools_manifest_loaded=tools_loaded,
        runtime_image_allowed=True,  # validated per-job, not at health time
    )


@app.get("/tools")
def list_tools() -> dict[str, Any]:
    """Public — agents need to discover what tools are available."""
    manifest = load_tools_manifest()
    return {
        "runtime": manifest.get("runtime"),
        "image_version": manifest.get("image_version"),
        "tools": list(manifest.get("tools", {}).keys()),
        "blocked_tools": sorted(manifest.get("shell_blocklist", [])),
        "blocked_template_dirs": sorted(
            manifest.get("tools", {}).get("nuclei.exposures_only", {}).get(
                "blocked_template_dirs", []
            )
        ),
    }


@app.post("/jobs", response_model=JobSubmittedResponse)
def submit_job(
    job: JobRequest,
    _: None = Depends(verify_bearer_token),
) -> JobSubmittedResponse:
    """Accept a typed job request, push to the worker queue, return job_id."""
    job_id = uuid.uuid4().hex
    submitted_at = time.time()

    log.info(
        "job.submitted",
        job_id=job_id,
        type=job.type,
        max_runtime_sec=job.max_runtime_sec,
    )

    _queue.enqueue(
        "kali_factory.worker.handlers.dispatch",
        job_id,
        job.model_dump(mode="json"),
        job_timeout=job.max_runtime_sec + 60,  # grace
        result_ttl=3600,
        failure_ttl=86400,
    )

    return JobSubmittedResponse(
        job_id=job_id,
        status=JobStatus.queued,
        submitted_at=submitted_at,
    )


@app.get("/jobs/{job_id}", response_model=JobResult)
def get_job(
    job_id: str,
    _: None = Depends(verify_bearer_token),
) -> JobResult:
    """Poll a job's status / fetch result envelope."""
    rq_job = _queue.fetch_job(job_id)
    if rq_job is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"job {job_id} not found",
        )

    status_map = {
        "queued": JobStatus.queued,
        "started": JobStatus.started,
        "finished": JobStatus.finished,
        "failed": JobStatus.failed,
        "stopped": JobStatus.timed_out,
    }
    rq_status = rq_job.get_status()

    # If the worker stored a JobResult dict on success, return it; otherwise
    # synthesize a minimal envelope from RQ metadata.
    if rq_status == "finished" and isinstance(rq_job.result, dict):
        return JobResult(**rq_job.result)

    return JobResult(
        job_id=job_id,
        status=status_map.get(rq_status, JobStatus.failed),
        job_type=(rq_job.kwargs or {}).get("type") or rq_job.args[1].get("type", "unknown")
        if rq_job.args else "unknown",
        submitted_at=rq_job.enqueued_at.timestamp() if rq_job.enqueued_at else 0,
        finished_at=rq_job.ended_at.timestamp() if rq_job.ended_at else None,
        duration_sec=(
            (rq_job.ended_at - rq_job.started_at).total_seconds()
            if rq_job.ended_at and rq_job.started_at else None
        ),
        error=str(rq_job.exc_info) if rq_status == "failed" else None,
    )


def run() -> None:
    """Console-script entrypoint."""
    import uvicorn

    uvicorn.run(
        "kali_factory.api.main:app",
        host=os.environ.get("KALI_FACTORY_API_HOST", "127.0.0.1"),
        port=int(os.environ.get("KALI_FACTORY_API_PORT", "8081")),
        log_level=os.environ.get("KALI_FACTORY_LOG_LEVEL", "info"),
    )
