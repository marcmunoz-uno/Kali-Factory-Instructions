"""Pydantic schemas for every accepted job type.

Every field that ends up as an argument to a Kali tool is declared here with
explicit type/regex/length constraints. This is what stops the agent from
slipping a `;` into a domain name and getting shell injection.
"""

from __future__ import annotations

from enum import StrEnum
from typing import Literal

from pydantic import BaseModel, Field, HttpUrl

# Strict identifier pattern: only used for things like image suffix or org name
_SAFE_NAME = r"^[a-zA-Z0-9._-]+$"
# pydantic-core uses Rust regex which doesn't support look-arounds. The 253-char
# RFC 1035 length cap is enforced separately via Field(max_length=...).
_DOMAIN = r"^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$"


class JobStatus(StrEnum):
    queued = "queued"
    started = "started"
    finished = "finished"
    failed = "failed"
    timed_out = "timed_out"
    rejected = "rejected"


# ─── Job request types (discriminated union by `type`) ──────────────────────


class _JobBase(BaseModel):
    type: str
    max_runtime_sec: int = Field(default=300, ge=10, le=3600)


class KaliProbeJob(_JobBase):
    type: Literal["kali_probe"] = "kali_probe"


class OSINTRunJob(_JobBase):
    """Generic typed-tool dispatch — caller specifies which manifest tool to invoke."""

    type: Literal["osint_run"] = "osint_run"
    tool: str = Field(
        pattern=_SAFE_NAME,
        description="Tool key from tools.json (e.g. 'amass.enum')",
    )
    args: dict[str, str] = Field(
        default_factory=dict,
        description="Args matching the tool's template",
    )


class SubdomainEnumJob(_JobBase):
    type: Literal["subdomain_enum"] = "subdomain_enum"
    domain: str = Field(pattern=_DOMAIN, max_length=253)
    passive_only: bool = True


class WebFingerprintJob(_JobBase):
    type: Literal["web_fingerprint"] = "web_fingerprint"
    url: HttpUrl


class LeakScanJob(_JobBase):
    type: Literal["leak_scan"] = "leak_scan"
    github_org: str = Field(pattern=_SAFE_NAME)
    max_runtime_sec: int = Field(default=1800, ge=60, le=3600)


class TrafficCaptureJob(_JobBase):
    type: Literal["traffic_capture"] = "traffic_capture"
    listen_port: int = Field(ge=8000, le=9999, default=8888)
    capture_seconds: int = Field(ge=10, le=600, default=60)


class NucleiExposuresJob(_JobBase):
    type: Literal["nuclei_exposures"] = "nuclei_exposures"
    url: HttpUrl
    # Must match policy.allowlist.ALLOWED_NUCLEI_TEMPLATE_SUBSETS exactly.
    # cves/, vulnerabilities/, default-logins/, fuzzing/, exploits/, and
    # network/ are never accepted — they send active payloads.
    template_subset: Literal[
        "exposures", "technologies", "misconfiguration", "dns", "ssl"
    ] = "exposures"


# Discriminated union — used in API request validation
JobRequest = (
    KaliProbeJob
    | OSINTRunJob
    | SubdomainEnumJob
    | WebFingerprintJob
    | LeakScanJob
    | TrafficCaptureJob
    | NucleiExposuresJob
)


# ─── Job result envelope ────────────────────────────────────────────────────


class JobResult(BaseModel):
    job_id: str
    status: JobStatus
    job_type: str
    submitted_at: float
    finished_at: float | None = None
    duration_sec: float | None = None
    exit_code: int | None = None
    output_summary: dict | None = None  # tool-specific structured output
    output_file: str | None = None      # path on host (if a job emits a file)
    error: str | None = None
    audit_log_id: str | None = None
