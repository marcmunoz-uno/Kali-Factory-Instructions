"""Job schemas — discriminated union of every job type the API accepts."""

from kali_factory.models.jobs import (
    JobRequest,
    JobResult,
    JobStatus,
    KaliProbeJob,
    LeakScanJob,
    NucleiExposuresJob,
    OSINTRunJob,
    SubdomainEnumJob,
    TrafficCaptureJob,
    WebFingerprintJob,
)

__all__ = [
    "JobRequest",
    "JobResult",
    "JobStatus",
    "KaliProbeJob",
    "OSINTRunJob",
    "SubdomainEnumJob",
    "WebFingerprintJob",
    "LeakScanJob",
    "TrafficCaptureJob",
    "NucleiExposuresJob",
]
