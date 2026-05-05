"""Allowlist policy — what images, tools, and template dirs are permitted.

Defense in depth: the API rejects bad requests before queuing, the worker
re-validates before executing, and the in-container Kali manifest re-validates
once more inside the runtime. Three layers, same constants.
"""

from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any


# Only these image prefixes can be exec'd by the worker. Built locally from
# runtimes/kali/Dockerfile; never pulled from arbitrary registries.
ALLOWED_RUNTIME_IMAGES: tuple[str, ...] = (
    "kali-factory/recon:",
    "kali-factory/recon-arm64:",
)

# Tools never callable, even if they accidentally end up in a built image.
# Mirror of the Dockerfile's apt-purge list.
BLOCKED_TOOLS: frozenset[str] = frozenset({
    "msfconsole", "msfvenom", "metasploit",
    "sqlmap",
    "hashcat", "john",
    "aircrack-ng", "airmon-ng", "airodump-ng",
    "exploitdb", "searchsploit",
    "hydra", "medusa", "ncrack",
    "nikto", "wpscan",
    "responder", "crackmapexec",
    "chisel", "ligolo-ng", "gost",
})

# Nuclei template directories that may NOT be invoked.
BLOCKED_TEMPLATE_DIRS: frozenset[str] = frozenset({
    "cves", "vulnerabilities", "default-logins",
    "fuzzing", "exploits", "miscellaneous/cve-bypass",
})


def load_tools_manifest(path: str | None = None) -> dict[str, Any]:
    """Load runtimes/kali/tools.json — the declarative tool registry."""
    p = Path(path or os.environ.get(
        "KALI_FACTORY_TOOLS_MANIFEST",
        str(Path(__file__).resolve().parents[3] / "runtimes" / "kali" / "tools.json"),
    ))
    if not p.exists():
        raise FileNotFoundError(f"tools manifest not found at {p}")
    return json.loads(p.read_text())


def is_image_allowed(image: str) -> bool:
    return any(image.startswith(prefix) for prefix in ALLOWED_RUNTIME_IMAGES)


def is_tool_blocked(tool_name: str) -> bool:
    """Conservative check on tool names. Strips arg variants (e.g. 'amass.enum' -> 'amass')."""
    base = tool_name.split(".")[0].split()[0]
    return base in BLOCKED_TOOLS


def is_template_blocked(template_path: str) -> bool:
    """Block any template path that traverses a forbidden directory."""
    parts = template_path.strip("/").split("/")
    return any(p in BLOCKED_TEMPLATE_DIRS for p in parts)
