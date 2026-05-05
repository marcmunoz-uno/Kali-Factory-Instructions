"""Allowlist policy — what images, tools, and template dirs are permitted.

Defense in depth: the API rejects bad requests before queuing, the worker
re-validates before executing, and the in-container Kali manifest re-validates
once more inside the runtime. Three layers, same constants.

Mirror of:
  - runtimes/kali/Dockerfile (apt-purge list)
  - runtimes/kali/tools.json (shell_blocklist)
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
# Categories are commented for review — keep this list and the Dockerfile
# purge list in lockstep.
BLOCKED_TOOLS: frozenset[str] = frozenset({
    # Exploit / payload frameworks
    "msfconsole", "msfvenom", "metasploit",
    "sqlmap", "commix",
    "xsser", "xsstrike",
    "weevely", "beef", "beef-xss",
    "setoolkit", "set",
    # Credential cracking
    "hashcat", "john",
    "hydra", "medusa", "ncrack", "patator", "kerbrute",
    # Wireless attacks
    "aircrack-ng", "airmon-ng", "airodump-ng",
    "kismet", "reaver", "wifite",
    # Active MITM / network spoofing
    "ettercap", "bettercap", "mitm6", "dsniff", "dnschef", "dnsspoof",
    "arpspoof", "macchanger",
    # Web app attack scanners (noisy / signature-active)
    "nikto", "wpscan",
    # Post-exploitation / AD attack
    "responder", "crackmapexec", "nxc",
    "evil-winrm", "bloodhound",
    "impacket-secretsdump", "impacket-psexec", "impacket-wmiexec",
    "impacket-smbexec", "impacket-getuserspns", "impacket-getnpusers",
    # Exploit databases / search
    "exploitdb", "searchsploit",
    # Router exploit framework
    "routersploit",
    # C2 frameworks
    "empire", "covenant", "mythic", "pupy",
    # Payload generators
    "thefatrat", "veil",
    # Tunneling / pivoting (offensive context)
    "chisel", "ligolo-ng", "gost",
    # Misc offensive
    "thc-ipv6",
})


# Nuclei template directories that may NOT be invoked.
# `network/` joins the blocked list because many of its templates send active
# probes; the safer template trees (exposures, technologies, misconfiguration,
# dns, ssl) cover the OSINT use case.
BLOCKED_TEMPLATE_DIRS: frozenset[str] = frozenset({
    "cves", "vulnerabilities", "default-logins",
    "fuzzing", "exploits", "network",
    "miscellaneous/cve-bypass",
})


# Template subsets the NucleiExposuresJob is allowed to request. Anything not
# in this set is rejected at the API layer.
ALLOWED_NUCLEI_TEMPLATE_SUBSETS: frozenset[str] = frozenset({
    "exposures", "technologies", "misconfiguration", "dns", "ssl",
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


def is_nuclei_subset_allowed(subset: str) -> bool:
    return subset in ALLOWED_NUCLEI_TEMPLATE_SUBSETS
