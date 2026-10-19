"""Shared safety utilities for the audit platform itself.

The security tool must be secure itself (spec 38): secret masking, path
confinement, safe archive extraction, SSRF-safe target validation.
"""
from __future__ import annotations

import ipaddress
import os
import re
import zipfile
from pathlib import Path

# ---------------------------------------------------------------------------
# Secret masking - evidence must never expose full secrets (spec 30).
# ---------------------------------------------------------------------------

_KNOWN_SECRET_PATTERNS = [
    # AWS access key id
    (re.compile(r"\b(AKIA|ASIA)[0-9A-Z]{16}\b"), lambda m: m.group(0)[:4] + "*" * 12 + m.group(0)[-2:]),
    # GitHub tokens
    (re.compile(r"\bgh[pousr]_[A-Za-z0-9]{20,}\b"), lambda m: m.group(0)[:7] + "*" * 8 + m.group(0)[-2:]),
    # Stripe keys
    (re.compile(r"\b(sk|pk|rk)_(live|test)_[A-Za-z0-9]{10,}\b"), lambda m: m.group(0)[:9] + "*" * 8 + m.group(0)[-2:]),
    # PEM private key blocks
    (re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]*?-----END [A-Z ]*PRIVATE KEY-----"),
     lambda m: "-----BEGIN PRIVATE KEY----- ***masked*** -----END PRIVATE KEY-----"),
    # generic long secrets assigned to suspicious names (tolerates quoted keys)
    (re.compile(r"(?i)(secret_key|api_key|apikey|password|passwd|token|private_key|client_secret)"
                r"['\"]?\s*[:=]\s*['\"]([^'\"\s]{8,})['\"]"),
     lambda m: m.group(1) + "='***masked***'"),
]


def mask_secret(value: str) -> str:
    """Mask a single secret value, keeping a couple of edge characters."""
    if not value:
        return value
    if len(value) <= 6:
        return "*" * len(value)
    keep_head = 4 if len(value) > 12 else 2
    keep_tail = 2 if len(value) > 12 else 1
    return f"{value[:keep_head]}{'*' * min(16, len(value) - keep_head - keep_tail)}{value[-keep_tail:]}"


def mask_secrets(text: str) -> str:
    """Apply all masking rules to an arbitrary string (evidence, snippets...)."""
    if not text:
        return text
    for pattern, repl in _KNOWN_SECRET_PATTERNS:
        text = pattern.sub(repl, text)
    return text


# ---------------------------------------------------------------------------
# Path confinement - never let scanner or extraction escape the workspace.
# ---------------------------------------------------------------------------

def is_within(base: str | os.PathLike, candidate: str | os.PathLike) -> bool:
    base = Path(base).resolve()
    cand = Path(candidate).resolve()
    try:
        cand.relative_to(base)
        return True
    except ValueError:
        return False


def safe_extract_zip(zip_path: str, dest_dir: str) -> list[str]:
    """Extract an archive refusing absolute paths, `..` traversal and symlinks.

    Returns the extracted member names. Raises ValueError on malicious input.
    """
    dest = Path(dest_dir).resolve()
    dest.mkdir(parents=True, exist_ok=True)
    extracted: list[str] = []
    with zipfile.ZipFile(zip_path) as zf:
        for info in zf.infolist():
            name = info.filename
            if name.endswith("/"):
                continue
            if os.path.isabs(name) or ".." in Path(name).parts:
                raise ValueError(f"unsafe path in archive: {name!r}")
            if info.create_system == 3 and (info.external_attr >> 28) == 0xA:  # symlink
                raise ValueError(f"symlink member rejected: {name!r}")
            target = (dest / name).resolve()
            if not is_within(dest, target):
                raise ValueError(f"path escapes destination: {name!r}")
            target.parent.mkdir(parents=True, exist_ok=True)
            with zf.open(info) as src, open(target, "wb") as out:
                out.write(src.read())
            extracted.append(name)
    return extracted


# ---------------------------------------------------------------------------
# Network target authorization (spec 2)
# ---------------------------------------------------------------------------

_PRIVATE_NETS = [
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("169.254.0.0/16"),
    ipaddress.ip_network("::1/128"),
    ipaddress.ip_network("fc00::/7"),
    ipaddress.ip_network("fe80::/10"),
]

_LOCAL_HOSTNAMES = {"localhost", "localhost.localdomain"}


def is_local_target(host: str) -> bool:
    if host in _LOCAL_HOSTNAMES:
        return True
    try:
        addr = ipaddress.ip_address(host)
    except ValueError:
        return False
    return any(addr in net for net in _PRIVATE_NETS)


def target_authorized(host: str, config: dict) -> tuple[bool, str]:
    """Decide whether a network/DAST target may be scanned.

    Defaults (spec 2): only 127.0.0.1 / localhost / private networks.  Public
    targets require BOTH an explicit entry in ``network.authorized_targets``
    AND ``network.allow_external_targets: true`` - the platform never scans
    arbitrary internet hosts.
    """
    net = config.get("network") or {}
    authorized = [str(t) for t in net.get("authorized_targets", [])]
    authorized = authorized or ["127.0.0.1", "localhost"]
    allow_external = bool(net.get("allow_external_targets", False))
    if host in authorized:
        if is_local_target(host) or host in _LOCAL_HOSTNAMES or allow_external:
            return True, "explicitly authorized in configuration"
        return False, (f"target {host!r} is a public address; set "
                       "network.allow_external_targets: true to scan explicitly listed "
                       "external targets - refusing by default")
    if is_local_target(host) and all(is_local_target(t) or t in _LOCAL_HOSTNAMES
                                     for t in authorized):
        return True, "local/private target within default authorization scope"
    return False, (f"target {host!r} is not in network.authorized_targets and is not a "
                   "local/private default target - refusing to scan")
