"""security-audit.yml configuration handling (spec 32)."""
from __future__ import annotations

from pathlib import Path
from typing import Optional

import yaml

DEFAULT_CONFIG: dict = {
    "project": {"framework": "django"},
    "scanning": {
        "sast": True,
        "dependencies": True,
        "network": True,
        "dast": True,
        "requirements": True,
        "security_tests": True,
    },
    "network": {
        "authorized_targets": ["127.0.0.1", "localhost"],
        "scan_ports": "common",
        "allow_external_targets": False,
        "allow_full_port_scan": False,
        "ports": "common",
        "timeout": 120,
    },
    "dast": {
        "enabled": True,
        "target": "auto",
        "allow_local_runserver": True,   # Django/SQLite local runtime
        "timeout": 300,
    },
    "requirements": {"total": 137},
    "severity": {"critical": True, "high": True, "medium": True, "low": True},
    "accounts": {},
}


def _deep_merge(base: dict, override: dict) -> dict:
    out = dict(base)
    for key, value in (override or {}).items():
        if isinstance(value, dict) and isinstance(out.get(key), dict):
            out[key] = _deep_merge(out[key], value)
        else:
            out[key] = value
    return out


def load_config(path: Optional[str] = None) -> dict:
    """Load security-audit.yml merged over secure defaults."""
    config = dict(DEFAULT_CONFIG)
    if path and Path(path).is_file():
        data = yaml.safe_load(Path(path).read_text(encoding="utf-8")) or {}
        config = _deep_merge(DEFAULT_CONFIG, data)
    return config


def write_default_config(path: str) -> Path:
    p = Path(path)
    text = (
        "# security-audit.yml - audit platform configuration\n"
        "# Only targets listed under network.authorized_targets may be network-scanned.\n"
        + yaml.safe_dump(DEFAULT_CONFIG, sort_keys=False)
    )
    p.write_text(text, encoding="utf-8")
    return p
