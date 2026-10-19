"""Regex/pattern SAST layer.

Covers what AST cannot: Django templates (|safe, autoescape off), secret
material in *any* file type (.env, configs, key files), and lightweight
control-presence signals.  Python sinks are handled by the AST analyzer; both
layers are merged and deduplicated by (file, line, rule).
"""
from __future__ import annotations

import re
from dataclasses import dataclass

SCAN_EXTENSIONS = {
    ".py", ".html", ".htm", ".jinja", ".jinja2", ".js", ".ts", ".tsx", ".jsx",
    ".yml", ".yaml", ".toml", ".ini", ".cfg", ".conf", ".env", ".json", ".sh",
    ".pem", ".key", ".crt", ".properties", ".txt",
}
SKIP_DIR_NAMES = {
    ".git", "node_modules", ".venv", "venv", "__pycache__", ".tox", ".mypy_cache",
    "dist", "build", ".next", "site-packages", "staticfiles", "vendor",
    ".pytest_cache", "migrations",          # REQ-132: generated artifacts excluded
}
MAX_FILE_SIZE = 1_500_000


@dataclass
class PatternRule:
    rule_id: str
    regex: re.Pattern
    extensions: tuple
    note: str = ""


def _c(p):
    return re.compile(p, re.IGNORECASE)


PATTERN_RULES = [
    # templates
    PatternRule("XSS-002", re.compile(r"\|\s*safe\b"), (".html", ".htm", ".jinja", ".jinja2"),
                "|safe filter disables autoescaping"),
    PatternRule("XSS-003", re.compile(r"\{%\s*autoescape\s+off\s*%\}"),
                (".html", ".htm", ".jinja", ".jinja2"), "autoescape off block"),
    # secrets in any text file
    PatternRule("SECRET-004", re.compile(r"\b(AKIA|ASIA)[0-9A-Z]{16}\b"), (), "AWS access key"),
    PatternRule("SECRET-005", re.compile(r"\bgh[pousr]_[A-Za-z0-9]{20,}\b"), (), "GitHub token"),
    PatternRule("SECRET-006", re.compile(r"\b(?:sk|rk)_(?:live|test)_[A-Za-z0-9]{10,}\b"), (),
                "Stripe secret key"),
    PatternRule("SECRET-003", re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----"),
                (".pem", ".key", ".txt", ".crt", ".env", ".py", ".yml", ".yaml", ".json"),
                "private key material"),
]

# generic credential assignment in non-python config-ish files
GENERIC_CRED = re.compile(
    r"(?im)^[^#\n]*\b(password|passwd|pwd|api[_-]?key|secret|token|client[_-]?secret)\b"
    r"\s*[:=]\s*['\"]?([A-Za-z0-9+/_\-\.!@#$%^&*]{8,})")
GENERIC_CRED_EXTS = (".env", ".ini", ".cfg", ".conf", ".yml", ".yaml", ".json",
                     ".properties", ".toml", ".txt", ".sh")

# control-presence (polarity=ok) signals
CONTROL_PATTERNS = [
    ("OK-DEFUSEDXML", re.compile(r"(?m)^\s*(import defusedxml|from defusedxml)"), (".py",),
     ("REQ-079",), "defusedxml imported (hardened XML parsing)"),
    ("OK-RATELIMIT", re.compile(r"(throttle_classes\s*=|@ratelimit|axes\.|django_ratelimit)"),
     (".py",), ("REQ-012", "REQ-049"), "rate limiting / throttling control present"),
    ("OK-SFU", re.compile(r"\.select_for_update\("), (".py",), ("REQ-074",),
     "select_for_update() used for race-sensitive access"),
]


def scan_file_text(relpath: str, text: str) -> tuple[list[dict], list[dict]]:
    """Return (vuln_hits, control_hits) for one file's text."""
    vulns: list[dict] = []
    controls: list[dict] = []
    ext = "." + relpath.rsplit(".", 1)[-1].lower() if "." in relpath else ""

    for rule in PATTERN_RULES:
        if rule.extensions and ext not in rule.extensions:
            continue
        for m in rule.regex.finditer(text):
            line = text.count("\n", 0, m.start()) + 1
            vulns.append({"rule_id": rule.rule_id, "line": line,
                          "snippet": m.group(0), "note": rule.note})

    if ext in GENERIC_CRED_EXTS:
        for m in GENERIC_CRED.finditer(text):
            value = m.group(2)
            if value.lower() in {"none", "null", "true", "false", "${}", "changeme-in-env"} or \
                    value.startswith(("$", "{{", "%(")):
                continue
            line = text.count("\n", 0, m.start()) + 1
            vulns.append({"rule_id": "SECRET-002", "line": line,
                          "snippet": m.group(0).strip(), "note": f"credential '{m.group(1)}' in config"})

    for key, rx, exts, reqs, summary in CONTROL_PATTERNS:
        if ext in exts and rx.search(text):
            controls.append({"rule_key": key, "req_ids": reqs, "summary": summary})

    return vulns, controls


def should_scan(relpath: str) -> bool:
    parts = relpath.split("/")
    if any(p in SKIP_DIR_NAMES for p in parts):
        return False
    if "." not in relpath:
        return False
    ext = "." + relpath.rsplit(".", 1)[1].lower()
    if relpath.endswith(".env") or relpath.split("/")[-1].startswith(".env"):
        return True
    return ext in SCAN_EXTENSIONS
