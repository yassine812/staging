"""Core scanner interfaces, finding/evidence models and enums.

Every scanner in the platform (SAST, AST, configuration, dependencies,
network, DAST, automated tests) implements :class:`BaseScanner` and returns a
:class:`ScanResult`.  Findings carry CWE/OWASP metadata and reproducible
evidence; evidence items have a *polarity* so the requirements engine can
distinguish proof-of-vulnerability from proof-of-compliance:

* ``vuln`` - positive evidence that a requirement is violated
* ``ok``   - positive evidence that a control works
* ``info`` - context that supports manual review
"""
from __future__ import annotations

import itertools
import uuid
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from typing import Any, Optional


# ---------------------------------------------------------------------------
# Enums / ordered scales
# ---------------------------------------------------------------------------

SEVERITIES = ["Critical", "High", "Medium", "Low", "Info"]
CONFIDENCES = ["Confirmed", "High", "Medium", "Low", "Potential"]
REQ_STATUSES = ["PASS", "FAIL", "PARTIAL", "NOT_TESTED", "NOT_APPLICABLE", "MANUAL_REVIEW"]
JOB_STATUSES = ["QUEUED", "RUNNING", "SUCCESS", "FAILED", "SKIPPED"]

_SEV_RANK = {s: i for i, s in enumerate(SEVERITIES)}          # lower == worse
_CONF_RANK = {c: i for i, c in enumerate(CONFIDENCES)}        # lower == stronger


def severity_rank(value: str) -> int:
    return _SEV_RANK.get(value, len(SEVERITIES))


def confidence_rank(value: str) -> int:
    return _CONF_RANK.get(value, len(CONFIDENCES))


def worst_severity(values: list[str]) -> str:
    vals = [v for v in values if v in _SEV_RANK]
    return min(vals, key=lambda v: _SEV_RANK[v]) if vals else "Info"


def strongest_confidence(values: list[str]) -> str:
    vals = [v for v in values if v in _CONF_RANK]
    return min(vals, key=lambda v: _CONF_RANK[v]) if vals else "Potential"


def _now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def _short_id(prefix: str) -> str:
    return f"{prefix}-{uuid.uuid4().hex[:10]}"


# ---------------------------------------------------------------------------
# Evidence
# ---------------------------------------------------------------------------

@dataclass
class Evidence:
    """One reproducible piece of audit evidence.

    ``location`` depends on the source type:
      sast/configuration: {"file": ..., "line": ..., "column": ..., "snippet": ...}
      dast/automated:     {"url": ..., "method": ..., "request": ..., "response": ..., "status": ...}
      network:            {"target": ..., "port": ..., "service": ..., "version": ...}
      dependencies:       {"package": ..., "version": ..., "spec": ...}
    Secrets must be masked before being stored (see apps.audits.utils.mask).
    """
    source: str                       # sast|dast|network|configuration|dependencies|automated|internal
    rule_id: str
    polarity: str                     # vuln | ok | info
    summary: str
    location: dict = field(default_factory=dict)
    requirement_ids: list = field(default_factory=list)
    confidence: str = "High"          # drives FAIL (Confirmed/High) vs PARTIAL (review)
    timestamp: str = field(default_factory=_now)
    id: str = field(default_factory=lambda: _short_id("EV"))

    def to_dict(self) -> dict:
        return asdict(self)

    @classmethod
    def from_dict(cls, d: dict) -> "Evidence":
        return cls(**d)


# ---------------------------------------------------------------------------
# Finding
# ---------------------------------------------------------------------------

@dataclass
class Finding:
    """A deduplicated security finding, potentially corroborated by several
    scanners (SAST + DAST + automated test evidence merged into one record)."""
    title: str
    description: str
    severity: str
    confidence: str
    category: str
    cwe: list = field(default_factory=list)
    owasp: str = ""
    requirement_ids: list = field(default_factory=list)
    sources: list = field(default_factory=list)        # which engines produced evidence
    evidence_ids: list = field(default_factory=list)
    file: Optional[str] = None
    line: Optional[int] = None
    endpoint: Optional[str] = None
    request: Optional[str] = None
    response: Optional[str] = None
    proof: str = ""
    remediation: str = ""
    status: str = "OPEN"                               # OPEN | FIXED | ACCEPTED | FALSE_POSITIVE
    dedup_key: str = ""
    retest_status: Optional[str] = None                # None|FIXED|STILL_PRESENT|NEW|REGRESSED
    first_seen: str = field(default_factory=_now)
    last_seen: str = field(default_factory=_now)
    id: str = field(default_factory=lambda: _short_id("FINDING"))

    def to_dict(self) -> dict:
        return asdict(self)

    @classmethod
    def from_dict(cls, d: dict) -> "Finding":
        return cls(**d)


# ---------------------------------------------------------------------------
# Scan result + scanner interface
# ---------------------------------------------------------------------------

@dataclass
class ScanResult:
    scanner: str
    status: str = "SUCCESS"                            # SUCCESS | FAILED | SKIPPED
    findings: list = field(default_factory=list)       # list[Finding]
    evidence: list = field(default_factory=list)       # list[Evidence]
    data: dict = field(default_factory=dict)           # scanner-specific payload
    error: Optional[str] = None
    started_at: str = field(default_factory=_now)
    finished_at: Optional[str] = None

    def to_dict(self) -> dict:
        d = asdict(self)
        d["findings"] = [f.to_dict() if hasattr(f, "to_dict") else f for f in self.findings]
        d["evidence"] = [e.to_dict() if hasattr(e, "to_dict") else e for e in self.evidence]
        return d


class BaseScanner:
    """Interface implemented by every engine.

    A scanner must NEVER raise out of :meth:`run`; it returns a ScanResult
    with status FAILED and an error message instead, so that one broken
    scanner cannot kill the whole audit (spec 36).
    """

    name: str = "base"
    description: str = ""

    def run(self, context: "AuditContext") -> ScanResult:  # pragma: no cover - interface
        raise NotImplementedError

    def safe_run(self, context: "AuditContext") -> ScanResult:
        try:
            result = self.run(context)
            result.finished_at = _now()
            if result.status not in JOB_STATUSES:
                result.status = "SUCCESS"
            return result
        except Exception as exc:  # noqa: BLE001 - intentional isolation boundary
            return ScanResult(scanner=self.name, status="FAILED", error=f"{type(exc).__name__}: {exc}",
                              finished_at=_now())


# ---------------------------------------------------------------------------
# Audit context passed to every scanner
# ---------------------------------------------------------------------------

@dataclass
class AuditContext:
    source_dir: str                                    # absolute path to scanned source
    profile: dict = field(default_factory=dict)        # project discovery output
    config: dict = field(default_factory=dict)         # effective security-audit.yml
    base_url: Optional[str] = None                     # DAST target once app is up
    accounts: dict = field(default_factory=dict)       # role -> {username,password,...}
    authorization_confirmed: bool = False              # required for network/DAST
    logger: Any = None                                 # callable(level, message)
    _counter: Any = field(default_factory=lambda: itertools.count(1), repr=False)

    def log(self, level: str, message: str) -> None:
        if self.logger:
            self.logger(level, message)

    def next_id(self, prefix: str) -> str:
        return f"{prefix}-{next(self._counter):04d}"

    def network_allowed(self) -> bool:
        return bool(self.authorization_confirmed and self.config.get("scanning", {}).get("network", True))

    def dast_allowed(self) -> bool:
        return bool(self.authorization_confirmed and self.config.get("scanning", {}).get("dast", True))
