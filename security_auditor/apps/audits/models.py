"""Audit state models (spec 33).

The Django host project uses SQLite for its application database. Scan state
is kept as auditable JSON artifacts so the platform also runs with zero
external services.
Every audit gets an isolated workspace:

    <workdir>/audits/<audit_id>/
        source/        cloned/extracted project (for github/zip inputs)
        audit.json     full audit state
        reports/       generated reports
        logs/          structured scan logs
"""
from __future__ import annotations

import json
import time
import uuid
from collections import Counter
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional


def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def new_audit_id() -> str:
    return f"audit-{uuid.uuid4().hex[:8]}"


@dataclass
class Project:
    name: str
    source_type: str                      # github | local | zip
    path: str                             # absolute source path to scan
    repo_url: Optional[str] = None
    branch: Optional[str] = None
    commit_sha: Optional[str] = None
    created_at: str = field(default_factory=now_iso)
    profile: dict = field(default_factory=dict)

    def to_dict(self):
        return asdict(self)

    @classmethod
    def from_dict(cls, d):
        return cls(**d)


@dataclass
class Audit:
    """Complete state of one audit run."""
    id: str
    project: dict
    created_at: str = field(default_factory=now_iso)
    finished_at: Optional[str] = None
    status: str = "CREATED"               # CREATED|RUNNING|COMPLETE|FAILED
    config: dict = field(default_factory=dict)
    authorization_confirmed: bool = False
    jobs: list = field(default_factory=list)          # ScanJob dicts
    profile: dict = field(default_factory=dict)
    endpoints: list = field(default_factory=list)
    evidence: list = field(default_factory=list)
    findings: list = field(default_factory=list)
    requirement_results: list = field(default_factory=list)
    test_executions: list = field(default_factory=list)
    settings_values: dict = field(default_factory=dict)
    dependencies_report: dict = field(default_factory=dict)
    network_report: dict = field(default_factory=dict)
    dast_report: dict = field(default_factory=dict)
    score: dict = field(default_factory=dict)
    sast_data: dict = field(default_factory=dict)
    report_paths: dict = field(default_factory=dict)
    logs: list = field(default_factory=list)
    retest_of: Optional[str] = None
    comparison: dict = field(default_factory=dict)
    errors: list = field(default_factory=list)

    def log(self, level: str, message: str) -> None:
        self.logs.append({"ts": now_iso(), "level": level, "message": message})

    def job(self, name: str) -> Optional[dict]:
        for j in self.jobs:
            if j["name"] == name:
                return j
        return None

    def set_job(self, name: str, status: str, error: Optional[str] = None) -> dict:
        job = self.job(name)
        if job is None:
            job = {"name": name, "status": status, "error": None,
                   "started_at": now_iso(), "finished_at": None}
            self.jobs.append(job)
        else:
            job["status"] = status
            if status == "RUNNING" and not job.get("started_at"):
                job["started_at"] = now_iso()
        if status in ("SUCCESS", "FAILED", "SKIPPED"):
            job["finished_at"] = now_iso()
        if error is not None:
            job["error"] = error
        return job

    def to_dict(self):
        return asdict(self)

    @classmethod
    def from_dict(cls, d):
        return cls(**d)


class AuditStore:
    """File-backed persistence: one directory per audit under the workdir."""

    def __init__(self, workdir: str):
        self.root = Path(workdir) / "audits"
        self.root.mkdir(parents=True, exist_ok=True)

    def dir_for(self, audit_id: str) -> Path:
        p = self.root / audit_id
        p.mkdir(parents=True, exist_ok=True)
        return p

    def save(self, audit: Audit) -> Path:
        d = self.dir_for(audit.id)
        # Replace atomically so the API never observes an empty/truncated JSON
        # file while the worker is persisting an in-progress audit.
        target = d / "audit.json"
        temporary = d / "audit.json.tmp"
        temporary.write_text(json.dumps(audit.to_dict(), indent=2, default=str),
                             encoding="utf-8")
        temporary.replace(target)
        self._update_index(audit)
        return d

    def load(self, audit_id: str) -> Audit:
        p = self.root / audit_id / "audit.json"
        if not p.exists():
            raise FileNotFoundError(f"audit {audit_id!r} not found")
        # Windows can briefly hold the target while an in-process worker
        # replaces it atomically.  Retry the read so the host dashboard never
        # turns a normal RUNNING audit into a transient 500/permission error.
        for attempt in range(8):
            try:
                payload = p.read_text(encoding="utf-8")
                return Audit.from_dict(json.loads(payload))
            except (PermissionError, FileNotFoundError):
                if attempt == 7:
                    raise
                time.sleep(0.02 * (attempt + 1))

    def list_audits(self) -> list[dict]:
        # Rebuild the history summary from persisted audit files.  This keeps
        # the dashboard useful after CLI scans and after a server restart;
        # index.json is only a cache, never the source of truth.
        items = []
        for f in sorted(self.root.glob("*/audit.json")):
            try:
                data = json.loads(f.read_text(encoding="utf-8"))
                findings = data.get("findings") or []
                reqs = data.get("requirement_results") or []
                statuses = Counter(r.get("status") for r in reqs)
                severities = Counter(x.get("severity") for x in findings)
                selected_axes = ((data.get("config") or {}).get("scanning") or {}).get(
                    "selected_axes") or []
                items.append({
                    "id": data["id"], "created_at": data.get("created_at"),
                    "status": data.get("status"),
                    "project": (data.get("project") or {}).get("name"),
                    "source_type": (data.get("project") or {}).get("source_type"),
                    "score": (data.get("score") or {}).get("score"),
                    "requirements": len(reqs),
                    "requirements_by_status": dict(statuses),
                    "findings": len(findings),
                    "critical": severities.get("Critical", 0),
                    "high": severities.get("High", 0),
                    "axes": selected_axes,
                })
            except Exception:
                continue
        items.sort(key=lambda i: i.get("created_at") or "", reverse=True)
        return items

    def _update_index(self, audit: Audit) -> None:
        items = [i for i in self.list_audits() if i.get("id") != audit.id]
        items.append({
            "id": audit.id, "created_at": audit.created_at, "status": audit.status,
            "project": (audit.project or {}).get("name"),
        })
        items.sort(key=lambda i: i.get("created_at") or "", reverse=True)
        (self.root / "index.json").write_text(json.dumps(items, indent=2), encoding="utf-8")
