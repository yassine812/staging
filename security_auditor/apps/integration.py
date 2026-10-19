"""Host-project integration facade.

The auditor is intended to be embedded in another application.  This module
is the stable boundary that host code calls; it does not upload projects and
it does not start a web server.  The host supplies its own project directory,
background job runner and UI.

Typical use from a host project's service or task:

    auditor = InternalSecurityAuditor(BASE_DIR / ".security-audits")
    result = auditor.run_scan(BASE_DIR, axes=["A1", "A2"])

The returned dictionary is the same enriched audit object used by the internal
dashboard/API, including the complete requirement matrix and traceability
locations.
"""
from __future__ import annotations

from pathlib import Path
from typing import Iterable

from security_auditor.apps.audits.axes import enrich
from security_auditor.apps.audits.models import Audit, AuditStore
from security_auditor.apps.audits.pipeline import AuditPipeline


class InternalSecurityAuditor:
    """Run security checks against modules in the host project.

    ``workdir`` belongs to the host application and stores scan history.  The
    auditor only reads the supplied project directory and writes its audit
    state under that workdir; it never accepts an uploaded archive.
    """

    def __init__(self, workdir: str | Path,
                 config_path: str | Path | None = None):
        self.workdir = Path(workdir).expanduser().resolve()
        self.store = AuditStore(str(self.workdir))
        self.pipeline = AuditPipeline(
            self.store,
            config_path=str(Path(config_path).expanduser().resolve())
            if config_path else None,
        )

    @staticmethod
    def _project(project_path: str | Path, name: str | None = None) -> dict:
        source = Path(project_path).expanduser().resolve()
        if not source.is_dir():
            raise ValueError(f"internal project directory not found: {source}")
        return {
            "name": name or source.name or "internal-project",
            "source_type": "local",
            "path": str(source),
        }

    def create_scan(self, project_path: str | Path,
                    axes: Iterable[str] | None = None,
                    authorization_confirmed: bool = False,
                    name: str | None = None) -> Audit:
        """Create and persist a scan before the host runs it in its worker."""
        return self.pipeline.create_audit(
            self._project(project_path, name=name),
            authorization_confirmed=authorization_confirmed,
            selected_axes=list(axes or []),
        )

    def run_scan(self, project_path: str | Path,
                 axes: Iterable[str] | None = None,
                 authorization_confirmed: bool = False,
                 name: str | None = None) -> dict:
        """Run one internal scan synchronously and return enriched JSON data."""
        audit = self.create_scan(project_path, axes=axes,
                                 authorization_confirmed=authorization_confirmed,
                                 name=name)
        completed = self.pipeline.run_full(audit)
        return enrich(completed.to_dict())

    def run_existing(self, audit_id: str) -> dict:
        """Resume a created audit from the host application's worker."""
        audit = self.store.load(audit_id)
        return enrich(self.pipeline.run_full(audit).to_dict())

    def get_scan(self, audit_id: str) -> dict:
        """Read one scan with axis and requirement-location enrichment."""
        return enrich(self.store.load(audit_id).to_dict())

    def history(self) -> list[dict]:
        """Return the host project's persisted scan history."""
        return self.store.list_audits()


def build_internal_app(workdir: str | Path,
                       config_path: str | Path | None = None,
                       mount_path: str = ""):
    """Build the optional dashboard/API sub-application for a host app.

    This creates an ASGI application but does not run a server.  A FastAPI or
    Starlette host can mount it, for example at ``/security-audit``.  Django
    or another host can use :class:`InternalSecurityAuditor` directly and
    render the returned dictionaries in its own internal UI.
    """
    from security_auditor.apps.api.server import build_app

    store = AuditStore(str(Path(workdir).expanduser().resolve()))
    return build_app(store,
                     config_path=str(Path(config_path).expanduser().resolve())
                     if config_path else None,
                     workdir=str(Path(workdir).expanduser().resolve()),
                     base_path=mount_path)
