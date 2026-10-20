"""REST API + dashboard server (FastAPI).

Endpoints (spec 34):
    POST /api/auth/token            obtain a bearer token
    GET  /api/projects              project registry (derived from audits)
    POST /api/projects              register project {name, source_type, path|repo_url}
    GET  /api/audits                list audits
    POST /api/audits                create + queue full audit
    GET  /api/audits/{id}           audit state
    GET  /api/audits/{id}/requirements | /findings | /endpoints | /jobs | /logs
    POST /api/audits/{id}/retest    queue a retest
    GET  /api/reports/{id}/{fmt}    download report (html|json|csv|pdf)
    GET  /api/jobs                  worker queue status

Authentication: Bearer tokens (scrypt-hashed users, RBAC).  The dashboard is
served at / (single page, calls this API).
"""
from __future__ import annotations

import json
from pathlib import Path
from typing import Optional

from fastapi import Depends, FastAPI, HTTPException, Request
from fastapi.responses import FileResponse, HTMLResponse, JSONResponse
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer

from security_auditor.apps.audits.models import AuditStore
from security_auditor.apps.audits.axes import normalize_selected_axes
from security_auditor.apps.audits.pipeline import AuditPipeline
from security_auditor.apps.audits.retest import run_retest
from security_auditor.apps.users.auth import AuthError, ROLE_PERMISSIONS, UserStore
from security_auditor.worker.queue import JobQueue

FRONTEND = Path(__file__).resolve().parents[2] / "web" / "dashboard.html"
bearer = HTTPBearer(auto_error=False)

def _discover_internal_modules(project_root: str | Path) -> list[dict]:
    """List Django apps belonging to the embedded host project."""
    root = Path(project_root).expanduser().resolve()
    # Support both common Django layouts: an ``apps/`` container (used by the
    # standalone auditor) and top-level app packages (used by audit2).
    apps_root = root / "apps"
    candidates = []
    if apps_root.is_dir():
        candidates.extend((folder, f"apps.{folder.name}")
                          for folder in apps_root.iterdir())
    candidates.extend(
        (folder, folder.name)
        for folder in root.iterdir()
        if folder.is_dir() and folder != apps_root
    )
    modules = []
    for folder, module_id in sorted(candidates, key=lambda item: item[0].name.lower()):
        if (folder / "apps.py").is_file():
            modules.append({
                "id": module_id,
                "name": folder.name.replace("_", " ").title(),
                "path": str(folder.relative_to(root)).replace("\\", "/"),
            })
    return modules


def build_app(store: AuditStore, config_path: str | None = None,
              workdir: str | None = None,
              base_path: str = "",
              project_root: str | None = None) -> FastAPI:
    workdir = workdir or str(store.root.parent)
    project_root = str(Path(project_root).expanduser().resolve()) if project_root else None
    users = UserStore(workdir)
    if not users._read()["users"]:                    # bootstrap default admin
        users.create_user("admin", "admin-audit-2026", "admin")
    queue = JobQueue(max_workers=2)
    app = FastAPI(title="Django Security Auditor", version="0.1.0")
    app.state.base_path = base_path.rstrip("/")

    def auth(request: Request, permission: str = "read"):
        # The Django integration authenticates the request before forwarding
        # it here.  In that mode, use the host session identity instead of
        # asking the user to authenticate a second time in the auditor store.
        django_user = request.headers.get("x-django-user", "").strip()
        if django_user:
            role = request.headers.get("x-django-role", "viewer").strip()
            if role not in ROLE_PERMISSIONS:
                role = "viewer"
            if permission not in ROLE_PERMISSIONS[role]:
                raise HTTPException(status_code=403,
                                    detail=f"role '{role}' lacks permission '{permission}'")
            return django_user, role

        creds: Optional[HTTPAuthorizationCredentials] = None
        header = request.headers.get("authorization", "")
        if header.lower().startswith("bearer "):
            creds = HTTPAuthorizationCredentials(scheme="bearer",
                                                 credentials=header.split(" ", 1)[1])
        try:
            return users.require(creds.credentials if creds else None, permission)
        except AuthError as exc:
            raise HTTPException(status_code=401, detail=str(exc))

    # ---- auth ---------------------------------------------------------
    @app.post("/api/auth/token")
    def token(body: dict):
        try:
            tok = users.verify(body.get("username", ""), body.get("password", ""))
        except AuthError as exc:
            raise HTTPException(status_code=401, detail=str(exc))
        users.audit_log("auth.login", {"username": body.get("username")})
        return {"token": tok}

    # ---- projects -------------------------------------------------------
    @app.get("/api/projects")
    def projects(request: Request):
        auth(request)
        seen = {}
        for item in store.list_audits():
            try:
                audit = store.load(item["id"])
                p = audit.project
                seen.setdefault(p.get("name"), p)
            except FileNotFoundError:
                continue
        return {"projects": list(seen.values())}

    @app.get("/api/modules")
    def modules(request: Request):
        auth(request)
        return {"modules": _discover_internal_modules(project_root)}

    # ---- requirement catalogue -------------------------------------------
    @app.get("/api/requirements/catalogue")
    def requirement_catalogue(request: Request):
        auth(request)
        from security_auditor.apps.requirements_engine.loader import load_requirements
        records = [item.to_dict() for item in load_requirements()]
        return {"requirements": records, "total": len(records)}

    @app.post("/api/requirements/catalogue")
    def create_catalogue_requirement(body: dict, request: Request):
        user, role = auth(request, "manage_requirements")
        from security_auditor.apps.requirements_engine.loader import save_catalogue_requirement
        try:
            record = save_catalogue_requirement(body)
        except (TypeError, ValueError) as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc
        users.audit_log("requirement.create", {"user": user, "requirement_id": record["id"]})
        return {"requirement": record}

    @app.put("/api/requirements/catalogue/{requirement_id}")
    def update_catalogue_requirement(requirement_id: str, body: dict, request: Request):
        user, role = auth(request, "manage_requirements")
        from security_auditor.apps.requirements_engine.loader import save_catalogue_requirement
        try:
            record = save_catalogue_requirement(body, requirement_id)
        except (TypeError, ValueError) as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc
        users.audit_log("requirement.update", {"user": user, "requirement_id": record["id"]})
        return {"requirement": record}

    @app.delete("/api/requirements/catalogue/{requirement_id}")
    def delete_catalogue_requirement(requirement_id: str, request: Request):
        user, role = auth(request, "manage_requirements")
        from security_auditor.apps.requirements_engine.loader import delete_catalogue_requirement as remove_requirement
        try:
            remove_requirement(requirement_id)
        except KeyError as exc:
            raise HTTPException(status_code=404, detail="exigence introuvable") from exc
        users.audit_log("requirement.delete", {"user": user, "requirement_id": requirement_id})
        return {"status": "deleted", "requirement_id": requirement_id}

    @app.post("/api/projects")
    def create_project(body: dict, request: Request):
        user, role = auth(request, "create_audit")
        users.audit_log("project.create", {"user": user, "project": body.get("name")})
        return {"status": "registered", "project": body}

    # ---- audits -----------------------------------------------------------
    @app.get("/api/audits")
    def audits(request: Request):
        auth(request)
        return {"audits": store.list_audits()}

    @app.post("/api/audits")
    def create_audit(body: dict, request: Request):
        user, role = auth(request, "create_audit")
        project = body.get("project") or {}
        try:
            selected_axes = normalize_selected_axes(body.get("axes") or [])
        except ValueError as exc:
            raise HTTPException(status_code=400, detail=str(exc))
        if project_root:
            selected_modules = body.get("modules")
            if not isinstance(selected_modules, list) or not selected_modules:
                raise HTTPException(status_code=400,
                                    detail="Sélectionnez au moins un module Django à analyser")
            project = {
                "name": project.get("name") or "Projet Django intégré",
                "source_type": "internal",
                "path": project_root,
                "modules": selected_modules,
            }
        elif not project.get("path") and not project.get("repo_url"):
            raise HTTPException(status_code=400, detail="project.path or repo_url required")
        if project.get("source_type") == "github":
            from security_auditor.apps.projects.sources import acquire_github
            import datetime as dt
            dest = str(Path(store.root) / f"clone-{dt.datetime.now().strftime('%H%M%S%f')}")
            info = acquire_github(project["repo_url"], dest, branch=project.get("branch"),
                                  token=project.get("token"))
            project = {"name": project.get("name") or Path(project["repo_url"]).name,
                       "source_type": "github", "path": info["path"],
                       "repo_url": info["repo_url"], "branch": info["branch"],
                       "commit_sha": info["commit_sha"]}
        else:
            project.setdefault("source_type", "local")
            project.setdefault("name", Path(project["path"]).name)
            project["path"] = str(Path(project["path"]).expanduser().resolve())

        pipeline = AuditPipeline(store, config_path)
        audit = pipeline.create_audit(project,
                                      authorization_confirmed=bool(
                                          body.get("authorization_confirmed")),
                                      selected_axes=selected_axes)
        network_override = body.get("network") or {}
        if project_root and network_override:
            targets = network_override.get("authorized_targets")
            if targets is not None:
                if not isinstance(targets, list) or not targets or len(targets) > 20:
                    raise HTTPException(status_code=400,
                                        detail="network.authorized_targets must contain 1-20 targets")
                audit.config.setdefault("network", {})["authorized_targets"] = [
                    str(target).strip() for target in targets if str(target).strip()
                ]
            net = audit.config.setdefault("network", {})
            allow_external = bool(network_override.get("allow_external_targets", False))
            full_scan = bool(network_override.get("allow_full_port_scan", False))
            requested_ports = network_override.get("scan_ports")
            if requested_ports is not None and (
                not isinstance(requested_ports, str) or requested_ports not in {"common", "all"}
            ):
                if not isinstance(requested_ports, list) or not requested_ports or len(requested_ports) > 100:
                    raise HTTPException(status_code=400,
                                        detail="network.scan_ports must contain 1-100 TCP ports")
                try:
                    requested_ports = [int(port) for port in requested_ports]
                except (TypeError, ValueError) as exc:
                    raise HTTPException(status_code=400,
                                        detail="network.scan_ports must contain valid TCP ports") from exc
                if any(port < 1 or port > 65535 for port in requested_ports):
                    raise HTTPException(status_code=400,
                                        detail="network.scan_ports values must be between 1 and 65535")
                requested_ports = list(dict.fromkeys(requested_ports))
            if (allow_external or full_scan) and not audit.authorization_confirmed:
                raise HTTPException(status_code=400,
                                    detail="authorization confirmation is required for public or full port scans")
            net["allow_external_targets"] = allow_external
            net["allow_full_port_scan"] = full_scan
            net["scan_ports"] = "all" if full_scan else (requested_ports or "common")
            store.save(audit)
        users.audit_log("audit.create", {"user": user, "audit_id": audit.id})
        queue.submit("full-audit", pipeline.run_full, audit)
        return {"audit_id": audit.id, "status": "QUEUED"}

    @app.get("/api/audits/{audit_id}")
    def audit_detail(audit_id: str, request: Request):
        auth(request)
        try:
            audit = store.load(audit_id)
        except FileNotFoundError:
            raise HTTPException(status_code=404, detail="audit not found")
        # enrich with the 4-axis attribution (same logic as the reports)
        from security_auditor.apps.audits.axes import enrich
        return enrich(audit.to_dict())

    def _sub(audit_id: str, attr: str, request: Request):
        auth(request)
        try:
            audit = store.load(audit_id)
        except FileNotFoundError:
            raise HTTPException(status_code=404, detail="audit not found")
        return {attr: getattr(audit, attr)}

    @app.get("/api/audits/{audit_id}/requirements")
    def audit_requirements(audit_id: str, request: Request):
        auth(request)
        try:
            audit = store.load(audit_id)
        except FileNotFoundError:
            raise HTTPException(status_code=404, detail="audit not found")
        from security_auditor.apps.audits.axes import enrich
        data = enrich(audit.to_dict())
        results = data.get("requirement_results", [])
        from security_auditor.apps.requirements_engine.loader import load_requirements
        catalogue_total = len(load_requirements())
        return {"requirement_results": results, "total": len(results),
                "catalogue_total": catalogue_total,
                "complete": len(results) == catalogue_total}

    @app.get("/api/audits/{audit_id}/findings")
    def audit_findings(audit_id: str, request: Request):
        return _sub(audit_id, "findings", request)

    @app.get("/api/audits/{audit_id}/endpoints")
    def audit_endpoints(audit_id: str, request: Request):
        return _sub(audit_id, "endpoints", request)

    @app.get("/api/audits/{audit_id}/jobs")
    def audit_jobs(audit_id: str, request: Request):
        return _sub(audit_id, "jobs", request)

    @app.get("/api/audits/{audit_id}/logs")
    def audit_logs(audit_id: str, request: Request):
        return _sub(audit_id, "logs", request)

    @app.get("/api/audits/{audit_id}/evidence")
    def audit_evidence(audit_id: str, request: Request):
        return _sub(audit_id, "evidence", request)

    @app.post("/api/audits/{audit_id}/retest")
    def retest(audit_id: str, body: dict, request: Request):
        user, role = auth(request, "retest")
        path = body.get("path")
        if not path:
            raise HTTPException(status_code=400, detail="path required")
        users.audit_log("audit.retest", {"user": user, "audit_id": audit_id})
        job = queue.submit("retest", run_retest, store, audit_id, path,
                           bool(body.get("authorization_confirmed")), config_path)
        return {"job_id": job.job_id, "status": "QUEUED"}

    @app.get("/api/jobs")
    def jobs(request: Request):
        auth(request)
        return {"jobs": queue.list()}

    # ---- reports -----------------------------------------------------------
    @app.get("/api/reports/{audit_id}/{fmt}")
    def report(audit_id: str, fmt: str, request: Request):
        auth(request)
        store.dir_for(audit_id)
        base = store.root / audit_id / "reports"
        names = {"html": "report.html", "json": "report.json", "pdf": "report.pdf",
                 "pdf-full": "report-full.pdf", "pdf_full": "report-full.pdf",
                 "pdf-req": "report-requirements.pdf", "pdf_req": "report-requirements.pdf",
                 "csv": "findings.csv", "csv-req": "requirements.csv",
                 "csv_requirements": "requirements.csv"}
        if fmt not in names:
            raise HTTPException(status_code=400,
                                detail="format must be html|json|pdf|pdf-full|pdf-req|csv|csv-req")
        f = base / names[fmt]
        if not f.exists():
            raise HTTPException(status_code=404, detail="report not generated yet")
        # The readable HTML report is UTF-8 so browsers and API clients decode
        # the French labels consistently on Windows and Linux.
        if fmt == "html":
            return FileResponse(f, media_type="text/html; charset=utf-8")
        return FileResponse(f)

    # ---- dashboard ------------------------------------------------------------
    @app.get("/", response_class=HTMLResponse)
    @app.get("/audits/{rest:path}", response_class=HTMLResponse)
    def dashboard():
        if FRONTEND.exists():
            page = FRONTEND.read_text(encoding="utf-8")
            # When the host mounts this sub-application below a prefix, make
            # the browser call the mounted API instead of the host root API.
            marker = 'const API="";'
            configured = f"const API={json.dumps(app.state.base_path)};"
            return page.replace(marker, configured, 1)
        return "<h1>dashboard missing</h1>"

    @app.exception_handler(Exception)
    async def unhandled(request: Request, exc: Exception):
        return JSONResponse(status_code=500, content={"detail": str(exc)[:300]})

    return app
