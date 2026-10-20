"""Audit orchestration pipeline (spec 1, 20).

Runs the full scan sequence as isolated jobs; a failing scanner degrades its
own step to FAILED/SKIPPED and dependent requirements become NOT_TESTED - it
never crashes the audit and never converts an unavailable test into PASS
(spec 36).
"""
from __future__ import annotations

import time
from datetime import datetime, timezone

from security_auditor.apps.audits.config import load_config
from security_auditor.apps.audits.models import Audit, AuditStore
from security_auditor.apps.audits.utils import mask_secrets
from security_auditor.apps.projects.discovery import discover_project
from security_auditor.apps.requirements_engine.loader import load_requirements
from security_auditor.scanners.base import AuditContext, Evidence, Finding
from security_auditor.scanners.configuration.django_settings import DjangoSettingsScanner
from security_auditor.scanners.correlation.engine import (compute_score, correlate_requirements,
                                         dedupe_findings, internal_checks)
from security_auditor.scanners.dast.endpoints import discover_endpoints
from security_auditor.scanners.dast.sandbox import start_application, stop_application
from security_auditor.scanners.dast.scanner import DASTScanner
from security_auditor.scanners.dependencies.scanner import DependencyScanner
from security_auditor.scanners.network.scanner import NetworkScanner
from security_auditor.scanners.sast.scanner import SASTScanner
from security_auditor.security_tests.framework import TestContext
from security_auditor.security_tests.tests import TestRunner

PIPELINE_STEPS = ["discovery", "requirements", "sast", "settings", "dependencies",
                  "endpoints", "app_start", "dast", "security_tests", "network",
                  "correlation", "report"]


def _evidence_location(item: dict) -> str:
    """Return a short, actionable location for a finding/evidence record."""
    location = item.get("location") or {}
    file_name = item.get("file") or location.get("file")
    line = item.get("line") or location.get("line")
    if file_name:
        return f"{file_name}:{line}" if line else str(file_name)
    endpoint = item.get("endpoint") or location.get("url") or location.get("endpoint")
    if endpoint:
        return str(endpoint)
    target = location.get("target")
    port = location.get("port")
    if target:
        return f"{target}:{port}" if port else str(target)
    package = location.get("package")
    if package:
        return f"dependency:{package}"
    setting = location.get("setting")
    if setting:
        return f"setting:{setting}"
    return "-"


class AuditPipeline:
    def __init__(self, store: AuditStore, config_path: str | None = None):
        self.store = store
        self.config_path = config_path
        self._log_listeners = []

    # ------------------------------------------------------------------
    @staticmethod
    def _applicability(requirements, profile: dict | None = None) -> dict:
        """Exigences non applicables au projet (évite un faux NOT_TESTED).

        Ex. : les exigences propres à Django REST Framework n'ont pas de sens
        sur un projet qui n'utilise pas DRF - elles deviennent NON APPLICABLES
        au lieu de rester « non testées » à jamais.
        """
        applicability: dict[str, bool] = {}
        profile = profile or {}
        deps = {str(d.get("name", "")).lower() for d in (profile.get("dependencies") or [])}
        uses_drf = any("djangorestframework" in d or d == "rest-framework" for d in deps)
        if not uses_drf:
            for req_id in ("REQ-045", "REQ-046", "REQ-047", "REQ-048", "REQ-052"):
                applicability[req_id] = False
        return applicability

    # ------------------------------------------------------------------
    def create_audit(self, project: dict, authorization_confirmed: bool = False,
                     retest_of: str | None = None,
                     selected_axes: list[str] | None = None) -> Audit:
        from security_auditor.apps.audits.models import new_audit_id
        config = load_config(self.config_path)
        if selected_axes:
            from security_auditor.apps.audits.axes import AXIS_SCANNERS, normalize_selected_axes
            selected = normalize_selected_axes(selected_axes)
            scanning = config.setdefault("scanning", {})
            scanning["selected_axes"] = selected
            scanner_jobs = {job for axis in selected for job in AXIS_SCANNERS[axis]}
            for job in ("sast", "settings", "dependencies", "network", "dast",
                        "security_tests"):
                scanning[job] = job in scanner_jobs
        audit = Audit(id=new_audit_id(), project=project, config=config,
                      authorization_confirmed=authorization_confirmed,
                      retest_of=retest_of)
        audit.log("INFO", f"Audit created for project '{project.get('name')}' "
                          f"(source: {project.get('source_type')})")
        self.store.save(audit)
        return audit

    # ------------------------------------------------------------------
    def run_full(self, audit: Audit) -> Audit:
        audit.status = "RUNNING"
        self.store.save(audit)
        ctx = AuditContext(
            source_dir=audit.project["path"],
            config=audit.config,
            authorization_confirmed=audit.authorization_confirmed,
            logger=lambda level, msg: audit.log(level, mask_secrets(msg)),
        )

        scanning = audit.config.get("scanning", {})

        # -- 1. project discovery ---------------------------------------
        self._job(audit, "discovery", lambda: self._step_discovery(audit, ctx))

        # -- 2. requirements initialization ------------------------------
        self._job(audit, "requirements", lambda: self._step_requirements(audit))

        # -- 3. SAST (pattern + AST) -------------------------------------
        if scanning.get("sast", True):
            self._job(audit, "sast", lambda: self._step_scanner(audit, ctx, SASTScanner()))
        else:
            audit.set_job("sast", "SKIPPED", "disabled in configuration")

        # -- 4. Django settings ------------------------------------------
        if scanning.get("settings", True):
            self._job(audit, "settings", lambda: self._step_scanner(audit, ctx,
                                                                     DjangoSettingsScanner()))
        else:
            audit.set_job("settings", "SKIPPED", "axis not selected")

        # -- 5. dependencies ------------------------------------------------
        if scanning.get("dependencies", True):
            self._job(audit, "dependencies", lambda: self._step_scanner(audit, ctx,
                                                                        DependencyScanner()))
        else:
            audit.set_job("dependencies", "SKIPPED", "disabled in configuration")

        # -- 6. endpoint discovery -------------------------------------------
        if scanning.get("dast", True) or scanning.get("security_tests", True):
            self._job(audit, "endpoints", lambda: self._step_endpoints(audit, ctx))
        else:
            audit.set_job("endpoints", "SKIPPED", "axis not selected")

        # -- 7. application startup (sandbox) -----------------------------------
        startup = None
        if ctx.dast_allowed() and scanning.get("dast", True):
            self._job(audit, "app_start", lambda: None)  # placeholder status
            audit.set_job("app_start", "RUNNING")
            audit.log("INFO", "Starting isolated application instance for DAST")
            startup = start_application(ctx.source_dir, audit.config,
                                        audit.project.get("source_type", "local"),
                                        profile=ctx.profile)
            if startup.started:
                ctx.base_url = startup.base_url
                audit.set_job("app_start", "SUCCESS")
                audit.log("INFO", f"Application started at {startup.base_url} "
                                  f"({startup.method})")
            else:
                audit.set_job("app_start", "FAILED", startup.reason)
                audit.log("WARN", f"Application could not start: {startup.reason[:300]}")
        else:
            reason = ("authorization not confirmed" if not audit.authorization_confirmed
                      else "DAST disabled in configuration")
            audit.set_job("app_start", "SKIPPED", reason)

        # -- 8. DAST -------------------------------------------------------------
        if scanning.get("dast", True):
            self._job(audit, "dast", lambda: self._step_scanner(audit, ctx, DASTScanner()))
        else:
            audit.set_job("dast", "SKIPPED", "disabled in configuration")

        # -- 9. automated security tests -------------------------------------------
        if scanning.get("security_tests", True) or scanning.get("dast", True):
            self._job(audit, "security_tests", lambda: self._step_security_tests(audit, ctx))
        else:
            audit.set_job("security_tests", "SKIPPED", "disabled in configuration")

        # -- 10. network ------------------------------------------------------------
        if scanning.get("network", True):
            self._job(audit, "network", lambda: self._step_scanner(audit, ctx, NetworkScanner()))
        else:
            audit.set_job("network", "SKIPPED", "disabled in configuration")

        # -- cleanup sandbox ---------------------------------------------------------
        if startup is not None:
            stop_application(startup)

        # -- 11. correlation -----------------------------------------------------------
        self._job(audit, "correlation", lambda: self._step_correlation(audit))

        # -- 12. report ------------------------------------------------------------------
        self._job(audit, "report", lambda: self._step_report(audit))

        audit.status = "COMPLETE"
        audit.finished_at = datetime.now(timezone.utc).isoformat(timespec="seconds")
        audit.log("INFO", "Audit complete")
        self.store.save(audit)
        return audit

    # ------------------------------------------------------------------
    def _job(self, audit: Audit, name: str, fn):
        audit.set_job(name, "RUNNING")
        self.store.save(audit)
        started = time.time()
        try:
            fn()
            job = audit.job(name)
            if job and job["status"] == "RUNNING":
                audit.set_job(name, "SUCCESS")
        except Exception as exc:  # noqa: BLE001 - isolation boundary
            audit.set_job(name, "FAILED", str(exc)[:500])
            audit.log("ERROR", f"step {name} failed: {exc}")
        finally:
            audit.log("INFO", f"step {name} finished in {time.time() - started:.1f}s")
            self.store.save(audit)

    # ------------------------------------------------------------------
    def _step_discovery(self, audit: Audit, ctx: AuditContext):
        profile = discover_project(ctx.source_dir)
        audit.profile = profile
        ctx.profile = profile
        audit.project["profile"] = {
            "is_django": profile["is_django"],
            "django_version_hint": profile.get("django_version_hint"),
            "databases": profile.get("databases"),
            "api": profile.get("api"),
        }
        if not profile["is_django"]:
            audit.log("WARN", "Django was not detected - audit continues but "
                              "Django-specific checks may be limited")
        audit.log("INFO", f"Project discovered: django={profile['is_django']}, "
                          f"deps={len(profile['dependencies'])}, "
                          f"py_files={profile['stats']['python_files']}")

    def _step_requirements(self, audit: Audit):
        reqs = load_requirements()
        audit.log("INFO", f"Loaded {len(reqs)} security requirements")
        audit.requirement_results = []   # filled by correlation
        return reqs

    def _step_scanner(self, audit: Audit, ctx: AuditContext, scanner):
        result = scanner.safe_run(ctx)
        audit.log("INFO", f"{scanner.name}: status={result.status}, "
                          f"findings={len(result.findings)}, evidence={len(result.evidence)}")
        if result.error:
            audit.set_job(scanner.name if scanner.name != "settings" else "settings",
                          result.status, result.error)
        audit.evidence += [e.to_dict() for e in result.evidence]
        audit.findings += [f.to_dict() for f in result.findings]
        if scanner.name == "sast":
            audit.sast_data = result.data
        elif scanner.name == "settings":
            audit.settings_values = result.data.get("settings", {})
        elif scanner.name == "dependencies":
            audit.dependencies_report = result.data
        elif scanner.name == "network":
            audit.network_report = result.data
        elif scanner.name == "dast":
            audit.dast_report = result.data
        if result.status == "FAILED":
            audit.set_job(scanner.name, "FAILED", result.error or "scanner error")
        elif result.status == "SKIPPED":
            audit.set_job(scanner.name, "SKIPPED", result.error)

    def _step_endpoints(self, audit: Audit, ctx: AuditContext):
        eps = discover_endpoints(ctx.source_dir, audit.profile.get("urls_files"))
        audit.endpoints = eps
        ctx.endpoints = eps
        audit.log("INFO", f"Endpoint discovery: {len(eps)} endpoints inventoried")

    def _step_security_tests(self, audit: Audit, ctx: AuditContext):
        tctx = TestContext(base_url=ctx.base_url, endpoints=audit.endpoints,
                           accounts=(audit.config.get("accounts") or {}),
                           profile=audit.profile)
        executions, evidence, findings = TestRunner().run_all(tctx)
        audit.test_executions = executions
        audit.evidence += [e.to_dict() for e in evidence]
        audit.findings += [f.to_dict() for f in findings]
        passed = sum(1 for e in executions if e["status"] == "PASS")
        failed = sum(1 for e in executions if e["status"] == "FAIL")
        not_tested = sum(1 for e in executions if e["status"] == "NOT_TESTED")
        audit.log("INFO", f"Security tests: {passed} passed, {failed} failed, "
                          f"{not_tested} not testable")

    def _step_correlation(self, audit: Audit):
        requirements = load_requirements()
        evidence = [Evidence.from_dict(e) for e in audit.evidence]
        findings = [Finding.from_dict(f) for f in audit.findings]

        # internal platform checks add evidence for REQ-130..137
        evidence += internal_checks(audit, findings, audit.sast_data or {})

        deduped = dedupe_findings(findings)
        audit.log("INFO", f"Deduplication: {len(findings)} raw findings -> "
                          f"{len(deduped)} unique findings")

        job_states = {j["name"]: j["status"] for j in audit.jobs}
        results = correlate_requirements(
            requirements, evidence, job_states,
            applicability=self._applicability(requirements, audit.profile or {}))
        # Make the requirement matrix self-contained: consumers should be able
        # to understand a result without reopening the YAML catalogue.
        from security_auditor.apps.audits.axes import enrich_requirement_result
        for result in results:
            enrich_requirement_result(result)
        audit.requirement_results = results
        audit.findings = [f.to_dict() for f in deduped]
        audit.evidence = [e.to_dict() for e in evidence]

        # link findings -> requirement results (cross refs for the UI/report)
        req_findings = {}
        for f in deduped:
            for rid in f.requirement_ids:
                req_findings.setdefault(rid, []).append(f.id)
        for r in audit.requirement_results:
            r["finding_ids"] = req_findings.get(r["requirement_id"], [])

        # Make the requirement matrix directly traceable.  A reviewer should
        # not have to open the raw evidence JSON to find the exact file:line
        # (or endpoint/target) behind an outcome.
        finding_by_id = {f["id"]: f for f in audit.findings}
        evidence_by_id = {e["id"]: e for e in audit.evidence}
        for r in audit.requirement_results:
            finding_details = []
            evidence_details = []
            locations = []
            for finding_id in r.get("finding_ids", []):
                finding = finding_by_id.get(finding_id)
                if not finding:
                    continue
                where = _evidence_location(finding)
                finding_details.append({
                    "id": finding_id,
                    "title": finding.get("title", ""),
                    "file": finding.get("file"),
                    "line": finding.get("line"),
                    "endpoint": finding.get("endpoint"),
                    "location": where,
                    "sources": finding.get("sources", []),
                    "proof": finding.get("proof", ""),
                })
                if where != "-":
                    locations.append(where)
            for evidence_id in r.get("evidence_ids", []):
                evidence_item = evidence_by_id.get(evidence_id)
                if not evidence_item:
                    continue
                where = _evidence_location(evidence_item)
                evidence_details.append({
                    "id": evidence_id,
                    "source": evidence_item.get("source", ""),
                    "rule_id": evidence_item.get("rule_id", ""),
                    "summary": evidence_item.get("summary", ""),
                    "location": where,
                })
                if where != "-":
                    locations.append(where)
            r["finding_details"] = finding_details
            r["evidence_details"] = evidence_details
            r["locations"] = list(dict.fromkeys(locations))

        # Put the affected requirements directly on each finding.  This is the
        # useful path for a reviewer: finding -> requirement -> axis -> fix.
        result_by_id = {r["requirement_id"]: r for r in audit.requirement_results}
        for f in audit.findings:
            refs = []
            for rid in f.get("requirement_ids", []):
                r = result_by_id.get(rid)
                if not r:
                    continue
                refs.append({
                    "requirement_id": rid,
                    "name": r.get("name", ""),
                    "status": r.get("status", ""),
                    "axis": r.get("axis"),
                    "axis_ids": r.get("axis_ids", []),
                    "description": r.get("description", ""),
                    "remediation": r.get("remediation", ""),
                })
            f["requirement_details"] = refs
            f["axis_ids"] = sorted({axis for ref in refs for axis in ref.get("axis_ids", [])})

        audit.score = compute_score(deduped, results, requirements)
        from collections import Counter
        counts = Counter(r["status"] for r in results)
        audit.log("INFO", f"Requirement statuses: {dict(counts)}")

    def _step_report(self, audit: Audit):
        from security_auditor.apps.reports.generator import generate_all_reports
        # Mark it before rendering so the generated PDF does not record itself
        # as still running.
        audit.set_job("report", "SUCCESS")
        paths = generate_all_reports(self.store, audit)
        audit.log("INFO", f"Reports generated: {', '.join(paths.keys())}")
        audit.report_paths = paths
