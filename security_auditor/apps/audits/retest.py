"""Retest & regression comparison (spec 29).

A retest runs a fresh audit of the (fixed) project and compares it with the
previous audit by finding dedup keys:

    Fixed          - present before, gone now
    Still present  - present before and now
    New            - not present before, appears now
    Regressed      - previously marked FIXED/accepted, appears again
"""
from __future__ import annotations

from security_auditor.apps.audits.models import Audit, AuditStore
from security_auditor.apps.audits.pipeline import AuditPipeline


def _fingerprint(finding: dict) -> str:
    return finding.get("dedup_key") or \
        f"{','.join(finding.get('cwe', []))}:{finding.get('file') or ''}:" \
        f"{finding.get('endpoint') or ''}:{finding.get('title')}"


def compare_audits(previous: Audit, current: Audit) -> dict:
    before = {_fingerprint(f): f for f in previous.findings}
    after = {_fingerprint(f): f for f in current.findings}

    fixed, still, new = [], [], []
    for key, f in before.items():
        if key in after:
            after[key]["retest_status"] = "STILL_PRESENT"
            still.append({"fingerprint": key, "title": f["title"], "severity": f["severity"],
                          "finding_id": after[key]["id"]})
        else:
            fixed.append({"fingerprint": key, "title": f["title"], "severity": f["severity"],
                          "finding_id": f["id"]})
    for key, f in after.items():
        if key not in before:
            prev_status = f.get("status")
            f["retest_status"] = "REGRESSED" if prev_status == "FIXED" else "NEW"
            new.append({"fingerprint": key, "title": f["title"], "severity": f["severity"],
                        "finding_id": f["id"], "kind": f["retest_status"]})

    req_before = {r["requirement_id"]: r["status"] for r in previous.requirement_results}
    req_changes = []
    for r in current.requirement_results:
        old = req_before.get(r["requirement_id"])
        if old and old != r["status"]:
            req_changes.append({"requirement_id": r["requirement_id"],
                                "before": old, "after": r["status"]})

    return {"retest_of": previous.id,
            "fixed": fixed, "still_present": still, "new": new,
            "requirement_changes": req_changes,
            "summary": {"fixed": len(fixed), "still_present": len(still), "new": len(new)}}


def run_retest(store: AuditStore, previous_audit_id: str, source_dir: str,
               authorization_confirmed: bool = False,
               config_path: str | None = None) -> Audit:
    previous = store.load(previous_audit_id)
    project = dict(previous.project)
    project["path"] = source_dir
    pipeline = AuditPipeline(store, config_path)
    audit = pipeline.create_audit(project, authorization_confirmed=authorization_confirmed,
                                  retest_of=previous_audit_id)
    audit = pipeline.run_full(audit)
    audit.comparison = compare_audits(previous, audit)
    audit.log("INFO", f"Retest comparison: {audit.comparison['summary']}")
    store.save(audit)
    return audit
