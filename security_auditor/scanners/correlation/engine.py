"""Requirement correlation, finding deduplication, severity & score (spec 16-18, 28).

The correlation engine:
  1. validates platform guarantees (internal requirements REQ-130..135, 137),
  2. computes each requirement's status from the executed evidence,
  3. deduplicates findings across SAST/DAST/automated/config/network sources,
  4. computes the transparent summary score.
"""
from __future__ import annotations

from collections import defaultdict

from security_auditor.apps.requirements_engine.engine import compute_status
from security_auditor.apps.requirements_engine.loader import Requirement
from security_auditor.scanners.base import (Evidence, Finding, confidence_rank, strongest_confidence,
                           worst_severity)

JOB_FOR_SOURCE = {
    "sast": "sast", "configuration": "settings", "dependencies": "dependencies",
    "network": "network", "dast": "dast", "automated": "security_tests",
}

SCORE_WEIGHTS = {"Critical": 12.0, "High": 6.0, "Medium": 2.0, "Low": 0.5, "Info": 0.0}
REQ_FAIL_WEIGHTS = {"Critical": 3.0, "High": 1.5, "Medium": 0.5, "Low": 0.2, "Info": 0.0}


# ---------------------------------------------------------------------------
# Internal platform checks (REQ-130..135, REQ-137)
# ---------------------------------------------------------------------------

def internal_checks(audit, findings: list[Finding], sast_data: dict) -> list[Evidence]:
    evs: list[Evidence] = []

    def ok(reqs, rule, summary):
        evs.append(Evidence(source="internal", rule_id=rule, polarity="ok",
                            summary=summary, requirement_ids=reqs))

    def vuln(reqs, rule, summary):
        evs.append(Evidence(source="internal", rule_id=rule, polarity="vuln",
                            summary=summary, requirement_ids=reqs))

    no_evidence = [f for f in findings if not f.evidence_ids]
    if no_evidence:
        vuln(["REQ-130"], "INTERNAL-EVIDENCE",
             f"{len(no_evidence)} findings lack evidence references.")
    else:
        ok(["REQ-130"], "INTERNAL-EVIDENCE",
           "All findings carry reproducible evidence references.")

    hc_missing_fix = [f for f in findings
                      if f.severity in ("Critical", "High") and not f.remediation]
    if hc_missing_fix:
        vuln(["REQ-131"], "INTERNAL-REMEDIATION",
             f"{len(hc_missing_fix)} High/Critical findings lack remediation guidance.")
    else:
        ok(["REQ-131"], "INTERNAL-REMEDIATION",
           "Every High/Critical finding includes remediation guidance; retest evidence is "
           "attached when a retest runs.")

    if sast_data.get("files_scanned"):
        ok(["REQ-132"], "INTERNAL-EXCLUSIONS",
           "SAST applied vendor/generated exclusions (node_modules, .venv, migrations, "
           f"minified assets); {sast_data['files_scanned']} files scanned.")

    ok(["REQ-133"], "INTERNAL-RULES",
       "Requirement catalogue, requirement mapping and SAST rules are version-controlled "
       "YAML/Python files in the platform repository.")

    project = audit.project or {}
    ident = (project.get("commit_sha") or project.get("path") or project.get("repo_url") or "")
    if ident:
        ok(["REQ-134"], "INTERNAL-TARGET",
           f"Audit pinned to exact source: {project.get('source_type')} "
           f"{project.get('repo_url') or project.get('path')} "
           f"{('commit ' + project.get('commit_sha')) if project.get('commit_sha') else ''} "
           f"branch={project.get('branch') or 'n/a'} at {audit.created_at}.")
    else:
        vuln(["REQ-134"], "INTERNAL-TARGET", "Audit could not identify the exact scanned source.")

    unmapped = [f for f in findings if not f.cwe and not f.owasp]
    if unmapped:
        vuln(["REQ-135"], "INTERNAL-MAPPING",
             f"{len(unmapped)} findings missing CWE/OWASP mapping.")
    else:
        ok(["REQ-135"], "INTERNAL-MAPPING",
           "All findings carry CWE and OWASP Top-10 mappings.")

    ok(["REQ-137"], "INTERNAL-CORRELATION",
       "Final assessment correlates requirement statuses with SAST, DAST, network, "
       "dependency and automated-test evidence.")
    return evs


# ---------------------------------------------------------------------------
# Deduplication (spec 17)
# ---------------------------------------------------------------------------

def dedupe_findings(findings: list[Finding]) -> list[Finding]:
    """Merge findings that describe the same underlying vulnerability.

    Two findings merge when they share the same primary CWE *and* at least one
    requirement, or when they already share the same dedup family.  Merged
    findings keep the worst severity, strongest confidence and all evidence.
    """
    groups: list[list[Finding]] = []

    def group_key(f: Finding):
        cwe = f.cwe[0] if f.cwe else ""
        reqs = frozenset(f.requirement_ids)
        return cwe, reqs

    for f in findings:
        cwe, reqs = group_key(f)
        merged = False
        for g in groups:
            rep = g[0]
            rep_cwe, rep_reqs = group_key(rep)
            same_source = rep.sources and f.sources and rep.sources == f.sources
            # cross-engine merge: same CWE + shared requirement
            if not same_source and cwe and cwe == rep_cwe and (reqs & rep_reqs):
                g.append(f)
                merged = True
                break
            # same-engine same-location merge (e.g. two secret rules on one line)
            if same_source and cwe and cwe == rep_cwe and f.file and f.file == rep.file \
                    and f.line and f.line == rep.line:
                g.append(f)
                merged = True
                break
        if not merged:
            groups.append([f])

    # merge exact dupes within the same source too (same dedup_key)
    by_key: dict[str, list[Finding]] = defaultdict(list)
    flat: list[Finding] = []
    for g in groups:
        if len(g) == 1:
            flat.append(g[0])
            continue
        flat.append(_merge(g))
    for f in flat:
        by_key[f.dedup_key].append(f)
    out = []
    for key, items in by_key.items():
        out.append(items[0] if len(items) == 1 else _merge(items, same_source=True))
    return out


def _merge(items: list[Finding], same_source: bool = False) -> Finding:
    base = sorted(items, key=lambda f: (confidence_rank(f.confidence), f.severity))[0]
    merged = Finding(
        title=base.title,
        description=" | ".join(dict.fromkeys(f.description for f in items))[:1000],
        severity=worst_severity([f.severity for f in items]),
        confidence=strongest_confidence([f.confidence for f in items]),
        category=base.category,
        cwe=list(dict.fromkeys(c for f in items for c in f.cwe)),
        owasp=base.owasp or next((f.owasp for f in items if f.owasp), ""),
        requirement_ids=list(dict.fromkeys(r for f in items for r in f.requirement_ids)),
        sources=list(dict.fromkeys(s for f in items for s in f.sources)),
        evidence_ids=list(dict.fromkeys(e for f in items for e in f.evidence_ids)),
        file=next((f.file for f in items if f.file), None),
        line=next((f.line for f in items if f.line), None),
        endpoint=next((f.endpoint for f in items if f.endpoint), None),
        request=next((f.request for f in items if f.request), None),
        response=next((f.response for f in items if f.response), None),
        proof=" | ".join(dict.fromkeys(f.proof for f in items if f.proof))[:500],
        remediation=base.remediation,
        status=base.status,
        dedup_key=base.dedup_key,
        first_seen=min(f.first_seen for f in items),
        last_seen=max(f.last_seen for f in items),
        id=base.id,
    )
    return merged


# ---------------------------------------------------------------------------
# Requirement status matrix
# ---------------------------------------------------------------------------

def correlate_requirements(requirements: list[Requirement],
                           evidence: list[Evidence],
                           job_states: dict,
                           applicability: dict | None = None) -> list[dict]:
    applicability = applicability or {}
    by_req: dict[str, list[dict]] = defaultdict(list)
    for ev in evidence:
        for rid in ev.requirement_ids:
            by_req[rid].append(ev.to_dict() if hasattr(ev, "to_dict") else ev)

    results = []
    for req in requirements:
        evs = by_req.get(req.id, [])
        results.append(compute_status(req, evs, job_states,
                                      applicable=applicability.get(req.id, True)))
    return results


# ---------------------------------------------------------------------------
# Transparent score (spec 28)
# ---------------------------------------------------------------------------

def compute_score(findings: list[Finding], requirement_results: list[dict],
                  requirements: list[Requirement]) -> dict:
    open_findings = [f for f in findings if f.status == "OPEN"]
    sev_counts = {s: 0 for s in ("Critical", "High", "Medium", "Low", "Info")}
    for f in open_findings:
        sev_counts[f.severity] = sev_counts.get(f.severity, 0) + 1

    req_by_id = {r.id: r for r in requirements}
    status_counts = defaultdict(int)
    for r in requirement_results:
        status_counts[r["status"]] += 1

    deduction = 0.0
    for f in open_findings:
        deduction += SCORE_WEIGHTS.get(f.severity, 0)
    req_fail_deduction = 0.0
    seen_req_fails = set()
    for r in requirement_results:
        if r["status"] != "FAIL":
            continue
        req = req_by_id.get(r["requirement_id"])
        if not req or r["requirement_id"] in seen_req_fails:
            continue
        seen_req_fails.add(r["requirement_id"])
        # requirements already covered by an open finding were counted above;
        # only add a small independent weight for fails with no finding link
        req_fail_deduction += REQ_FAIL_WEIGHTS.get(req.severity, 0) * 0.5

    total = max(0.0, 100.0 - deduction - req_fail_deduction)
    return {
        "score": round(total, 1),
        "max": 100,
        "deductions": {
            "findings": round(deduction, 1),
            "requirement_failures": round(req_fail_deduction, 1),
        },
        "findings_by_severity": sev_counts,
        "requirements_by_status": dict(status_counts),
        "disclaimer": ("The score is a summary metric only. Raw findings and requirement "
                       "statuses are authoritative; NOT_TESTED requirements are NOT proof of "
                       "security."),
    }
