"""Requirements status engine.

Core rule (spec 7 / 45): *absence of findings is never proof of compliance*.
A requirement is PASS only when at least one executed automated check produced
positive ("ok") evidence and the requirement is fully automatable.  Otherwise
the engine degrades gracefully to PARTIAL / NOT_TESTED / MANUAL_REVIEW.

Status logic per requirement:

* automation MANUAL / NOT_AUTOMATABLE           -> MANUAL_REVIEW
* any executed evidence with polarity "vuln"    -> FAIL
* else executed "ok" evidence:
    - FULLY_AUTOMATED                           -> PASS
    - PARTIALLY_AUTOMATED                       -> PARTIAL
* else (no executed evidence)                   -> NOT_TESTED
  (with a note listing scanners that were mapped but unavailable)
"""
from __future__ import annotations

from .loader import Requirement

# verification method -> audit job name that must have run to count as executed
SOURCE_JOBS = {
    "sast": "sast",
    "configuration": "settings",
    "dependencies": "dependencies",
    "network": "network",
    "dast": "dast",
    "automated": "security_tests",
    "internal": "correlation",
}


def _result(requirement: Requirement, data: dict) -> dict:
    """Attach the catalogue data to every result.

    A status without the requirement name or its verification objective is hard
    to use in a report.  Keep the stable status fields, but also return the
    small, human-readable catalogue record so API clients and reports do not
    have to load the YAML file a second time.
    """
    data.update({
        "name": requirement.name,
        "category": requirement.category,
        "severity": requirement.severity,
        "description": requirement.description,
        "remediation": requirement.remediation,
        "automation_level": requirement.automation_level,
        "verification_method": requirement.verification_method,
        "scanner_mapping": requirement.scanner_mapping,
        "cwe": requirement.cwe,
        "owasp": requirement.owasp,
        "test_definition": requirement.test_definition,
    })
    return data


def compute_status(requirement: Requirement,
                   evidence: list[dict],
                   job_states: dict[str, str],
                   applicable: bool = True) -> dict:
    """Return a RequirementResult dict for one requirement.

    ``evidence``: evidence dicts already tagged with this requirement id.
    ``job_states``: job name -> QUEUED|RUNNING|SUCCESS|FAILED|SKIPPED.
    """
    if not applicable:
        return _result(requirement, {"requirement_id": requirement.id, "status": "NOT_APPLICABLE",
                "notes": ["Requirement not applicable to this project profile."],
                "evidence_ids": [], "sources": []})

    if requirement.is_manual:
        notes = ["Requires manual review (automation level: "
                 f"{requirement.automation_level})."]
        notes += [f"{ev['source']}/{ev['rule_id']}: {ev['summary']}" for ev in evidence]
        return _result(requirement, {"requirement_id": requirement.id, "status": "MANUAL_REVIEW",
                "notes": notes, "evidence_ids": [ev["id"] for ev in evidence],
                "sources": sorted({ev["source"] for ev in evidence})})

    vuln = [ev for ev in evidence if ev["polarity"] == "vuln"]
    ok = [ev for ev in evidence if ev["polarity"] == "ok"]
    info = [ev for ev in evidence if ev["polarity"] == "info"]

    # spec 19: only Confirmed/High-confidence vulnerability evidence is a hard
    # FAIL; weaker detections are review items (PARTIAL).
    strong_vuln = [ev for ev in vuln if ev.get("confidence", "High") in ("Confirmed", "High")]
    weak_vuln = [ev for ev in vuln if ev.get("confidence", "High") not in ("Confirmed", "High")]

    if strong_vuln:
        notes = [f"{ev['source']}/{ev['rule_id']}: {ev['summary']}" for ev in strong_vuln]
        if weak_vuln:
            notes.append(f"+{len(weak_vuln)} lower-confidence detection(s) attached.")
        return _result(requirement, {"requirement_id": requirement.id, "status": "FAIL", "notes": notes,
                "evidence_ids": [ev["id"] for ev in evidence],
                "sources": sorted({ev["source"] for ev in evidence})})

    if weak_vuln:
        notes = [f"{ev['source']}/{ev['rule_id']}: {ev['summary']}" for ev in weak_vuln]
        notes.append("Lower-confidence detection: manual validation required (spec 19).")
        return _result(requirement, {"requirement_id": requirement.id, "status": "PARTIAL", "notes": notes,
                "evidence_ids": [ev["id"] for ev in evidence],
                "sources": sorted({ev["source"] for ev in evidence})})

    if ok:
        status = "PASS" if requirement.automation_level == "FULLY_AUTOMATED" else "PARTIAL"
        notes = [f"{ev['source']}/{ev['rule_id']}: {ev['summary']}" for ev in ok]
        if status == "PARTIAL":
            notes.append("Requirement is only partially automatable; residual risk needs review.")
        return _result(requirement, {"requirement_id": requirement.id, "status": status, "notes": notes,
                "evidence_ids": [ev["id"] for ev in evidence],
                "sources": sorted({ev["source"] for ev in evidence})})

    if info and requirement.automation_level == "PARTIALLY_AUTOMATED":
        notes = [f"{ev['source']}/{ev['rule_id']}: {ev['summary']}" for ev in info]
        notes.append("Informational evidence collected; human review completes verification.")
        return _result(requirement, {"requirement_id": requirement.id, "status": "PARTIAL", "notes": notes,
                "evidence_ids": [ev["id"] for ev in evidence],
                "sources": sorted({ev["source"] for ev in evidence})})

    # No evidence executed at all -> NOT_TESTED, explain why.
    notes = []
    for method, job in SOURCE_JOBS.items():
        if method in requirement.verification_method and job in job_states \
                and job_states[job] in ("FAILED", "SKIPPED"):
            notes.append(f"{job} scanner did not run ({job_states[job]}); "
                         "this requirement could not be verified.")
    if not notes:
        notes.append("No scanner produced evidence for this requirement in the current run.")
    return _result(requirement, {"requirement_id": requirement.id, "status": "NOT_TESTED", "notes": notes,
            "evidence_ids": [], "sources": []})
