"""Axis model shared by the pipeline, the reports and the dashboard.

Four axes:
  A1 Code (SAST)          A2 Configuration & secrets
  A3 Dependencies         A4 Network, DAST & security tests

Findings are placed by their dedup_key prefix / sources.  Requirements are
placed by the scanner_mapping declared in the 137-requirement catalogue, which
is the authoritative source: a requirement that no scanner can cover is still
attached to the axis that owns it (and shows up as NOT_TESTED there).
"""
from __future__ import annotations

from functools import lru_cache
from pathlib import Path

AXES = [
    ("Axe 1 — Code (SAST)", "sast"),
    ("Axe 2 — Configuration & secrets", "configuration"),
    ("Axe 3 — Dépendances (CVE)", "dependencies"),
    ("Axe 4 — Réseau/ports & DAST", "network"),
]
AXIS_TOOLS = {
    0: "SAST (motifs de code, analyse de flux)",
    1: "Analyseur de settings / secrets",
    2: "Analyseur de dépendances + avis CVE",
    3: "Scanner de ports + DAST + tests de sécurité",
}
# Scanner jobs belonging to each selectable audit axis.  A4 deliberately
# groups network/ports, DAST and automated runtime checks because they all
# require an authorized runtime target.
AXIS_SCANNERS = {
    "A1": ("sast",),
    "A2": ("settings",),
    "A3": ("dependencies",),
    "A4": ("endpoints", "app_start", "dast", "security_tests", "network"),
}
CATALOGUE = Path(__file__).resolve().parents[2] / "requirements" / "django_137_requirements.yml"


def normalize_selected_axes(values) -> list[str]:
    """Normalize UI/CLI axis values and reject unknown axes."""
    if not values:
        return []
    out = []
    for value in values:
        key = str(value).upper().strip()
        if key.isdigit():
            key = f"A{key}"
        if key not in AXIS_SCANNERS:
            raise ValueError(f"unknown audit axis: {value}")
        if key not in out:
            out.append(key)
    if len(out) > 4:
        raise ValueError("choose at most four audit axes per scan")
    return out


def axis_of_finding(item: dict) -> int:
    dk = (item.get("dedup_key") or "")
    src = set(item.get("sources") or [])
    if dk.startswith("sast:") or "sast" in src:
        return 0
    if dk.startswith("config:") or "configuration" in src:
        return 1
    if dk.startswith("dep:") or "dependencies" in src:
        return 2
    return 3


@lru_cache(maxsize=1)
def _catalogue_axes() -> dict:
    """requirement id -> axis index, from scanner_mapping in the catalogue."""
    mapping: dict[str, int] = {}
    try:
        import yaml
        data = yaml.safe_load(CATALOGUE.read_text(encoding="utf-8"))
        reqs = data["requirements"] if isinstance(data, dict) and "requirements" in data else data
    except Exception:  # noqa: BLE001 - catalogue optional at runtime
        return mapping
    order = ("sast", "configuration", "dependencies", "network")
    for req in reqs or []:
        sm = (req.get("scanner_mapping") or {})
        idx = None
        for i, key in enumerate(order):
            if sm.get(key) or (i == 3 and (sm.get("dast") or sm.get("automated"))):
                idx = i
                break
        if idx is None:
            vm = req.get("verification_method") or []
            key = next((k for k in ("sast", "configuration", "dependencies", "network")
                        if k in vm), None)
            idx = ("sast", "configuration", "dependencies", "network").index(key) if key else None
        if idx is None:
            continue
        mapping[str(req.get("id"))] = idx
    return mapping


@lru_cache(maxsize=1)
def _catalogue_axes_all() -> dict[str, tuple[int, ...]]:
    """Return every axis that can verify each catalogue requirement.

    The primary axis is useful for compact grouping, but a requirement can be
    covered by more than one engine (for example SAST + DAST).  Keeping all
    axes makes that relationship explicit in the UI and in exported reports.
    """
    mapping: dict[str, tuple[int, ...]] = {}
    try:
        import yaml
        data = yaml.safe_load(CATALOGUE.read_text(encoding="utf-8"))
        reqs = data["requirements"] if isinstance(data, dict) and "requirements" in data else data
    except Exception:  # noqa: BLE001 - catalogue optional at runtime
        return mapping
    for req in reqs or []:
        sm = req.get("scanner_mapping") or {}
        axes = set()
        if sm.get("configuration") or sm.get("dependencies") or sm.get("internal"):
            axes.add(1)  # requirements/configuration/dependencies
        if sm.get("network"):
            axes.add(3)  # network/ports
        if sm.get("sast"):
            axes.add(0)  # SAST
        if sm.get("dast") or sm.get("automated"):
            axes.add(3)  # DAST and dynamic security tests
        if not axes and any(m in (req.get("verification_method") or [])
                            for m in ("manual", "internal")):
            axes.add(1)
        mapping[str(req.get("id"))] = tuple(sorted(axes))
    return mapping


SCANNER_SOURCES = {"sast", "configuration", "dependencies", "network", "dast", "automated"}


def catalogue_axis(requirement_id: str) -> int | None:
    """Axe déclaré par le catalogue des 137, ou None si l'exigence est transverse."""
    return _catalogue_axes().get(str(requirement_id or ""))


def catalogue_axes(requirement_id: str) -> tuple[int, ...]:
    """Return all zero-based axes declared for a requirement."""
    rid = str(requirement_id or "")
    axes = _catalogue_axes_all().get(rid)
    if axes:
        return axes
    primary = _catalogue_axes().get(rid)
    return (primary,) if primary is not None else ()


def is_transverse(item: dict) -> bool:
    """True : exigence sans scanner dédié (processus / revue manuelle)."""
    if catalogue_axis(item.get("requirement_id")) is not None:
        return False
    return not (set(item.get("sources") or []) & SCANNER_SOURCES)


def axis_of_requirement(item: dict) -> int:
    """Catalogue axis when known, else fall back to the evidence sources."""
    idx = catalogue_axis(item.get("requirement_id"))
    if idx is not None:
        return idx
    src = set(item.get("sources") or [])
    dk = (item.get("dedup_key") or "")
    if dk.startswith("sast:") or "sast" in src:
        return 0
    if dk.startswith("config:") or "configuration" in src:
        return 1
    if dk.startswith("dep:") or "dependencies" in src:
        return 2
    return 3


def enrich_requirement_result(result: dict) -> dict:
    """Add stable axis metadata to one requirement result."""
    ids = catalogue_axes(result.get("requirement_id"))
    if not ids:
        ids = (axis_of_requirement(result),)
    result["axis"] = ids[0] + 1
    result["axis_ids"] = [f"A{i + 1}" for i in ids]
    result["axis_labels"] = [axis_label(i) for i in ids]
    result["axes"] = [{"id": f"A{i + 1}", "label": axis_label(i)} for i in ids]
    result["test_axes"] = result["axis_ids"]
    return result


def _item_location(item: dict) -> str:
    """Return the most precise location available for a finding/evidence."""
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


def attach_requirement_locations(audit_dict: dict) -> dict:
    """Backfill requirement locations for current and older persisted audits.

    Older audit JSON files were created before ``locations`` was added to the
    requirement matrix.  Rebuilding this small relation at API-read time
    makes those scans immediately traceable too, without forcing a rescan.
    """
    findings = audit_dict.get("findings") or []
    evidence = audit_dict.get("evidence") or []
    finding_by_id = {f.get("id"): f for f in findings if f.get("id")}
    evidence_by_id = {e.get("id"): e for e in evidence if e.get("id")}
    finding_refs: dict[str, list[str]] = {}
    for finding in findings:
        for rid in finding.get("requirement_ids") or []:
            finding_refs.setdefault(rid, []).append(finding.get("id"))

    for result in audit_dict.get("requirement_results") or []:
        rid = result.get("requirement_id")
        ids = result.get("finding_ids")
        if ids is None:
            ids = finding_refs.get(rid, [])
            result["finding_ids"] = ids
        locations = []
        finding_details = []
        for finding_id in ids or []:
            finding = finding_by_id.get(finding_id)
            if not finding:
                continue
            where = _item_location(finding)
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

        evidence_details = []
        for evidence_id in result.get("evidence_ids") or []:
            evidence_item = evidence_by_id.get(evidence_id)
            if not evidence_item:
                continue
            where = _item_location(evidence_item)
            evidence_details.append({
                "id": evidence_id,
                "source": evidence_item.get("source", ""),
                "rule_id": evidence_item.get("rule_id", ""),
                "summary": evidence_item.get("summary", ""),
                "location": where,
            })
            if where != "-":
                locations.append(where)

        result["finding_details"] = finding_details
        result["evidence_details"] = evidence_details
        result["locations"] = list(dict.fromkeys(locations))
    return audit_dict


def enrich(audit_dict: dict) -> dict:
    """Ajoute l'axe (1-4) à chaque constat/exigence + les métadonnées d'axes.

    Utilisé par l'API (tableau de bord) et par l'export statique, pour que la
    répartition par axe soit identique partout.
    """
    for f in audit_dict.get("findings", []):
        f["axis"] = axis_of_finding(f) + 1
    for r in audit_dict.get("requirement_results", []):
        enrich_requirement_result(r)
        r["transverse"] = is_transverse(r)
    attach_requirement_locations(audit_dict)
    audit_dict["axes"] = [{"id": f"A{i + 1}", "label": AXES[i][0]} for i in range(len(AXES))]
    reqs = audit_dict.get("requirement_results", [])
    audit_dict["requirements_coverage"] = {
        "catalogue_total": 137,
        "evaluated": len(reqs),
        "missing": max(0, 137 - len(reqs)),
        "complete": len(reqs) == 137,
    }
    return audit_dict


def axis_label(idx: int) -> str:
    return AXES[max(0, min(idx, len(AXES) - 1))][0]


def axis_short(idx: int) -> str:
    return f"A{max(0, min(idx, len(AXES) - 1)) + 1}"
