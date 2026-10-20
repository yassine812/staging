"""Génération des rapports : PDF, HTML, JSON, CSV.

Tous les rapports sont dérivés de l'état d'audit persisté.  Les rapports
PDF/HTML (en français) contiennent les sections exigées par la spécification,
y compris les limites : la plateforme ne prétend jamais que l'application est
sûre — elle rapporte la couverture réellement obtenue.

JSON et CSV restent en anglais (clés stables, lisibles par machine/Excel).
"""
from __future__ import annotations

import csv
import html
import io
import json
from collections import Counter, defaultdict
from pathlib import Path

from security_auditor.apps.audits.axes import (AXES, AXIS_TOOLS, axis_label, axis_of_finding,
                              axis_of_requirement, axis_short, is_transverse)
from security_auditor.apps.audits.models import Audit, AuditStore
from security_auditor.apps.reports.fix_examples import fix_for

SEV_COLORS = {"Critical": "#7f1d1d", "High": "#b91c1c", "Medium": "#d97706",
              "Low": "#2563eb", "Info": "#6b7280"}
STATUS_COLORS = {"PASS": "#059669", "FAIL": "#dc2626", "PARTIAL": "#d97706",
                 "NOT_TESTED": "#6b7280", "NOT_APPLICABLE": "#9ca3af",
                 "MANUAL_REVIEW": "#7c3aed"}

# --- vocabulaire français (affichage ; les clés internes restent anglaises) ---
SEV_FR = {"Critical": "Critique", "High": "Élevé", "Medium": "Moyen",
          "Low": "Faible", "Info": "Info"}
STATUS_FR = {"PASS": "Vérifié", "FAIL": "Échec", "PARTIAL": "Partiel",
             "NOT_TESTED": "Non testé", "MANUAL_REVIEW": "Revue manuelle",
             "NOT_APPLICABLE": "Non applicable"}
SEVERITY_ORDER = ["Critical", "High", "Medium", "Low", "Info"]
SEVERITY_MEANING = {
    "Critical": "Exploitable immédiatement, impact grave — corriger en priorité absolue",
    "High": "Faiblesse sérieuse, exploitable — corriger avant mise en production",
    "Medium": "Faiblesse réelle, impact limité — corriger au prochain sprint",
    "Low": "Durcissement / bonnes pratiques",
    "Info": "Élément à revoir, pas une violation",
}
STATUS_MEANING = {
    "PASS": "vérifié par des preuves automatiques",
    "FAIL": "violation confirmée",
    "PARTIAL": "couverture partielle",
    "NOT_TESTED": "aucune couverture automatique — point ouvert",
    "MANUAL_REVIEW": "vérification humaine requise",
    "NOT_APPLICABLE": "non applicable à ce projet",
}
SEV_RANK = {s: i for i, s in enumerate(SEVERITY_ORDER)}


def sev_fr(sev: str) -> str:
    return SEV_FR.get(sev, sev or "")


def status_fr(status: str) -> str:
    return STATUS_FR.get(status, status or "")


# ---------------------------------------------------------------------------
# shared section extraction
# ---------------------------------------------------------------------------

def _severity_counts(audit: Audit) -> dict:
    return dict(Counter(f["severity"] for f in audit.findings))


def _status_counts(audit: Audit) -> dict:
    return dict(Counter(r["status"] for r in audit.requirement_results))


def _cwe_map(audit: Audit) -> dict:
    m = defaultdict(list)
    for f in audit.findings:
        for c in f.get("cwe", []):
            m[c].append(f["title"])
    return m


def _owasp_map(audit: Audit) -> dict:
    m = defaultdict(list)
    for f in audit.findings:
        if f.get("owasp"):
            m[f["owasp"]].append(f["title"])
    return m


# ---------------------------------------------------------------------------
# 4 axes (Code / Configuration / Dépendances / Réseau+DAST)
# ---------------------------------------------------------------------------

def _axis_index(item: dict) -> int:
    """Axe d'un constat (0-3) — logique partagée avec le tableau de bord."""
    return axis_of_finding(item)


def _axis_groups(audit: Audit) -> list[list[dict]]:
    groups: list[list[dict]] = [[] for _ in AXES]
    for f in _sorted_findings(audit):
        groups[_axis_index(f)].append(f)
    return groups


def _axis_req_groups(audit: Audit) -> tuple[list[list[dict]], list[dict]]:
    """Exigences par axe (catalogue des 137) + exigences transverses (revue manuelle)."""
    groups: list[list[dict]] = [[] for _ in AXES]
    transverse: list[dict] = []
    # Older persisted audits only contain id/status/notes.  Backfill the
    # catalogue fields while rendering so every report has the same detail as
    # a newly generated audit.
    try:
        from security_auditor.apps.requirements_engine.loader import load_requirements
        catalogue = {req.id: req.to_dict() for req in load_requirements()}
    except Exception:  # noqa: BLE001 - report generation must remain resilient
        catalogue = {}
    from security_auditor.apps.audits.axes import (attach_requirement_locations,
                                  enrich_requirement_result)
    report_results = []
    for raw in audit.requirement_results:
        r = dict(catalogue.get(raw.get("requirement_id"), {}))
        r.update(raw)
        enrich_requirement_result(r)
        report_results.append(r)
    attach_requirement_locations({"findings": audit.findings,
                                  "evidence": audit.evidence,
                                  "requirement_results": report_results})
    for r in report_results:
        if is_transverse(r):
            transverse.append(r)
        else:
            groups[axis_of_requirement(r)].append(r)
    return groups, transverse


def _sort_reqs(reqs: list[dict]) -> list[dict]:
    rank = {s: i for i, s in enumerate(STATUS_PRIORITY)}
    return sorted(reqs, key=lambda r: (rank.get(r["status"], 9),
                                       str(r.get("requirement_id", ""))))


def _axis_result_line(reqs: list[dict]) -> str:
    """'Vérifié 5 · Échec 20 · Non testé 12' pour un axe."""
    c = Counter(r["status"] for r in reqs)
    parts = [f"{status_fr(s)} {c[s]}" for s in
             ("PASS", "FAIL", "PARTIAL", "NOT_TESTED", "MANUAL_REVIEW") if c.get(s)]
    return " · ".join(parts) or "aucune exigence"


def _limitations(audit: Audit) -> list[str]:
    items = []
    for job in audit.jobs:
        if job["status"] in ("FAILED", "SKIPPED"):
            items.append(f"{job['name']} : {job['status']} — {job.get('error') or 'non exécuté'}")
    n_not_tested = _status_counts(audit).get("NOT_TESTED", 0)
    n_manual = _status_counts(audit).get("MANUAL_REVIEW", 0)
    if n_not_tested:
        items.append(f"{n_not_tested} exigences n'ont pas pu être testées automatiquement "
                     "et restent NON TESTÉES — l'absence de constat ne prouve pas la sécurité.")
    if n_manual:
        items.append(f"{n_manual} exigences nécessitent une revue manuelle.")
    items.append("Les sondes DAST sont heuristiques : un résultat propre ne garantit pas "
                 "l'absence de vulnérabilités.")
    items.append("L'analyse réseau a été limitée aux cibles explicitement autorisées.")
    return items


STATUS_PRIORITY = ["FAIL", "PARTIAL", "NOT_TESTED", "MANUAL_REVIEW", "PASS", "NOT_APPLICABLE"]


def _req_row(r: dict) -> str:
    """Ligne compacte d'une exigence : statut, sources, preuve/note."""
    note = " | ".join(r.get("notes") or [])
    locations = "; ".join(r.get("locations") or [])
    if locations:
        note = f"Emplacement: {locations} | {note}" if note else f"Emplacement: {locations}"
    return note[:180]


def _req_names(r: dict) -> str:
    """Compact affected-requirement label for finding rows."""
    refs = r.get("requirement_details") or []
    if refs:
        return " ; ".join(
            f"{x.get('requirement_id', '')} — {x.get('name', '')}"
            for x in refs)
    return ", ".join(r.get("requirement_ids") or []) or "-"


def _req_axes(r: dict) -> str:
    refs = r.get("requirement_details") or []
    axes = sorted({a for x in refs for a in x.get("axis_ids", [])})
    if axes:
        return ", ".join(axes)
    return ", ".join(r.get("axis_ids") or []) or axis_short(_axis_index(r))


def _pct(n: int, total: int) -> str:
    return f"{(100.0 * n / total):.0f}%" if total else "0%"


def _location(item: dict) -> str:
    """Meilleur « où » disponible : fichier:ligne > endpoint > manifeste/preuve."""
    f = item.get("file")
    if f:
        line = item.get("line")
        return f"{f}:{line}" if line else str(f)
    if item.get("endpoint"):
        return str(item["endpoint"])
    srcs = set(item.get("sources") or [])
    if srcs & {"dependencies"}:
        return f"manifeste de dépendances — {item.get('proof', '')}".strip(" —")
    if srcs & {"network"}:
        return item.get("proof") or "cible autorisée"
    return item.get("proof") or "-"


def _sorted_findings(audit: Audit) -> list[dict]:
    return sorted(audit.findings,
                  key=lambda f: (SEV_RANK.get(f.get("severity"), 9), f.get("title", "")))


def _hotspots(audit: Audit, limit: int = 10) -> list[tuple[str, int, str]]:
    """Fichiers (ou endpoints) portant le plus de constats : (où, nombre, mix sévérités)."""
    groups: dict[str, list[dict]] = defaultdict(list)
    for f in audit.findings:
        if f.get("file"):
            key = str(f["file"])
        elif f.get("endpoint"):
            key = str(f["endpoint"])
        elif "dependencies" in (f.get("sources") or []):
            key = "(manifests de dépendances)"
        elif f.get("sources"):
            key = f"({f['sources'][0]})"
        else:
            key = "(sans emplacement)"
        groups[key].append(f)
    rows = []
    for key, fs in groups.items():
        mix = Counter(x["severity"] for x in fs)
        mix_txt = ", ".join(f"{sev_fr(s)} {mix[s]}" for s in SEVERITY_ORDER if mix.get(s))
        rows.append((key, len(fs), mix_txt))
    rows.sort(key=lambda r: (-r[1], r[0]))
    return rows[:limit]


# ---------------------------------------------------------------------------
# JSON
# ---------------------------------------------------------------------------

def write_json(audit: Audit, path: Path) -> None:
    path.write_text(json.dumps(audit.to_dict(), indent=2, default=str), encoding="utf-8")


# ---------------------------------------------------------------------------
# CSV (clés anglaises stables + colonne axis)
# ---------------------------------------------------------------------------

def write_csv(audit: Audit, dirpath: Path) -> list[str]:
    paths = []
    fp = dirpath / "findings.csv"
    with open(fp, "w", newline="", encoding="utf-8") as fh:
        w = csv.writer(fh)
        w.writerow(["id", "axis", "axes", "title", "severity", "confidence", "category", "cwe", "owasp",
                    "requirements", "requirement_names", "sources", "file", "line", "endpoint", "status",
                    "retest_status", "remediation"])
        for f in audit.findings:
            w.writerow([f["id"], axis_short(_axis_index(f)), _req_axes(f), f["title"], f["severity"],
                        f["confidence"], f["category"],
                        ";".join(f.get("cwe", [])), f.get("owasp", ""),
                        ";".join(f.get("requirement_ids", [])), _req_names(f), ";".join(f.get("sources", [])),
                        f.get("file") or "", f.get("line") or "", f.get("endpoint") or "",
                        f.get("status", ""), f.get("retest_status") or "",
                        f.get("remediation", "")])
    paths.append(str(fp))

    # CSV requirements is a complete catalogue export, including older audits
    # whose persisted rows predate the human-readable catalogue fields.
    try:
        from security_auditor.apps.requirements_engine.loader import load_requirements
        from security_auditor.apps.audits.axes import (attach_requirement_locations,
                                      enrich_requirement_result)
        catalogue = {req.id: req.to_dict() for req in load_requirements()}
        requirement_rows = []
        for raw in audit.requirement_results:
            row = dict(catalogue.get(raw.get("requirement_id"), {}))
            row.update(raw)
            enrich_requirement_result(row)
            requirement_rows.append(row)
        attach_requirement_locations({"findings": audit.findings,
                                      "evidence": audit.evidence,
                                      "requirement_results": requirement_rows})
    except Exception:  # noqa: BLE001 - reports remain available if catalogue is unavailable
        requirement_rows = audit.requirement_results

    rp = dirpath / "requirements.csv"
    with open(rp, "w", newline="", encoding="utf-8") as fh:
        w = csv.writer(fh)
        w.writerow(["requirement_id", "name", "category", "severity", "axis", "axes", "status",
                    "sources", "findings", "locations", "description", "remediation", "notes"])
        for r in requirement_rows:
            w.writerow([r["requirement_id"], r.get("name", ""), r.get("category", ""),
                        r.get("severity", ""), axis_short(axis_of_requirement(r)),
                        ";".join(r.get("axis_ids", [])), r["status"],
                        ";".join(r.get("sources", [])),
                        ";".join(r.get("finding_ids", [])),
                        ";".join(r.get("locations", [])),
                        r.get("description", ""), r.get("remediation", ""),
                        " | ".join(r.get("notes", []))[:500]])
    paths.append(str(rp))
    return paths


# ---------------------------------------------------------------------------
# HTML
# ---------------------------------------------------------------------------

def _write_html_simple(audit: Audit, path: Path) -> None:
    """Write the readable report shown to reviewers by default.

    The previous HTML mixed the executive summary, every scanner's raw output,
    remediation examples and the complete matrix into one very long page.
    This version starts with the decision-making information and keeps the 137
    requirements in collapsible axis sections.  Raw evidence remains available
    in JSON/CSV and in the full PDF.
    """
    e = lambda value: html.escape(str(value)) if value is not None else ""
    sev = _severity_counts(audit)
    statuses = _status_counts(audit)
    fg = _axis_groups(audit)
    rg, transverse = _axis_req_groups(audit)
    total_requirements = len(audit.requirement_results)
    coverage = f"{total_requirements}/137"

    status_cards = "".join(
        f"<span class='card'><b>{statuses.get(s, 0)}</b> {e(status_fr(s))}</span>"
        for s in ("FAIL", "PARTIAL", "NOT_TESTED", "MANUAL_REVIEW", "PASS"))

    axis_rows = "".join(
        f"<tr><td><b>{e(name)}</b></td><td>{len(rs)}/{total_requirements}</td>"
        f"<td>{len(fs)}</td><td>{e(_axis_result_line(rs))}</td>"
        f"<td>{e(AXIS_TOOLS[i])}</td></tr>"
        for i, ((name, _key), fs, rs) in enumerate(zip(AXES, fg, rg)))
    if transverse:
        axis_rows += (f"<tr><td><b>Exigences transverses</b></td><td>{len(transverse)}</td>"
                      f"<td>—</td><td>{e(_axis_result_line(transverse))}</td>"
                      "<td>Revue manuelle</td></tr>")

    priority = [f for f in _sorted_findings(audit)
                if f.get("severity") in ("Critical", "High")]
    priority_rows = "".join(
        f"<tr><td>{e(sev_fr(f.get('severity')))}</td><td>{e(axis_short(_axis_index(f)))}</td>"
        f"<td><code>{e(_location(f))}</code></td><td><b>{e(f.get('title'))}</b>"
        f"<div class='muted'>{e(_req_names(f))}</div></td>"
        f"<td>{e((f.get('remediation') or '')[:260])}</td></tr>"
        for f in priority[:30]) or "<tr><td colspan='5'>Aucun constat critique ou élevé.</td></tr>"

    findings_rows = "".join(
        f"<tr><td>{e(f.get('id'))}</td><td>{e(sev_fr(f.get('severity')))}</td>"
        f"<td>{e(axis_short(_axis_index(f)))}</td><td>{e(f.get('title'))}"
        f"<div class='muted'>{e(_req_names(f))}</div></td>"
        f"<td><code>{e(_location(f))}</code></td><td>{e((f.get('proof') or '')[:180])}</td></tr>"
        for f in _sorted_findings(audit)) or "<tr><td colspan='6'>Aucun constat.</td></tr>"

    def requirement_table(reqs: list[dict]) -> str:
        rows = "".join(
            f"<tr><td><b>{e(r.get('requirement_id'))}</b></td>"
            f"<td>{e(r.get('name') or 'Nom indisponible')}"
            f"<div class='muted'>{e(r.get('category') or '')}</div></td>"
            f"<td>{e(', '.join(r.get('axis_ids') or [axis_short(axis_of_requirement(r))]))}</td>"
            f"<td class='status-{e(r.get('status'))}'><b>{e(status_fr(r.get('status')))}</b>"
            f"<div class='muted'>{e(', '.join(r.get('sources') or []))}</div></td>"
            f"<td><code>{e('; '.join(r.get('locations') or ['-']))}</code></td>"
            f"<td>{e(_req_row(r))}"
            f"<details><summary>Détail</summary><p>{e(r.get('description') or '')}</p>"
            f"<b>Correction :</b> {e(r.get('remediation') or 'Revue manuelle nécessaire.')}</details></td></tr>"
            for r in _sort_reqs(reqs))
        return ("<table><tr><th>ID</th><th>Exigence</th><th>Axe(s)</th>"
                "<th>Statut</th><th>Fichier / ligne (ou endpoint)</th><th>Preuve / correction</th></tr>" +
                (rows or "<tr><td colspan='6'>Aucune exigence.</td></tr>") + "</table>")

    requirement_sections = "".join(
        f"<details open><summary><b>{e(name)}</b> &mdash; {len(reqs)} exigence(s) — "
        f"{e(_axis_result_line(reqs))}</summary>{requirement_table(reqs)}</details>"
        for (name, _key), reqs in zip(AXES, rg))
    if transverse:
        requirement_sections += (f"<details><summary><b>Exigences transverses</b> — "
                                 f"{len(transverse)}</summary>{requirement_table(transverse)}</details>")

    cwe_rows = "".join(f"<li><b>{e(k)}</b> : {len(v)} constat(s)</li>"
                       for k, v in _cwe_map(audit).items()) or "<li>Aucun</li>"
    owasp_rows = "".join(f"<li><b>{e(k)}</b> : {len(v)} constat(s)</li>"
                         for k, v in _owasp_map(audit).items()) or "<li>Aucun</li>"
    limitations = "".join(f"<li>{e(item)}</li>" for item in _limitations(audit))
    network_rows = "".join(
        f"<tr><td><b>{e(host)}</b></td><td>{e(_network_ports_text(info))}</td></tr>"
        for host, info in ((audit.network_report or {}).get("hosts") or {}).items()
    ) or "<tr><td colspan='2'>Aucun résultat réseau disponible.</td></tr>"
    project = audit.project or {}
    score = audit.score or {}
    document = f"""<!DOCTYPE html>
<html lang="fr"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Rapport simple — {e(audit.id)}</title><style>
body{{font-family:system-ui,Segoe UI,sans-serif;background:#f6f7fb;color:#172033;margin:0}}
.wrap{{max-width:1180px;margin:auto;padding:24px}} h1{{margin:0 0 6px}} h2{{margin-top:28px;border-bottom:2px solid #dbe1ee;padding-bottom:6px}}
.muted{{color:#657089;font-size:.88em}} .banner,.card,details{{background:#fff;border:1px solid #dbe1ee;border-radius:9px;padding:12px;margin:8px 0}}
.cards{{display:flex;gap:8px;flex-wrap:wrap}} .card b{{font-size:1.3em}} table{{width:100%;border-collapse:collapse;background:#fff;margin:10px 0;font-size:13px}}
th,td{{border-bottom:1px solid #e3e7f0;padding:8px;text-align:left;vertical-align:top}} th{{background:#eef2f8;color:#4b5870}}
code{{background:#eef2f8;padding:2px 4px;border-radius:4px}} .status-FAIL{{color:#b42318}} .status-PARTIAL{{color:#b54708}}
.status-NOT_TESTED,.status-MANUAL_REVIEW{{color:#667085}} .status-PASS{{color:#067647}} summary{{cursor:pointer;padding:2px}}
.warning{{background:#fff4ed;border-color:#f7b27a}} a{{color:#175cd3}}
</style></head><body><main class="wrap">
<h1>Rapport d’audit Django</h1><p class="muted">{e(audit.id)} · {e(project.get('name'))} · {e(audit.created_at)}</p>
<h2> Synth\u00e8se </h2>
<div class="banner"><b>À retenir :</b> score indicatif <b>{e(score.get('score', '—'))}/100</b> ·
<b>{coverage}</b> exigences évaluées · <b>{len(audit.findings)}</b> constats.
Les exigences en échec, partielles, non testées ou en revue manuelle restent à traiter.</div>
<h2>1. R\u00e9sum\u00e9 en une minute</h2><div class="cards">{status_cards}</div>
<table><tr><th>Priorité</th><th>Constats</th><th>Signification</th></tr>
{''.join(f"<tr><td>{e(sev_fr(s))}</td><td>{sev.get(s, 0)}</td><td>{e(SEVERITY_MEANING[s])}</td></tr>" for s in SEVERITY_ORDER)}</table>
<h2>2. R\u00e9sultats par axe (4 axes)</h2>
<table><tr><th>Axe</th><th>Exigences</th><th>Constats</th><th>Résultat</th><th>Contrôles</th></tr>{axis_rows}</table>
<h2>3. Actions prioritaires</h2><table><tr><th>Gravité</th><th>Axe</th><th>Où</th><th>Constat et exigences concernées</th><th>Correction</th></tr>{priority_rows}</table>
<h2>4. R\u00e9sultats des exigences, group\u00e9s par axe — matrice des 137 exigences</h2><p class="muted">Chaque exigence est test\u00e9e ou explicitement marqu\u00e9e non test\u00e9e. Ouvrez une ligne « D\u00e9tail » pour voir l’objectif et la correction. Les axes multiples sont affich\u00e9s dans la colonne Axe(s).</p>
{requirement_sections}
<h2>5. Vuln\u00e9rabilit\u00e9s / constats avec preuve</h2><table><tr><th>ID</th><th>Gravit\u00e9</th><th>Axe</th><th>Constat / exigences concern\u00e9es</th><th>Emplacement</th><th>Preuve</th></tr>{findings_rows}</table>
<h2>6. Correspondance CWE / OWASP et rem\u00e9diation</h2><p><b>CWE</b></p><ul>{cwe_rows}</ul><p><b>OWASP</b></p><ul>{owasp_rows}</ul><p><b>Rem\u00e9diation :</b> les corrections sont affich\u00e9es dans les actions prioritaires et le d\u00e9tail de chaque exigence.</p>
<h2>7. Résultats réseau — ports réellement vérifiés</h2><table><tr><th>Cible</th><th>Ports testés</th></tr>{network_rows}</table>
<h2>8. Limites</h2><ul>{limitations}</ul><div class="banner warning">L’absence de constat ne prouve pas la s\u00e9curit\u00e9. Les sondes DAST sont heuristiques et les exigences non test\u00e9es n\u00e9cessitent une v\u00e9rification compl\u00e9mentaire.</div>
<p class="muted">Pour le détail brut : report.json, findings.csv et requirements.csv. Pour le rapport exhaustif : report-full.pdf.</p>
</main></body></html>"""
    # Keep the report UTF-8: browsers, API clients and Windows Python readers
    # can all consume the same file without locale-dependent decoding errors.
    path.write_text(document, encoding="utf-8")

def write_html(audit: Audit, path: Path) -> None:
    _write_html_simple(audit, path)
    return
    sev = _severity_counts(audit)
    st = _status_counts(audit)
    e = lambda s: html.escape(str(s)) if s is not None else ""

    cards = "".join(
        f'<div class="card" style="border-left:6px solid {SEV_COLORS[s]}">'
        f'<div class="num">{sev.get(s, 0)}</div><div>{sev_fr(s)}</div></div>'
        for s in SEVERITY_ORDER)
    req_cards = "".join(
        f'<div class="card"><div class="num">{st.get(s, 0)}</div>'
        f'<div style="color:{STATUS_COLORS[s]}">{status_fr(s)}</div>'
        f'<div class="small">{s}</div></div>'
        for s in ("PASS", "FAIL", "PARTIAL", "NOT_TESTED", "MANUAL_REVIEW"))

    findings_rows = "".join(
        f"<tr><td>{e(f['id'])}</td><td>{e(f['title'])}</td>"
        f"<td style='color:{SEV_COLORS.get(f['severity'], '#000')}'>{e(sev_fr(f['severity']))}</td>"
        f"<td>{e(f['confidence'])}</td>"
        f"<td>{e(axis_label(_axis_index(f)))}<div class='small'>{e(', '.join(f.get('sources', [])))}</div></td>"
        f"<td>{e(', '.join(f.get('cwe', [])))}</td>"
        f"<td>{e(f.get('owasp', ''))}</td>"
        f"<td>{e(', '.join(f.get('requirement_ids', [])))}</td>"
        f"<td><code>{e(_location(f))}</code></td>"
        f"<td><code>{e((f.get('proof') or '')[:160])}</code></td></tr>"
        for f in _sorted_findings(audit))

    # ---- sections 4 axes (constats + résultats des exigences) -------------
    fg = _axis_groups(audit)
    rg, transverse = _axis_req_groups(audit)
    axes_html = ""
    for i, ((name, _key), fs, rs) in enumerate(zip(AXES, fg, rg)):
        stc = Counter(r["status"] for r in rs)
        sevc = Counter(f["severity"] for f in fs)
        sevc_txt = ", ".join(sev_fr(k) + ": " + str(v) for k, v in sevc.items()) or "aucun"
        mini = " &middot; ".join(
            f"<span style='color:{STATUS_COLORS[s]}'>{stc.get(s, 0)} {status_fr(s)}</span>"
            for s in ("PASS", "FAIL", "PARTIAL", "NOT_TESTED", "MANUAL_REVIEW"))
        rows = "".join(
            f"<tr><td>{e(f['title'])}</td>"
            f"<td style='color:{SEV_COLORS.get(f['severity'], '#000')}'>{e(sev_fr(f['severity']))}</td>"
            f"<td>{e(f['confidence'])}</td>"
            f"<td><code>{e(_location(f))}</code></td>"
            f"<td><code>{e((f.get('proof') or '')[:120])}</code></td>"
            f"<td>{e(fix_for(f)['after'][:220])}</td></tr>"
            for f in fs)
        axes_html += f"""<h2>{e(name)} — résultats</h2>
<p class="small" style="font-size:12px">{len(fs)} constat(s) ({e(sevc_txt)}) &nbsp;|&nbsp;
{len(rs)} exigence(s) de cet axe : {mini}</p>
<table><tr><th>Constat</th><th>Sévérité</th><th>Confiance</th><th>Emplacement</th>
<th>Code / preuve</th><th>Correction exacte</th></tr>
{rows or '<tr><td colspan=6>Aucun constat sur cet axe</td></tr>'}</table>
"""
    if transverse:
        stc = Counter(r["status"] for r in transverse)
        mini_t = " &middot; ".join(
            f"<span style='color:{STATUS_COLORS[s]}'>{stc.get(s, 0)} {status_fr(s)}</span>"
            for s in ("PASS", "FAIL", "PARTIAL", "NOT_TESTED", "MANUAL_REVIEW"))
        axes_html += (f"""<h2>Exigences transverses — résultats</h2>
<p class="small" style="font-size:12px">{len(transverse)} exigence(s) sans scanner dédié
(processus, gouvernance, revue manuelle) : {mini_t}</p>""")
    fix_blocks = "".join(
        (lambda fx: f"""<div class=\"banner\" style=\"border-left:6px solid {SEV_COLORS.get(f['severity'],'#334155')}\">
 <b>[{e(sev_fr(f['severity']))}] {e(f['title'])}</b> &mdash; <code>{e(_location(f))}</code><br>
 {('<b>Code vulnérable :</b> <code>' + e(f.get('proof') or '') + '</code><br>') if f.get('proof') else ''}
 {(('<b>Pourquoi c&#39;est dangereux :</b> ' + e(fx['problem']) + '<br>') if fx['problem'] else '')}
 <b>Au lieu de :</b><pre style=\"background:#0b1220;padding:8px;border-radius:6px;overflow:auto\">{e(fx['before'])}</pre>
 <b>Faire ceci :</b><pre style=\"background:#0b1220;padding:8px;border-radius:6px;overflow:auto\">{e(fx['after'])}</pre>
 <b>Remédiation :</b> {e(f.get('remediation', ''))}
 </div>""")(fix_for(f))
        for f in _sorted_findings(audit))

    def _req_table(reqs: list[dict]) -> str:
        rows = "".join(
            f"<tr><td><b>{e(r['requirement_id'])}</b></td>"
            f"<td style='color:{STATUS_COLORS.get(r['status'], '#000')}'>{e(status_fr(r['status']))}"
            f"<div class='small'>{e(r['status'])}</div></td>"
            f"<td>{e(', '.join(r.get('sources', [])))}</td>"
            f"<td>{e(' | '.join(r.get('notes', []))[:300])}</td></tr>"
            for r in _sort_reqs(reqs))
        return ("<table><tr><th style='width:90px'>Exigence</th>"
                "<th style='width:120px'>Statut</th><th style='width:140px'>Sources</th>"
                f"<th>Preuve / note</th></tr>{rows or '<tr><td colspan=4>Aucune</td></tr>'}"
                "</table>")

    req_axis_html = ""
    for i, ((name, _key), reqs) in enumerate(zip(AXES, rg)):
        req_axis_html += (f"<h3>{e(name)} &mdash; {len(reqs)} exigence(s)</h3>"
                          f"<p class='small' style='font-size:12px'>{e(_axis_result_line(reqs))} "
                          f"&middot; {e(AXIS_TOOLS[i])}</p>{_req_table(reqs)}")
    if transverse:
        req_axis_html += (f"<h3>Exigences transverses &mdash; {len(transverse)} exigence(s)</h3>"
                          "<p class='small' style='font-size:12px'>Aucun scanner dédié : "
                          f"processus, gouvernance, revue manuelle. {e(_axis_result_line(transverse))}</p>"
                          f"{_req_table(transverse)}")

    jobs_rows = "".join(
        f"<tr><td>{e(j['name'])}</td><td>{e(j['status'])}</td><td>{e(j.get('error') or '')}</td></tr>"
        for j in audit.jobs)

    _total = len(audit.findings)
    _sev = _severity_counts(audit)
    sev_meaning_rows = "".join(
        f"<tr><td style='color:{SEV_COLORS.get(s, '#000')}'><b>{e(sev_fr(s))}</b>"
        f"<div class='small'>{s}</div></td><td>{_sev.get(s, 0)}</td>"
        f"<td>{_pct(_sev.get(s, 0), _total)}</td><td>{e(SEVERITY_MEANING[s])}</td></tr>"
        for s in SEVERITY_ORDER)
    axis_share_rows = "".join(
        f"<tr><td>{e(name)}</td><td>{len(fs)}</td><td>{_pct(len(fs), _total)}</td>"
        f"<td>{len(rs)} exigences : {e(_axis_result_line(rs))}</td>"
        f"<td>{e(AXIS_TOOLS[i])}</td></tr>"
        for i, ((name, _k), fs, rs) in enumerate(zip(AXES, fg, rg))) + (
        f"<tr><td>Exigences transverses (aucun scanner dédié)</td><td>-</td><td>-</td>"
        f"<td>{len(transverse)} exigences : {e(_axis_result_line(transverse))}</td>"
        f"<td>revue manuelle</td></tr>" if transverse else "")
    priority_rows = "".join(
        f"<tr><td style='color:{SEV_COLORS.get(f['severity'], '#000')}'>"
        f"<b>{e(sev_fr(f['severity']))}</b></td><td>{e(axis_short(_axis_index(f)))} "
        f"{e(axis_label(_axis_index(f)))}</td>"
        f"<td><code>{e(_location(f))}</code></td><td>{e(f['title'])}</td>"
        f"<td>{e((f.get('remediation') or '')[:200])}</td></tr>"
        for f in _sorted_findings(audit) if f["severity"] in ("Critical", "High")) \
        or "<tr><td colspan=5>Aucun constat Critique ou Élevé.</td></tr>"
    hotspot_rows = "".join(
        f"<tr><td><code>{e(where)}</code></td><td>{n}</td><td>{e(mix)}</td></tr>"
        for where, n, mix in _hotspots(audit, limit=15))
    hotspot_html = ("<h3>Emplacements les plus touchés (fichiers / endpoints)</h3>"
                    "<table><tr><th>Fichier / endpoint</th><th>Constats</th>"
                    "<th>Mix sévérités</th></tr>"
                    f"{hotspot_rows}</table>") if hotspot_rows else ""

    project = audit.project or {}
    score = audit.score or {}
    doc = f"""<!DOCTYPE html>
<html lang="fr"><head><meta charset="utf-8">
<title>Rapport d'audit de sécurité - {e(audit.id)}</title>
<style>
 body{{font-family:ui-sans-serif,system-ui,Segoe UI,Roboto,sans-serif;margin:0;background:#0f172a;color:#e2e8f0}}
 .wrap{{max-width:1200px;margin:0 auto;padding:24px}}
 h1{{font-size:22px}} h2{{font-size:16px;margin-top:34px;border-bottom:1px solid #334155;padding-bottom:6px}}
 .cards{{display:flex;flex-wrap:wrap;gap:12px;margin:14px 0}}
 .card{{background:#1e293b;border-radius:8px;padding:10px 18px;min-width:110px}}
 .card .num{{font-size:26px;font-weight:700}}
 .small{{font-size:11px;color:#94a3b8}}
 table{{border-collapse:collapse;width:100%;font-size:12px;margin-top:8px}}
 th,td{{border:1px solid #334155;padding:6px 8px;text-align:left;vertical-align:top}}
 th{{background:#1e293b}}
 .banner{{background:#1e293b;border-radius:10px;padding:16px;margin:12px 0}}
 .disclaimer{{background:#7c2d12;border-radius:8px;padding:10px 14px;font-size:13px}}
 code{{background:#0b1220;padding:1px 5px;border-radius:4px}}
</style></head><body><div class="wrap">
<h1>Rapport d'audit de sécurité Django</h1>
<div class="banner">
 <b>Audit :</b> {e(audit.id)} &nbsp; <b>Projet :</b> {e(project.get('name'))} &nbsp;
 <b>Source :</b> {e(project.get('source_type'))} {e(project.get('repo_url') or project.get('path') or '')}
 {('<br><b>Commit :</b> <code>' + e(project.get('commit_sha')) + '</code> <b>Branche :</b> ' + e(project.get('branch'))) if project.get('commit_sha') else ''}
 <br><b>Créé le :</b> {e(audit.created_at)} &nbsp; <b>Statut :</b> {e(audit.status)}
</div>

<h2>1. Synthèse</h2>
<div class="banner">Score de sécurité : <b>{e(score.get('score'))}/{e(score.get('max', 100))}</b>
(indicateur seulement — les constats et les statuts d'exigences font foi)</div>
<table><tr><th>Sévérité</th><th>Constats</th><th>Part</th><th>Ce que cela signifie</th></tr>
{sev_meaning_rows}</table>
<h3>2. Résultats par axe (4 axes)</h3>
<table><tr><th>Axe</th><th>Constats</th><th>Part</th><th>Résultats des exigences</th><th>Outils</th></tr>
{axis_share_rows}</table>
<h3>3. Actions prioritaires (Critique + Élevé) avec emplacements</h3>
<table><tr><th>Sévérité</th><th>Axe</th><th>Emplacement</th><th>Constat</th><th>Correction</th></tr>
{priority_rows}</table>
{hotspot_html}
<div class="cards">{cards}</div>
<div class="cards">{req_cards}</div>
<p>Exigences évaluées : <b>{len(audit.requirement_results)}</b> &middot;
Constats (dédupliqués) : <b>{len(audit.findings)}</b></p>

{axes_html}

<h2>4. Environnement d'analyse / tâches du pipeline</h2>
<table><tr><th>Tâche</th><th>Statut</th><th>Erreur</th></tr>{jobs_rows}</table>

<h2>5. Vulnérabilités (constats dédupliqués)</h2>
<table><tr><th>ID</th><th>Titre</th><th>Sévérité</th><th>Confiance</th><th>Axe / moteur</th><th>CWE</th>
<th>OWASP</th><th>Exigences</th><th>Emplacement</th><th>Code / preuve</th></tr>
{findings_rows or '<tr><td colspan=10>Aucun constat</td></tr>'}</table>

<h2>6. Comment corriger (remédiation exacte)</h2>
{fix_blocks or "<p>Aucun constat à corriger.</p>"}

<h2>7. Résultats des exigences, groupés par axe ({len(audit.requirement_results)} exigences)</h2>
{req_axis_html}

<h2>8. Correspondance CWE</h2><ul>{''.join(f'<li><b>{e(k)}</b> : {len(v)} constat(s)</li>' for k, v in _cwe_map(audit).items())}</ul>

<h2>9. Correspondance OWASP Top 10</h2><ul>{''.join(f'<li><b>{e(k)}</b> : {len(v)} constat(s)</li>' for k, v in _owasp_map(audit).items())}</ul>

<h2>10. Remédiation prioritaire</h2><ul>{''.join(f"<li><b>{e(f['title'])}</b> ({e(sev_fr(f['severity']))}) : {e(f.get('remediation', ''))}</li>" for f in _sorted_findings(audit) if f['severity'] in ('Critical', 'High'))}</ul>

<h2>11. Limites</h2><ul>{''.join(f'<li>{e(x)}</li>' for x in _limitations(audit))}</ul>
<div class="disclaimer">Ce rapport reflète uniquement une vérification automatique et
semi-automatique. Les exigences NON TESTÉES et en REVUE MANUELLE restent ouvertes.
Un score élevé ne signifie PAS que l'application est sûre : l'absence de constat
ne prouve pas la sécurité.</div>
</div></body></html>"""
    path.write_text(doc, encoding="utf-8")


# ---------------------------------------------------------------------------
# PDF
# ---------------------------------------------------------------------------

def write_pdf(audit: Audit, path: Path, full: bool = False) -> None:
    """PDF de synthèse (court, 3-6 pages) ou rapport détaillé complet (full=True).

    La version de synthèse répond à : qu'est-ce qui est critique, où, sur quel
    axe, quelle part du total — et renvoie aux artefacts détaillés.
    """
    from security_auditor.apps.reports.pdf import render_pdf
    blocks = _pdf_blocks_full(audit) if full else _pdf_blocks_executive(audit)
    path.write_bytes(render_pdf(blocks, f"Audit {audit.id}"))


def _network_ports_text(info: dict) -> str:
    """Return the exact ports tested for one host, including detected service names."""
    ports = info.get("ports") or []
    if not ports:
        return "Aucun détail de port disponible"
    values = []
    for item in ports:
        port = item.get("port", "?")
        service = item.get("service") or "service inconnu"
        state = item.get("state") or "inconnu"
        values.append(f"{port} ({service}, {state})")
    return ", ".join(values)


def write_requirements_pdf(audit: Audit, path: Path) -> None:
    """Rapport des 137 exigences : statut de chacune, groupé par axe.

    Une section par axe (SAST / configuration / dépendances / réseau-ports & DAST)
    puis les exigences transverses (aucun scanner dédié) et les non applicables.
    """
    from security_auditor.apps.reports.pdf import render_pdf
    blocks: list[tuple[str, str]] = []
    project = audit.project or {}
    rr = audit.requirement_results or []
    rg, transverse = _axis_req_groups(audit)
    st = _status_counts(audit)

    blocks.append(("h1", "Rapport des exigences — résultats par axe"))
    blocks.append(("body", f"Audit {audit.id} — créé le {audit.created_at}"))
    blocks.append(("body", f"Projet : {project.get('name')} "
                           f"({project.get('source_type')} : "
                           f"{project.get('repo_url') or project.get('path') or ''})"))
    blocks.append(("hr", ""))
    blocks.append(("h2", "Comment lire ce rapport"))
    blocks.append(("body", f"{len(rr)} exigences sont évaluées. Chaque exigence est rattachée à "
                           "l'axe qui la porte (déclaré dans le catalogue des 137), puis son "
                           "résultat est indiqué : Vérifié, Échec, Partiel, Non testé, Revue "
                           "manuelle, Non applicable."))
    blocks.append(("body", "Statuts : " + ", ".join(
        f"{status_fr(k)} {v}" for k, v in sorted(st.items()) if v)))

    for i, ((name, _key), reqs) in enumerate(zip(AXES, rg)):
        blocks.append(("h2", f"{name} — {len(reqs)} exigence(s)"))
        blocks.append(("body", f"Résultats : {_axis_result_line(reqs)} | outils : {AXIS_TOOLS[i]}"))
        if not reqs:
            blocks.append(("body", "Aucune exigence rattachée à cet axe."))
            continue
        blocks.append(("th:0,45,185,230,320,420", "ID|Exigence|Axe(s)|Statut|Fichier / ligne|Preuve / correction"))
        for r in _sort_reqs(reqs):
            blocks.append(("t:0,45,185,230,320,420",
                           f"{r['requirement_id']}|{r.get('name', '')}|"
                           f"{', '.join(r.get('axis_ids') or [axis_short(axis_of_requirement(r))])}|"
                           f"{status_fr(r['status'])}|{'; '.join(r.get('locations') or ['-'])}|{_req_row(r)}"))

    if transverse:
        blocks.append(("h2", f"Exigences transverses — {len(transverse)} exigence(s)"))
        blocks.append(("body", "Aucun scanner dédié : processus, gouvernance, revue manuelle. "
                               f"Résultats : {_axis_result_line(transverse)}"))
        blocks.append(("th:0,45,185,230,320,420", "ID|Exigence|Axe(s)|Statut|Fichier / ligne|Preuve / correction"))
        for r in _sort_reqs(transverse):
            blocks.append(("t:0,45,185,230,320,420",
                           f"{r['requirement_id']}|{r.get('name', '')}|"
                           f"{', '.join(r.get('axis_ids') or ['—'])}|"
                           f"{status_fr(r['status'])}|{'; '.join(r.get('locations') or ['-'])}|{_req_row(r)}"))

    na = [r for r in rr if r["status"] == "NOT_APPLICABLE"]
    if na:
        blocks.append(("h2", f"Non applicables — {len(na)} exigence(s)"))
        blocks.append(("body", ", ".join(r["requirement_id"] for r in na)))

    blocks.append(("h2", "Rappel — ce que ce rapport ne dit pas"))
    blocks.append(("body", "Une exigence « Vérifié » est couverte par des preuves automatiques ; "
                           "« Non testé » et « Revue manuelle » restent des points ouverts. "
                           "L'absence de constat ne prouve pas la sécurité."))
    path.write_bytes(render_pdf(blocks, f"Exigences {audit.id}"))

def _pdf_blocks_executive(audit: Audit) -> list[tuple[str, str]]:
    project = audit.project or {}
    score = audit.score or {}
    sev = _severity_counts(audit)
    st = _status_counts(audit)
    total = len(audit.findings)
    blocks: list[tuple[str, str]] = []

    blocks.append(("h1", "Rapport d'audit de sécurité Django — Synthèse"))
    blocks.append(("body", f"Audit {audit.id} — créé le {audit.created_at}"))
    blocks.append(("body", f"Projet : {project.get('name')} "
                           f"({project.get('source_type')} : "
                           f"{project.get('repo_url') or project.get('path') or ''})"))
    if project.get("commit_sha"):
        blocks.append(("body", f"Commit {project.get('commit_sha')} branche {project.get('branch')}"))
    blocks.append(("hr", ""))

    # -- 1. synthèse --------------------------------------------------------
    blocks.append(("h2", "1. Synthèse"))
    blocks.append(("body", f"Score de sécurité : {score.get('score')}/100 (indicateur seulement — "
                           "les constats et les statuts d'exigences font foi)."))
    blocks.append(("body", f"{total} constat(s) sur {len(audit.requirement_results)} "
                           "exigences évaluées."))
    blocks.append(("th:0,80,200,320", "Sévérité|Constats|Part|Ce que cela signifie"))
    for s in SEVERITY_ORDER:
        n = sev.get(s, 0)
        blocks.append((f"t:0,80,200,320",
                       f"{sev_fr(s)}|{n}|{_pct(n, total)}|{SEVERITY_MEANING[s]}"))
    blocks.append(("t:0,80,200,320", f"TOTAL|{total}|100%|"))
    blocks.append(("kv", "codes (JSON/CSV) : Critical=Critique, High=Élevé, Medium=Moyen, "
                         "Low=Faible, Info=Info"))
    blocks.append(("body", "Exigences : " + ", ".join(
        f"{status_fr(k)} {v}" for k, v in sorted(st.items(), key=lambda kv: kv[0]))))

    # -- 2. résultats par axe ----------------------------------------------
    blocks.append(("h2", "2. Résultats par axe (4 axes)"))
    blocks.append(("th:0,195,250,495", "Axe|Constats|Exig.|Résultats des exigences (statuts)"))
    rg, transverse = _axis_req_groups(audit)
    for i, ((name, _key), fs, rs) in enumerate(zip(AXES, _axis_groups(audit), rg)):
        sevc = Counter(f["severity"] for f in fs)
        mix = ", ".join(f"{sev_fr(s)} {sevc[s]}" for s in SEVERITY_ORDER if sevc.get(s))
        blocks.append(("t:0,195,250,495",
                       f"{name}|{len(fs)} · {_pct(len(fs), total)}|{len(rs)}|"
                       f"{_axis_result_line(rs)}"))
        if mix:
            blocks.append(("kv", f"      constats : {mix} | outils : {AXIS_TOOLS[i]}"))
    if transverse:
        blocks.append(("t:0,195,250,495",
                       f"Exigences transverses (aucun scanner dédié)|-|-|{_axis_result_line(transverse)}"))

    # -- 3. contrôle réseau ------------------------------------------------
    blocks.append(("h2", "3. Contrôle réseau — ports réellement vérifiés"))
    network_hosts = (audit.network_report or {}).get("hosts") or {}
    if network_hosts:
        for host, info in network_hosts.items():
            blocks.append(("kv", f"{host} : {_network_ports_text(info)}"))
    else:
        blocks.append(("body", "Aucun résultat réseau disponible pour cet audit."))

    # -- 4. actions prioritaires -------------------------------------------
    prio = [f for f in _sorted_findings(audit) if f["severity"] in ("Critical", "High")]
    blocks.append(("h2", "3. Actions prioritaires (Critique + Élevé)"))
    if not prio:
        blocks.append(("body", "Aucun constat Critique ou Élevé sur ce run — voir le rapport "
                               "complet pour les points Moyen/Faible."))
    else:
        blocks.append(("th:0,45,75,255", "Sévérité|Axe|Emplacement|Constat"))
        for f in prio[:30]:
            blocks.append(("t:0,45,75,255",
                           f"{sev_fr(f['severity'])}|{axis_short(_axis_index(f))}|"
                           f"{_location(f)}|{f['title']}"))
            fix = (f.get("remediation") or "").strip()
            if fix:
                blocks.append(("kv", f"      correction : {fix[:220]}"))
        if len(prio) > 30:
            blocks.append(("body", f"... et {len(prio) - 30} autres constats Critique/Élevé "
                                   "(voir le rapport complet ou findings.csv)."))

    # -- 5. emplacements les plus touchés ----------------------------------
    hot = _hotspots(audit)
    if hot:
        blocks.append(("h2", "4. Emplacements les plus touchés (fichiers / endpoints)"))
        blocks.append(("th:0,240,290,470", "Fichier / endpoint|Constats|Mix sévérités|"))
        for where, n, mix in hot:
            blocks.append(("t:0,240,290,470", f"{where}|{n}|{mix}|"))

    # -- 6. couverture des exigences ---------------------------------------
    blocks.append(("h2", "5. Couverture des exigences"))
    blocks.append(("th:0,150,210,300", "Statut|Exigences|Part|Signification"))
    for s in ("PASS", "FAIL", "PARTIAL", "NOT_TESTED", "MANUAL_REVIEW", "NOT_APPLICABLE"):
        n = st.get(s, 0)
        if not n:
            continue
        blocks.append(("t:0,150,210,300",
                       f"{status_fr(s)} ({s})|{n}|"
                       f"{_pct(n, len(audit.requirement_results))}|{STATUS_MEANING[s]}"))
    fails = [r["requirement_id"] for r in audit.requirement_results if r["status"] == "FAIL"]
    if fails:
        blocks.append(("body", "Exigences en ÉCHEC : " + ", ".join(fails[:40])
                               + (f" (+{len(fails) - 40} autres)" if len(fails) > 40 else "")))

    # -- 7. couverture des analyseurs --------------------------------------
    blocks.append(("h2", "6. Analyseurs et couverture"))
    for j in audit.jobs:
        blocks.append(("kv", f"{j['name']} : {j['status']}"
                             + (f" ({j.get('error')})" if j.get("error") else "")))

    # -- 8. limites ---------------------------------------------------------
    blocks.append(("h2", "7. Limites — ce qui n'est PAS prouvé"))
    for x in _limitations(audit):
        blocks.append(("bullet", x))

    # -- 9. où trouver le détail -------------------------------------------
    blocks.append(("h2", "8. Détail complet"))
    blocks.append(("body", "Chaque constat avec preuve, requête/réponse, correction exacte du "
                           "code et rattachement aux exigences se trouve dans :"))
    blocks.append(("kv", "reports/report.html — détail complet, imprimable"))
    blocks.append(("kv", "reports/report.pdf (ce fichier) — synthèse"))
    blocks.append(("kv", "reports/report-full.pdf — détail complet en PDF"))
    blocks.append(("kv", "reports/report-requirements.pdf — les 137 exigences groupées par axe"))
    blocks.append(("kv", "reports/findings.csv — une ligne par constat (Excel)"))
    blocks.append(("kv", "reports/report.json — état d'audit lisible par machine"))
    blocks.append(("body", "Un score élevé ou l'absence de constat ne prouve PAS que "
                           "l'application est sûre. Les exigences non testées et en revue "
                           "manuelle restent ouvertes."))
    return blocks


def _pdf_blocks_full(audit: Audit) -> list[tuple[str, str]]:
    blocks: list[tuple[str, str]] = []
    project = audit.project or {}
    score = audit.score or {}
    sev = score.get("findings_by_severity", _severity_counts(audit))
    st = _status_counts(audit)
    total = len(audit.findings)

    blocks.append(("h1", "Rapport d'audit de sécurité Django — Détail complet"))
    blocks.append(("body", f"Audit {audit.id} — créé le {audit.created_at}"))

    blocks.append(("h2", "1. Synthèse"))
    blocks.append(("body", f"Score de sécurité : {score.get('score')}/100 (indicateur seulement — "
                           "les constats et les statuts d'exigences font foi)."))
    blocks.append(("th:0,80,200,320", "Sévérité|Constats|Part|Ce que cela signifie"))
    for s in SEVERITY_ORDER:
        n = sev.get(s, 0)
        blocks.append(("t:0,80,200,320",
                       f"{sev_fr(s)} ({s})|{n}|{_pct(n, total)}|{SEVERITY_MEANING[s]}"))
    blocks.append(("body", "Exigences : " + ", ".join(
        f"{status_fr(k)} : {v}" for k, v in sorted(st.items()))))

    blocks.append(("h2", "1bis. Résultats par axe (4 axes)"))
    rg, transverse = _axis_req_groups(audit)
    for i, ((name, _key), fs, rs) in enumerate(zip(AXES, _axis_groups(audit), rg)):
        sevc = Counter(f["severity"] for f in fs)
        mix = ", ".join(f"{sev_fr(k)} : {v}" for k, v in sevc.items()) or "aucun"
        blocks.append(("kv", f"{name} : {len(fs)} constat(s) [{mix}] ; "
                             f"{len(rs)} exigences [{_axis_result_line(rs)}] ; "
                             f"outils : {AXIS_TOOLS[i]}"))
    if transverse:
        blocks.append(("kv", f"Exigences transverses (aucun scanner dédié) : "
                             f"{len(transverse)} exigences [{_axis_result_line(transverse)}]"))

    blocks.append(("h2", "2. Informations projet"))
    blocks.append(("kv", f"nom : {project.get('name')}"))
    blocks.append(("kv", f"source : {project.get('source_type')} "
                         f"{project.get('repo_url') or project.get('path') or ''}"))
    if project.get("commit_sha"):
        blocks.append(("kv", f"commit : {project.get('commit_sha')} "
                             f"branche : {project.get('branch')}"))

    blocks.append(("h2", "3. Environnement d'analyse"))
    for j in audit.jobs:
        blocks.append(("kv", f"{j['name']} : {j['status']}"
                             + (f" ({j.get('error')})" if j.get("error") else "")))

    blocks.append(("h2", "4. Résultats des exigences, groupés par axe"))
    blocks.append(("body", f"{len(audit.requirement_results)} exigences évaluées. "
                           "Statuts : " + ", ".join(
                               f"{status_fr(k)} {v}" for k, v in sorted(st.items()) if v)))
    rg4, transverse4 = _axis_req_groups(audit)
    for i, ((name, _key), reqs) in enumerate(zip(AXES, rg4)):
        blocks.append(("h3", f"{name} — {len(reqs)} exigence(s) : {_axis_result_line(reqs)}"))
        blocks.append(("th:0,62,135,205", "Exigence|Statut|Sources|Preuve / note"))
        for r in _sort_reqs(reqs):
            blocks.append(("t:0,62,135,205",
                           f"{r['requirement_id']}|{status_fr(r['status'])}|"
                           f"{', '.join(r.get('sources') or [])}|{_req_row(r)}"))
    if transverse4:
        blocks.append(("h3", f"Exigences transverses — {len(transverse4)} : "
                             f"{_axis_result_line(transverse4)}"))
        blocks.append(("th:0,62,135,205", "Exigence|Statut|Sources|Preuve / note"))
        for r in _sort_reqs(transverse4):
            blocks.append(("t:0,62,135,205",
                           f"{r['requirement_id']}|{status_fr(r['status'])}|"
                           f"{', '.join(r.get('sources') or [])}|{_req_row(r)}"))

    blocks.append(("h2", "6. Résultats SAST"))
    blocks.append(("body", f"Fichiers analysés : {audit.sast_data.get('files_scanned', 'n/a')}, "
                           f"constats attribués au SAST : "
                           f"{sum(1 for f in audit.findings if 'sast' in f.get('sources', []))}"))

    blocks.append(("h2", "7. Résultats dépendances"))
    d = audit.dependencies_report or {}
    blocks.append(("body", f"Paquets : {d.get('total', 'n/a')}, épinglés : {d.get('pinned', 'n/a')}, "
                           f"non épinglés : {d.get('unpinned', 'n/a')}, entrées vulnérables : "
                           f"{d.get('vulnerable', 'n/a')}"))

    blocks.append(("h2", "8. Résultats réseau"))
    n = audit.network_report or {}
    for host, info in (n.get("hosts") or {}).items():
        s = (info.get("summary") or {})
        blocks.append(("kv", f"{host} : ouverts={s.get('open')} fermés={s.get('closed')} "
                             f"filtrés={s.get('filtered')} méthode={info.get('method')}"))
        blocks.append(("body", f"Ports réellement vérifiés : {_network_ports_text(info)}"))

    blocks.append(("h2", "9. Résultats DAST"))
    da = audit.dast_report or {}
    blocks.append(("body", f"base_url : {da.get('base_url', 'non démarré')}, contrôles : "
                           f"{da.get('checks_run', 0)}"))

    blocks.append(("h2", "10. Vulnérabilités"))
    for f in _sorted_findings(audit):
        blocks.append(("h3", f"[{sev_fr(f['severity'])}/{f['confidence']}] {f['title']}"))
        blocks.append(("body", f"{f['description'][:300]}"))
        blocks.append(("kv", f"axe : {axis_label(_axis_index(f))}  "
                             f"emplacement : {_location(f)}"))
        blocks.append(("kv", f"CWE : {', '.join(f.get('cwe', []))}  OWASP : {f.get('owasp', '')}  "
                             f"exigences : {', '.join(f.get('requirement_ids', []))}"))
        blocks.append(("kv", f"preuve : {f.get('proof', '')[:200]}"))
        blocks.append(("kv", f"remédiation : {f.get('remediation', '')[:200]}"))
        fx = fix_for(f)
        if fx["after"]:
            blocks.append(("kv", f"au lieu de : {fx['before'][:180]}"))
            blocks.append(("kv", f"faire ceci : {fx['after'][:400]}"))

    blocks.append(("h2", "11. Correspondance CWE"))
    for k, v in _cwe_map(audit).items():
        blocks.append(("kv", f"{k} : {len(v)} constat(s)"))
    blocks.append(("h2", "12. Correspondance OWASP"))
    for k, v in _owasp_map(audit).items():
        blocks.append(("kv", f"{k} : {len(v)} constat(s)"))

    blocks.append(("h2", "13. Remédiation prioritaire"))
    for f in _sorted_findings(audit):
        if f["severity"] in ("Critical", "High"):
            blocks.append(("kv", f"- {f['title']} : {f.get('remediation', '')[:180]}"))

    if audit.comparison:
        blocks.append(("h2", "14. Résultats du retest"))
        c = audit.comparison
        blocks.append(("body", f"corrigés : {len(c.get('fixed', []))}, toujours présents : "
                               f"{len(c.get('still_present', []))}, nouveaux : {len(c.get('new', []))}"))
        for t in c.get("fixed", []):
            blocks.append(("kv", f"CORRIGÉ : {t}"))
        for t in c.get("still_present", []):
            blocks.append(("kv", f"TOUJOURS PRÉSENT : {t}"))
        for t in c.get("new", []):
            blocks.append(("kv", f"NOUVEAU : {t}"))

    blocks.append(("h2", "15. Limites"))
    for x in _limitations(audit):
        blocks.append(("bullet", x))
    blocks.append(("body", "Un score élevé ou l'absence de constat ne prouve PAS que "
                           "l'application est sûre. Les exigences non testées et en revue "
                           "manuelle restent ouvertes."))
    return blocks


# ---------------------------------------------------------------------------

def generate_all_reports(store: AuditStore, audit: Audit) -> dict:
    d = store.dir_for(audit.id) / "reports"
    d.mkdir(parents=True, exist_ok=True)
    paths = {}
    write_json(audit, d / "report.json")
    paths["json"] = str(d / "report.json")
    write_html(audit, d / "report.html")
    paths["html"] = str(d / "report.html")
    csv_paths = write_csv(audit, d)
    paths["csv"] = csv_paths[0]
    write_pdf(audit, d / "report.pdf")                  # synthèse (court)
    paths["pdf"] = str(d / "report.pdf")
    write_pdf(audit, d / "report-full.pdf", full=True)  # détail complet
    paths["pdf_full"] = str(d / "report-full.pdf")
    write_requirements_pdf(audit, d / "report-requirements.pdf")   # 137 exigences par axe
    paths["pdf_req"] = str(d / "report-requirements.pdf")
    return paths
