"""SAST orchestrator: merges AST analysis + pattern scanning into findings.

Produces one Finding per unique (file, line, rule) hit plus Evidence records.
Secrets are masked in every stored snippet (spec 30).  Confidence may be
upgraded by taint analysis (spec 19).
"""
from __future__ import annotations

from pathlib import Path

from security_auditor.apps.audits.utils import mask_secrets
from security_auditor.scanners.base import (BaseScanner, Evidence, Finding, ScanResult,
                           confidence_rank, worst_severity)
from security_auditor.scanners.sast.ast_analyzer import analyze_source
from security_auditor.scanners.sast.patterns import (MAX_FILE_SIZE, scan_file_text, should_scan)
from security_auditor.scanners.sast.rules import RULES


class SASTScanner(BaseScanner):
    name = "sast"
    description = "Static application security testing (patterns + AST + taint)"

    def run(self, context) -> ScanResult:
        root = Path(context.source_dir)
        result = ScanResult(scanner=self.name)
        seen: set[tuple] = set()
        files_scanned = py_files = 0
        all_controls: list[dict] = []

        for path in sorted(root.rglob("*")):
            if not path.is_file():
                continue
            rel = path.relative_to(root).as_posix()
            if not should_scan(rel):
                continue
            try:
                if path.stat().st_size > MAX_FILE_SIZE:
                    continue
                text = path.read_text(encoding="utf-8", errors="replace")
            except OSError:
                continue
            files_scanned += 1

            # --- pattern layer -----------------------------------------
            vulns, controls = scan_file_text(rel, text)
            for c in controls:
                all_controls.append({**c, "file": rel, "line": 0})
            for v in vulns:
                key = (rel, v["line"], v["rule_id"])
                if key in seen:
                    continue
                seen.add(key)
                self._emit(result, rel, v["line"], v["rule_id"],
                           confidence=None, note=v.get("note", ""),
                           snippet=v.get("snippet", ""))

            # --- AST layer (python only) -------------------------------
            if rel.endswith(".py"):
                py_files += 1
                try:
                    ast_result = analyze_source(rel, text)
                except RecursionError:
                    continue
                for hit in ast_result.hits:
                    key = (rel, hit.line, hit.rule_id)
                    if key in seen:
                        continue
                    seen.add(key)
                    snippet = text.splitlines()[hit.line - 1].strip() \
                        if 0 < hit.line <= len(text.splitlines()) else ""
                    self._emit(result, rel, hit.line, hit.rule_id,
                               confidence=hit.confidence, note=hit.note,
                               snippet=snippet)
                for c in ast_result.controls:
                    all_controls.append({"rule_key": c.rule_key, "req_ids": c.req_ids,
                                         "summary": c.summary, "file": rel, "line": c.line})

        # control-presence evidence (polarity=ok)
        for c in all_controls:
            result.evidence.append(Evidence(
                source="sast", rule_id=c.get("rule_key", "OK"), polarity="ok",
                summary=mask_secrets(c["summary"]),
                location={"file": c.get("file"), "line": c.get("line")},
                requirement_ids=list(c.get("req_ids", [])),
            ))

        # Negative ("checked, clean") evidence (spec 45: coverage, not silence).
        # A rule that ran over the source tree and matched nothing is positive
        # proof of coverage for the requirements it targets - without this the
        # requirement would stay NOT_TESTED even though it WAS verified.
        if files_scanned:
            matched = {(f.dedup_key or "").split(":")[1]
                       for f in result.findings if (f.dedup_key or "").count(":") >= 2}
            matched_reqs = {rid for f in result.findings for rid in (f.requirement_ids or [])}
            clean_by_req: dict[str, list[str]] = {}
            for rule_id, rule in RULES.items():
                if rule_id in matched:
                    continue
                for req in rule.requirements:
                    if req in matched_reqs:
                        continue        # une autre règle a déjà signalé cet exigence
                    clean_by_req.setdefault(req, []).append(rule_id)
            for req, rule_ids in sorted(clean_by_req.items()):
                shown = ", ".join(sorted(rule_ids)[:8])
                more = f" (+{len(rule_ids) - 8})" if len(rule_ids) > 8 else ""
                result.evidence.append(Evidence(
                    source="sast", rule_id="SAST-CLEAN", polarity="ok",
                    summary=(f"Analyse statique exécutée sur {files_scanned} fichier(s) : "
                             f"aucune correspondance pour {len(rule_ids)} règle(s) "
                             f"[{shown}{more}] — contrôle vérifié, rien à signaler."),
                    location={"rules_checked": sorted(rule_ids), "files_scanned": files_scanned},
                    requirement_ids=[req],
                ))

        result.data = {"files_scanned": files_scanned, "python_files": py_files,
                       "findings": len(result.findings),
                       "evidence_items": len(result.evidence)}
        context.log("INFO", f"SAST completed: {files_scanned} files, "
                            f"{len(result.findings)} findings")
        return result

    # ------------------------------------------------------------------
    def _emit(self, result: ScanResult, rel: str, line: int, rule_id: str,
              confidence: str | None, note: str, snippet: str) -> None:
        rule = RULES[rule_id]
        conf = confidence if confidence and \
            confidence_rank(confidence) < confidence_rank(rule.confidence) else rule.confidence
        masked_snippet = mask_secrets(snippet)[:240]
        evidence = Evidence(
            source="sast", rule_id=rule_id, polarity="vuln",
            summary=f"{rule.title}{': ' + mask_secrets(note) if note else ''}",
            location={"file": rel, "line": line, "column": 0, "snippet": masked_snippet},
            requirement_ids=list(rule.requirements),
            confidence=conf,
        )
        finding = Finding(
            title=rule.title,
            description=f"{rule.message}{(' ' + mask_secrets(note)) if note else ''}",
            severity=rule.severity,
            confidence=conf,
            category=rule.category,
            cwe=list(rule.cwe),
            owasp=rule.owasp,
            requirement_ids=list(rule.requirements),
            sources=["sast"],
            evidence_ids=[evidence.id],
            file=rel,
            line=line,
            proof=masked_snippet,
            remediation=rule.remediation,
            dedup_key=f"sast:{rule_id}:{rel}:{line}",
        )
        result.evidence.append(evidence)
        result.findings.append(finding)


def sast_only_scan(source_dir: str) -> ScanResult:
    """Convenience wrapper used by the CLI `sast` subcommand and tests."""
    from security_auditor.scanners.base import AuditContext
    ctx = AuditContext(source_dir=source_dir)
    return SASTScanner().safe_run(ctx)
