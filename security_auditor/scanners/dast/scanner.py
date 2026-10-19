"""DAST scanner (spec 12).

Runs against the isolated application instance started by the sandbox.  All
probes target 127.0.0.1 only.  OWASP ZAP is used when configured
(``dast.zap_api_url``); otherwise the built-in probe suite runs.
"""
from __future__ import annotations

import json
import time
import urllib.error
import urllib.parse
import urllib.request

from security_auditor.scanners.base import BaseScanner, Evidence, Finding, ScanResult
from security_auditor.scanners.dast.http_util import Client

SENSITIVE_PROBES = [
    ("/.env", "dotenv file", ["REQ-084"]),
    ("/.git/HEAD", "git metadata", ["REQ-085"]),
    ("/settings.py", "settings source file", ["REQ-083"]),
    ("/db.sqlite3", "SQLite database file", ["REQ-083"]),
    ("/web.config", "web.config", ["REQ-083"]),
    ("/backup.sql", "database dump", ["REQ-083"]),
]

DOCS_PROBES = ["/api/docs/", "/docs/", "/swagger/", "/redoc/", "/api/schema/",
               "/api/v1/docs/"]

SQL_ERROR_MARKERS = ("syntax error at or near", "sqlite3.OperationalError",
                     "psycopg2.errors", "MySQLdb", "mysql.connector",
                     "ORA-01756", "Unclosed quotation mark",
                     "django.db.utils.", "OperationalError", "ProgrammingError")

XSS_PAYLOAD = "<dsosec9x7>alert(1)</dsosec9x7>"
TRAVERSAL_PROBES = ("?file=..%2f..%2f..%2fetc%2fpasswd", "?path=..%2f..%2fetc%2fpasswd",
                    "?page=..%2f..%2f..%2fetc%2fpasswd")
REDIR_PROBE = "?next=http%3A%2F%2Fevil.example.com%2F"


class DASTScanner(BaseScanner):
    name = "dast"
    description = "Dynamic testing against the isolated application instance"

    def run(self, context) -> ScanResult:
        result = ScanResult(scanner=self.name)
        base = context.base_url
        if not base:
            result.status = "SKIPPED"
            result.error = "no running application instance (base URL not set)"
            return result
        if not context.dast_allowed():
            result.status = "SKIPPED"
            result.error = "DAST disabled or authorization not confirmed"
            return result

        client = Client()
        checks_run = 0

        # ---- ZAP integration hook (optional) --------------------------------
        zap_cfg = ((context.config or {}).get("dast") or {}).get("zap_api_url")
        if zap_cfg and self._zap_available(zap_cfg):
            zap_findings = self._run_zap(context, result, zap_cfg, base)
            if zap_findings is not None:
                result.data["zap"] = {"alerts": zap_findings}
                return result

        # ---- 0. liveness (REQ-136) ------------------------------------------
        home = client.get(base + "/")
        checks_run += 1
        if home.status:
            result.evidence.append(Evidence(
                source="dast", rule_id="DAST-HEALTH-001", polarity="ok",
                summary=f"Application reachable at {base} (HTTP {home.status}).",
                location={"url": base + "/", "status": home.status},
                requirement_ids=["REQ-136"]))
        else:
            result.status = "FAILED"
            result.error = f"application not reachable at {base}: {home.error}"
            return result

        # ---- 1. security headers ---------------------------------------------
        header_checks = [
            ("Strict-Transport-Security", "DAST-HDR-HSTS", ["REQ-020", "REQ-067"], "Medium", "High"),
            ("X-Content-Type-Options", "DAST-HDR-NOSNIFF", ["REQ-021", "REQ-067"], "Low", "High"),
            ("X-Frame-Options", "DAST-HDR-XFO", ["REQ-022", "REQ-067"], "Low", "High"),
            ("Content-Security-Policy", "DAST-HDR-CSP", ["REQ-068"], "Low", "Medium"),
            ("Referrer-Policy", "DAST-HDR-REFERRER", ["REQ-069"], "Low", "High"),
            ("Permissions-Policy", "DAST-HDR-PERMPOL", ["REQ-070"], "Low", "Medium"),
        ]
        for header, rule, reqs, sev, conf in header_checks:
            value = home.header(header)
            if value:
                result.evidence.append(Evidence(
                    source="dast", rule_id=rule, polarity="ok",
                    summary=f"{header}: {value[:120]}",
                    location={"url": base + "/", "header": header, "value": value[:200]},
                    requirement_ids=reqs))
            else:
                self._vuln(result, rule, sev, f"Missing security header {header}",
                           f"Response from {base}/ lacks the {header} header.",
                           reqs, url=base + "/", response=f"HTTP {home.status}, headers: "
                           + ", ".join(sorted(home.headers)), confidence=conf)

        # ---- 2. cookie flags ------------------------------------------------------
        set_cookies = home.cookies()
        for sc in set_cookies:
            name = sc.split("=", 1)[0].strip()
            if name in ("sessionid",):
                if "httponly" in sc.lower():
                    result.evidence.append(Evidence(
                        source="dast", rule_id="DAST-COOKIE-FLAGS", polarity="ok",
                        summary="sessionid cookie is HttpOnly.",
                        location={"url": base + "/", "cookie": name},
                        requirement_ids=["REQ-023"]))
                else:
                    self._vuln(result, "DAST-COOKIE-FLAGS", "Medium",
                               "session cookie without HttpOnly",
                               f"Set-Cookie for {name} lacks HttpOnly flag.",
                               ["REQ-023"], url=base + "/", response=sc[:200])
                if "secure" in sc.lower():
                    result.evidence.append(Evidence(
                        source="dast", rule_id="DAST-COOKIE-FLAGS", polarity="ok",
                        summary="sessionid cookie has Secure flag.",
                        location={"url": base + "/", "cookie": name},
                        requirement_ids=["REQ-018"]))
            if name == "csrftoken" and "httponly" in sc.lower():
                result.evidence.append(Evidence(
                    source="dast", rule_id="DAST-COOKIE-FLAGS", polarity="ok",
                    summary="csrftoken cookie is HttpOnly.",
                    location={"url": base + "/", "cookie": name},
                    requirement_ids=["REQ-024"]))

        # ---- 3. sensitive file exposure --------------------------------------------
        for probe, label, reqs in SENSITIVE_PROBES:
            resp = client.get(base + probe)
            checks_run += 1
            if resp.status == 200 and len(resp.body) > 0:
                self._vuln(result, "DAST-ENV-001", "High", f"{label} web-accessible",
                           f"GET {probe} returned HTTP 200 with content "
                           f"({len(resp.body)} bytes).", reqs,
                           url=base + probe, response=resp.body[:200])
            elif resp.status in (403, 404):
                result.evidence.append(Evidence(
                    source="dast", rule_id="DAST-ENV-001", polarity="ok",
                    summary=f"{label} not exposed (HTTP {resp.status}).",
                    location={"url": base + probe, "status": resp.status},
                    requirement_ids=reqs))

        # ---- 4. debug / stack traces ---------------------------------------------------
        resp = client.get(base + "/audit-nonexistent-page-x9/")
        checks_run += 1
        if "DEBUG = True" in resp.body or ("Traceback" in resp.body and "Django" in resp.body):
            self._vuln(result, "DAST-DEBUG-001", "High",
                       "Django debug page / stack trace exposed",
                       "A request to a missing page returned the Django debug error page.",
                       ["REQ-082", "REQ-053"], url=base + "/audit-nonexistent-page-x9/",
                       response=resp.body[:300])
        else:
            result.evidence.append(Evidence(
                source="dast", rule_id="DAST-DEBUG-001", polarity="ok",
                summary=f"No debug stack trace on 404 (HTTP {resp.status}).",
                location={"url": base + "/audit-nonexistent-page-x9/", "status": resp.status},
                requirement_ids=["REQ-082"]))

        # ---- 5. admin surface -----------------------------------------------------------
        resp = client.get(base + "/admin/")
        checks_run += 1
        if resp.status == 200 and ("administration" in resp.body.lower() or
                                    "Django administration" in resp.body):
            self._vuln(result, "DAST-ADMIN-001", "Medium",
                       "Django admin reachable anonymously",
                       "GET /admin/ returned the admin login/administration page to an "
                       "unauthenticated client. Verify rate limiting and network protection.",
                       ["REQ-054", "REQ-006"], url=base + "/admin/",
                       response=f"HTTP {resp.status}")
        elif resp.status in (301, 302, 403):
            result.evidence.append(Evidence(
                source="dast", rule_id="DAST-ADMIN-001", polarity="ok",
                summary=f"/admin/ gated for anonymous users (HTTP {resp.status}).",
                location={"url": base + "/admin/", "status": resp.status},
                requirement_ids=["REQ-054"]))

        # ---- 6. API docs exposure ----------------------------------------------------------
        for probe in DOCS_PROBES:
            resp = client.get(base + probe)
            checks_run += 1
            if resp.status == 200 and ("swagger" in resp.body.lower() or
                                       "redoc" in resp.body.lower() or
                                       "openapi" in resp.body.lower()):
                self._vuln(result, "DAST-DOCS-001", "Low", f"API docs exposed at {probe}",
                           "Interactive API documentation reachable without authentication.",
                           ["REQ-118"], url=base + probe, response=f"HTTP {resp.status}")

        # ---- 7. endpoint probes (XSS reflection, SQLi errors, traversal, redirect) ----------
        endpoints = context.endpoints if hasattr(context, "endpoints") else []
        probed = 0
        for ep in endpoints or []:
            if probed >= 15:
                break
            if ep["method"] != "GET" or "{" in ep["path"]:
                continue
            url = base + ep["path"]
            probed += 1
            checks_run += 1

            r = client.get(url + "?q=" + urllib.parse.quote(XSS_PAYLOAD))
            if XSS_PAYLOAD in r.body:
                self._vuln(result, "DAST-XSS-001", "High",
                           f"Reflected XSS on {ep['path']}",
                           f"Payload reflected unencoded in response of GET {ep['path']}?q=...",
                           ["REQ-027", "REQ-122"], url=url, request="GET ?q=" + XSS_PAYLOAD,
                           response=r.body[:300], confidence="Confirmed")

            r = client.get(url + "?id=%27%20OR%20%271%27%3D%271")
            if any(marker in r.body for marker in SQL_ERROR_MARKERS):
                self._vuln(result, "DAST-SQLI-001", "Critical",
                           f"SQL error disclosure / injection indicator on {ep['path']}",
                           "The endpoint returned a database error for a quoted parameter.",
                           ["REQ-008", "REQ-123"], url=url, response=r.body[:300],
                           confidence="Confirmed")

            for tp in TRAVERSAL_PROBES:
                r = client.get(url + tp)
                if "root:" in r.body and "/bin/" in r.body:
                    self._vuln(result, "DAST-TRAVERSAL-001", "High",
                               f"Path traversal on {ep['path']}",
                               f"GET {url}{tp} returned filesystem content.",
                               ["REQ-032", "REQ-125"], url=url + tp, response=r.body[:200],
                               confidence="Confirmed")
                    break

            r = client.get(url + REDIR_PROBE)
            if r.status in (301, 302) and "evil.example.com" in r.header("Location"):
                self._vuln(result, "DAST-REDIR-001", "Medium",
                           f"Open redirect on {ep['path']}",
                           f"GET {url}{REDIR_PROBE} redirects to an attacker-controlled host.",
                           ["REQ-038", "REQ-001"], url=url + REDIR_PROBE,
                           response="Location: " + r.header("Location"), confidence="Confirmed")

        # ---- 8. rate limiting heuristic ---------------------------------------------------
        if endpoints:
            target = base + (endpoints[0]["path"])
            t0 = time.time()
            codes = [client.get(target).status for _ in range(25)]
            elapsed = time.time() - t0
            if all(c == 200 for c in codes if c):
                result.evidence.append(Evidence(
                    source="dast", rule_id="DAST-RATE-001", polarity="info",
                    summary=f"25 rapid requests to {target} all succeeded in {elapsed:.1f}s - "
                            "no throttling observed on this endpoint.",
                    location={"url": target}, requirement_ids=["REQ-049", "REQ-075"]))
            elif any(c == 429 for c in codes):
                result.evidence.append(Evidence(
                    source="dast", rule_id="DAST-RATE-001", polarity="ok",
                    summary=f"Throttling observed on {target} (HTTP 429).",
                    location={"url": target}, requirement_ids=["REQ-049", "REQ-075"]))

        result.data = {"base_url": base, "checks_run": checks_run,
                       "findings": len(result.findings)}
        context.log("INFO", f"DAST completed: {checks_run} checks against {base}")
        return result

    # ------------------------------------------------------------------
    def _vuln(self, result: ScanResult, rule_id: str, severity: str, title: str,
              description: str, reqs: list, url: str = "", request: str = "",
              response: str = "", confidence: str = "High") -> None:
        evidence = Evidence(
            source="dast", rule_id=rule_id, polarity="vuln", summary=title,
            location={"url": url, "request": request, "response": response[:400]},
            requirement_ids=list(reqs))
        finding = Finding(
            title=title, description=description, severity=severity, confidence=confidence,
            category="Dynamic Testing", cwe=["CWE-20"], owasp="A05:2021",
            requirement_ids=list(reqs), sources=["dast"], evidence_ids=[evidence.id],
            endpoint=url, request=request or None, response=response[:400] or None,
            proof=f"GET {url} -> {response[:160]}" if url else response[:160],
            remediation="See the mapped requirement remediation; verify with a retest.",
            dedup_key=f"dast:{rule_id}:{url}")
        result.evidence.append(evidence)
        result.findings.append(finding)

    # --- ZAP -----------------------------------------------------------
    def _zap_available(self, zap_url: str) -> bool:
        try:
            with urllib.request.urlopen(zap_url + "/JSON/core/view/version/", timeout=3) as r:
                return r.status == 200
        except (urllib.error.URLError, OSError):
            return False

    def _run_zap(self, context, result: ScanResult, zap_url: str, base: str) -> int | None:
        """Drive an OWASP ZAP spider + passive scan via its API (best effort)."""
        try:
            def zap(path: str):
                with urllib.request.urlopen(zap_url + path, timeout=120) as r:
                    return json.loads(r.read())
            zap(f"/JSON/spider/action/scan/?url={urllib.parse.quote(base, safe='')}&maxChildren=10")
            for _ in range(60):
                prog = zap("/JSON/spider/view/status/")
                if int(prog.get("status", 100)) >= 100:
                    break
                time.sleep(1)
            zap(f"/JSON/pscan/action/enableAllScanners/")
            alerts = zap("/JSON/alert/view/alerts/").get("alerts", [])
            sev_map = {"High": "High", "Medium": "Medium", "Low": "Low",
                       "Informational": "Info"}
            for a in alerts[:100]:
                result.evidence.append(Evidence(
                    source="dast", rule_id=f"ZAP-{a.get('pluginId', '0')}",
                    polarity="vuln" if a.get("risk") != "Informational" else "info",
                    summary=f"ZAP: {a.get('name')} ({a.get('risk')})",
                    location={"url": a.get("url"), "response": (a.get("evidence") or "")[:200]},
                    requirement_ids=["REQ-136"]))
                if a.get("risk") in sev_map:
                    result.findings.append(Finding(
                        title=f"ZAP: {a.get('name')}", description=a.get("description", "")[:400],
                        severity=sev_map[a["risk"]], confidence="Medium",
                        category="Dynamic Testing",
                        cwe=[f"CWE-{a.get('cweid')}"] if a.get("cweid") else [],
                        owasp="", requirement_ids=[], sources=["dast"],
                        evidence_ids=[result.evidence[-1].id], endpoint=a.get("url"),
                        remediation=a.get("solution", "")[:400],
                        dedup_key=f"zap:{a.get('pluginId')}:{a.get('url')}"))
            context.log("INFO", f"ZAP scan completed with {len(alerts)} alerts")
            return len(alerts)
        except Exception as exc:  # noqa: BLE001
            context.log("WARN", f"ZAP integration failed ({exc}); using built-in probes")
            return None
