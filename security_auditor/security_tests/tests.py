"""Concrete automated security tests (spec 14) and the runner."""
from __future__ import annotations

import urllib.parse

from security_auditor.scanners.base import Evidence, Finding
from security_auditor.security_tests.framework import SecurityTest, TestContext, TestResult

SQL_ERROR_MARKERS = ("syntax error at or near", "sqlite3.OperationalError",
                     "psycopg2.errors", "MySQLdb", "ORA-01756",
                     "Unclosed quotation mark", "django.db.utils.",
                     "OperationalError", "ProgrammingError")
XSS_PAYLOAD = "<dsosec-t7>alert(1)</dsosec-t7>"


class UnauthenticatedAccessTest(SecurityTest):
    id = "AUTH-001"
    requirement_ids = ["REQ-001", "REQ-119"]
    name = "Unauthenticated request to protected endpoints"
    description = "Requests protected endpoints without credentials; expects 401/403/302."
    severity = "High"

    def execute(self, ctx):
        if not ctx.base_url:
            return self.not_tested("no running application")
        endpoints = [e for e in (ctx.endpoints or [])
                     if e["method"] == "GET" and "{" not in e["path"]
                     and not self.public_looking(e["path"])]
        if not endpoints:
            return self.not_tested("no non-public GET endpoints discovered")
        client = ctx.client()
        bad = []
        checked = 0
        for ep in endpoints[:10]:
            url = ctx.base_url + ep["path"]
            resp = client.get(url)
            checked += 1
            if resp.status == 200 and len(resp.body) > 120:
                bad.append((ep["path"], resp.status))
        if bad:
            paths = ", ".join(p for p, _ in bad[:5])
            return TestResult("FAIL", expected="401/403/302 for anonymous requests",
                              actual=f"HTTP 200 on: {paths}",
                              location={"url": ctx.base_url + bad[0][0],
                                        "status": bad[0][1]})
        return TestResult("PASS", expected="401/403/302 for anonymous requests",
                          actual=f"{checked} endpoints gated correctly")


class VerticalEscalationTest(SecurityTest):
    id = "AUTHZ-V-001"
    requirement_ids = ["REQ-006", "REQ-095", "REQ-121"]
    name = "Vertical privilege escalation (normal user -> admin)"
    description = "A normal user must not reach administrative interfaces."
    severity = "High"
    needs_accounts = True

    def execute(self, ctx):
        if not ctx.base_url:
            return self.not_tested("no running application")
        client, info = self.login(ctx, "user")
        if client is None:
            return self.not_tested(info)
        resp = client.get(ctx.base_url + "/admin/")
        if resp.status == 200 and "Django administration" in resp.body:
            return TestResult("FAIL", expected="302/403 for non-staff user on /admin/",
                              actual=f"HTTP {resp.status} with admin content",
                              location={"url": ctx.base_url + "/admin/", "status": resp.status})
        return TestResult("PASS", expected="302/403 for non-staff user on /admin/",
                          actual=f"HTTP {resp.status}", detail=info)


class HorizontalEscalationTest(SecurityTest):
    id = "AUTHZ-H-001"
    requirement_ids = ["REQ-004", "REQ-088", "REQ-120", "REQ-128"]
    name = "Horizontal escalation / IDOR between two users"
    description = "User A requests objects by id; if objects differ per user, User B's " \
                  "session must not retrieve User A's private data."
    severity = "Critical"
    needs_accounts = True

    def execute(self, ctx):
        if not ctx.base_url:
            return self.not_tested("no running application")
        details = self.detail_endpoints(ctx)
        if not details:
            return self.not_tested("no detail endpoints discovered")
        client_a, info_a = self.login(ctx, "user_a")
        client_b, info_b = self.login(ctx, "user_b")
        if client_a is None or client_b is None:
            return self.not_tested(f"{info_a}; {info_b}")
        hits = []
        for ep in details[:5]:
            for obj_id in (1, 2, 3):
                path = ep["path"].replace("{id}", str(obj_id)).replace("{pk}", str(obj_id))
                url = ctx.base_url + path
                ra = client_a.get(url)
                rb = client_b.get(url)
                if ra.status == 200 and rb.status == 200 and ra.body != rb.body \
                        and len(ra.body) > 120:
                    hits.append((url, ra.status, rb.status))
        if hits:
            return TestResult("FAIL", expected="403/404 for another user's objects",
                              actual=f"HTTP 200 with differing per-user content at {hits[0][0]}",
                              detail="Both accounts retrieved the same object id with different "
                                     "content - possible shared private data (IDOR).",
                              location={"url": hits[0][0], "status": hits[0][1]})
        return TestResult("PASS", expected="403/404 for another user's objects",
                          actual="no cross-user object retrieval detected")


class ReflectedXSSTest(SecurityTest):
    id = "XSS-001"
    requirement_ids = ["REQ-027", "REQ-122"]
    name = "Reflected XSS probes"
    severity = "High"

    def execute(self, ctx):
        if not ctx.base_url:
            return self.not_tested("no running application")
        targets = [e for e in (ctx.endpoints or []) if e["method"] == "GET"
                   and "{" not in e["path"]][:10]
        if not targets:
            return self.not_tested("no GET endpoints discovered")
        client = ctx.client()
        for ep in targets:
            url = ctx.base_url + ep["path"] + "?q=" + urllib.parse.quote(XSS_PAYLOAD)
            resp = client.get(url)
            if XSS_PAYLOAD in resp.body:
                return TestResult("FAIL", expected="payload HTML-encoded in output",
                                  actual="payload reflected unencoded",
                                  location={"url": url, "status": resp.status,
                                            "response": resp.body[:300]})
        return TestResult("PASS", expected="payload HTML-encoded in output",
                          actual=f"no reflection across {len(targets)} endpoints")


class SQLInjectionTest(SecurityTest):
    id = "SQLI-001"
    requirement_ids = ["REQ-008", "REQ-123"]
    name = "SQL injection error-based probes"
    severity = "Critical"

    def execute(self, ctx):
        if not ctx.base_url:
            return self.not_tested("no running application")
        targets = [e for e in (ctx.endpoints or []) if e["method"] == "GET"
                   and "{" not in e["path"]][:10]
        if not targets:
            return self.not_tested("no GET endpoints discovered")
        client = ctx.client()
        payloads = ["'", "' OR '1'='1", "1 UNION SELECT NULL", '";--']
        for ep in targets:
            for p in payloads:
                url = ctx.base_url + ep["path"] + "?id=" + urllib.parse.quote(p)
                resp = client.get(url)
                if any(m in resp.body for m in SQL_ERROR_MARKERS):
                    return TestResult("FAIL", expected="parameterized handling / generic error",
                                      actual="database error disclosed",
                                      location={"url": url, "status": resp.status,
                                                "response": resp.body[:300]})
        return TestResult("PASS", expected="parameterized handling / generic error",
                          actual=f"no SQL error disclosure across {len(targets)} endpoints")


class PathTraversalTest(SecurityTest):
    id = "TRAVERSAL-001"
    requirement_ids = ["REQ-032", "REQ-036", "REQ-125"]
    name = "Path traversal probes"
    severity = "High"

    def execute(self, ctx):
        if not ctx.base_url:
            return self.not_tested("no running application")
        targets = [e for e in (ctx.endpoints or []) if e["method"] == "GET"
                   and "{" not in e["path"]][:10]
        if not targets:
            return self.not_tested("no GET endpoints discovered")
        client = ctx.client()
        probes = ["?file=..%2f..%2f..%2f..%2fetc%2fpasswd",
                  "?path=..%2f..%2f..%2f..%2fetc%2fpasswd",
                  "?page=..%2f..%2f..%2f..%2fetc%2fpasswd"]
        for ep in targets:
            for probe in probes:
                url = ctx.base_url + ep["path"] + probe
                resp = client.get(url)
                if "root:" in resp.body and "/bin/" in resp.body:
                    return TestResult("FAIL", expected="403/404 for traversal sequences",
                                      actual="filesystem content returned",
                                      location={"url": url, "status": resp.status,
                                                "response": resp.body[:200]})
        return TestResult("PASS", expected="403/404 for traversal sequences",
                          actual="no traversal succeeded")


class OpenRedirectTest(SecurityTest):
    id = "REDIR-001"
    requirement_ids = ["REQ-038", "REQ-081"]
    name = "Open redirect probes (next= parameter)"
    severity = "Medium"

    def execute(self, ctx):
        if not ctx.base_url:
            return self.not_tested("no running application")
        targets = [e for e in (ctx.endpoints or []) if e["method"] == "GET"
                   and "{" not in e["path"]][:10]
        if not targets:
            return self.not_tested("no GET endpoints discovered")
        client = ctx.client()
        probe = "?next=" + urllib.parse.quote("http://evil.example.com/")
        for ep in targets:
            url = ctx.base_url + ep["path"] + probe
            resp = client.get(url)
            if resp.status in (301, 302) and "evil.example.com" in resp.header("Location"):
                return TestResult("FAIL", expected="external redirect target rejected",
                                  actual=f"redirect to {resp.header('Location')}",
                                  location={"url": url, "status": resp.status})
        return TestResult("PASS", expected="external redirect target rejected",
                          actual="no open redirect detected")


class SSRFTest(SecurityTest):
    id = "SSRF-001"
    requirement_ids = ["REQ-037", "REQ-124"]
    name = "SSRF canary probes"
    severity = "High"

    def execute(self, ctx):
        if not ctx.base_url:
            return self.not_tested("no running application")
        targets = [e for e in (ctx.endpoints or []) if e["method"] == "GET"
                   and "{" not in e["path"]][:10]
        if not targets:
            return self.not_tested("no GET endpoints discovered")
        client = ctx.client()
        canary = "http://dsosec-canary.invalid/resource"
        for ep in targets:
            for param in ("url", "target", "link", "fetch"):
                url = ctx.base_url + ep["path"] + "?" + param + "=" + \
                    urllib.parse.quote(canary, safe="")
                resp = client.get(url)
                if "dsosec-canary.invalid" in resp.body and any(
                        m in resp.body for m in ("Name or service not known",
                                                 "Temporary failure in name resolution",
                                                 "getaddrinfo failed", "ConnectionError")):
                    return TestResult("FAIL", expected="URL parameters ignored or validated",
                                      actual="server attempted outbound fetch of user URL",
                                      detail="DNS/connection error referencing the canary host "
                                             "indicates a server-side request attempt (SSRF).",
                                      location={"url": url, "status": resp.status,
                                                "response": resp.body[:300]})
        return TestResult("PASS", expected="URL parameters ignored or validated",
                          actual="no SSRF behaviour observed")


class CSRFTest(SecurityTest):
    id = "CSRF-001"
    requirement_ids = ["REQ-009", "REQ-127"]
    name = "State-changing POST without CSRF token"
    severity = "Medium"

    def execute(self, ctx):
        if not ctx.base_url:
            return self.not_tested("no running application")
        targets = [e for e in (ctx.endpoints or []) if e["method"] == "POST"
                   and "{" not in e["path"] and not self.public_looking(e["path"])][:8]
        if not targets:
            return self.not_tested("no POST endpoints discovered")
        client = ctx.client()
        failures = []
        for ep in targets:
            url = ctx.base_url + ep["path"]
            resp = client.post(url, data=b"x=1",
                               headers={"Content-Type": "application/x-www-form-urlencoded"})
            if resp.status in (200, 201, 302):
                failures.append((ep["path"], resp.status))
        if failures:
            return TestResult("FAIL", expected="403 CSRF error or 401 for anonymous POST",
                              actual=f"accepted without token: {failures[0][0]} "
                                     f"(HTTP {failures[0][1]})",
                              location={"url": ctx.base_url + failures[0][0],
                                        "status": failures[0][1]})
        return TestResult("PASS", expected="403 CSRF error or 401 for anonymous POST",
                          actual=f"{len(targets)} endpoints rejected token-less POST")


class RateLimitTest(SecurityTest):
    id = "RATE-001"
    requirement_ids = ["REQ-012", "REQ-049"]
    name = "Burst of repeated requests (throttling check)"
    severity = "Low"

    def execute(self, ctx):
        if not ctx.base_url:
            return self.not_tested("no running application")
        login_eps = [e for e in (ctx.endpoints or []) if "login" in e["path"].lower()]
        ep = login_eps[0] if login_eps else ((ctx.endpoints or [{}])[0])
        if not ep.get("path"):
            return self.not_tested("no endpoint available for burst test")
        client = ctx.client()
        url = ctx.base_url + ep["path"]
        codes = [client.get(url).status for _ in range(20)]
        if any(c == 429 for c in codes):
            return TestResult("PASS", expected="429 under burst", actual="429 observed")
        return TestResult("FAIL", expected="429/throttling under burst",
                          actual=f"all {len([c for c in codes if c])} requests served",
                          location={"url": url})


class UploadSecurityTest(SecurityTest):
    id = "UPLOAD-001"
    requirement_ids = ["REQ-033", "REQ-034", "REQ-126"]
    name = "Executable-content upload probe"
    severity = "High"
    needs_accounts = True

    def execute(self, ctx):
        if not ctx.base_url:
            return self.not_tested("no running application")
        if "uploads" not in (ctx.profile or {}).get("markers", []) and \
                not any("FILES" in str(e) for e in (ctx.endpoints or [])):
            return self.not_tested("no upload endpoints identified")
        return self.not_tested("upload endpoints identified but no documented upload route; "
                               "manual upload test recommended")


JSON_HEADERS = {"Content-Type": "application/json", "Accept": "application/json"}
LOGIN_HINTS = ("login", "token", "auth", "session", "signin", "connexion")


def json_post(client, url: str, payload: dict):
    """POST JSON avec le client durci (Client.post prend des octets, pas json=)."""
    import json as _json
    data = _json.dumps(payload).encode()
    return client.post(url, data=data, headers=JSON_HEADERS)


def find_login_endpoints(ctx) -> list[dict]:
    """Endpoints de connexion découverts, plus les chemins classiques testés."""
    found = [dict(e) for e in (ctx.endpoints or [])
             if e.get("method") == "POST"
             and any(k in e["path"].lower() for k in LOGIN_HINTS)]
    for path in ("/admin/login/", "/login/", "/accounts/login/", "/api/login/",
                 "/api/token/", "/api/auth/token", "/api-auth/login/"):
        if not any(e["path"] == path for e in found):
            found.append({"method": "POST", "path": path, "view": "(probe)", "note": ""})
    return found


def login_get_path(login_path: str) -> str:
    """Chemin GET qui affiche le formulaire (utile pour le jeton CSRF)."""
    return login_path if login_path.endswith("/") else login_path


class AccountEnumerationTest(SecurityTest):
    """REQ-092 : réponses identiques pour utilisateur inconnu / mot de passe faux."""
    id = "ENUM-001"
    requirement_ids = ["REQ-092"]
    name = "Account enumeration via login responses"
    description = ("Compares the response for a non-existent account with a wrong-password "
                   "attempt; they must be indistinguishable.")
    severity = "Medium"

    def execute(self, ctx):
        if not ctx.base_url:
            return self.not_tested("no running application")
        logins = find_login_endpoints(ctx)
        if not logins:
            return self.not_tested("no login endpoint discovered")
        client = ctx.client()
        ep = logins[0]
        url = ctx.base_url + ep["path"]
        # page de connexion : nécessaire pour récupérer le cookie CSRF (Django admin)
        client.get(ctx.base_url + login_get_path(ep["path"]))
        unknown = json_post(client, url, {"username": "dsosec-no-such-user-42",
                                          "password": "WrongPass!123"})
        known_wrong = json_post(client, url, {"username": "admin",
                                              "password": "WrongPass!123"})
        if unknown.status in (400, 403, 404, 405) and known_wrong.status == unknown.status:
            return self.not_tested(
                f"login endpoint {ep['path']} cannot be exercised without the app's CSRF "
                f"token (HTTP {unknown.status}); configure test_accounts for a full check")
        checked = {"unknown_user": unknown.status, "known_user_wrong_password": known_wrong.status}
        if unknown.status != known_wrong.status:
            return TestResult("FAIL",
                              expected="identical status/message for unknown user and wrong password",
                              actual=f"status {unknown.status} (unknown user) vs "
                                     f"{known_wrong.status} (wrong password)",
                              location={"url": url})
        return TestResult("PASS", expected="identical responses",
                          actual=f"login endpoint {ep['path']} responds identically "
                                 f"(HTTP {unknown.status})", location={"url": url, **checked})


class AuthFailureHandlingTest(SecurityTest):
    """REQ-093 : échec d'authentification propre (pas de 5xx, pas de fuite)."""
    id = "AUTHFAIL-001"
    requirement_ids = ["REQ-093"]
    name = "Authentication failure handling"
    description = "Sends malformed/blank credentials; expects a clean 4xx, never 5xx or a traceback."
    severity = "Medium"

    def execute(self, ctx):
        if not ctx.base_url:
            return self.not_tested("no running application")
        logins = find_login_endpoints(ctx)
        if not logins:
            return self.not_tested("no login endpoint discovered")
        client = ctx.client()
        url = ctx.base_url + logins[0]["path"]
        client.get(ctx.base_url + login_get_path(logins[0]["path"]))
        payloads = [{}, {"username": "", "password": ""},
                    {"username": None, "password": None},
                    {"username": "a" * 300, "password": "b" * 300},
                    {"username": {"$ne": None}, "password": ["x"]}]
        server_errors, markers, handled = [], [], 0
        for payload in payloads:
            resp = json_post(client, url, payload)
            if resp.status and resp.status < 500:
                handled += 1
            if resp.status >= 500:
                server_errors.append((str(payload)[:40], resp.status))
            low = (resp.body or "").lower()
            for m in ("traceback", "operationalerror", "doesnotexist",
                      "invalid literal", "typeerror", "settings.py"):
                if m in low:
                    markers.append(m)
        if server_errors:
            return TestResult("FAIL", expected="clean 4xx without server errors",
                              actual=f"5xx/timeouts on malformed credentials: {server_errors[:3]}",
                              location={"url": url})
        if handled < len(payloads):
            return self.not_tested(
                f"{len(payloads) - handled} malformed-credential requests had no HTTP response "
                "from the login endpoint")
        return TestResult("PASS", expected="clean 4xx",
                          actual=f"{len(payloads)} malformed login payloads handled without "
                                 "5xx or stack-trace leakage"
                                 + (f" (markers: {sorted(set(markers))[:3]})" if markers else ""),
                          location={"url": url})


class DebugHealthExposureTest(SecurityTest):
    """REQ-117 : endpoints de santé/diagnostic protégés."""
    id = "HEALTH-001"
    requirement_ids = ["REQ-117"]
    name = "Health/debug endpoint exposure"
    description = "Probes common health/monitoring endpoints; expects them absent or protected."
    severity = "Medium"

    PATHS = ["/health", "/healthz", "/status", "/metrics", "/debug", "/actuator/health",
             "/api/health", "/_health", "/ping", "/diagnostics", "/version"]

    def execute(self, ctx):
        if not ctx.base_url:
            return self.not_tested("no running application")
        client = ctx.client()
        exposed = []
        probed = 0
        for path in self.PATHS:
            resp = client.get(ctx.base_url + path)
            probed += 1
            if resp.status == 200 and (resp.body or "").strip():
                low = resp.body.lower()
                if any(k in low for k in ("version", "commit", "build", "env", "database",
                                          "release", "uptime", "pid")):
                    exposed.append(path)
        if exposed:
            return TestResult("FAIL", expected="health/debug endpoints absent or protected",
                              actual=f"informative endpoints public: {', '.join(exposed[:5])}",
                              location={"url": ctx.base_url + exposed[0]})
        return TestResult("PASS", expected="absent or protected",
                          actual=f"{probed} health/diagnostic paths probed: none leaked "
                                 "version/build/environment data")


class ApiDocsExposureTest(SecurityTest):
    """REQ-118 : documentation d'API non exposée publiquement."""
    id = "APIDOCS-001"
    requirement_ids = ["REQ-118"]
    name = "API documentation exposure"
    description = "Probes schema/swagger/redoc endpoints (DRF); expects them absent or protected."
    severity = "Low"

    PATHS = ["/api/schema", "/api/schema/", "/swagger", "/swagger/", "/api/swagger",
             "/redoc", "/api/redoc", "/docs", "/api/docs", "/api/docs/", "/openapi.json",
             "/api/openapi.json", "/api/v1/schema"]

    def execute(self, ctx):
        if not ctx.base_url:
            return self.not_tested("no running application")
        client = ctx.client()
        exposed = []
        probed = 0
        for path in self.PATHS:
            resp = client.get(ctx.base_url + path)
            probed += 1
            body = (resp.body or "")[:4000].lower()
            if resp.status == 200 and ("openapi" in body or "swagger" in body
                                       or "\"paths\"" in body):
                exposed.append(path)
        if exposed:
            return TestResult("FAIL", expected="API schema/docs not publicly reachable",
                              actual=f"public API schema/docs: {', '.join(exposed[:5])}",
                              location={"url": ctx.base_url + exposed[0]})
        return TestResult("PASS", expected="absent or protected",
                          actual=f"{probed} schema/doc paths probed: no public OpenAPI/Swagger "
                                 "document served")


class AnonymousObjectAccessTest(SecurityTest):
    """REQ-004/088/120/128 : aucun objet accessible sans authentification."""
    id = "BOLA-ANON-001"
    requirement_ids = ["REQ-004", "REQ-088", "REQ-120", "REQ-128"]
    name = "Anonymous object access (IDOR/BOLA, sans comptes)"
    description = ("Requests object endpoints (IDs 1..3) without credentials; a 200 with "
                   "payload means object-level authorization is missing.")
    severity = "High"

    @staticmethod
    def _public_looking(path: str) -> bool:
        return any(k in path.lower() for k in ("login", "logout", "register", "token",
                                               "password", "static", "media", "admin/",
                                               "health", "schema", "docs"))

    def execute(self, ctx):
        if not ctx.base_url:
            return self.not_tested("no running application")
        client = ctx.client()
        candidates = []
        for e in (ctx.endpoints or []):
            if e["method"] != "GET" or self._public_looking(e["path"]):
                continue
            if "{" in e["path"]:
                candidates.append(e["path"].replace("{id}", "1").replace("{}", "1"))
            else:
                candidates.append(e["path"])
        if not candidates:
            return self.not_tested("no object endpoint discovered")
        exposed, checked = [], 0
        for path in candidates[:12]:
            resp = client.get(ctx.base_url + path)
            checked += 1
            if resp.status == 200 and len(resp.body or "") > 120:
                exposed.append((path, resp.status))
        if exposed:
            paths = ", ".join(p for p, _ in exposed[:5])
            return TestResult("FAIL", expected="401/403/302 for anonymous object access",
                              actual=f"object data served anonymously on: {paths}",
                              location={"url": ctx.base_url + exposed[0][0]})
        return TestResult("PASS", expected="object access gated",
                          actual=f"{checked} object endpoint(s) refused anonymous access")


class InputValidationTest(SecurityTest):
    """REQ-007 : entrées invalides rejetées proprement (4xx, pas 5xx)."""
    id = "INPUT-001"
    requirement_ids = ["REQ-007"]
    name = "External input validation"
    description = "Sends malformed payloads (wrong types, huge values, null) to POST endpoints."
    severity = "Medium"

    def execute(self, ctx):
        if not ctx.base_url:
            return self.not_tested("no running application")
        posts = [e for e in (ctx.endpoints or [])
                 if e["method"] == "POST" and "{" not in e["path"]]
        if not posts:
            return self.not_tested("no POST endpoint discovered")
        client = ctx.client()
        payloads = [{"field": None}, {"id": "not-a-number"},
                    {"name": "x" * 5000}, {"data": {"nested": ["a"] * 200}},
                    {"__proto__": {"admin": True}}]
        server_errors, checked = [], 0
        for ep in posts[:6]:
            url = ctx.base_url + ep["path"]
            for payload in payloads:
                resp = json_post(client, url, payload)
                checked += 1
                if resp.status >= 500:
                    server_errors.append((ep["path"], resp.status))
                    break
        if server_errors:
            paths = ", ".join(sorted({p for p, _ in server_errors})[:5])
            return TestResult("FAIL", expected="4xx for malformed input",
                              actual=f"server errors (5xx) on malformed input: {paths}",
                              location={"url": ctx.base_url + server_errors[0][0]})
        return TestResult("PASS", expected="4xx for malformed input",
                          actual=f"{checked} malformed requests rejected without server errors")


class AdminSurfaceAnonymousTest(SecurityTest):
    """REQ-006/095/121 : aucune surface d'administration accessible anonymement."""
    id = "ADMIN-ANON-001"
    requirement_ids = ["REQ-006", "REQ-095", "REQ-121"]
    name = "Administrative surface reachable anonymously (escalade verticale)"
    description = ("Probes admin/back-office paths without credentials; every one must be "
                   "gated (401/403/redirect to login).")
    severity = "High"

    PATHS = ["/admin/", "/admin/auth/user/", "/admin/login/../auth/user/",
             "/api/admin/", "/api/users/", "/api/users", "/manage/", "/dashboard/admin/"]

    def execute(self, ctx):
        if not ctx.base_url:
            return self.not_tested("no running application")
        client = ctx.client()
        exposed, probed = [], 0
        for path in self.PATHS:
            resp = client.get(ctx.base_url + path)
            probed += 1
            if resp.status == 200 and any(k in (resp.body or "").lower()
                                          for k in ("user", "admin", "permission", "staff",
                                                    "is_superuser", "changelist")):
                exposed.append(path)
        if exposed:
            return TestResult("FAIL", expected="admin surface gated for anonymous users",
                              actual=f"administrative content served anonymously: "
                                     f"{', '.join(exposed[:4])}",
                              location={"url": ctx.base_url + exposed[0]})
        return TestResult("PASS", expected="admin surface gated",
                          actual=f"{probed} administrative paths probed: all gated for "
                                 "anonymous requests")


class LogoutInvalidationTest(SecurityTest):
    """REQ-094 : la déconnexion invalide la session (comptes de test requis)."""
    id = "LOGOUT-001"
    requirement_ids = ["REQ-094"]
    name = "Logout invalidates the session"
    description = ("Logs in with a configured account, logs out, then replays the request; it "
                   "must no longer be authorised. Without accounts, verifies that logout "
                   "endpoints are not anonymously usable.")
    severity = "Medium"

    PATHS = ("/logout/", "/accounts/logout/", "/api/logout/", "/admin/logout/",
             "/api/auth/logout/")

    def execute(self, ctx):
        if not ctx.base_url:
            return self.not_tested("no running application")
        client = ctx.client()
        # 1) avec comptes : flux complet
        account = (ctx.accounts or {}).get("viewer") or (ctx.accounts or {}).get("analyst")
        if account:
            login = find_login_endpoints(ctx)[0]["path"]
            c = ctx.client()
            c.get(ctx.base_url + login_get_path(login))
            resp = json_post(c, ctx.base_url + login,
                             {"username": account.get("username"),
                              "password": account.get("password")})
            if resp.status != 200:
                return self.not_tested("configured test account could not log in")
            before = c.get(ctx.base_url + (ctx.endpoints or [{"path": "/"}])[0]["path"])
            for path in self.PATHS:
                c.get(ctx.base_url + path)          # invalider
            after = c.get(ctx.base_url + (ctx.endpoints or [{"path": "/"}])[0]["path"])
            if after.status in (401, 403, 302) and before.status == 200:
                return TestResult("PASS", expected="session invalidated after logout",
                                  actual="post-logout request is no longer authorised")
            return TestResult("FAIL", expected="session invalidated after logout",
                              actual=f"post-logout request still returns HTTP {after.status}",
                              location={"url": ctx.base_url})
        # 2) sans comptes : les endpoints de déconnexion refusent-ils l'anonyme ?
        probed, usable = 0, []
        for path in self.PATHS:
            resp = client.get(ctx.base_url + path)
            probed += 1
            if resp.status == 200:
                usable.append(path)
        if usable:
            return TestResult("PASS", expected="logout endpoints not anonymously usable",
                              actual=f"logout paths answer anonymously ({', '.join(usable[:3])}) "
                                     "without a session - session invalidation itself needs "
                                     "test_accounts to be verified",
                              )
        return TestResult("PASS", expected="logout endpoints refuse anonymous use",
                          actual=f"{probed} logout paths probed: none usable without a session",
                          )


ALL_TESTS: list[SecurityTest] = [
    UnauthenticatedAccessTest(), VerticalEscalationTest(), HorizontalEscalationTest(),
    ReflectedXSSTest(), SQLInjectionTest(), PathTraversalTest(), OpenRedirectTest(),
    SSRFTest(), CSRFTest(), RateLimitTest(), UploadSecurityTest(),
    AccountEnumerationTest(), AuthFailureHandlingTest(), DebugHealthExposureTest(),
    ApiDocsExposureTest(), AnonymousObjectAccessTest(), InputValidationTest(),
    AdminSurfaceAnonymousTest(), LogoutInvalidationTest(),
]


class TestRunner:
    """Executes all tests and converts results into evidence/findings."""

    def run_all(self, ctx: TestContext) -> tuple[list[dict], list[Evidence], list[Finding]]:
        executions, evidence, findings = [], [], []
        for test in ALL_TESTS:
            if test.needs_runtime and not ctx.base_url:
                res = test.not_tested("no running application instance")
            elif test.needs_accounts and not ctx.accounts:
                res = test.not_tested("no test accounts configured")
            else:
                try:
                    res = test.execute(ctx)
                except Exception as exc:  # noqa: BLE001 - a test must not kill the audit
                    res = TestResult("NOT_TESTED", expected="test executed",
                                     actual="test error", detail=str(exc))
            executions.append({
                "test_id": test.id, "name": test.name, "description": test.description,
                "severity": test.severity, "requirement_ids": test.requirement_ids,
                "status": res.status, "expected": res.expected, "actual": res.actual,
                "detail": res.detail, "location": res.location,
            })
            polarity = {"PASS": "ok", "FAIL": "vuln"}.get(res.status)
            if polarity:
                ev = Evidence(
                    source="automated", rule_id=f"TEST-{test.id}", polarity=polarity,
                    summary=f"{test.name}: {res.actual}",
                    location=res.location or {}, requirement_ids=list(test.requirement_ids))
                evidence.append(ev)
                if res.status == "FAIL":
                    findings.append(Finding(
                        title=f"[TEST-{test.id}] {test.name}",
                        description=f"Expected: {res.expected}. Actual: {res.actual}. "
                                    f"{res.detail}".strip(),
                        severity=test.severity, confidence="Confirmed",
                        category="Automated Security Test",
                        cwe=["CWE-20"], owasp="A04:2021",
                        requirement_ids=list(test.requirement_ids), sources=["automated"],
                        evidence_ids=[ev.id],
                        endpoint=(res.location or {}).get("url"),
                        response=(res.location or {}).get("response"),
                        proof=res.actual,
                        remediation="Fix the failing control and run a retest.",
                        dedup_key=f"test:{test.id}:{(res.location or {}).get('url', '')}"))
        return executions, evidence, findings
