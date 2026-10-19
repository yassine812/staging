"""Automated security test framework (spec 14).

Each test declares its requirement mapping, whether it needs a running app
and/or configured test accounts, and returns a TestResult with explicit
expected vs actual outcomes.  A test that cannot run reports NOT_TESTED - it
never silently becomes a PASS (spec 36/45).
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field

from security_auditor.scanners.dast.http_util import Client


@dataclass
class TestResult:
    status: str                      # PASS | FAIL | NOT_TESTED
    expected: str
    actual: str
    detail: str = ""
    location: dict = field(default_factory=dict)


@dataclass
class TestContext:
    base_url: str | None
    endpoints: list
    accounts: dict
    profile: dict = field(default_factory=dict)

    def client(self) -> Client:
        return Client()


class SecurityTest:
    id: str = "TEST-000"
    requirement_ids: list = []
    name: str = ""
    description: str = ""
    severity: str = "Medium"
    needs_runtime: bool = True
    needs_accounts: bool = False

    def execute(self, ctx: TestContext) -> TestResult:     # pragma: no cover - interface
        raise NotImplementedError

    # ------------------------------------------------------------------
    def not_tested(self, reason: str) -> TestResult:
        return TestResult("NOT_TESTED", expected="test executed", actual="not executed",
                          detail=reason)

    def login(self, ctx: TestContext, role: str) -> tuple[Client | None, str]:
        """Best-effort session login for a configured test account."""
        account = (ctx.accounts or {}).get(role)
        if not account:
            return None, f"no account configured for role '{role}'"
        client = ctx.client()
        username = account.get("username", "")
        password = account.get("password", "")
        login_urls = account.get("login_url") or [
            "/accounts/login/", "/admin/login/", "/login/", "/auth/login/"]
        if isinstance(login_urls, str):
            login_urls = [login_urls]
        username_field = account.get("username_field", "username")
        password_field = account.get("password_field", "password")

        for login_path in login_urls:
            url = (ctx.base_url or "") + login_path
            page = client.get(url)
            if page.status not in (200, 301, 302):
                continue
            csrf = ""
            m = re.search(r'name=["\']csrfmiddlewaretoken["\'] value=["\']([^"\']+)', page.body)
            if m:
                csrf = m.group(1)
            else:
                for cookie in client.jar:
                    if cookie.name == "csrftoken":
                        csrf = cookie.value
            body = ("csrfmiddlewaretoken=" + csrf +
                    f"&{username_field}=" + username +
                    f"&{password_field}=" + password).encode()
            resp = client.request("POST", url, data=body, headers={
                "Content-Type": "application/x-www-form-urlencoded", "Referer": url})
            if resp.status in (200, 301, 302) and resp.status != 403:
                # heuristic: login page re-rendered with errors means failure
                if resp.status == 200 and ("error" in resp.body.lower() and
                                            "password" in resp.body.lower()):
                    continue
                return client, f"logged in via {login_path}"
        return None, "login attempt failed on all candidate URLs"

    def detail_endpoints(self, ctx: TestContext) -> list[dict]:
        return [e for e in (ctx.endpoints or []) if "{id}" in e["path"] or
                "{" in e["path"] and "pk}" in e["path"]]

    def public_looking(self, path: str) -> bool:
        p = path.lower()
        return any(k in p for k in ("login", "logout", "register", "signup", "signin",
                                    "health", "status", "docs", "schema", "password",
                                    "reset", "verify", "activate", "api-auth"))
