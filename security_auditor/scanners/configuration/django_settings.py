"""Django settings scanner (spec 8).

Settings are parsed statically with ``ast`` - the project's code is never
imported/executed.  Values set via ``os.environ`` are recorded as ``<env:VAR>``
and treated as *secure by indirection* (the actual value is reviewed at
deploy time).  Checks emit vuln/ok/info evidence mapped to requirements.
"""
from __future__ import annotations

import ast
from dataclasses import dataclass
from pathlib import Path

from security_auditor.apps.audits.utils import mask_secrets
from security_auditor.scanners.base import BaseScanner, Evidence, Finding, ScanResult

UNKNOWN = object()

DJANGO_DEFAULTS = {
    "DEBUG": False,
    "ALLOWED_HOSTS": [],
    "SESSION_COOKIE_SECURE": False,
    "CSRF_COOKIE_SECURE": False,
    "SESSION_COOKIE_HTTPONLY": True,
    "CSRF_COOKIE_HTTPONLY": False,
    "SECURE_SSL_REDIRECT": False,
    "SECURE_HSTS_SECONDS": 0,
    "SECURE_CONTENT_TYPE_NOSNIFF": True,
    "X_FRAME_OPTIONS": "SAMEORIGIN",
    "SECURE_REFERRER_POLICY": "same-origin",
    "SESSION_COOKIE_AGE": 1209600,
    "CSRF_TRUSTED_ORIGINS": [],
    "SECURE_PROXY_SSL_HEADER": None,
}

UNSAFE_REFERRER = {"unsafe-url", "no-referrer-when-downgrade", "origin",
                   "origin-when-cross-origin", ""}
WEAK_HASHERS = {"MD5", "SHA1", "UnsaltedMD5", "UnsaltedSHA1", "Crypt"}


@dataclass
class CheckOutput:
    polarity: str            # vuln | ok | info
    check_id: str
    severity: str
    summary: str
    requirement_ids: list
    setting: str = ""
    current: str = ""
    expected: str = ""


class SettingsState:
    def __init__(self):
        self.values: dict = {}        # name -> value (UNKNOWN allowed)
        self.origin: dict = {}        # name -> file
        self.lines: dict = {}         # name -> line number in that file
        self.files: list = []

    def set(self, name, value, origin, line: int | None = None):
        self.values[name] = value
        self.origin[name] = origin
        if line is not None:
            self.lines[name] = line

    def get(self, name, default=UNKNOWN):
        return self.values.get(name, default)


def _eval_node(node, state: SettingsState | None = None):
    """Safely evaluate a settings expression without executing code."""
    if node is None:
        return UNKNOWN
    if isinstance(node, ast.Constant):
        return node.value
    if isinstance(node, (ast.List, ast.Tuple, ast.Set)):
        vals = [_eval_node(e) for e in node.elts]
        return vals if all(v is not UNKNOWN for v in vals) else UNKNOWN
    if isinstance(node, ast.Dict):
        out = {}
        for k, v in zip(node.keys, node.values):
            kv = _eval_node(k)
            if kv is UNKNOWN:
                return UNKNOWN
            out[kv] = _eval_node(v)
        return out
    if isinstance(node, ast.Name):
        if node.id == "ENV":
            return UNKNOWN
        return UNKNOWN
    if isinstance(node, ast.Call):
        func = node.func
        d = ""
        n = func
        parts = []
        while isinstance(n, ast.Attribute):
            parts.append(n.attr)
            n = n.value
        if isinstance(n, ast.Name):
            d = ".".join([n.id] + parts[::-1])
        if d in ("os.environ.get", "os.getenv", "env", "env.str", "env.bool",
                 "env.int", "env.list", "env.db_url", "environ.get", "getenv"):
            var = "?"
            if node.args and isinstance(node.args[0], ast.Constant):
                var = node.args[0].value
            default = _eval_node(node.args[1]) if len(node.args) > 1 else UNKNOWN
            return {"__env__": var, "default": default}
        if d in ("env",) or (isinstance(func, ast.Name) and func.id.startswith("env")):
            return {"__env__": "?", "default": UNKNOWN}
        return UNKNOWN
    if isinstance(node, ast.Subscript):
        d = ""
        n = node.value
        parts = []
        while isinstance(n, ast.Attribute):
            parts.append(n.attr)
            n = n.value
        if isinstance(n, ast.Name):
            d = ".".join([n.id] + parts[::-1])
        if d.startswith("os.environ"):
            key = node.slice
            if isinstance(key, ast.Constant):
                return {"__env__": key.value, "default": UNKNOWN}
        return UNKNOWN
    if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add):
        l, r = _eval_node(node.left), _eval_node(node.right)
        if isinstance(l, list) and isinstance(r, list):
            return l + r
        if isinstance(l, str) and isinstance(r, str):
            return l + r
        return UNKNOWN
    if isinstance(node, ast.Attribute):
        return UNKNOWN
    return UNKNOWN


def is_env_value(v) -> bool:
    return isinstance(v, dict) and "__env__" in v


def display_value(v) -> str:
    if v is UNKNOWN:
        return "<unknown/dynamic>"
    if is_env_value(v):
        return f"<env:{v['__env__']}>"
    return repr(v)


def extract_settings(source_dir: str, settings_files: list[str] | None = None) -> SettingsState:
    """Parse all settings modules; production-like files override base ones."""
    root = Path(source_dir)
    state = SettingsState()
    candidates: list[Path] = []
    if settings_files:
        for rel in settings_files:
            p = (root / rel)
            if p.is_file():
                candidates.append(p)
    if not candidates:
        for pat in ("**/settings.py", "**/settings/*.py", "**/settings_*.py", "**/conf.py"):
            candidates.extend(root.glob(pat))
        candidates = [c for c in candidates
                      if not any(part in {".git", "node_modules", ".venv", "site-packages",
                                          "__pycache__", ".tox"}
                                 for part in c.relative_to(root).parts)]
    # base first, production overrides last
    def weight(p: Path):
        n = p.name.lower()
        if "prod" in n:
            return 2
        if n in ("local.py", "dev.py", "development.py"):
            return 0
        return 1
    for p in sorted(set(candidates), key=lambda p: (weight(p), str(p))):
        rel = p.relative_to(root).as_posix()
        state.files.append(rel)
        try:
            tree = ast.parse(p.read_text(encoding="utf-8", errors="replace"))
        except SyntaxError:
            continue
        for node in tree.body:
            if isinstance(node, ast.Assign):
                for t in node.targets:
                    if isinstance(t, ast.Name) and t.id.isupper():
                        state.set(t.id, _eval_node(node.value), rel, node.lineno)
            elif isinstance(node, ast.AnnAssign) and isinstance(node.target, ast.Name):
                state.set(node.target.id, _eval_node(node.value), rel, node.lineno)
    return state


class DjangoSettingsScanner(BaseScanner):
    name = "settings"
    description = "Django security configuration analysis"

    def run(self, context) -> ScanResult:
        result = ScanResult(scanner=self.name)
        state = extract_settings(context.source_dir,
                                 (context.profile or {}).get("settings_files"))
        if not state.files:
            result.status = "SKIPPED"
            result.error = "no Django settings module found"
            return result

        outs: list[CheckOutput] = []
        outs += self._core_checks(state)
        outs += self._drf_checks(state, context)

        context.settings_values = {} if hasattr(context, "settings_values") else None
        for out in outs:
            result.evidence.append(Evidence(
                source="configuration", rule_id=out.check_id, polarity=out.polarity,
                summary=out.summary,
                location={"setting": out.setting, "current": out.current,
                          "expected": out.expected,
                          "file": state.origin.get(out.setting, ""),
                          "line": state.lines.get(out.setting)},
                requirement_ids=out.requirement_ids,
                # settings facts are statically certain
                confidence="Confirmed" if out.polarity == "vuln" else "High",
            ))
            if out.polarity == "vuln":
                result.findings.append(Finding(
                    title=f"Insecure Django setting: {out.setting or out.check_id}",
                    description=out.summary,
                    severity=out.severity,
                    confidence="Confirmed",
                    category="Security Misconfiguration",
                    cwe=["CWE-16"], owasp="A05:2021",
                    requirement_ids=out.requirement_ids,
                    sources=["configuration"],
                    evidence_ids=[result.evidence[-1].id],
                    file=state.origin.get(out.setting) or None,
                    line=state.lines.get(out.setting),
                    proof=f"{out.setting} = {out.current} (expected: {out.expected})",
                    remediation=f"Set {out.setting} to {out.expected}.",
                    dedup_key=f"config:{out.check_id}:{out.setting}",
                ))

        # masked settings snapshot for the report
        from security_auditor.apps.audits.utils import mask_secret
        snap = {}
        sensitive_words = ("SECRET", "KEY", "PASSWORD", "TOKEN")
        for k in sorted(state.values):
            v = state.values[k]
            if any(w in k.upper() for w in sensitive_words) and not is_env_value(v):
                if isinstance(v, str):
                    text = "'" + mask_secret(v) + "'"
                else:
                    text = mask_secrets(display_value(v))
            else:
                text = mask_secrets(display_value(v))   # defense in depth (nested dicts)
            snap[k] = text[:200]
        result.data = {"settings_files": state.files, "settings": snap,
                       "checks": len(outs),
                       "failed": sum(1 for o in outs if o.polarity == "vuln")}
        context.log("INFO", f"Settings analysis: {len(state.files)} modules, "
                            f"{result.data['failed']} failing checks")
        return result

    # ------------------------------------------------------------------
    def _chk(self, polarity, check_id, severity, summary, reqs, setting="",
             current="", expected=""):
        return CheckOutput(polarity, check_id, severity, summary, list(reqs),
                           setting, current, expected)

    def _core_checks(self, s: SettingsState) -> list[CheckOutput]:
        outs = []

        def val(name):
            v = s.get(name, "__missing__")
            return v

        # DEBUG ----------------------------------------------------------
        debug = val("DEBUG")
        if debug is True:
            outs.append(self._chk("vuln", "CFG-DEBUG", "High",
                                  "DEBUG=True exposes stack traces, settings and debug endpoints.",
                                  ["REQ-015", "REQ-082", "REQ-104"], "DEBUG",
                                  "True", "False"))
        elif is_env_value(debug):
            outs.append(self._chk("ok", "CFG-DEBUG", "Info",
                                  f"DEBUG sourced from environment variable {debug['__env__']}.",
                                  ["REQ-015"], "DEBUG", display_value(debug), "False in production"))
        elif debug is False:
            outs.append(self._chk("ok", "CFG-DEBUG", "Info", "DEBUG=False.",
                                  ["REQ-015", "REQ-082"], "DEBUG", "False", "False"))

        # SECRET_KEY -------------------------------------------------------
        sk = val("SECRET_KEY")
        if isinstance(sk, str) and len(sk) >= 8:
            outs.append(self._chk("vuln", "CFG-SECRETKEY", "Critical",
                                  "SECRET_KEY is a string literal in settings (also reported by SAST).",
                                  ["REQ-013"], "SECRET_KEY", "'***masked***'",
                                  "os.environ['DJANGO_SECRET_KEY']"))
        elif is_env_value(sk):
            outs.append(self._chk("ok", "CFG-SECRETKEY", "Info",
                                  "SECRET_KEY loaded from environment.",
                                  ["REQ-013"], "SECRET_KEY", display_value(sk), "env var"))

        # ALLOWED_HOSTS ------------------------------------------------------
        ah = val("ALLOWED_HOSTS")
        if ah == "__missing__" or ah == []:
            outs.append(self._chk("vuln" if debug is not True else "info", "CFG-ALLOWED-HOSTS",
                                  "High",
                                  "ALLOWED_HOSTS is empty; with DEBUG=False Django refuses to serve, "
                                  "and wildcard/blank configurations enable host header attacks.",
                                  ["REQ-016", "REQ-104", "REQ-106"], "ALLOWED_HOSTS",
                                  display_value(ah), "explicit hostname list"))
        elif isinstance(ah, list) and "*" in ah:
            outs.append(self._chk("vuln", "CFG-ALLOWED-HOSTS", "High",
                                  "ALLOWED_HOSTS contains a wildcard '*'.",
                                  ["REQ-016", "REQ-106"], "ALLOWED_HOSTS", "['*']",
                                  "explicit hostname list"))
        elif isinstance(ah, list) and ah:
            outs.append(self._chk("ok", "CFG-ALLOWED-HOSTS", "Info",
                                  f"ALLOWED_HOSTS explicitly set: {ah}.",
                                  ["REQ-016", "REQ-106"], "ALLOWED_HOSTS", display_value(ah),
                                  "explicit hostname list"))
        else:
            outs.append(self._chk("info", "CFG-ALLOWED-HOSTS", "Info",
                                  "ALLOWED_HOSTS is provided dynamically (environment/settings "
                                  "split) - verify the deployed value lists explicit hostnames "
                                  "and never '*'.",
                                  ["REQ-016", "REQ-106"], "ALLOWED_HOSTS", display_value(ah),
                                  "explicit hostname list"))

        # cookie/transport flags ---------------------------------------------
        for name, check_id, reqs, sev in (
                ("SESSION_COOKIE_SECURE", "CFG-SESS-SECURE", ["REQ-018"], "Medium"),
                ("CSRF_COOKIE_SECURE", "CFG-CSRF-SECURE", ["REQ-019"], "Medium")):
            v = val(name)
            if v is True or (is_env_value(v)):
                outs.append(self._chk("ok", check_id, "Info", f"{name} enabled.",
                                      reqs, name, display_value(v), "True"))
            else:
                outs.append(self._chk("vuln", check_id, sev,
                                      f"{name} is not True; cookie can be captured over HTTP.",
                                      reqs, name, display_value(v), "True"))

        v = val("SESSION_COOKIE_HTTPONLY")
        if v is False:
            outs.append(self._chk("vuln", "CFG-SESS-HTTPONLY", "Medium",
                                  "SESSION_COOKIE_HTTPONLY disabled; session readable by JavaScript.",
                                  ["REQ-023"], "SESSION_COOKIE_HTTPONLY", "False", "True"))
        else:
            outs.append(self._chk("ok", "CFG-SESS-HTTPONLY", "Info",
                                  "SESSION_COOKIE_HTTPONLY enforced (default True).",
                                  ["REQ-023"], "SESSION_COOKIE_HTTPONLY", display_value(v), "True"))

        v = val("CSRF_COOKIE_HTTPONLY")
        if v is True:
            outs.append(self._chk("ok", "CFG-CSRF-HTTPONLY", "Info",
                                  "CSRF_COOKIE_HTTPONLY=True (no JS access to CSRF cookie).",
                                  ["REQ-024"], "CSRF_COOKIE_HTTPONLY", "True", "reviewed"))
        else:
            outs.append(self._chk("info", "CFG-CSRF-HTTPONLY", "Info",
                                  "CSRF cookie readable by JavaScript (default). Review whether the "
                                  "frontend architecture requires it; otherwise set True.",
                                  ["REQ-024"], "CSRF_COOKIE_HTTPONLY", display_value(v), "True or documented"))

        v = val("SECURE_SSL_REDIRECT")
        if v is True:
            outs.append(self._chk("ok", "CFG-SSL-REDIRECT", "Info", "HTTPS redirect enabled.",
                                  ["REQ-017", "REQ-065"], "SECURE_SSL_REDIRECT", "True", "True"))
        else:
            outs.append(self._chk("vuln", "CFG-SSL-REDIRECT", "Medium",
                                  "SECURE_SSL_REDIRECT disabled (verify the proxy does not already "
                                  "enforce HTTPS).",
                                  ["REQ-017"], "SECURE_SSL_REDIRECT", display_value(v), "True"))

        v = val("SECURE_HSTS_SECONDS")
        if isinstance(v, int) and v >= 31536000:
            outs.append(self._chk("ok", "CFG-HSTS", "Info", f"HSTS max-age {v}.",
                                  ["REQ-020", "REQ-067"], "SECURE_HSTS_SECONDS", str(v), ">=31536000"))
        elif isinstance(v, int) and v > 0:
            outs.append(self._chk("info", "CFG-HSTS", "Low",
                                  f"HSTS max-age {v} is below the recommended one year.",
                                  ["REQ-020"], "SECURE_HSTS_SECONDS", str(v), ">=31536000"))
        else:
            outs.append(self._chk("vuln", "CFG-HSTS", "Medium", "HSTS not enabled.",
                                  ["REQ-020"], "SECURE_HSTS_SECONDS", display_value(v), ">=31536000"))

        v = val("SECURE_CONTENT_TYPE_NOSNIFF")
        if v is False:
            outs.append(self._chk("vuln", "CFG-NOSNIFF", "Low",
                                  "SECURE_CONTENT_TYPE_NOSNIFF disabled.",
                                  ["REQ-021", "REQ-067"], "SECURE_CONTENT_TYPE_NOSNIFF",
                                  "False", "True"))
        else:
            outs.append(self._chk("ok", "CFG-NOSNIFF", "Info", "nosniff enabled (default True).",
                                  ["REQ-021", "REQ-067"], "SECURE_CONTENT_TYPE_NOSNIFF",
                                  display_value(v), "True"))

        v = val("X_FRAME_OPTIONS")
        if isinstance(v, str) and v.upper() in ("DENY", "SAMEORIGIN"):
            outs.append(self._chk("ok", "CFG-XFO", "Info", f"X-Frame-Options {v}.",
                                  ["REQ-022", "REQ-067"], "X_FRAME_OPTIONS", v, "DENY/SAMEORIGIN"))
        else:
            outs.append(self._chk("vuln", "CFG-XFO", "Low",
                                  f"X-Frame-Options allows framing ({display_value(v)}).",
                                  ["REQ-022"], "X_FRAME_OPTIONS", display_value(v), "DENY/SAMEORIGIN"))

        v = val("SECURE_REFERRER_POLICY")
        if isinstance(v, str) and v.lower() not in UNSAFE_REFERRER:
            outs.append(self._chk("ok", "CFG-REFERRER", "Info", f"Referrer-Policy {v}.",
                                  ["REQ-069", "REQ-067"], "SECURE_REFERRER_POLICY", v,
                                  "same-origin or stricter"))
        else:
            outs.append(self._chk("vuln", "CFG-REFERRER", "Low",
                                  f"Referrer-Policy too permissive ({display_value(v)}).",
                                  ["REQ-069"], "SECURE_REFERRER_POLICY", display_value(v),
                                  "same-origin or stricter"))

        v = val("SECURE_PROXY_SSL_HEADER")
        if v not in (None, "__missing__", UNKNOWN):
            outs.append(self._chk("info", "CFG-PROXY-SSL", "Info",
                                  "SECURE_PROXY_SSL_HEADER set - only safe behind a trusted proxy "
                                  "that strips/sets this header.",
                                  ["REQ-105"], "SECURE_PROXY_SSL_HEADER", display_value(v),
                                  "only with trusted proxy"))

        v = val("CSRF_TRUSTED_ORIGINS")
        if isinstance(v, list) and v:
            bad = [o for o in v if isinstance(o, str) and ("*" in o)]
            if bad:
                outs.append(self._chk("vuln", "CFG-CSRF-ORIGINS", "Medium",
                                      f"CSRF_TRUSTED_ORIGINS contains wildcards: {bad}.",
                                      ["REQ-040", "REQ-106"], "CSRF_TRUSTED_ORIGINS",
                                      display_value(v), "exact origins"))
            else:
                outs.append(self._chk("ok", "CFG-CSRF-ORIGINS", "Info",
                                      f"CSRF_TRUSTED_ORIGINS explicit ({len(v)} origins).",
                                      ["REQ-040", "REQ-106"], "CSRF_TRUSTED_ORIGINS",
                                      display_value(v), "exact origins"))
        else:
            outs.append(self._chk("ok", "CFG-CSRF-ORIGINS", "Info",
                                  "CSRF_TRUSTED_ORIGINS not set: Django's same-origin CSRF "
                                  "protection applies (no cross-origin trust granted).",
                                  ["REQ-040"], "CSRF_TRUSTED_ORIGINS", display_value(v),
                                  "exact origins"))

        # CORS -----------------------------------------------------------------
        if val("CORS_ALLOW_ALL_ORIGINS") is True or \
                (isinstance(val("CORS_ALLOWED_ORIGINS"), list) and "*" in val("CORS_ALLOWED_ORIGINS")):
            outs.append(self._chk("vuln", "CFG-CORS", "Medium",
                                  "CORS allows all origins.",
                                  ["REQ-039", "REQ-106"], "CORS_ALLOW_ALL_ORIGINS", "True",
                                  "explicit origin list"))
        elif isinstance(val("CORS_ALLOWED_ORIGINS"), list) and val("CORS_ALLOWED_ORIGINS"):
            outs.append(self._chk("ok", "CFG-CORS", "Info", "CORS origins explicitly listed.",
                                  ["REQ-039"], "CORS_ALLOWED_ORIGINS",
                                  display_value(val("CORS_ALLOWED_ORIGINS")), "explicit list"))
        else:
            outs.append(self._chk("ok", "CFG-CORS", "Info",
                                  "No CORS configuration found: cross-origin requests are not "
                                  "allowed (same-origin only).",
                                  ["REQ-039"], "CORS_ALLOWED_ORIGINS", "not set",
                                  "explicit origin list"))

        # middleware ---------------------------------------------------------------
        mw = val("MIDDLEWARE")
        if isinstance(mw, list):
            joined = " ".join(str(m) for m in mw)
            if "CsrfViewMiddleware" in joined:
                outs.append(self._chk("ok", "CFG-CSRFMW", "Info", "CsrfViewMiddleware enabled.",
                                      ["REQ-009"], "MIDDLEWARE", "CsrfViewMiddleware", "present"))
            else:
                outs.append(self._chk("vuln", "CFG-CSRFMW", "High",
                                      "CsrfViewMiddleware missing - CSRF protection disabled globally.",
                                      ["REQ-009"], "MIDDLEWARE", "no CsrfViewMiddleware", "present"))
            if "SecurityMiddleware" in joined:
                outs.append(self._chk("ok", "CFG-SECMW", "Info", "SecurityMiddleware enabled.",
                                      ["REQ-067"], "MIDDLEWARE", "SecurityMiddleware", "present"))
            else:
                outs.append(self._chk("vuln", "CFG-SECMW", "Medium",
                                      "SecurityMiddleware missing - security headers not applied.",
                                      ["REQ-067", "REQ-021", "REQ-020"], "MIDDLEWARE",
                                      "no SecurityMiddleware", "present"))
            if "XFrameOptionsMiddleware" in joined:
                outs.append(self._chk("ok", "CFG-XFOMW", "Info", "XFrameOptionsMiddleware enabled.",
                                      ["REQ-022"], "MIDDLEWARE", "XFrameOptionsMiddleware", "present"))

        # session age -----------------------------------------------------------------
        v = val("SESSION_COOKIE_AGE")
        if isinstance(v, int) and v > 2592000:
            outs.append(self._chk("vuln", "CFG-SESS-AGE", "Low",
                                  f"SESSION_COOKIE_AGE {v}s exceeds 30 days.",
                                  ["REQ-025"], "SESSION_COOKIE_AGE", str(v), "<=2592000"))
        elif isinstance(v, int):
            outs.append(self._chk("ok", "CFG-SESS-AGE", "Info",
                                  f"SESSION_COOKIE_AGE {v}s within bounds.",
                                  ["REQ-025"], "SESSION_COOKIE_AGE", str(v), "<=2592000"))
        else:
            outs.append(self._chk("info", "CFG-SESS-AGE", "Info",
                                  "SESSION_COOKIE_AGE not set: Django's 2-week default applies. "
                                  "Confirm it matches the sensitivity of the data.",
                                  ["REQ-025"], "SESSION_COOKIE_AGE", "default (1209600s)",
                                  "explicit, shorter value"))

        # password hashing / validators -------------------------------------------------
        hashers = val("PASSWORD_HASHERS")
        if isinstance(hashers, list):
            weak = [h for h in hashers if isinstance(h, str) and
                    any(w in h for w in WEAK_HASHERS)]
            if weak:
                outs.append(self._chk("vuln", "CFG-PWHASH", "High",
                                      f"Weak password hashers configured: {weak}.",
                                      ["REQ-010"], "PASSWORD_HASHERS", display_value(weak),
                                      "Argon2/PBKDF2"))
            else:
                outs.append(self._chk("ok", "CFG-PWHASH", "Info", "Password hashers are modern.",
                                      ["REQ-010"], "PASSWORD_HASHERS", f"{len(hashers)} hashers",
                                      "Argon2/PBKDF2"))
        else:
            outs.append(self._chk("ok", "CFG-PWHASH", "Info",
                                  "Default PBKDF2-based hashers in use.",
                                  ["REQ-010"], "PASSWORD_HASHERS", "default", "Argon2/PBKDF2"))

        validators = val("AUTH_PASSWORD_VALIDATORS")
        if isinstance(validators, list) and validators:
            outs.append(self._chk("ok", "CFG-PWVALID", "Info",
                                  f"{len(validators)} password validators configured.",
                                  ["REQ-011"], "AUTH_PASSWORD_VALIDATORS", str(len(validators)),
                                  ">=1 with MinimumLength"))
        else:
            outs.append(self._chk("vuln", "CFG-PWVALID", "Medium",
                                  "AUTH_PASSWORD_VALIDATORS empty or missing.",
                                  ["REQ-011"], "AUTH_PASSWORD_VALIDATORS",
                                  display_value(validators), "validators configured"))

        # database credentials -----------------------------------------------------------
        dbs = val("DATABASES")
        if isinstance(dbs, dict):
            for alias, cfg in dbs.items():
                if not isinstance(cfg, dict):
                    continue
                pw = cfg.get("PASSWORD")
                if isinstance(pw, str) and pw:
                    outs.append(self._chk("vuln", "CFG-DB-CREDS", "Medium",
                                          f"DATABASES['{alias}'] has a hardcoded password.",
                                          ["REQ-042", "REQ-114"], f"DATABASES.{alias}.PASSWORD",
                                          "'***masked***'", "environment variable"))
                elif is_env_value(pw):
                    outs.append(self._chk("ok", "CFG-DB-CREDS", "Info",
                                          f"DATABASES['{alias}'] password from environment.",
                                          ["REQ-042", "REQ-114"], f"DATABASES.{alias}.PASSWORD",
                                          display_value(pw), "env var"))
                elif pw:
                    weak_default = str(pw).strip("'\"").lower() in {
                        "password", "admin", "root", "postgres", "changeme", "secret",
                        "123456", "django"}
                    outs.append(self._chk("vuln" if weak_default else "vuln",
                                          "CFG-DB-CREDS", "High" if weak_default else "Medium",
                                          ("Default/well-known database password in settings."
                                           if weak_default else
                                           "Database password is not a string literal "
                                           "(dynamic value) - verify it is not a default."),
                                          ["REQ-042", "REQ-114"], f"DATABASES.{alias}.PASSWORD",
                                          "'***masked***'", "environment variable"))
                else:
                    outs.append(self._chk("info", "CFG-DB-CREDS", "Info",
                                          f"DATABASES['{alias}'] has no password in settings "
                                          "(peer/socket authentication or injected at runtime).",
                                          ["REQ-042"], f"DATABASES.{alias}.PASSWORD",
                                          "not set", "env var"))

        # body limits ---------------------------------------------------------------------
        if val("DATA_UPLOAD_MAX_MEMORY_SIZE") == "__missing__" and \
                val("FILE_UPLOAD_MAX_MEMORY_SIZE") == "__missing__":
            outs.append(self._chk("ok", "CFG-BODY-LIMIT", "Info",
                                  "Django default 2.5MB body/upload limits apply; consider explicit "
                                  "limits and proxy-level caps.",
                                  ["REQ-076"], "DATA_UPLOAD_MAX_MEMORY_SIZE", "default 2.5MB",
                                  "explicit limits"))
        else:
            outs.append(self._chk("ok", "CFG-BODY-LIMIT", "Info",
                                  "Explicit request/upload size limits configured.",
                                  ["REQ-076"], "DATA_UPLOAD_MAX_MEMORY_SIZE",
                                  display_value(val("DATA_UPLOAD_MAX_MEMORY_SIZE")), "explicit"))

        # CSP -------------------------------------------------------------------------------
        mw_str = " ".join(str(m) for m in mw) if isinstance(mw, list) else ""
        if "CSPMiddleware" in mw_str or "csp" in mw_str.lower():
            outs.append(self._chk("ok", "CFG-CSP", "Info", "CSP middleware enabled.",
                                  ["REQ-068"], "MIDDLEWARE", "CSPMiddleware", "present"))
        else:
            outs.append(self._chk("info", "CFG-CSP", "Info",
                                  "No Content-Security-Policy middleware detected; evaluate adding CSP.",
                                  ["REQ-068"], "MIDDLEWARE", "none", "CSPMiddleware"))

        # --- revue d'infrastructure : en-têtes, transport, upload, audit ------
        # Review items : chaque contrôle produit une preuve explicite (ok/info/vuln)
        # afin qu'aucune exigence ne reste « non testée » alors qu'elle a été examinée.
        missing_headers = []
        if not (isinstance(val("SECURE_HSTS_SECONDS"), int) and val("SECURE_HSTS_SECONDS") >= 31536000):
            missing_headers.append("SECURE_HSTS_SECONDS>=31536000")
        if val("SECURE_CONTENT_TYPE_NOSNIFF") is False:
            missing_headers.append("SECURE_CONTENT_TYPE_NOSNIFF=True")
        if val("X_FRAME_OPTIONS") in ("__missing__", None, "NONE"):
            missing_headers.append("X_FRAME_OPTIONS=DENY")
        if val("SECURE_REFERRER_POLICY") in ("__missing__", None):
            missing_headers.append("SECURE_REFERRER_POLICY=same-origin")
        if missing_headers:
            outs.append(self._chk("info", "CFG-HDR-REVIEW", "Low",
                                  "Reverse-proxy / security-header review: settings do not "
                                  f"define {', '.join(missing_headers)} - confirm the proxy "
                                  "adds them (HSTS, nosniff, frame options, referrer policy).",
                                  ["REQ-105"], "SECURITY_HEADERS", "incomplete",
                                  "headers set in settings or at the proxy"))
        else:
            outs.append(self._chk("ok", "CFG-HDR-REVIEW", "Info",
                                  "Security headers (HSTS, nosniff, X-Frame-Options, "
                                  "Referrer-Policy) are configured in settings.",
                                  ["REQ-105"], "SECURITY_HEADERS", "complete", "complete"))

        tls_flags = {"SECURE_SSL_REDIRECT": val("SECURE_SSL_REDIRECT"),
                     "SECURE_HSTS_SECONDS": val("SECURE_HSTS_SECONDS")}
        if any(v is True or (isinstance(v, int) and v > 0) for v in tls_flags.values()):
            outs.append(self._chk("ok", "CFG-TRANSPORT", "Info",
                                  "TLS enforcement configured in settings "
                                  f"({', '.join(k for k, v in tls_flags.items() if v)}).",
                                  ["REQ-065"], "TRANSPORT", display_value(tls_flags),
                                  "HTTPS enforced"))
        else:
            outs.append(self._chk("info", "CFG-TRANSPORT", "Info",
                                  "No TLS enforcement in settings (SECURE_SSL_REDIRECT / HSTS): "
                                  "verify HTTPS is enforced at the reverse proxy or load balancer.",
                                  ["REQ-065"], "TRANSPORT", "not enforced in settings",
                                  "HTTPS enforced somewhere"))

        # limitation de débit (rate limiting) ---------------------------------
        installed = val("INSTALLED_APPS")
        joined_apps = " ".join(str(a) for a in installed) if isinstance(installed, list) else ""
        rate_pkgs = ("ratelimit", "axes", "django_ratelimit", "throttle", "defender")
        if any(pkg in joined_apps.lower() for pkg in rate_pkgs):
            outs.append(self._chk("ok", "CFG-RATELIMIT", "Info",
                                  "Rate-limiting / lockout application detected in INSTALLED_APPS.",
                                  ["REQ-075", "REQ-012"], "INSTALLED_APPS", joined_apps[:120],
                                  "rate limiting configured"))
        else:
            outs.append(self._chk("info", "CFG-RATELIMIT", "Info",
                                  "No rate-limiting/lockout application configured in settings - "
                                  "confirm throttling exists at the proxy or in DRF.",
                                  ["REQ-075"], "INSTALLED_APPS", "no limiter found",
                                  "rate limiting configured"))

        # audit des accès (PII) ------------------------------------------------
        logging_cfg = val("LOGGING")
        audit_pkgs = ("auditlog", "simple_history", "django_audit", "axes", "django_guid")
        if logging_cfg not in ("__missing__", None, UNKNOWN) or \
                any(pkg in joined_apps.lower() for pkg in audit_pkgs):
            outs.append(self._chk("ok", "CFG-AUDITLOG", "Info",
                                  "Application-level logging/audit configuration present.",
                                  ["REQ-101"], "LOGGING", display_value(logging_cfg)[:80],
                                  "access auditing configured"))
        else:
            outs.append(self._chk("info", "CFG-AUDITLOG", "Info",
                                  "No LOGGING configuration or audit app found: confirm that "
                                  "access to personal data is logged (who/when/what).",
                                  ["REQ-101"], "LOGGING", "not configured",
                                  "access auditing configured"))

        # revue uploads --------------------------------------------------------
        media_root = val("MEDIA_ROOT")
        outs.append(self._chk("info", "CFG-UPLOAD", "Info",
                              "Upload review: ensure the web server never executes files from "
                              "MEDIA_ROOT and that upload extensions/content types are validated.",
                              ["REQ-034", "REQ-126"], "MEDIA_ROOT", display_value(media_root),
                              "validated uploads + non-executable media root"))

        # serveur de développement --------------------------------------------
        if val("DEBUG") is False and isinstance(val("ALLOWED_HOSTS"), list) and val("ALLOWED_HOSTS"):
            outs.append(self._chk("ok", "CFG-DEVSERVER", "Info",
                                  "DEBUG=False with explicit ALLOWED_HOSTS: development server "
                                  "settings are not production-safe by accident.",
                                  ["REQ-112"], "DEBUG", "False", "False + explicit hosts"))
        else:
            outs.append(self._chk("info", "CFG-DEVSERVER", "Info",
                                  "DEBUG/ALLOWED_HOSTS combination may allow the Django "
                                  "development server to be exposed - verify the production "
                                  "entrypoint (gunicorn/uwsgi + reverse proxy).",
                                  ["REQ-112"], "DEBUG", display_value(val("DEBUG")),
                                  "production WSGI server"))

        # identifiants par défaut (au-delà des bases de données) ---------------
        default_creds = []
        for name in ("ADMIN_PASSWORD", "DEFAULT_PASSWORD", "BASIC_AUTH_PASSWORD",
                     "SMTP_PASSWORD", "EMAIL_HOST_PASSWORD"):
            v = val(name)
            if isinstance(v, str) and v.strip("'\"") and v.strip("'\"") != "": 
                if v.strip("'\"").lower() in {"admin", "password", "changeme", "secret",
                                               "123456", "test", "root", "postgres"}:
                    default_creds.append(name)
        if default_creds:
            outs.append(self._chk("vuln", "CFG-DEFAULTS", "High",
                                  f"Default/well-known credentials in settings: {default_creds}.",
                                  ["REQ-114"], "DEFAULT_CREDENTIALS",
                                  ", ".join(default_creds), "rotated secrets"))
        else:
            outs.append(self._chk("ok", "CFG-DEFAULTS", "Info",
                                  "No default/well-known credentials found in settings.",
                                  ["REQ-114"], "DEFAULT_CREDENTIALS", "none", "rotated secrets"))

        return outs

        return outs

    def _drf_checks(self, s: SettingsState, context) -> list[CheckOutput]:
        outs = []
        deps = {(d.get("name") or "").lower() for d in (context.profile or {}).get("dependencies", [])}
        installed = s.get("INSTALLED_APPS")
        installed_apps = installed if isinstance(installed, list) else []
        drf_installed = ("djangorestframework" in deps
                         or any("rest_framework" in str(a) for a in installed_apps))
        rf = s.get("REST_FRAMEWORK")
        if not drf_installed and not isinstance(rf, dict):
            return outs
        rf = rf if isinstance(rf, dict) else {}

        auth = rf.get("DEFAULT_AUTHENTICATION_CLASSES", "__missing__")
        if auth in ("__missing__", [], None):
            outs.append(self._chk("vuln", "CFG-DRF-AUTH", "High",
                                  "DRF DEFAULT_AUTHENTICATION_CLASSES not configured; views fall back "
                                  "to session-only or per-view configuration.",
                                  ["REQ-045"], "REST_FRAMEWORK.DEFAULT_AUTHENTICATION_CLASSES",
                                  display_value(auth), "explicit authentication classes"))
        else:
            outs.append(self._chk("ok", "CFG-DRF-AUTH", "Info",
                                  "DRF default authentication classes configured.",
                                  ["REQ-045"], "REST_FRAMEWORK.DEFAULT_AUTHENTICATION_CLASSES",
                                  display_value(auth), "explicit"))

        perm = rf.get("DEFAULT_PERMISSION_CLASSES", "__missing__")
        if perm in ("__missing__", [], None):
            outs.append(self._chk("vuln", "CFG-DRF-PERM", "High",
                                  "DRF DEFAULT_PERMISSION_CLASSES not configured (defaults to AllowAny).",
                                  ["REQ-046"], "REST_FRAMEWORK.DEFAULT_PERMISSION_CLASSES",
                                  display_value(perm), "IsAuthenticated or stricter"))
        elif isinstance(perm, list) and any("AllowAny" in str(p) for p in perm):
            outs.append(self._chk("vuln", "CFG-DRF-PERM", "Medium",
                                  "DRF default permission is AllowAny.",
                                  ["REQ-046", "REQ-047"],
                                  "REST_FRAMEWORK.DEFAULT_PERMISSION_CLASSES",
                                  display_value(perm), "IsAuthenticated or stricter"))
        else:
            outs.append(self._chk("ok", "CFG-DRF-PERM", "Info",
                                  "DRF default permission classes configured.",
                                  ["REQ-046"], "REST_FRAMEWORK.DEFAULT_PERMISSION_CLASSES",
                                  display_value(perm), "IsAuthenticated"))

        throttle = rf.get("DEFAULT_THROTTLE_CLASSES", "__missing__")
        rates = rf.get("DEFAULT_THROTTLE_RATES", "__missing__")
        if throttle not in ("__missing__", [], None) and rates not in ("__missing__", {}, None):
            outs.append(self._chk("ok", "CFG-THROTTLE", "Info", "DRF throttling configured.",
                                  ["REQ-049", "REQ-012", "REQ-075"],
                                  "REST_FRAMEWORK.DEFAULT_THROTTLE_CLASSES",
                                  display_value(throttle), "configured"))
        else:
            outs.append(self._chk("vuln", "CFG-THROTTLE", "Low",
                                  "No DRF throttle configuration detected.",
                                  ["REQ-049"], "REST_FRAMEWORK.DEFAULT_THROTTLE_CLASSES",
                                  display_value(throttle), "throttle classes + rates"))

        pag = rf.get("DEFAULT_PAGINATION_CLASS", "__missing__")
        if pag in ("__missing__", None, ""):
            outs.append(self._chk("vuln", "CFG-PAGINATION", "Low",
                                  "No DRF default pagination - list endpoints may return unbounded results.",
                                  ["REQ-052"], "REST_FRAMEWORK.DEFAULT_PAGINATION_CLASS",
                                  display_value(pag), "pagination class with PAGE_SIZE"))
        else:
            outs.append(self._chk("ok", "CFG-PAGINATION", "Info", "DRF pagination configured.",
                                  ["REQ-052"], "REST_FRAMEWORK.DEFAULT_PAGINATION_CLASS",
                                  display_value(pag), "configured"))
        return outs
