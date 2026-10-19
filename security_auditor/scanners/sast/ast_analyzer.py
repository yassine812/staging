"""AST-based SAST analysis (spec 9).

Goes beyond regex: resolves imports, performs lightweight intra-function taint
tracking, and upgrades confidence when request data demonstrably flows into a
dangerous sink.  Never executes the scanned project's code.
"""
from __future__ import annotations

import ast
import re
from dataclasses import dataclass, field

from .rules import RULES
from .taint import FunctionTaint, is_dynamic, is_sensitive_name

LOG_METHODS = {"debug", "info", "warning", "warn", "error", "exception", "critical", "log"}
LOG_ROOTS = {"logging", "logger", "log", "LOG", "LOGGER", "logger_"}

HTTP_SINKS = {
    "requests.get", "requests.post", "requests.put", "requests.delete",
    "requests.patch", "requests.head", "requests.request",
    "httpx.get", "httpx.post", "httpx.put", "httpx.delete", "httpx.patch",
    "httpx.head", "httpx.request", "httpx.stream",
    "urllib.request.urlopen", "urllib.urlopen", "urlopen",
    "aiohttp.ClientSession.get", "aiohttp.ClientSession.post",
    "aiohttp.ClientSession.request",
}

XML_SINKS = {
    "xml.etree.ElementTree.parse", "xml.etree.ElementTree.fromstring",
    "xml.etree.ElementTree.XML", "ET.parse", "ET.fromstring",
    "lxml.etree.parse", "lxml.etree.fromstring", "etree.parse", "etree.fromstring",
    "xml.dom.minidom.parse", "xml.dom.minidom.parseString",
    "xml.sax.parseString", "xml.sax.make_parser",
}

SUBPROCESS_CALLS = {"subprocess.call", "subprocess.run", "subprocess.Popen",
                    "subprocess.check_call", "subprocess.check_output",
                    "subprocess.getoutput", "subprocess.getstatusoutput"}

SENSITIVE_SER_FIELDS = {"password", "passwd", "secret", "secret_key", "token",
                        "api_key", "apikey", "access_token", "refresh_token",
                        "ssn", "card_number", "private_key", "otp"}

NESTED_QUANTIFIER = re.compile(r"\([^()]*[+*][^()]*\)[+*{]|\(\?[^)]*[+*]\)\+?")


@dataclass
class Hit:
    rule_id: str
    line: int
    col: int = 0
    confidence: str | None = None          # None -> rule default
    note: str = ""

    def to_dict(self):
        return {"rule_id": self.rule_id, "line": self.line, "col": self.col,
                "confidence": self.confidence, "note": self.note}


@dataclass
class ControlHit:
    """Positive evidence that a security control exists (polarity=ok)."""
    req_ids: tuple
    rule_key: str
    summary: str
    line: int = 0


@dataclass
class AstResult:
    hits: list = field(default_factory=list)
    controls: list = field(default_factory=list)


def _dotted(node: ast.AST) -> str | None:
    # unwrap call chains: logging.getLogger(...).info -> logging.getLogger.info
    while isinstance(node, ast.Call):
        node = node.func
    parts = []
    while isinstance(node, ast.Attribute):
        parts.append(node.attr)
        node = node.value
    if isinstance(node, ast.Name):
        parts.append(node.id)
        return ".".join(reversed(parts))
    return None


class ModuleAnalyzer:
    def __init__(self, relpath: str, source: str):
        self.relpath = relpath
        self.source = source
        self.lines = source.splitlines()
        try:
            self.tree = ast.parse(source)
        except SyntaxError:
            self.tree = None
        self.imports: dict[str, str] = {}      # local name -> dotted module
        self.uses_defusedxml = "defusedxml" in source
        self.result = AstResult()

    # ------------------------------------------------------------------ api
    def analyze(self) -> AstResult:
        if self.tree is None:
            return self.result
        self._collect_imports()
        self._module_level()
        self._inside_func: set[int] = set()
        for node in ast.walk(self.tree):
            if isinstance(node, ast.ClassDef):
                self._analyze_class(node)
            elif isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                for sub in ast.walk(node):
                    self._inside_func.add(id(sub))
                self._analyze_function(node)
        self._module_level_calls()
        return self.result

    def _module_level_calls(self) -> None:
        """Checks that also apply outside function bodies (e.g. module-level
        re.compile with a ReDoS-prone pattern)."""
        for node in ast.walk(self.tree):
            if not isinstance(node, ast.Call) or id(node) in self._inside_func:
                continue
            resolved = self._resolve(node.func) or ""
            if resolved in ("re.compile", "re.match", "re.search", "re.fullmatch") \
                    and node.args and isinstance(node.args[0], ast.Constant) \
                    and isinstance(node.args[0].value, str) \
                    and NESTED_QUANTIFIER.search(node.args[0].value):
                self.result.hits.append(Hit("DOS-001", node.lineno,
                                            note=node.args[0].value[:80]))

    # ------------------------------------------------------------- imports
    def _collect_imports(self) -> None:
        for node in ast.walk(self.tree):
            if isinstance(node, ast.Import):
                for a in node.names:
                    self.imports[a.asname or a.name.split(".")[0]] = a.name
            elif isinstance(node, ast.ImportFrom):
                mod = node.module or ""
                for a in node.names:
                    if a.name == "*":
                        continue
                    self.imports[a.asname or a.name] = f"{mod}.{a.name}" if mod else a.name

    def _resolve(self, node: ast.AST) -> str | None:
        dotted = _dotted(node)
        if not dotted:
            return None
        head, _, rest = dotted.partition(".")
        base = self.imports.get(head, head)
        return f"{base}.{rest}" if rest else base

    # ------------------------------------------------------- module level
    def _module_level(self) -> None:
        in_tests = any(p in ("tests", "test", "fixtures") for p in self.relpath.split("/"))
        for node in self.tree.body:
            if isinstance(node, (ast.Assign, ast.AnnAssign)):
                self._check_secret_assignment(node, in_tests)

    def _check_secret_assignment(self, node, in_tests) -> None:
        targets = node.targets if isinstance(node, ast.Assign) else [node.target]
        value = node.value
        for target in targets:
            if not isinstance(target, ast.Name):
                continue
            name = target.id
            if name == "SECRET_KEY" and isinstance(value, ast.Constant) and \
                    isinstance(value.value, str) and len(value.value) >= 8:
                self.result.hits.append(Hit("SECRET-001", node.lineno,
                                            note="SECRET_KEY literal in source"))
            elif name.upper().startswith(("SIMPLE_JWT", "JWT")) and isinstance(value, ast.Dict):
                for k, v in zip(value.keys, value.values):
                    if isinstance(k, ast.Constant) and k.value in ("SIGNING_KEY", "SECRET_KEY") \
                            and isinstance(v, ast.Constant) and isinstance(v.value, str) \
                            and len(v.value) >= 8:
                        self.result.hits.append(Hit("SECRET-007", node.lineno,
                                                    note=f"{name} signing key literal"))
            elif is_sensitive_name(name) and isinstance(value, ast.Constant) and \
                    isinstance(value.value, str) and len(value.value) >= 8 and not in_tests:
                self.result.hits.append(Hit("SECRET-002", node.lineno,
                                            confidence="Medium", note=f"literal assigned to {name}"))

    # ------------------------------------------------------------- classes
    def _base_names(self, node: ast.ClassDef) -> list[str]:
        names = []
        for b in node.bases:
            d = _dotted(b)
            if d:
                names.append(d.split(".")[-1])
        return names

    def _analyze_class(self, node: ast.ClassDef) -> None:
        bases = self._base_names(node)
        for deco in node.decorator_list:
            if _dotted(deco) and _dotted(deco).endswith("csrf_exempt"):
                self.result.hits.append(Hit("CSRF-001", deco.lineno))

        is_drf_view = any(("APIView" in b or "ViewSet" in b) for b in bases)
        is_detail_view = any(("Retrieve" in b or "Update" in b or "Destroy" in b or
                              "ViewSet" in b) for b in bases)
        is_serializer = any(b.endswith("Serializer") for b in bases)

        perm_classes: list | None = None
        auth_classes: list | None = None
        has_get_queryset = False
        has_queryset_all = False
        throttle_seen = False
        object_perm_words = ("Object", "Owner", "Tenant")

        for child in node.body:
            if isinstance(child, (ast.FunctionDef, ast.AsyncFunctionDef)):
                if child.name == "get_queryset":
                    has_get_queryset = True
            if isinstance(child, ast.Assign) and len(child.targets) == 1 and \
                    isinstance(child.targets[0], ast.Name):
                attr = child.targets[0].id
                if attr == "permission_classes" and isinstance(child.value, (ast.List, ast.Tuple)):
                    perm_classes = child.value.elts
                    if not perm_classes:
                        self.result.hits.append(Hit("AUTHZ-002", child.lineno,
                                                    note=f"{node.name}.permission_classes is empty"))
                    else:
                        for elt in perm_classes:
                            d = _dotted(elt) or ""
                            if d.split(".")[-1] == "AllowAny":
                                self.result.hits.append(Hit("AUTHZ-001", child.lineno,
                                                            note=f"{node.name} allows anonymous access"))
                elif attr == "authentication_classes" and isinstance(child.value, (ast.List, ast.Tuple)) \
                        and not child.value.elts:
                    auth_classes = child.value.elts
                    self.result.hits.append(Hit("AUTHZ-003", child.lineno,
                                                note=f"{node.name}.authentication_classes is empty"))
                elif attr == "throttle_classes" and isinstance(child.value, (ast.List, ast.Tuple)) \
                        and child.value.elts:
                    throttle_seen = True
                elif attr == "queryset":
                    d = _dotted(child.value)
                    if d and d.endswith("objects.all"):
                        has_queryset_all = True
            if isinstance(child, ast.ClassDef) and child.name == "Meta" and is_serializer:
                self._check_serializer_meta(node, child)

        if is_drf_view and is_detail_view and not has_get_queryset and \
                (has_queryset_all or perm_classes is None) and \
                not any(any(w in (_dotted(p) or "") for w in object_perm_words)
                        for p in (perm_classes or [])):
            self.result.hits.append(Hit("AUTHZ-OBJECT-001", node.lineno, confidence="Potential",
                                        note=f"{node.name}: detail view without scoped get_queryset "
                                             "or object permissions"))
        if throttle_seen:
            self.result.controls.append(ControlHit(("REQ-049",), "OK-THROTTLE",
                                                   f"{node.name} configures throttle_classes", node.lineno))

    def _check_serializer_meta(self, owner: ast.ClassDef, meta: ast.ClassDef) -> None:
        write_only: set[str] = set()
        fields: list[str] = []
        fields_line = meta.lineno
        for child in meta.body:
            if isinstance(child, ast.Assign) and len(child.targets) == 1 and \
                    isinstance(child.targets[0], ast.Name):
                name = child.targets[0].id
                if name == "fields" and isinstance(child.value, (ast.List, ast.Tuple)):
                    fields = [e.value for e in child.value.elts
                              if isinstance(e, ast.Constant) and isinstance(e.value, str)]
                    fields_line = child.lineno
        # write_only declarations on owner class
        for child in owner.body:
            if isinstance(child, ast.Assign) and isinstance(child.value, ast.Call):
                func_name = _dotted(child.value.func) or ""
                if any(kw.arg == "write_only" and isinstance(kw.value, ast.Constant)
                       and kw.value.value for kw in child.value.keywords):
                    for t in child.targets:
                        if isinstance(t, ast.Name):
                            write_only.add(t.id.lower())
        exposed = [f for f in fields
                   if f.lower() in SENSITIVE_SER_FIELDS and f.lower() not in write_only]
        if exposed:
            self.result.hits.append(Hit("SENSITIVE-001", fields_line, confidence="Medium",
                                        note=f"{owner.name}.Meta.fields exposes: {', '.join(exposed)}"))

    # ------------------------------------------------------------ functions
    def _is_view_function(self, func) -> bool:
        for deco in func.decorator_list:
            d = _dotted(deco.func if isinstance(deco, ast.Call) else deco) or ""
            if any(k in d for k in ("api_view", "login_required", "permission_required",
                                    "csrf_exempt", "user_passes_test", "ratelimit")):
                return True
        if "views" in self.relpath.split("/"):
            return True
        args = [a.arg for a in func.args.args]
        return bool(args) and args[0] == "request"

    def _analyze_function(self, func) -> None:
        for deco in func.decorator_list:
            d = _dotted(deco.func if isinstance(deco, ast.Call) else deco)
            if d and d.endswith("csrf_exempt"):
                self.result.hits.append(Hit("CSRF-001", deco.lineno, note=f"on {func.name}"))

        is_view = self._is_view_function(func)
        taint = FunctionTaint(func, request_param_taints_args=is_view)
        assign_names: dict[int, str] = {}       # id(call node) -> assigned name
        get_vars: set[str] = set()              # vars assigned from .get(...) calls
        redirects_validated = False

        # first pass: collect assignment metadata
        for node in ast.walk(func):
            if isinstance(node, ast.Assign) and isinstance(node.value, ast.Call):
                tgt = node.targets[0]
                if isinstance(tgt, ast.Name):
                    assign_names[id(node.value)] = tgt.id
                    d = _dotted(node.value.func)
                    if d and d.endswith(".get"):
                        get_vars.add(tgt.id)
            if isinstance(node, ast.Call):
                d = self._resolve(node.func)
                if d and d.endswith("url_has_allowed_host_and_scheme"):
                    redirects_validated = True

        for node in ast.walk(func):
            if isinstance(node, ast.Call):
                self._check_call(node, func, taint, assign_names, get_vars, redirects_validated)
            elif isinstance(node, ast.AugAssign) and isinstance(node.target, ast.Attribute) \
                    and isinstance(node.target.value, ast.Name) \
                    and node.target.value.id in get_vars:
                self.result.hits.append(Hit("RACE-001", node.lineno, confidence="Potential",
                                            note=f"'{node.target.value.id}.{node.target.attr}' "
                                                 "read-modify-write after .get()"))

        # upload heuristic
        for node in ast.walk(func):
            if isinstance(node, ast.Attribute) and node.attr == "FILES" and \
                    isinstance(node.value, ast.Name) and node.value.id in ("request", "req"):
                source_blob = ast.get_source_segment(self.source, func) or ""
                if "valid" not in source_blob.lower() and "content_type" not in source_blob:
                    self.result.hits.append(Hit("UPLOAD-001", node.lineno, confidence="Potential",
                                                note=f"request.FILES used in {func.name} without "
                                                     "visible validation"))
                break

    # ----------------------------------------------------------- call checks
    def _check_call(self, node: ast.Call, func, taint: FunctionTaint,
                    assign_names: dict, get_vars: set, redirects_validated: bool) -> None:
        # --- mass assignment (independent check, any call with **request.data) ---
        for kw in node.keywords:
            if kw.arg is None and taint.expr_tainted(kw.value):
                self.result.hits.append(Hit("MASS-001", node.lineno, confidence="Confirmed",
                                            note=f"**request.data into {_dotted(node.func) or 'call'}"))
                leaf_name = (_dotted(node.func) or "").split(".")[-1]
                if leaf_name in ("create", "update", "save"):
                    self.result.hits.append(Hit("SER-001", node.lineno, confidence="Confirmed"))

        resolved = self._resolve(node.func) or ""
        leaf = resolved.split(".")[-1]
        args = node.args
        first = args[0] if args else None
        tainted_first = taint.expr_tainted(first)

        def conf_if_tainted(expr=None, base="Medium"):
            """Confirmed only for *direct* request data flowing into the sink
            (spec 19); indirect taint keeps the rule's default confidence."""
            if expr is not None and taint.is_request_data(expr):
                return "Confirmed"
            return base

        # --- dynamic code ------------------------------------------------
        if leaf in ("eval", "exec", "compile") and isinstance(node.func, ast.Name):
            if first is not None and not (isinstance(first, ast.Constant) and leaf == "compile"):
                self.result.hits.append(Hit("DYN-001", node.lineno,
                                            confidence=conf_if_tainted(first, "High"),
                                            note=f"{leaf}() in {func.name}"))
        elif leaf == "__import__":
            self.result.hits.append(Hit("DYN-002", node.lineno, confidence=conf_if_tainted(first)))

        # --- deserialization ----------------------------------------------
        elif resolved in ("pickle.load", "pickle.loads", "cPickle.load", "cPickle.loads",
                          "_pickle.load", "_pickle.loads"):
            self.result.hits.append(Hit("DESER-001", node.lineno, confidence=conf_if_tainted(first, "High")))
        elif resolved in ("marshal.loads", "shelve.open"):
            self.result.hits.append(Hit("DESER-003", node.lineno))
        elif resolved in ("yaml.load", "yaml.unsafe_load", "yaml.full_load"):
            safe = any(kw.arg == "Loader" and (_dotted(kw.value) or "").endswith(
                ("SafeLoader", "CSafeLoader")) for kw in node.keywords)
            if resolved == "yaml.load" and not safe:
                self.result.hits.append(Hit("DESER-002", node.lineno, confidence=conf_if_tainted(first, "High")))
            elif resolved != "yaml.load":
                self.result.hits.append(Hit("DESER-002", node.lineno, confidence=conf_if_tainted(first, "High")))
        elif resolved == "yaml.safe_load":
            self.result.controls.append(ControlHit(("REQ-080",), "OK-SAFEYAML",
                                                   "yaml.safe_load used", node.lineno))

        # --- command execution ----------------------------------------------
        elif resolved in ("os.system", "os.popen"):
            self.result.hits.append(Hit("CMD-001", node.lineno, confidence=conf_if_tainted(first, "High"),
                                        note=f"argument {'is' if tainted_first else 'may be'} dynamic"))
        elif resolved in SUBPROCESS_CALLS:
            shell_true = any(kw.arg == "shell" and isinstance(kw.value, ast.Constant)
                             and kw.value.value for kw in node.keywords)
            if shell_true:
                self.result.hits.append(Hit("CMD-002", node.lineno,
                                            confidence=conf_if_tainted(first, "High"),
                                            note=f"shell=True in {func.name}"))
            elif tainted_first:
                self.result.hits.append(Hit("CMD-003", node.lineno, confidence="Confirmed"))
            elif first is not None and is_dynamic(first):
                self.result.hits.append(Hit("CMD-003", node.lineno, confidence="Potential"))
        elif resolved in ("os.path.join",) and tainted_first:
            pass  # handled by open() sink check

        # --- SQL ---------------------------------------------------------------
        elif leaf in ("execute", "executemany"):
            if first is not None and is_dynamic(first):
                if tainted_first and taint.is_request_data(first):
                    confidence = "Confirmed"
                elif tainted_first:
                    confidence = "High"
                elif isinstance(first, (ast.JoinedStr, ast.BinOp)) or (
                        isinstance(first, ast.Call) and (_dotted(first.func) or "").endswith("format")):
                    confidence = "High"
                else:
                    confidence = "Medium"
                self.result.hits.append(Hit("SQLI-001", node.lineno, confidence=confidence,
                                            note=f".{leaf}() with dynamic SQL in {func.name}"))
        elif leaf == "raw" and first is not None and is_dynamic(first):
            self.result.hits.append(Hit("SQLI-002", node.lineno,
                                        confidence=conf_if_tainted(first, "High"), note=".raw() dynamic SQL"))
        elif leaf == "extra":
            for kw in node.keywords:
                if kw.arg in ("where", "select", "tables") and is_dynamic(kw.value):
                    self.result.hits.append(Hit("SQLI-002", node.lineno, confidence="Medium",
                                                note=f".extra({kw.arg}=...) is dynamic"))
        elif leaf == "RawSQL" and first is not None and is_dynamic(first):
            self.result.hits.append(Hit("SQLI-003", node.lineno, confidence=conf_if_tainted(first, "High")))

        # --- XSS -----------------------------------------------------------------
        elif leaf == "mark_safe" and first is not None:
            if not isinstance(first, ast.Constant):
                self.result.hits.append(Hit("XSS-001", node.lineno,
                                            confidence=conf_if_tainted(first, "Medium"),
                                            note=f"mark_safe() in {func.name}"))
        elif resolved == "django.utils.html.format_html":
            pass  # safe by design

        # --- files -----------------------------------------------------------------
        elif leaf == "open" and first is not None and is_dynamic(first):
            conf = "High" if (tainted_first and taint.is_request_data(first)) else \
                   ("Low" if tainted_first else "Low")
            self.result.hits.append(Hit("PATH-001", node.lineno, confidence=conf,
                                        note=f"open() in {func.name}"))
        elif leaf in ("FileResponse", "sendfile", "serve") and first is not None and is_dynamic(first):
            self.result.hits.append(Hit("PATH-002", node.lineno, confidence=conf_if_tainted(first)))
        elif resolved == "tempfile.mktemp":
            self.result.hits.append(Hit("TMP-001", node.lineno))
        elif resolved == "zipfile.ZipFile.extractall":
            pass  # member validation check would need interprocedural context

        # --- SSRF / redirect ---------------------------------------------------------
        elif resolved in HTTP_SINKS:
            url_arg = first
            if url_arg is None:
                for kw in node.keywords:
                    if kw.arg == "url":
                        url_arg = kw.value
            if url_arg is not None and is_dynamic(url_arg):
                self.result.hits.append(Hit("SSRF-001", node.lineno,
                                            confidence=conf_if_tainted(first),
                                            note=f"{resolved}() with dynamic URL"))
        elif leaf in ("redirect", "HttpResponseRedirect", "HttpResponsePermanentRedirect") \
                and first is not None and is_dynamic(first):
            if redirects_validated:
                self.result.controls.append(ControlHit(("REQ-038",), "OK-REDIR",
                                                       "redirect guarded by url_has_allowed_host_and_scheme",
                                                       node.lineno))
            else:
                self.result.hits.append(Hit("REDIR-001", node.lineno,
                                            confidence=conf_if_tainted(first),
                                            note=f"{leaf}() with dynamic target"))

        # --- crypto --------------------------------------------------------------------
        elif resolved in ("hashlib.md5", "hashlib.sha1"):
            if not any(kw.arg == "usedforsecurity" and isinstance(kw.value, ast.Constant)
                       and kw.value.value is False for kw in node.keywords):
                self.result.hits.append(Hit("CRYPTO-001", node.lineno, note=resolved))
        elif resolved.startswith("Crypto.Cipher.DES") or resolved.startswith("Crypto.Cipher.Blowfish") \
                or resolved.endswith(".new") and any(isinstance(a, ast.Constant) and a.value == "ECB"
                                                      for a in args):
            self.result.hits.append(Hit("CRYPTO-004", node.lineno))
        elif resolved.startswith("random.") and id(node) in assign_names and \
                is_sensitive_name(assign_names[id(node)]):
            self.result.hits.append(Hit("CRYPTO-002", node.lineno,
                                        note=f"random used for '{assign_names[id(node)]}'"))

        # --- XML ------------------------------------------------------------------------
        elif resolved in XML_SINKS and not self.uses_defusedxml:
            self.result.hits.append(Hit("XXE-001", node.lineno, note=resolved))

        # --- templates ----------------------------------------------------------------------
        elif leaf == "Template" and first is not None and is_dynamic(first):
            self.result.hits.append(Hit("TPL-001", node.lineno, confidence=conf_if_tainted(first),
                                        note="Template() constructed with dynamic source"))
        elif leaf == "from_string" and first is not None and is_dynamic(first):
            self.result.hits.append(Hit("TPL-001", node.lineno, confidence=conf_if_tainted(first)))

        # --- mass assignment handled at top of method ---------------------------

        # --- logging -----------------------------------------------------------------------------
        if leaf in LOG_METHODS:
            root = _dotted(node.func)
            root_head = root.split(".")[0] if root else None
            if root_head in LOG_ROOTS or leaf == "log":
                sensitive_logged = False
                request_logged = False
                for a in args:
                    for sub in ast.walk(a):
                        if isinstance(sub, ast.Name):
                            if is_sensitive_name(sub.id):
                                sensitive_logged = True
                            if taint.expr_tainted(sub):
                                request_logged = True
                        if isinstance(sub, ast.Constant) and isinstance(sub.value, str) and \
                                any(s in sub.value.lower() for s in ("%s", "{")):
                            continue
                    if isinstance(a, ast.JoinedStr):
                        for v in a.values:
                            if isinstance(v, ast.FormattedValue) and isinstance(v.value, ast.Name):
                                if is_sensitive_name(v.value.id):
                                    sensitive_logged = True
                                if taint.expr_tainted(v.value):
                                    request_logged = True
                if sensitive_logged:
                    self.result.hits.append(Hit("LOG-001", node.lineno,
                                                note=f"sensitive value logged in {func.name}"))
                if request_logged:
                    self.result.hits.append(Hit("LOG-002", node.lineno))

        # --- regex DoS ------------------------------------------------------------------------------
        if resolved in ("re.compile", "re.match", "re.search", "re.fullmatch", "re.findall") \
                and first is not None and isinstance(first, ast.Constant) and \
                isinstance(first.value, str) and NESTED_QUANTIFIER.search(first.value):
            self.result.hits.append(Hit("DOS-001", node.lineno, note=first.value[:80]))

        # --- race condition heuristic ------------------------------------------------------------------
        pass

    # ------------------------------------------------------------------ end

def analyze_source(relpath: str, source: str) -> AstResult:
    return ModuleAnalyzer(relpath, source).analyze()
