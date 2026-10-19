"""API/endpoint discovery from urls.py, DRF routers and view decorators.

Static analysis only (spec 15): builds the endpoint inventory used by DAST
and the automated security tests.  ``include()`` prefixes are resolved
recursively so routes are reported with their full mounted path.
"""
from __future__ import annotations

import ast
import re
from pathlib import Path

SKIP_DIRS = {".git", "node_modules", ".venv", "venv", "__pycache__", ".tox",
             "site-packages", "dist", "build"}


def _const(node) -> str | None:
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return node.value
    return None


def _path_to_route(raw: str) -> str:
    """Convert Django path converters / regex groups to {param} placeholders."""
    out = re.sub(r"<(?:[a-zA-Z_][\w:]*:)?(\w+)>", r"{\1}", raw)
    out = re.sub(r"\(\?P?<(\w+)>[^)]*\)", r"{\1}", out)
    return out.lstrip("^").rstrip("$")


def _join(prefix: str, route: str) -> str:
    """Join URL segments, collapsing duplicate slashes, keeping trailing slash."""
    joined = re.sub(r"/+", "/", (prefix.rstrip("/") + "/" + route).lstrip("/"))
    return joined


def _dotted_ref(node) -> str | None:
    parts = []
    n = node
    while isinstance(n, ast.Attribute):
        parts.append(n.attr)
        n = n.value
    if isinstance(n, ast.Name):
        parts.append(n.id)
        return ".".join(reversed(parts))
    return None


def _view_ref(node) -> str:
    if isinstance(node, ast.Call):
        inner = _dotted_ref(node.func)
        return (inner or "<dynamic>") + "(...)"
    return _dotted_ref(node) or "<dynamic>"


def discover_endpoints(source_dir: str, urls_files: list[str] | None = None) -> list[dict]:
    root = Path(source_dir)
    if not root.is_dir():
        return []

    # collect all urls.py modules: dotted name -> file
    all_urls: list[Path] = []
    if urls_files:
        all_urls = [root / rel for rel in urls_files if (root / rel).is_file()]
    if not all_urls:
        all_urls = [p for p in root.rglob("urls.py")
                    if not (set(p.relative_to(root).parts[:-1]) & SKIP_DIRS)]

    module_map: dict[str, Path] = {}
    for f in all_urls:
        rel = f.relative_to(root)
        parts = list(rel.parts)
        if parts[-1] == "urls.py":
            parts = parts[:-1] + ["urls"]
        module_map[".".join(parts)] = f

    # determine which modules are included by others -> roots are the rest
    included: set[str] = set()
    for f in all_urls:
        try:
            tree = ast.parse(f.read_text(encoding="utf-8", errors="replace"))
        except SyntaxError:
            continue
        for node in ast.walk(tree):
            if isinstance(node, ast.Call) and _dotted_ref(node.func) == "include":
                mod = _const(node.args[0]) if node.args else None
                if mod:
                    included.add(mod)

    roots = [f for mod, f in module_map.items() if mod not in included]
    if not roots:
        roots = all_urls[:1]

    endpoints: list[dict] = []
    seen: set[tuple] = set()
    visited: set[str] = set()

    def add(method: str, path: str, view: str, source: str, note: str = "",
            auth: str = "unknown", permission: str = "unknown"):
        path = "/" + path.lstrip("/")
        key = (method, path)
        if key in seen:
            return
        seen.add(key)
        endpoints.append({"method": method, "path": path, "view": view,
                          "source_file": source, "note": note,
                          "authentication": auth, "permission": permission})

    def parse_file(f: Path, prefix: str):
        rel = f.relative_to(root).as_posix()
        mod_name = ".".join(Path(rel).with_suffix("").parts).replace(".urls", ".urls")
        if mod_name in visited:
            return
        visited.add(mod_name)
        try:
            tree = ast.parse(f.read_text(encoding="utf-8", errors="replace"))
        except SyntaxError:
            return

        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue
            fname = _dotted_ref(node.func) or ""

            # router.register('prefix', ViewSet)
            if isinstance(node.func, ast.Attribute) and node.func.attr == "register" \
                    and len(node.args) >= 2:
                rp = _const(node.args[0])
                view = _view_ref(node.args[1])
                if rp is None:
                    continue
                base = _join(prefix, rp.strip("/"))
                for m in ("GET", "POST"):
                    add(m, f"{base}/", view, rel, note="router list route")
                for m in ("GET", "PUT", "PATCH", "DELETE"):
                    add(m, f"{base}/{{id}}/", view, rel, note="router detail route")
                continue

            if fname not in ("path", "re_path", "url") or len(node.args) < 2:
                continue
            route = _const(node.args[0])
            if route is None:
                continue
            full = _join(prefix, _path_to_route(route))
            target = node.args[1]

            # include(...)
            if isinstance(target, ast.Call) and _dotted_ref(target.func) == "include":
                mod = _const(target.args[0]) if target.args else None
                if mod == "django.contrib.admin.urls" or (mod or "").endswith("admin.urls"):
                    add("GET", full if full.endswith("/") else full + "/",
                        "django.contrib.admin", rel,
                        note="Django admin", auth="session", permission="is_staff")
                    continue
                if mod and mod in module_map:
                    parse_file(module_map[mod], full)
                continue

            # admin.site.urls passed directly
            ref = _dotted_ref(target)
            if ref and ref.endswith(".site.urls"):
                add("GET", full if full.endswith("/") else full + "/",
                    "django.contrib.admin", rel,
                    note="Django admin", auth="session", permission="is_staff")
                continue

            view = _view_ref(target)
            if "as_view" in view or "ViewSet" in view or "APIView" in view:
                for m in ("GET", "POST", "PUT", "PATCH", "DELETE"):
                    add(m, "/" + full, view, rel)
            else:
                add("GET", "/" + full, view, rel)
                add("POST", "/" + full, view, rel)

    for f in roots:
        parse_file(f, "")

    endpoints.sort(key=lambda e: (e["path"], e["method"]))
    return endpoints
