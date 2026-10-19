"""Lightweight intra-function taint tracking.

Purpose (spec 19): distinguish *potential* findings from *confirmed* ones.
A variable is tainted when it derives from request-controlled sources
(request.GET/POST/data/FILES/body/META/query_params or view URL parameters).
"""
from __future__ import annotations

import ast

REQUEST_ATTRS = {"GET", "POST", "data", "query_params", "FILES", "body", "META",
                 "COOKIES", "headers"}

_SENSITIVE_TARGET_NAMES = ("token", "secret", "key", "password", "passwd", "salt",
                           "api_key", "apikey", "credential", "auth")


def is_sensitive_name(name: str) -> bool:
    n = name.lower()
    return any(s in n for s in _SENSITIVE_TARGET_NAMES)


def _root_name(node: ast.AST) -> str | None:
    """Return the root Name of an attribute/subscript chain, if any."""
    while isinstance(node, (ast.Attribute, ast.Subscript, ast.Call)):
        if isinstance(node, ast.Call):
            node = node.func
        elif isinstance(node, ast.Attribute):
            node = node.value
        else:
            node = node.value
    return node.id if isinstance(node, ast.Name) else None


def _is_request_source(node: ast.AST) -> bool:
    """request.GET.get(...), request.data['x'], request.META[...], ..."""
    if isinstance(node, ast.Call):
        return _is_request_source(node.func)
    if isinstance(node, ast.Subscript):
        return _is_request_source(node.value)
    if isinstance(node, ast.Attribute):
        if isinstance(node.value, ast.Name) and node.value.id in ("request", "req") \
                and node.attr in REQUEST_ATTRS:
            return True
        return _is_request_source(node.value)
    return False


class FunctionTaint:
    """Build and query the taint set of one function body."""

    def __init__(self, func: ast.FunctionDef, request_param_taints_args: bool = False):
        self.tainted: set[str] = set()
        self.request_param = None
        args = [a.arg for a in func.args.args]
        if args and args[0] in ("request", "req"):
            self.request_param = args[0]
            # view URL captures (other positional args / kwargs) are user input
            if request_param_taints_args:
                for a in args[1:]:
                    self.tainted.add(a)
                if func.args.kwarg:
                    self.tainted.add(func.args.kwarg.arg)
        self._walk(func)

    # -- building ----------------------------------------------------------
    def _walk(self, node: ast.AST) -> None:
        for child in ast.walk(node):
            if isinstance(child, ast.Assign):
                if self.expr_tainted(child.value):
                    for t in child.targets:
                        self._add_target(t)
            elif isinstance(child, (ast.AnnAssign, ast.AugAssign)):
                target = child.target
                value = getattr(child, "value", None)
                if value is not None and self.expr_tainted(value):
                    self._add_target(target)
            elif isinstance(child, ast.For):
                if self.expr_tainted(child.iter):
                    self._add_target(child.target)
            elif isinstance(child, (ast.FunctionDef, ast.AsyncFunctionDef)) and child is not node:
                # inner function: taint its parameters if they shadow request
                for a in child.args.args:
                    if a.arg in ("request", "req"):
                        self.tainted.add(a.arg)

    def _add_target(self, target: ast.AST) -> None:
        if isinstance(target, ast.Name):
            self.tainted.add(target.id)
        elif isinstance(target, (ast.Tuple, ast.List)):
            for elt in target.elts:
                self._add_target(elt)

    # -- queries -----------------------------------------------------------
    def expr_tainted(self, node: ast.AST | None) -> bool:
        if node is None:
            return False
        if _is_request_source(node):
            return True
        if isinstance(node, ast.Name):
            return node.id in self.tainted
        if isinstance(node, ast.Subscript):
            return self.expr_tainted(node.value) or self.expr_tainted(node.slice)
        if isinstance(node, ast.Attribute):
            return self.expr_tainted(node.value)
        if isinstance(node, ast.Call):
            return self.expr_tainted(node.func) or \
                any(self.expr_tainted(a) for a in node.args) or \
                any(self.expr_tainted(k.value) for k in node.keywords)
        if isinstance(node, ast.BinOp):
            return self.expr_tainted(node.left) or self.expr_tainted(node.right)
        if isinstance(node, ast.JoinedStr):
            return any(self.expr_tainted(v) for v in node.values)
        if isinstance(node, ast.FormattedValue):
            return self.expr_tainted(node.value)
        if isinstance(node, (ast.Tuple, ast.List, ast.Set)):
            return any(self.expr_tainted(e) for e in node.elts)
        if isinstance(node, ast.Dict):
            return any(self.expr_tainted(v) for v in node.values if v is not None)
        if isinstance(node, ast.IfExp):
            return self.expr_tainted(node.body) or self.expr_tainted(node.orelse)
        if isinstance(node, ast.Starred):
            return self.expr_tainted(node.value)
        return False

    def is_request_data(self, node: ast.AST | None) -> bool:
        """True when the expression is *directly* request data (strongest)."""
        return _is_request_source(node) if node is not None else False


def is_dynamic(node: ast.AST | None) -> bool:
    """False only for compile-time constants (incl. tuples/lists of them)."""
    if node is None:
        return False
    if isinstance(node, ast.Constant):
        return False
    if isinstance(node, (ast.Tuple, ast.List)):
        return any(is_dynamic(e) for e in node.elts)
    return True


def snippet_from_source(source_lines: list[str], lineno: int) -> str:
    if 1 <= lineno <= len(source_lines):
        return source_lines[lineno - 1].strip()[:240]
    return ""
