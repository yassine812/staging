"""Small hardened HTTP client used by DAST and the security tests."""
from __future__ import annotations

import http.cookiejar
import socket
import urllib.error
import urllib.request
from dataclasses import dataclass, field

USER_AGENT = "django-security-auditor/0.1 (authorized audit)"


@dataclass
class HttpResponse:
    status: int
    headers: dict = field(default_factory=dict)
    body: str = ""
    url: str = ""
    error: str = ""

    @property
    def ok(self) -> bool:
        return 200 <= self.status < 400

    def header(self, name: str) -> str:
        for k, v in self.headers.items():
            if k.lower() == name.lower():
                return v
        return ""

    def cookies(self) -> list[str]:
        return [v for k, v in self.headers.items() if k.lower() == "set-cookie"]


class Client:
    """Session client with an isolated cookie jar and bounded behaviour."""

    def __init__(self, timeout: float = 8.0, follow_redirects: bool = False):
        self.jar = http.cookiejar.CookieJar()
        self.timeout = timeout
        self.follow = follow_redirects

    def _opener(self):
        handlers = [urllib.request.HTTPCookieProcessor(self.jar)]
        if not self.follow:
            class NoRedirect(urllib.request.HTTPRedirectHandler):
                def redirect_request(self, *args, **kwargs):
                    return None
            handlers.append(NoRedirect)
        return urllib.request.build_opener(*handlers)

    def request(self, method: str, url: str, data: bytes | None = None,
                headers: dict | None = None) -> HttpResponse:
        hdrs = {"User-Agent": USER_AGENT, "Accept": "*/*"}
        if headers:
            hdrs.update(headers)
        req = urllib.request.Request(url, data=data, method=method, headers=hdrs)
        opener = self._opener()
        try:
            with opener.open(req, timeout=self.timeout) as resp:
                body = resp.read(1_000_000).decode("utf-8", "replace")
                return HttpResponse(resp.status, dict(resp.headers.items()), body,
                                    resp.geturl())
        except urllib.error.HTTPError as e:
            try:
                body = e.read(1_000_000).decode("utf-8", "replace")
            except (OSError, socket.timeout):
                body = ""
            return HttpResponse(e.code, dict(e.headers.items()) if e.headers else {}, body, url)
        except (urllib.error.URLError, OSError, TimeoutError) as e:
            return HttpResponse(0, {}, "", url, error=str(e))

    def get(self, url: str, **kw) -> HttpResponse:
        return self.request("GET", url, **kw)

    def post(self, url: str, data: bytes | None = None, **kw) -> HttpResponse:
        return self.request("POST", url, data=data, **kw)
