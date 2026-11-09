from django.conf import settings
from django.http import HttpResponseNotFound
from django.urls import Resolver404, resolve


class ClientAccountHostMiddleware:
    """Restrict the optional form host before sessions and authentication run."""

    def __init__(self, get_response):
        self.get_response = get_response

    @staticmethod
    def unavailable():
        response = HttpResponseNotFound("Page indisponible.", content_type="text/plain; charset=utf-8")
        response["Cache-Control"] = "no-store"
        return response

    def __call__(self, request):
        public_host = settings.CLIENT_ACCOUNTS_PUBLIC_HOST
        host = request.get_host().split(":", 1)[0].lower()
        is_public_host = bool(public_host and host == public_host)
        is_module_path = any(
            request.path_info == path or request.path_info.startswith(path + "/")
            for path in ("/creer-compte", "/creation-comptes-clients", "/essai-comptes-clients")
        )
        if not settings.CLIENT_ACCOUNTS_ENABLED and (is_public_host or is_module_path):
            return self.unavailable()
        if is_public_host:
            request.urlconf = "client_accounts.portal_urls"
            try:
                resolve(request.path_info, urlconf=request.urlconf)
            except Resolver404:
                return self.unavailable()
            # Even a parent-domain admin session cookie must not log a visitor in here.
            request.COOKIES = request.COOKIES.copy()
            request.COOKIES.pop(settings.SESSION_COOKIE_NAME, None)
            response = self.get_response(request)
            response["Referrer-Policy"] = "no-referrer"
            response["X-Frame-Options"] = "DENY"
            response["Cache-Control"] = "no-store"
            return response
        if public_host and (request.path_info == "/creer-compte" or request.path_info.startswith("/creer-compte/")):
            return self.unavailable()
        return self.get_response(request)
