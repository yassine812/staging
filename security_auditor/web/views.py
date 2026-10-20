from pathlib import Path

from django.conf import settings
from django.contrib.auth.decorators import login_required
from django.http import HttpResponse
from django.shortcuts import render
from django.views.decorators.csrf import csrf_exempt

from security_auditor.apps.integration import InternalSecurityAuditor


FRONTEND = Path(__file__).resolve().parent / "dashboard.html"
MOUNT_PATH = "/security-auditor"
CONFIG_PATH = Path(__file__).resolve().parents[1] / "security-audit.yml"


def _auditor_role(user):
    """Map the existing Django authorization flags to auditor permissions."""
    if user.is_superuser or user.is_staff:
        return "admin"
    if getattr(user, "is_auditeur", False):
        return "analyst"
    return "viewer"


def _fastapi_app():
    from security_auditor.apps.api.server import build_app

    auditor = InternalSecurityAuditor(settings.BASE_DIR / ".security-audits")
    return build_app(
        auditor.store,
        config_path=str(CONFIG_PATH),
        workdir=str(auditor.workdir),
        base_path=MOUNT_PATH,
        project_root=str(settings.BASE_DIR),
    )


@login_required
def dashboard(request):
    if not FRONTEND.exists():
        return HttpResponse("Security Auditor dashboard missing", status=500)
    return render(request, "security_auditor/dashboard_global.html", {
        "api_base": MOUNT_PATH,
    })


@login_required
@csrf_exempt
def api_proxy(request, rest=""):
    """Forward dashboard API requests to the in-process auditor API."""
    from starlette.testclient import TestClient

    path = "/api/" + rest.lstrip("/")
    headers = {}
    for name in ("authorization", "content-type", "accept"):
        value = request.headers.get(name)
        if value:
            headers[name] = value
    # Never trust browser-supplied auditor credentials.  The Django session
    # is the single source of identity for this mounted application.
    headers.pop("authorization", None)
    headers["x-django-user"] = request.user.get_username()
    headers["x-django-role"] = _auditor_role(request.user)
    query = {key: values for key, values in request.GET.lists()}
    with TestClient(_fastapi_app()) as client:
        response = client.request(
            request.method,
            path,
            headers=headers,
            content=request.body,
            params=query,
        )
    return HttpResponse(
        response.content,
        status=response.status_code,
        content_type=response.headers.get("content-type", "application/json"),
    )

