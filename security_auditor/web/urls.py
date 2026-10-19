from django.urls import path

from .views import api_proxy, dashboard

app_name = "security_auditor"

urlpatterns = [
    path("", dashboard, name="dashboard"),
    path("api/", api_proxy, name="api-root"),
    path("api/<path:rest>", api_proxy, name="api"),
    path("audits/<path:rest>", dashboard, name="dashboard-route"),
]

