"""URL configuration principale du projet audit2 (reloaded)."""

from django.contrib import admin
from django.urls import include, path
from django.conf import settings
from django.conf.urls.static import static
from django.contrib.staticfiles.views import serve
from core_views import login_view, logout_view, home_view, profile_view, update_profile, change_password

urlpatterns = [
    # ── Racine ───────────────────────────────────────────────────────────────
    path("", home_view, name="home"),
    path("login/", login_view, name="login"),
    path("logout/", logout_view, name="logout"),
    path("profile/", profile_view, name="profile"),
    path("profile/update/", update_profile, name="update_profile"),
    path("profile/change-password/", change_password, name="change_password"),
    # ── Admin Django ─────────────────────────────────────────────────────────
    path("admin/", admin.site.urls),
    # ── Modules métier ───────────────────────────────────────────────────────
    path("audit/", include(("audit.urls", "audit"), namespace="audit")),
    path("accidents/", include(("accident_travail.urls", "at"), namespace="at")),
    path("reclamations/", include(("reclamation_client.urls", "reclamation"), namespace="reclamation")),
    path("achats/", include(("achats.urls", "achats"), namespace="achats")),
    path("gestion-documentaire/", include(("gestion_documentaire.urls", "gestion_documentaire"), namespace="gestion_documentaire")),
    # ── Gestion des Congés ───────────────────────────────────────────────────
    path("conges/", include(("conge.urls", "conge"), namespace="conge")),
    # ── Plan de Prévention Simplifié ─────────────────────────────────────────
    path("plan-prevention/", include(("plan_prevention.urls", "plan_prevention"), namespace="plan_prevention")),
    # ── Administration (comptes, utilisateurs, sections…) ────────────────────
    path("administration/", include(("accounts.urls", "administration"), namespace="administration")),
    # ── Prospection Commerciale ──────────────────────────────────────────────
    path("prospection/", include(("prospection.urls", "prospection"), namespace="prospection")),
    # ── Logs d'Audit Centralisés ─────────────────────────────────────────────
    path("audit-logs/", include(("audit_logs.urls", "audit_logs"), namespace="audit_logs")),
    # ── Security Auditor intégré ───────────────────────────────────────────
    path("security-auditor/", include(("security_auditor.web.urls", "security_auditor"), namespace="security_auditor")),
    # Service Worker Firebase (doit être servi depuis la racine)
    path("firebase-messaging-sw.js", serve, {"path": "js/firebase-messaging-sw.js"}),
]

if settings.DEBUG:
    urlpatterns += static(settings.MEDIA_URL, document_root=settings.MEDIA_ROOT)
    urlpatterns += static(settings.STATIC_URL, document_root=settings.STATIC_ROOT)

