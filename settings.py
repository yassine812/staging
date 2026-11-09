"""Paramètres Django du workspace audit2."""

from pathlib import Path
import os
from dotenv import load_dotenv

load_dotenv(Path(__file__).resolve().parent / ".env")

BASE_DIR = Path(__file__).resolve().parent

# Compatibility patch for Django template context copying on Python 3.14+
# refs: https://code.djangoproject.com/ticket/35844
import copy
from django.template import context

def _patched_copy(self):
    duplicate = context.BaseContext()
    duplicate.__class__ = self.__class__
    duplicate.__dict__ = copy.copy(self.__dict__)
    duplicate.dicts = self.dicts[:]
    return duplicate

context.BaseContext.__copy__ = _patched_copy

SECRET_KEY = os.getenv("DJANGO_SECRET_KEY", "dev-only-secret-key-change-me")
DEBUG = os.getenv("DJANGO_DEBUG", "1") == "1"
ALLOWED_HOSTS = [h.strip() for h in os.getenv("DJANGO_ALLOWED_HOSTS", "*").split(",") if h.strip()]

# ── Sage Web Services ────────────────────────────────────────────────────────
SAGE_API_TOKEN = os.getenv("SAGE_API_TOKEN", "")
SAGE_API_HOST  = os.getenv("SAGE_API_HOST", "http://185.17.241.250:52345")

INSTALLED_APPS = [
    "django.contrib.admin",
    "django.contrib.auth",
    "django.contrib.contenttypes",
    "django.contrib.sessions",
    "django.contrib.messages",
    "django.contrib.staticfiles",
    "accounts",
    "audit",
    "accident_travail",
    "achats",
    "gestion_documentaire",
    "audit_logs",
    "reclamation_client",
    # ── Plan de Prévention Simplifié ─────────────────────────────────────────
    "plan_prevention",
    # ── Gestion des Congés ───────────────────────────────────────────────────
    "conge",
    # ── Prospection commerciale ──────────────────────────────────────────────
    "prospection.apps.ProspectionConfig",
    "django_celery_beat",
    "rest_framework",
    "rest_framework.authtoken",
    "corsheaders",
    # ── Security Auditor intégré ───────────────────────────────────────────
    "security_auditor.web.apps.SecurityAuditorConfig",
]

MIDDLEWARE = [
    "django.middleware.security.SecurityMiddleware",
    "django.contrib.sessions.middleware.SessionMiddleware",
    "corsheaders.middleware.CorsMiddleware",
    "django.middleware.common.CommonMiddleware",
    "django.middleware.csrf.CsrfViewMiddleware",
    "django.contrib.auth.middleware.AuthenticationMiddleware",
    "audit_logs.middleware.CurrentUserMiddleware",
    "django.contrib.messages.middleware.MessageMiddleware",
    "django.middleware.clickjacking.XFrameOptionsMiddleware",
    "prospection.middleware.RedirectBackMiddleware",
]

X_FRAME_OPTIONS = "SAMEORIGIN"

ROOT_URLCONF = "urls"

TEMPLATES = [
    {
        "BACKEND": "django.template.backends.django.DjangoTemplates",
        "DIRS": [BASE_DIR / "templates", BASE_DIR / "audit" / "templates", BASE_DIR / "reclamation_client" / "templates", BASE_DIR / "plan_prevention" / "templates"],
        "APP_DIRS": True,
        "OPTIONS": {
            "context_processors": [
                "django.template.context_processors.debug",
                "django.template.context_processors.request",
                "django.contrib.auth.context_processors.auth",
                "django.contrib.messages.context_processors.messages",
                # ── Prospection ──────────────────────────────────────────────
                "prospection.context_processors.firebase_config",
                "prospection.context_processors.notifications",
            ],
        },
    },
]

WSGI_APPLICATION = "wsgi.application"
ASGI_APPLICATION = "asgi.application"

# PostgreSQL cible (stack demandée), avec fallback SQLite pour bootstrap local.
if os.getenv("POSTGRES_DB"):
    DATABASES = {
        "default": {
            "ENGINE": "django.db.backends.postgresql",
            "NAME": os.getenv("POSTGRES_DB"),
            "USER": os.getenv("POSTGRES_USER", "postgres"),
            "PASSWORD": os.getenv("POSTGRES_PASSWORD", ""),
            "HOST": os.getenv("POSTGRES_HOST", "localhost"),
            "PORT": os.getenv("POSTGRES_PORT", "5432"),
        }
    }
else:
    DATABASES = {
        "default": {
            "ENGINE": "django.db.backends.sqlite3",
            "NAME": BASE_DIR / "db.sqlite3",
        }
    }

AUTH_PASSWORD_VALIDATORS = [
    {"NAME": "django.contrib.auth.password_validation.UserAttributeSimilarityValidator"},
    {"NAME": "django.contrib.auth.password_validation.MinimumLengthValidator"},
    {"NAME": "django.contrib.auth.password_validation.CommonPasswordValidator"},
    {"NAME": "django.contrib.auth.password_validation.NumericPasswordValidator"},
]

LANGUAGE_CODE = "fr-fr"
TIME_ZONE = "Africa/Tunis"
USE_I18N = True
USE_TZ = True

STATIC_URL = "static/"
STATIC_ROOT = BASE_DIR / "staticfiles"
# Dossiers sources de fichiers statiques (en plus des static/ de chaque app)
STATICFILES_DIRS = [
    BASE_DIR / "assets",
]
MEDIA_URL = "/media/"
MEDIA_ROOT = BASE_DIR / "media"

DEFAULT_AUTO_FIELD = "django.db.models.BigAutoField"

AUTH_USER_MODEL = "accounts.User"

# ─── Authentification ─────────────────────────────────────────────────────────
# Page de connexion unifiée pour tout le système
LOGIN_URL = "/login/"
LOGIN_REDIRECT_URL = "/"

# Pages d'erreur personnalisées
handler403 = "audit.views.custom_403_view"
handler404 = "audit.views.custom_404_view"

# ─── Configuration email ──────────────────────────────────────────────────────
# En développement (EMAIL_HOST non défini) → les emails s'affichent dans la console.
# En production, définir les variables d'environnement ci-dessous.
if os.getenv("EMAIL_HOST"):
    EMAIL_BACKEND = "django.core.mail.backends.smtp.EmailBackend"
    EMAIL_HOST = os.getenv("EMAIL_HOST")
    EMAIL_PORT = int(os.getenv("EMAIL_PORT", "587"))
    EMAIL_USE_TLS = os.getenv("EMAIL_USE_TLS", "1") == "1"
    EMAIL_HOST_USER = os.getenv("EMAIL_HOST_USER", "")
    EMAIL_HOST_PASSWORD = os.getenv("EMAIL_HOST_PASSWORD", "")
    DEFAULT_FROM_EMAIL = os.getenv("DEFAULT_FROM_EMAIL", EMAIL_HOST_USER)
else:
    EMAIL_BACKEND = "django.core.mail.backends.console.EmailBackend"
    DEFAULT_FROM_EMAIL = "noreply@accidents-travail.local"

# ─── REST Framework ───────────────────────────────────────────────────────────
REST_FRAMEWORK = {
    "DEFAULT_AUTHENTICATION_CLASSES": [
        "rest_framework.authentication.TokenAuthentication",
        "rest_framework.authentication.SessionAuthentication",
    ],
}

# ─── CORS ─────────────────────────────────────────────────────────────────────
CORS_ALLOW_ALL_ORIGINS = True
CORS_ALLOWED_ORIGINS = [
    "http://localhost:19006",
    "http://localhost:8000",
]
CSRF_TRUSTED_ORIGINS = os.getenv(
    "CSRF_TRUSTED_ORIGINS",
    "http://localhost:8000,https://*.trycloudflare.com"
).split(",")
# ─── Session ─────────────────────────────────────────────────────────────────
SESSION_COOKIE_AGE = 2592000  # 30 jours
SESSION_EXPIRE_AT_BROWSER_CLOSE = False

# ─── IA générative : OpenAI (principal) + Gemini (repli) ────────────────────
OPENAI_API_KEY = os.getenv("OPENAI_API_KEY", "")
OPENAI_MODEL = os.getenv("OPENAI_MODEL", "gpt-4o-mini")
GEMINI_API_KEY = os.getenv("GEMINI_API_KEY", "")
GEMINI_MODEL = os.getenv("GEMINI_MODEL", "models/gemini-1.5-flash")

# ─── Firebase / FCM (notifications push mobiles) ─────────────────────────────
FCM_APIKEY = os.getenv("FCM_APIKEY", "")
FCM_DEVICE_MODEL = "prospection.models.FCMDevice"
FCM_AUTH_DOMAIN = os.getenv("FCM_AUTH_DOMAIN", "")
FCM_PROJECT_ID = os.getenv("FCM_PROJECT_ID", "")
FCM_STORAGE_BUCKET = os.getenv("FCM_STORAGE_BUCKET", "")
FCM_SENDER_ID = os.getenv("FCM_SENDER_ID", "")
FCM_APP_ID = os.getenv("FCM_APP_ID", "")
FCM_VAPID_KEY = os.getenv("FCM_VAPID_KEY", "")

# ─── Celery ───────────────────────────────────────────────────────────────────
CELERY_BROKER_URL = os.getenv("CELERY_BROKER_URL", "redis://localhost:6379/0")
CELERY_RESULT_BACKEND = os.getenv("CELERY_RESULT_BACKEND", "redis://localhost:6379/0")
CELERY_BEAT_SCHEDULER = "django_celery_beat.schedulers:DatabaseScheduler"
CELERY_TASK_SERIALIZER = "json"
CELERY_RESULT_SERIALIZER = "json"
CELERY_ACCEPT_CONTENT = ["json"]
CELERY_TIMEZONE = "Africa/Tunis"
