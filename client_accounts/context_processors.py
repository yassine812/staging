from django.conf import settings


def module_visibility(request):
    return {"client_accounts_enabled": settings.CLIENT_ACCOUNTS_ENABLED}
