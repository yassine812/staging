from django.urls import include, path

# This host deliberately exposes no login, admin, profile or business routes.
urlpatterns = [path("creer-compte/", include("client_accounts.public_urls"))]
