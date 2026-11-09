from django.urls import path

from . import views

app_name = "client_accounts_public"
urlpatterns = [
    path("<uuid:token>/", views.client_form, name="form"),
    path("<uuid:token>/sections/", views.search_sections, name="sections"),
    path("<uuid:token>/creer/", views.create_account, name="create"),
]
