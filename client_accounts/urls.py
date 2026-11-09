from django.urls import path

from . import views

app_name = "client_accounts"
urlpatterns = [
    path("", views.manage, name="manage"),
    path("societe/<int:societe_id>/", views.configure, name="configure"),
    path("rs/<uuid:token>/", views.client_form, name="form"),
    path("rs/<uuid:token>/sections/", views.search_sections, name="sections"),
    path("rs/<uuid:token>/creer/", views.create_account, name="create"),
]
