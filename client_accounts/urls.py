from django.urls import path

from . import views

app_name = "client_accounts"
urlpatterns = [
    path("", views.manage, name="manage"),
    path("societe/<int:societe_id>/", views.configure, name="configure"),
]
