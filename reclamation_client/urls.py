"""Routes du module Réclamation Client."""

from django.urls import path
from . import views

app_name = "reclamation"

urlpatterns = [
    path("", views.ReclamationDashboardView.as_view(), name="dashboard"),
    path("liste/", views.ReclamationListView.as_view(), name="liste"),
    path("nouveau/", views.ReclamationCreateView.as_view(), name="create"),
    path("<int:pk>/", views.ReclamationDetailView.as_view(), name="detail"),
    path("<int:pk>/modifier-entete/", views.reclamation_edit_header, name="edit_header"),
    path("<int:pk>/editer-8d/", views.reclamation_update_8d, name="update_8d"),
    path("<int:pk>/editer-doc05/", views.reclamation_update_doc05, name="update_doc05"),
    path("<int:pk>/api/d4-arbre/<str:axe>/", views.reclamation_d4_arbre_api, name="d4_arbre_api"),
    path("<int:pk>/autosave/", views.autosave_reclamation_8d, name="autosave"),
    path("api/chart-evolution/", views.api_evolution_chart_data, name="api_evolution_chart"),
    path("<int:pk>/export-pdf-8d/", views.reclamation_export_pdf_8d, name="export_pdf_8d"),
    path("<int:pk>/export-pdf-doc05/", views.reclamation_export_pdf_doc05, name="export_pdf_doc05"),
    path("<int:pk>/changer-support/", views.reclamation_changer_support, name="changer_support"),
]
