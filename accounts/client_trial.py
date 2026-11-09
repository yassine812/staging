"""Formulaire client et recherche des sections de la base courante."""

import re

from django.contrib.auth.decorators import login_required
from django.core.exceptions import PermissionDenied
from django.http import JsonResponse
from django.shortcuts import render
from django.views.decorators.cache import never_cache
from django.views.decorators.http import require_GET

from .models import Section


def _can_use_form(user):
    return user.is_authenticated and user.is_active and (user.is_superuser or user.is_RS)


@login_required
@require_GET
@never_cache
def client_form(request):
    if not _can_use_form(request.user):
        raise PermissionDenied
    return render(request, "essai-comptes-clients.html")


@require_GET
@never_cache
def search_sections(request):
    if not request.user.is_authenticated:
        return JsonResponse({"error": "Reconnectez-vous pour rechercher les sections."}, status=401)
    if not _can_use_form(request.user):
        return JsonResponse({"error": "Accès réservé aux RS et administrateurs."}, status=403)

    code = request.GET.get("code", "").strip()
    if not re.fullmatch(r"[0-9]{1,20}", code):
        return JsonResponse({"error": "Saisissez un code de section numérique."}, status=400)

    sections = Section.objects.filter(
        Nom__regex=rf"^\s*{code}([^0-9]|$)"
    ).select_related("societe").order_by("Nom", "pk")
    return JsonResponse({"sections": [
        {
            "id": str(section.pk),
            "code": code,
            "label": f"{section.Nom} — {section.societe.nom}" if section.societe else section.Nom,
        }
        for section in sections
    ]})
