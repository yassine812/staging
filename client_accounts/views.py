import re
import uuid

from django.contrib.auth.decorators import login_required
from django.contrib.auth.models import Group
from django.core.exceptions import PermissionDenied, ValidationError
from django.db import IntegrityError, transaction
from django.http import JsonResponse
from django.shortcuts import get_object_or_404, redirect, render
from django.urls import reverse
from django.views.decorators.cache import never_cache
from django.views.decorators.http import require_GET, require_POST

from accounts.models import Section, Societe
from .models import ClientAccountModule
from .forms import ClientDetailsForm
from .creation import save_client


def _require_admin(user):
    if not user.is_active or not user.is_superuser:
        raise PermissionDenied


@login_required
@require_GET
@never_cache
def manage(request):
    _require_admin(request.user)
    modules = {
        module.societe_id: module
        for module in ClientAccountModule.objects.filter(admin=request.user)
    }
    rows = []
    for societe in Societe.objects.exclude(nom__iexact="Client"):
        module = modules.get(societe.pk)
        link = ""
        if module and module.enabled:
            link = request.build_absolute_uri(reverse("client_accounts:form", args=[module.token]))
        rows.append({"societe": societe, "link": link})
    return render(request, "client_accounts/manage.html", {"rows": rows})


@login_required
@require_POST
def configure(request, societe_id):
    _require_admin(request.user)
    societe = get_object_or_404(Societe.objects.exclude(nom__iexact="Client"), pk=societe_id)
    action = request.POST.get("action")
    if action not in ("activate", "deactivate"):
        return JsonResponse({"error": "Action invalide."}, status=400)
    with transaction.atomic():
        module, _ = ClientAccountModule.objects.get_or_create(admin=request.user, societe=societe)
        module = ClientAccountModule.objects.select_for_update().get(pk=module.pk)
        enabled = action == "activate"
        if enabled:
            Societe.objects.get_or_create(nom="Client")
            Group.objects.get_or_create(name="CLT")
        if module.enabled != enabled:
            module.enabled = enabled
            module.token = uuid.uuid4()
            module.save(update_fields=["enabled", "token"])
    return redirect("client_accounts:manage")


def _active_module(token):
    # The unguessable, revocable link grants access only to this module's form.
    # Never authenticate its visitor as the module owner or a generated account.
    return get_object_or_404(
        ClientAccountModule.objects.select_related("societe", "admin").exclude(societe__nom__iexact="Client"),
        token=token,
        enabled=True,
        admin__is_active=True,
        admin__is_superuser=True,
    )


@require_GET
@never_cache
def client_form(request, token):
    module = _active_module(token)
    response = render(request, "essai-comptes-clients.html", {
        "societe": module.societe,
        "section_search_url": reverse("client_accounts:sections", args=[module.token]),
        "create_account_url": reverse("client_accounts:create", args=[module.token]),
    })
    response["Referrer-Policy"] = "no-referrer"
    return response


@require_GET
@never_cache
def search_sections(request, token):
    module = _active_module(token)
    code = request.GET.get("code", "").strip()
    if not re.fullmatch(r"[0-9]{1,20}", code):
        return JsonResponse({"error": "Saisissez un code de section numérique."}, status=400)
    sections = Section.objects.filter(
        societe=module.societe, Nom__regex=rf"^\s*{code}([^0-9]|$)"
    ).order_by("Nom", "pk")
    return JsonResponse({"sections": [
        {"id": str(section.pk), "code": code, "label": section.Nom}
        for section in sections
    ]})


@require_POST
@never_cache
def create_account(request, token):
    try:
        with transaction.atomic():
            module = _active_module(token)
            module = get_object_or_404(
                ClientAccountModule.objects.select_for_update(), pk=module.pk, token=token, enabled=True,
            )
            # Serialize module creations across companies before checking email and identifiers.
            client_societe = Societe.objects.select_for_update().get(nom="Client")
            group = Group.objects.get(name="CLT")
            form = ClientDetailsForm(module.societe, request.POST)
            if not form.is_valid():
                return JsonResponse({"errors": form.errors.get_json_data()}, status=400)
            actor = request.user if request.user.is_authenticated else None
            account = save_client(module, actor, form.cleaned_data, client_societe, group)
            return JsonResponse({
                "username": account.user.username,
                "matricule": account.matricule,
                "section": form.cleaned_data["section"].Nom,
                "timezone": account.user.timezone,
            }, status=201)
    except (Societe.DoesNotExist, Group.DoesNotExist):
        return JsonResponse({"error": "L’administrateur doit réactiver le module pour rétablir sa configuration."}, status=409)
    except ValidationError as error:
        return JsonResponse({"error": " ".join(error.messages)}, status=400)
    except IntegrityError:
        return JsonResponse({"error": "Une création concurrente a utilisé ces informations. Vérifiez l’e-mail puis réessayez."}, status=409)
