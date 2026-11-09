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
    module = ClientAccountModule.objects.filter(is_shared=True).first()
    link = ""
    if module and module.enabled:
        link = request.build_absolute_uri(reverse("client_accounts_public:form", args=[module.token]))
    return render(request, "client_accounts/manage.html", {"link": link})


@login_required
@require_POST
def configure(request):
    _require_admin(request.user)
    action = request.POST.get("action")
    if action not in ("activate", "deactivate"):
        return JsonResponse({"error": "Action invalide."}, status=400)
    with transaction.atomic():
        module, _ = ClientAccountModule.objects.get_or_create(is_shared=True)
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
        ClientAccountModule.objects,
        token=token,
        enabled=True,
        is_shared=True,
    )


@require_GET
@never_cache
def client_form(request, token):
    module = _active_module(token)
    response = render(request, "essai-comptes-clients.html", {
        "section_search_url": reverse("client_accounts_public:sections", args=[module.token]),
        "create_account_url": reverse("client_accounts_public:create", args=[module.token]),
    })
    response["Referrer-Policy"] = "no-referrer"
    return response


@require_GET
@never_cache
def search_sections(request, token):
    _active_module(token)
    code = request.GET.get("code", "").strip()
    if not re.fullmatch(r"[0-9]{1,20}", code):
        return JsonResponse({"error": "Saisissez un code de section numérique."}, status=400)
    sections = Section.objects.filter(
        Nom__regex=rf"^\s*{code}([^0-9]|$)"
    ).select_related("societe").order_by("Nom", "pk")
    return JsonResponse({"sections": [
        {"id": str(section.pk), "code": code,
         "label": f"{section.Nom} — {section.societe.nom}" if section.societe_id else section.Nom}
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
            form = ClientDetailsForm(request.POST)
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
