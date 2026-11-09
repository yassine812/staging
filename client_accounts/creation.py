import re
import secrets

from django.core.exceptions import ValidationError

from accounts.forms import UserCreateForm
from accounts.models import User
from .models import CreatedClientAccount


def available_username(first_name, last_name):
    base = User.normalize_username(first_name[0].upper() + last_name)
    base = re.sub(r"[^\w.@+-]", "", base)[:150]
    if not base:
        raise ValidationError("Le prénom et le nom doivent permettre de former un username.")
    username = base
    suffix = 0
    while User.objects.filter(username__iexact=username).exists():
        suffix += 1
        number = str(suffix)
        username = base[:150 - len(number)] + number
    return username


def available_matricule(section_code, country_code):
    prefix = f"CLT{section_code}{country_code}"
    start = secrets.randbelow(10000)
    for offset in range(10000):
        matricule = f"{prefix}{(start + offset) % 10000:04d}"
        if not CreatedClientAccount.objects.filter(matricule=matricule).exists():
            return matricule
    raise ValidationError("Tous les matricules sont utilisés pour cette section et ce pays.")


def save_client(module, actor, details, client_societe, group):
    """Called inside the transaction holding the module and Client company locks."""
    username = available_username(details["first_name"], details["last_name"])
    matricule = available_matricule(details["section_code"], details["country_code"])
    password = secrets.token_urlsafe(24)
    form = UserCreateForm({
        "username": username,
        "first_name": details["first_name"],
        "last_name": details["last_name"],
        "email": details["email"],
        "pays": details["pays"],
        "section": details["section"].pk,
        "societe": client_societe.pk,
        "timezone": details["timezone"],
        "password1": password,
        "password2": password,
        "is_active": True,
        "is_CLT": True,
    })
    if not form.is_valid():
        raise ValidationError([message for errors in form.errors.values() for message in errors])
    user = form.save()
    user.groups.add(group)
    return CreatedClientAccount.objects.create(
        user=user, module=module, created_by=actor, matricule=matricule,
    )
