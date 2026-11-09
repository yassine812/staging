import re

from django import forms

from accounts.models import Section, User
from .countries import resolve_country


class ClientDetailsForm(forms.Form):
    first_name = forms.CharField(max_length=150)
    last_name = forms.CharField(max_length=150)
    email = forms.EmailField(max_length=254)
    pays = forms.CharField(max_length=100)
    section = forms.ModelChoiceField(queryset=Section.objects.all())

    def clean_email(self):
        email = self.cleaned_data["email"].lower()
        if User.objects.filter(email__iexact=email).exists():
            raise forms.ValidationError("Cette adresse e-mail est déjà utilisée.")
        return email

    def clean_pays(self):
        country = self.cleaned_data["pays"]
        profile = resolve_country(country)
        if profile is None:
            raise forms.ValidationError("Pays non reconnu. Saisissez son nom complet, par exemple Maroc ou Canada.")
        if not profile["timezone"]:
            raise forms.ValidationError("Ce territoire nécessite un fuseau horaire précisé par l’administrateur.")
        self.cleaned_data["country_code"] = "GR" if profile["iso"] == "DE" else profile["iso"]
        self.cleaned_data["timezone"] = profile["timezone"]
        return country

    def clean_section(self):
        section = self.cleaned_data["section"]
        match = re.match(r"^\s*([0-9]{1,20})([^0-9]|$)", section.Nom)
        if not match:
            raise forms.ValidationError("La section doit comporter un code numérique.")
        self.cleaned_data["section_code"] = match.group(1)
        return section
