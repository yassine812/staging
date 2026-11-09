import re

from django import forms

from accounts.models import Section, User


COUNTRIES = [
    (("france",), "FR", "Europe/Paris"),
    (("allemagne", "germany", "deutschland"), "GR", "Europe/Berlin"),
    (("pologne", "poland", "polska"), "PL", "Europe/Warsaw"),
    (("tunisie", "tunisia"), "TN", "Africa/Tunis"),
]


class ClientDetailsForm(forms.Form):
    first_name = forms.CharField(max_length=150)
    last_name = forms.CharField(max_length=150)
    email = forms.EmailField(max_length=254)
    pays = forms.CharField(max_length=100)
    section = forms.ModelChoiceField(queryset=Section.objects.none())

    def __init__(self, societe, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.fields["section"].queryset = Section.objects.filter(societe=societe)

    def clean_email(self):
        email = self.cleaned_data["email"].lower()
        if User.objects.filter(email__iexact=email).exists():
            raise forms.ValidationError("Cette adresse e-mail est déjà utilisée.")
        return email

    def clean_pays(self):
        country = self.cleaned_data["pays"]
        for names, code, timezone in COUNTRIES:
            if country.lower() in names:
                self.cleaned_data["country_code"] = code
                self.cleaned_data["timezone"] = timezone
                return country
        raise forms.ValidationError("Pays non configuré. Contactez votre administrateur.")

    def clean_section(self):
        section = self.cleaned_data["section"]
        match = re.match(r"^\s*([0-9]{1,20})([^0-9]|$)", section.Nom)
        if not match:
            raise forms.ValidationError("La section doit comporter un code numérique.")
        self.cleaned_data["section_code"] = match.group(1)
        return section
