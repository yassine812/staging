"""Formulaires du module gestion documentaire."""

import os

from django import forms
from django.forms import inlineformset_factory, modelformset_factory
from django.db import models

from .models import (
    Document,
    DossierDocumentaire,
    FichierBibliotheque,
    Indicateur,
    IndicateurQuotidien,
    Processus,
    RegleAccesDossier,
    VersionDocument,
)


class DossierDocumentaireForm(forms.ModelForm):
    ROLE_CHOICES = [
        ("is_CE", "CE"),
        ("is_RS", "RS"),
        ("is_RO", "RO"),
        ("is_assistante", "Assistante"),
        ("is_auditeur", "Auditeur"),
    ]
    roles_autorises = forms.MultipleChoiceField(
        choices=ROLE_CHOICES, required=False, widget=forms.CheckboxSelectMultiple
    )
    ACTION_CHOICES = [
        ("lire", "Lire"),
        ("modifier", "Modifier"),
        ("telecharger", "Télécharger"),
    ]
    actions_autorisees = forms.MultipleChoiceField(
        choices=ACTION_CHOICES,
        required=False,
        initial=["lire"],
        widget=forms.CheckboxSelectMultiple,
    )

    class Meta:
        model = DossierDocumentaire
        fields = [
            "nom", "description", "couleur", "acces_restreint", "roles_autorises",
            "actions_autorisees",
            "societes_autorisees", "sections_autorisees", "utilisateurs_autorises",
        ]
        widgets = {
            "couleur": forms.TextInput(attrs={"type": "color"}),
            "utilisateurs_autorises": forms.SelectMultiple(attrs={"size": 6}),
            "societes_autorisees": forms.SelectMultiple(attrs={"size": 5}),
            "sections_autorisees": forms.SelectMultiple(attrs={"size": 6}),
        }

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        placeholders = {
            "nom": "Ex. Procédures qualité",
            "description": "Décrivez brièvement le contenu et l’usage de ce dossier",
            "societes_autorisees": "Rechercher une société…",
            "sections_autorisees": "Rechercher une section…",
            "utilisateurs_autorises": "Rechercher un utilisateur…",
        }
        for name, field in self.fields.items():
            if name == "roles_autorises":
                field.widget.attrs["class"] = "access-role-list"
            elif name == "actions_autorisees":
                field.widget.attrs["class"] = "access-action-list"
            elif name == "acces_restreint":
                field.widget.attrs["class"] = "access-toggle"
            elif name == "couleur":
                field.widget.attrs["class"] = "folder-color-input"
            else:
                field.widget.attrs.setdefault("class", "form-control")
            if name in placeholders:
                field.widget.attrs.setdefault("placeholder", placeholders[name])
                field.widget.attrs.setdefault("data-placeholder", placeholders[name])

    def clean(self):
        cleaned = super().clean()
        if cleaned.get("acces_restreint") and not any([
            cleaned.get("roles_autorises"),
            cleaned.get("societes_autorisees"),
            cleaned.get("sections_autorisees"),
            cleaned.get("utilisateurs_autorises"),
        ]):
            raise forms.ValidationError(
                "Choisissez au moins un rôle, une société, une section ou un utilisateur."
            )
        if cleaned.get("acces_restreint") and not cleaned.get("actions_autorisees"):
            raise forms.ValidationError("Choisissez au moins une action autorisée.")
        return cleaned


class DossierParametresForm(forms.ModelForm):
    class Meta:
        model = DossierDocumentaire
        fields = ["nom", "description", "couleur", "acces_restreint"]
        widgets = {"couleur": forms.TextInput(attrs={"type": "color"})}

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.fields["nom"].widget.attrs.update({"class": "form-control", "placeholder": "Ex. Procédures qualité"})
        self.fields["description"].widget.attrs.update({
            "class": "form-control",
            "placeholder": "Décrivez brièvement le contenu de ce dossier",
        })
        self.fields["couleur"].widget.attrs["class"] = "folder-color-input"
        self.fields["acces_restreint"].widget.attrs["class"] = "access-toggle"


class RegleAccesDossierForm(forms.ModelForm):
    ACTION_CHOICES = list(RegleAccesDossier.Action.choices)
    actions_autorisees = forms.MultipleChoiceField(
        choices=ACTION_CHOICES,
        required=True,
        widget=forms.CheckboxSelectMultiple,
    )
    roles_autorises = forms.MultipleChoiceField(
        choices=DossierDocumentaireForm.ROLE_CHOICES,
        required=False,
        widget=forms.CheckboxSelectMultiple,
    )

    class Meta:
        model = RegleAccesDossier
        fields = [
            "actions_autorisees", "roles_autorises", "societes_autorisees",
            "sections_autorisees", "utilisateurs_autorises",
        ]

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        for name in ("societes_autorisees", "sections_autorisees", "utilisateurs_autorises"):
            self.fields[name].widget.attrs.update({"class": "form-control", "size": 5})

    def clean(self):
        cleaned = super().clean()
        if cleaned.get("DELETE"):
            return cleaned
        if self.has_changed() and not any([
            cleaned.get("roles_autorises"),
            cleaned.get("societes_autorisees"),
            cleaned.get("sections_autorisees"),
            cleaned.get("utilisateurs_autorises"),
        ]):
            raise forms.ValidationError(
                "Sélectionnez au moins un rôle, une société, une section ou un utilisateur."
            )
        return cleaned


RegleAccesDossierFormSet = inlineformset_factory(
    DossierDocumentaire,
    RegleAccesDossier,
    form=RegleAccesDossierForm,
    extra=1,
    can_delete=True,
)

NouvelleRegleAccesFormSet = modelformset_factory(
    RegleAccesDossier,
    form=RegleAccesDossierForm,
    extra=1,
    can_delete=True,
)


class FichierBibliothequeForm(forms.ModelForm):
    EXTENSIONS_AUTORISEES = {".doc", ".docx", ".docs", ".xls", ".xlsx", ".pdf"}

    class Meta:
        model = FichierBibliotheque
        fields = ["fichier"]

    def clean_fichier(self):
        fichier = self.cleaned_data["fichier"]
        extension = os.path.splitext(fichier.name)[1].lower()
        if extension not in self.EXTENSIONS_AUTORISEES:
            raise forms.ValidationError(
                "Format interdit. Formats acceptés : DOC, DOCX, DOCS, XLS, XLSX et PDF."
            )
        return fichier


class DocumentFilterForm(forms.Form):
    """Filtres GET pour la liste documentaire."""

    q = forms.CharField(required=False, label="Recherche")
    type_document = forms.ChoiceField(required=False, label="Type")
    processus = forms.ModelChoiceField(
        queryset=Processus.objects.filter(is_active=True).order_by("code"),
        required=False,
        label="Processus",
    )
    statut = forms.ChoiceField(required=False, label="Statut")

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.fields["type_document"].choices = [("", "Tous")] + list(Document.TypeDocument.choices)
        self.fields["statut"].choices = [("", "Tous")] + list(Document.Statut.choices)
        self.fields["type_document"].widget.attrs["placeholder"] = "Filtrer par type"
        self.fields["processus"].widget.attrs["placeholder"] = "Filtrer par processus"
        self.fields["statut"].widget.attrs["placeholder"] = "Filtrer par statut"

        placeholder_map = {
            "q": "Rechercher par code ou titre",
        }
        for field_name, field in self.fields.items():
            if field_name in placeholder_map:
                field.widget.attrs["placeholder"] = placeholder_map[field_name]
            field.widget.attrs.setdefault("class", "form-control")


class DocumentForm(forms.ModelForm):
    """Formulaire de création/édition d'un document QSE."""

    class Meta:
        model = Document
        fields = [
            "type_document",
            "dossier",
            "processus",
            "numero_ordre",
            "titre",
            "objet",
            "domaine_application",
            "definitions",
            "responsabilites",
            "regles_etapes",
            "modalites_diffusion",
            "modalites_modification",
            "modalites_archivage",
            "poste_service_activite",
            "prerequis",
            "equipements_outils_logiciels",
            "etapes_detaillees",
            "points_controle",
            "criteres_acceptation",
            "consignes_securite",
            "enregistrements_a_completer",
            "anomalies_actions",
            "reference_documentaire",
            "schema_collecte",
            "service_concerne",
            "visas_validations",
            "lien_externe",
            "motif_remplacement",
        ]

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        textarea_fields = {
            "objet",
            "domaine_application",
            "definitions",
            "responsabilites",
            "regles_etapes",
            "modalites_diffusion",
            "modalites_modification",
            "modalites_archivage",
            "poste_service_activite",
            "prerequis",
            "equipements_outils_logiciels",
            "etapes_detaillees",
            "points_controle",
            "criteres_acceptation",
            "consignes_securite",
            "enregistrements_a_completer",
            "anomalies_actions",
            "visas_validations",
            "motif_remplacement",
        }
        for field_name, field in self.fields.items():
            if field_name in textarea_fields:
                field.widget = forms.Textarea(attrs={"rows": 3, "class": "form-control"})
            else:
                field.widget.attrs.setdefault("class", "form-control")

        placeholder_map = {
            "numero_ordre": "Ex: 1",
            "titre": "Titre du document",
            "objet": "Objet du document",
            "domaine_application": "Périmètre d'application",
            "definitions": "Définitions clés",
            "responsabilites": "Rôles et responsabilités",
            "regles_etapes": "Règles et étapes à appliquer",
            "modalites_diffusion": "Comment diffuser ce document",
            "modalites_modification": "Comment initier une modification",
            "modalites_archivage": "Règles d'archivage",
            "poste_service_activite": "Poste, service ou activité concerné",
            "prerequis": "Prérequis nécessaires",
            "equipements_outils_logiciels": "Liste des équipements/outils/logiciels",
            "etapes_detaillees": "Étapes détaillées de réalisation",
            "points_controle": "Points de contrôle",
            "criteres_acceptation": "Critères d'acceptation",
            "consignes_securite": "Consignes sécurité",
            "enregistrements_a_completer": "Enregistrements à compléter",
            "anomalies_actions": "Anomalies possibles et actions correctives",
            "reference_documentaire": "Référence documentaire interne",
            "schema_collecte": '{"champs": []}',
            "service_concerne": "Personne ou service concerné",
            "visas_validations": "Visas et validations requises",
            "lien_externe": "https://...",
            "motif_remplacement": "Motif de remplacement / retrait",
        }
        for field_name, placeholder in placeholder_map.items():
            if field_name in self.fields:
                self.fields[field_name].widget.attrs.setdefault("placeholder", placeholder)


class VersionDocumentForm(forms.ModelForm):
    """Formulaire de création d'une nouvelle version documentaire."""

    class TypeIncrement(models.TextChoices):
        MAJEUR = "majeur", "Version majeure"
        MINEUR = "mineur", "Indice mineur"

    type_increment = forms.ChoiceField(
        choices=TypeIncrement.choices,
        initial=TypeIncrement.MINEUR,
        label="Type de révision",
    )

    class Meta:
        model = VersionDocument
        fields = [
            "fichier_reference",
            "fichier_editable",
            "resume_changements",
            "type_increment",
        ]

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.fields["resume_changements"].widget = forms.Textarea(
            attrs={"rows": 4, "class": "form-control", "placeholder": "Décrire les changements apportés"}
        )
        self.fields["fichier_reference"].widget.attrs.update({"class": "form-control-file"})
        self.fields["fichier_editable"].widget.attrs.update({"class": "form-control-file"})
        self.fields["type_increment"].widget.attrs.setdefault("class", "form-control")
        self.fields["fichier_reference"].widget.attrs.setdefault("placeholder", "Sélectionner le PDF de référence")
        self.fields["fichier_editable"].widget.attrs.setdefault("placeholder", "Sélectionner le fichier modifiable")

    def clean(self):
        cleaned_data = super().clean()
        if not cleaned_data.get("fichier_reference") and not cleaned_data.get("fichier_editable"):
            raise forms.ValidationError("Ajoutez au moins un fichier à cette version.")
        reference = cleaned_data.get("fichier_reference")
        if reference and not reference.name.lower().endswith(".pdf"):
            self.add_error("fichier_reference", "Le fichier de référence doit être au format PDF.")
        return cleaned_data
class ProcessusForm(forms.ModelForm):
    """Formulaire de création/modification d'un processus SMQS."""

    class Meta:
        model = Processus
        fields = ["code", "nom", "description", "societe", "RO", "RS", "CE", "is_active"]
        widgets = {
            "code": forms.TextInput(attrs={"class": "form-control", "placeholder": "Ex : CE (auto si vide)"}),
            "nom": forms.TextInput(attrs={"class": "form-control", "placeholder": "Nom du processus"}),
            "description": forms.Textarea(attrs={"class": "form-control", "rows": 3, "placeholder": "Description (optionnelle)"}),
            "societe": forms.Select(attrs={"class": "form-control"}),
            "RO": forms.SelectMultiple(attrs={"class": "form-control", "size": "5"}),
            "RS": forms.SelectMultiple(attrs={"class": "form-control", "size": "5"}),
            "CE": forms.SelectMultiple(attrs={"class": "form-control", "size": "5"}),
            "is_active": forms.CheckboxInput(attrs={"class": "form-check-input"}),
        }
        labels = {
            "code": "Code processus",
            "nom": "Nom du processus",
            "description": "Description",
            "societe": "Société",
            "RO": "Responsables Opérationnels (RO)",
            "RS": "Responsables Système (RS)",
            "CE": "Correspondants Établissement (CE)",
            "is_active": "Processus actif",
        }

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.fields["code"].required = False

    def clean(self):
        cleaned_data = super().clean()
        code = cleaned_data.get("code")
        nom = cleaned_data.get("nom")
        if not code and nom:
            from .views import generer_code_processus_depuis_nom
            generated = generer_code_processus_depuis_nom(nom)
            cleaned_data["code"] = generated
            self.cleaned_data["code"] = generated
            if "code" in self._errors:
                del self._errors["code"]
        return cleaned_data



class IndicateurForm(forms.ModelForm):
    """Formulaire de création/modification d'un indicateur SMQS."""

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.fields["code"].required = False
        self.fields["sens_objectif"].required = False
        self.fields["mode_calcul"].required = False
        if not self.instance.pk and not self.initial.get("sens_objectif"):
            self.initial["sens_objectif"] = Indicateur.SensObjectif.ATTEINDRE
        if not self.instance.pk and not self.initial.get("mode_calcul"):
            self.initial["mode_calcul"] = Indicateur.ModeCalcul.AUTOMATIQUE

    def clean_sens_objectif(self):
        val = self.cleaned_data.get("sens_objectif")
        if not val:
            return Indicateur.SensObjectif.ATTEINDRE
        return val

    class Meta:
        model = Indicateur
        fields = ["processus", "code", "nom", "periodicite", "mode_agregation", "sens_objectif", "mode_calcul", "formule", "is_active"]
        widgets = {
            "processus": forms.Select(attrs={"class": "form-control"}),
            "code": forms.TextInput(attrs={"class": "form-control", "placeholder": "Ex : IND-01 (auto si vide)"}),
            "nom": forms.TextInput(attrs={"class": "form-control", "placeholder": "Nom de l'indicateur"}),
            "periodicite": forms.Select(attrs={"class": "form-control"}),
            "mode_agregation": forms.Select(attrs={"class": "form-control"}),
            "sens_objectif": forms.Select(attrs={"class": "form-control"}),
            "mode_calcul": forms.Select(attrs={"class": "form-control"}),
            "formule": forms.TextInput(attrs={"class": "form-control font-monospace", "placeholder": "Ex : (accidents * 1000000) / heures"}),
            "is_active": forms.CheckboxInput(attrs={"class": "form-check-input"}),
        }

    def clean_mode_calcul(self):
        val = self.cleaned_data.get("mode_calcul")
        if not val:
            return Indicateur.ModeCalcul.AUTOMATIQUE
        return val


class IndicateurQuotidienForm(forms.ModelForm):
    class Meta:
        model = IndicateurQuotidien
        fields = ["code", "nom", "description", "unite", "is_active"]
        help_texts = {
            "unite": "Remplacez % par l’unité de la valeur saisie, par exemple h, pièces ou dossiers.",
        }
        widgets = {
            "code": forms.TextInput(attrs={"class": "form-control", "placeholder": "Ex : ADH-01"}),
            "nom": forms.TextInput(attrs={"class": "form-control", "placeholder": "Ex : Taux d'adhérence"}),
            "description": forms.Textarea(attrs={"class": "form-control", "rows": 3}),
            "unite": forms.TextInput(attrs={
                "class": "form-control",
                "placeholder": "%, h, pièces…",
                "aria-describedby": "daily-indicator-unit-help",
            }),
            "is_active": forms.CheckboxInput(attrs={"class": "form-check-input"}),
        }


