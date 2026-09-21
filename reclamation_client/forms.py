"""Formulaires du module Réclamation Client."""

from django import forms
from django.forms import inlineformset_factory

from accident_travail.models import ActionCorrective
from .models import (
    ReclamationClient,
    Participant8D,
    DescriptionQQOQCCP,
    MesureConservatoireD3,
    AnalyseCausesDoubleAxeD4,
    ActionTestD5,
    ActionPermanenteD6,
    CapitalisationSMQSD7,
    DocumentSMQSD7,
    ClotureRecevabiliteD8,
    FicheIncidentDoc05,
)


class DateInput(forms.DateInput):
    input_type = "date"

    def __init__(self, *args, **kwargs):
        kwargs.setdefault("format", "%Y-%m-%d")
        super().__init__(*args, **kwargs)


class ReclamationQuickCreateForm(forms.ModelForm):
    """Formulaire de saisie rapide / accusé de réception initial (P05)."""

    class Meta:
        model = ReclamationClient
        fields = [
            "type_signalement", "mode_traitement", "societe", "site",
            "client_nom", "contact_client", "description_piece", "reference_piece",
            "quantite_impactee", "date_alerte_client", "accuse_reception_envoye",
        ]
        widgets = {
            "date_alerte_client": DateInput(attrs={"class": "form-control"}),
            "type_signalement": forms.Select(attrs={"class": "form-control", "id": "id_type_signalement"}),
            "mode_traitement": forms.Select(attrs={
                "class": "form-control text-dark font-weight-bold",
                "id": "id_mode_traitement",
                "disabled": "disabled",
                "style": "background-color: #e9ecef; cursor: not-allowed;",
            }),
            "societe": forms.Select(attrs={"class": "form-control"}),
            "site": forms.Select(attrs={"class": "form-control"}),
            "client_nom": forms.TextInput(attrs={"class": "form-control", "placeholder": "Nom du client"}),
            "contact_client": forms.TextInput(attrs={"class": "form-control", "placeholder": "Contact chez le client"}),
            "description_piece": forms.TextInput(attrs={"class": "form-control", "placeholder": "Nom / Description de la pièce"}),
            "reference_piece": forms.TextInput(attrs={"class": "form-control", "placeholder": "Réf. pièce"}),
            "quantite_impactee": forms.NumberInput(attrs={"class": "form-control", "min": 0}),
            "accuse_reception_envoye": forms.CheckboxInput(attrs={"class": "form-check-input"}),
        }

    def __init__(self, *args, **kwargs):
        self.is_admin = kwargs.pop("is_admin", False)
        self.editing_header = kwargs.pop("editing_header", False)
        super().__init__(*args, **kwargs)
        if self.editing_header:
            # A header edit must not alter the signalement classification or its workflow.
            self.fields.pop("type_signalement", None)
            self.fields.pop("mode_traitement", None)
        else:
            self.fields["mode_traitement"].required = False
            self.fields["mode_traitement"].disabled = False
            self.fields["mode_traitement"].choices = [
                (ReclamationClient.MODE_8D, "Rapport 8D"),
                (ReclamationClient.MODE_DOC05, "Fiche d'incident (Doc 05)"),
            ]
            if self.is_admin:
                self.fields["mode_traitement"].widget.attrs.pop("disabled", None)
                self.fields["mode_traitement"].widget.attrs.pop("style", None)
            else:
                self.fields["mode_traitement"].widget.attrs["disabled"] = "disabled"
                self.fields["mode_traitement"].widget.attrs["style"] = "background-color: #e9ecef; cursor: not-allowed;"

    def clean(self):
        cleaned_data = super().clean()
        type_sig = cleaned_data.get("type_signalement")
        raw_mode = cleaned_data.get("mode_traitement") or (self.data.get("mode_traitement") if hasattr(self, "data") else None)
        if type_sig == ReclamationClient.TYPE_INCIDENT:
            if self.is_admin and raw_mode in [ReclamationClient.MODE_8D, ReclamationClient.MODE_DOC05]:
                cleaned_data["mode_traitement"] = raw_mode
            else:
                cleaned_data["mode_traitement"] = ReclamationClient.MODE_DOC05
        elif type_sig == ReclamationClient.TYPE_AMELIORATION:
            cleaned_data["mode_traitement"] = ReclamationClient.MODE_DOC05_FAI
        elif type_sig == ReclamationClient.TYPE_RECLAMATION:
            if self.is_admin and raw_mode in [ReclamationClient.MODE_8D, ReclamationClient.MODE_DOC05]:
                cleaned_data["mode_traitement"] = raw_mode
            elif self.instance and self.instance.pk and self.instance.mode_traitement:
                cleaned_data["mode_traitement"] = self.instance.mode_traitement
            else:
                cleaned_data["mode_traitement"] = ReclamationClient.MODE_8D
        return cleaned_data


class ReclamationNumeroForm(forms.ModelForm):
    """Mini-formulaire pour saisir N° Interne et N° Réclamation Client depuis la fiche Doc 05."""

    class Meta:
        model = ReclamationClient
        fields = ["numero_interne", "numero_reclamation_client"]
        widgets = {
            "numero_interne": forms.TextInput(attrs={"class": "form-control", "placeholder": "Ex : INT-2024-001"}),
            "numero_reclamation_client": forms.TextInput(attrs={"class": "form-control", "placeholder": "Ex : RC-CLIENT-456"}),
        }


class ReclamationHeaderForm(forms.ModelForm):
    """Formulaire En-tête Réclamation & Jalons (Doc 83)."""

    class Meta:
        model = ReclamationClient
        fields = [
            "numero_interne", "numero_reclamation_client", "type_signalement",
            "mode_traitement", "statut", "societe", "section", "site",
            "client_nom", "contact_client", "description_piece", "reference_piece",
            "quantite_impactee", "est_probleme_repetitif", "date_alerte_client",
            "date_ouverture", "date_incident", "date_envoi_d1_d3",
            "accuse_reception_envoye", "date_accuse_reception",
        ]
        widgets = {
            "date_alerte_client": DateInput(attrs={"class": "form-control"}),
            "date_ouverture": DateInput(attrs={"class": "form-control"}),
            "date_incident": DateInput(attrs={"class": "form-control"}),
            "date_envoi_d1_d3": DateInput(attrs={"class": "form-control"}),
            "date_accuse_reception": DateInput(attrs={"class": "form-control"}),
            "type_signalement": forms.Select(attrs={"class": "form-control"}),
            "mode_traitement": forms.Select(attrs={
                "class": "form-control text-dark font-weight-bold",
                "disabled": "disabled",
                "style": "background-color: #e9ecef; cursor: not-allowed;",
            }),
            "statut": forms.Select(attrs={"class": "form-control"}),
            "societe": forms.Select(attrs={"class": "form-control"}),
            "section": forms.Select(attrs={"class": "form-control"}),
            "site": forms.Select(attrs={"class": "form-control"}),
            "numero_interne": forms.TextInput(attrs={"class": "form-control"}),
            "numero_reclamation_client": forms.TextInput(attrs={"class": "form-control"}),
            "client_nom": forms.TextInput(attrs={"class": "form-control"}),
            "contact_client": forms.TextInput(attrs={"class": "form-control"}),
            "description_piece": forms.TextInput(attrs={"class": "form-control"}),
            "reference_piece": forms.TextInput(attrs={"class": "form-control"}),
            "quantite_impactee": forms.NumberInput(attrs={"class": "form-control"}),
            "est_probleme_repetitif": forms.CheckboxInput(attrs={"class": "form-check-input"}),
            "accuse_reception_envoye": forms.CheckboxInput(attrs={"class": "form-check-input"}),
        }

    def __init__(self, *args, **kwargs):
        self.is_admin = kwargs.pop("is_admin", False)
        super().__init__(*args, **kwargs)
        self.fields["mode_traitement"].required = False
        self.fields["mode_traitement"].disabled = False
        self.fields["mode_traitement"].choices = [
            (ReclamationClient.MODE_8D, "Rapport 8D"),
            (ReclamationClient.MODE_DOC05, "Fiche d'incident (Doc 05)"),
        ]
        if self.is_admin:
            self.fields["mode_traitement"].widget.attrs.pop("disabled", None)
            self.fields["mode_traitement"].widget.attrs.pop("style", None)
        else:
            self.fields["mode_traitement"].widget.attrs["disabled"] = "disabled"
            self.fields["mode_traitement"].widget.attrs["style"] = "background-color: #e9ecef; cursor: not-allowed;"

    def clean(self):
        cleaned_data = super().clean()
        type_sig = cleaned_data.get("type_signalement")
        raw_mode = cleaned_data.get("mode_traitement") or (self.data.get("mode_traitement") if hasattr(self, "data") else None)
        if type_sig == ReclamationClient.TYPE_INCIDENT:
            if self.is_admin and raw_mode in [ReclamationClient.MODE_8D, ReclamationClient.MODE_DOC05]:
                cleaned_data["mode_traitement"] = raw_mode
            elif self.instance and self.instance.pk and self.instance.mode_traitement in [
                ReclamationClient.MODE_8D,
                ReclamationClient.MODE_DOC05,
            ]:
                cleaned_data["mode_traitement"] = self.instance.mode_traitement
            else:
                cleaned_data["mode_traitement"] = ReclamationClient.MODE_DOC05
        elif type_sig == ReclamationClient.TYPE_AMELIORATION:
            cleaned_data["mode_traitement"] = ReclamationClient.MODE_DOC05_FAI
        elif type_sig == ReclamationClient.TYPE_RECLAMATION:
            if self.is_admin and raw_mode in [ReclamationClient.MODE_8D, ReclamationClient.MODE_DOC05]:
                cleaned_data["mode_traitement"] = raw_mode
            elif self.instance and self.instance.pk and self.instance.mode_traitement:
                cleaned_data["mode_traitement"] = self.instance.mode_traitement
            else:
                cleaned_data["mode_traitement"] = ReclamationClient.MODE_8D
        return cleaned_data


class Participant8DForm(forms.ModelForm):
    class Meta:
        model = Participant8D
        fields = ["user", "nom_externe", "fonction", "est_pilote"]
        widgets = {
            "user": forms.Select(attrs={"class": "form-control"}),
            "nom_externe": forms.TextInput(attrs={"class": "form-control", "placeholder": "Nom si externe"}),
            "fonction": forms.TextInput(attrs={"class": "form-control", "placeholder": "Fonction"}),
            "est_pilote": forms.CheckboxInput(attrs={"class": "form-check-input"}),
        }

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.fields["fonction"].required = False

    def clean(self):
        cleaned_data = super().clean()
        user = cleaned_data.get("user")
        nom_externe = cleaned_data.get("nom_externe")
        fonction = cleaned_data.get("fonction")
        if (user or nom_externe) and not fonction:
            self.add_error("fonction", "La fonction est obligatoire si un participant est renseigné.")
        return cleaned_data

    def has_changed(self):
        if not self.instance.pk:
            u = str(self.data.get(self.add_prefix("user")) or "").strip()
            nom = str(self.data.get(self.add_prefix("nom_externe")) or "").strip()
            fonc = str(self.data.get(self.add_prefix("fonction")) or "").strip()
            if not u and not nom and not fonc:
                return False
        return super().has_changed()


Participant8DFormSet = inlineformset_factory(
    ReclamationClient,
    Participant8D,
    form=Participant8DForm,
    extra=0,
    can_delete=True,
)


class DescriptionQQOQCCPForm(forms.ModelForm):
    """Matrice Le Problème EST / N'EST PAS (D2)."""

    class Meta:
        model = DescriptionQQOQCCP
        fields = [
            "description_client",
            "quoi_est", "quoi_nest_pas",
            "qui_est", "qui_nest_pas",
            "ou_est", "ou_nest_pas",
            "quand_est", "quand_nest_pas",
            "comment_est", "comment_nest_pas",
            "combien_est", "combien_nest_pas",
            "pourquoi_est", "pourquoi_nest_pas",
        ]
        widgets = {
            "description_client": forms.Textarea(attrs={"class": "form-control", "rows": 3, "placeholder": "Description transmise par le client..."}),
            "quoi_est": forms.Textarea(attrs={"class": "form-control", "rows": 2}),
            "quoi_nest_pas": forms.Textarea(attrs={"class": "form-control", "rows": 2}),
            "qui_est": forms.Textarea(attrs={"class": "form-control", "rows": 2}),
            "qui_nest_pas": forms.Textarea(attrs={"class": "form-control", "rows": 2}),
            "ou_est": forms.Textarea(attrs={"class": "form-control", "rows": 2}),
            "ou_nest_pas": forms.Textarea(attrs={"class": "form-control", "rows": 2}),
            "quand_est": forms.Textarea(attrs={"class": "form-control", "rows": 2}),
            "quand_nest_pas": forms.Textarea(attrs={"class": "form-control", "rows": 2}),
            "comment_est": forms.Textarea(attrs={"class": "form-control", "rows": 2}),
            "comment_nest_pas": forms.Textarea(attrs={"class": "form-control", "rows": 2}),
            "combien_est": forms.Textarea(attrs={"class": "form-control", "rows": 2}),
            "combien_nest_pas": forms.Textarea(attrs={"class": "form-control", "rows": 2}),
            "pourquoi_est": forms.Textarea(attrs={"class": "form-control", "rows": 2}),
            "pourquoi_nest_pas": forms.Textarea(attrs={"class": "form-control", "rows": 2}),
        }


class MesureConservatoireD3Form(forms.ModelForm):
    class Meta:
        model = MesureConservatoireD3
        fields = ["type_mesure", "selectionne", "quantite_triee", "quantite_nok", "commentaires"]
        widgets = {
            "type_mesure": forms.Select(attrs={"class": "form-control"}),
            "selectionne": forms.CheckboxInput(attrs={"class": "form-check-input"}),
            "quantite_triee": forms.NumberInput(attrs={"class": "form-control", "min": 0}),
            "quantite_nok": forms.NumberInput(attrs={"class": "form-control", "min": 0}),
            "commentaires": forms.TextInput(attrs={"class": "form-control", "placeholder": "Remarques..."}),
        }

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.fields["quantite_triee"].required = False
        self.fields["quantite_nok"].required = False

    def clean(self):
        cleaned_data = super().clean()
        if cleaned_data.get("quantite_triee") is None:
            cleaned_data["quantite_triee"] = 0
        if cleaned_data.get("quantite_nok") is None:
            cleaned_data["quantite_nok"] = 0
        return cleaned_data


MesureConservatoireD3FormSet = inlineformset_factory(
    ReclamationClient,
    MesureConservatoireD3,
    form=MesureConservatoireD3Form,
    extra=0,
    can_delete=False,
)


class AnalyseCausesDoubleAxeForm(forms.ModelForm):
    """Analyse des causes D4 (Synthèses D4.1 et D4.2)."""

    class Meta:
        model = AnalyseCausesDoubleAxeD4
        fields = ["cause_principale_non_detection", "cause_principale_technique"]
        widgets = {
            "cause_principale_non_detection": forms.Textarea(attrs={"class": "form-control pq-conclusion-field", "rows": 3, "placeholder": "Synthèse de la cause principale de non-détection..."}),
            "cause_principale_technique": forms.Textarea(attrs={"class": "form-control pq-conclusion-field", "rows": 3, "placeholder": "Synthèse de la cause principale technique..."}),
        }


class ActionTestD5Form(forms.ModelForm):
    class Meta:
        model = ActionTestD5
        fields = ["description_action", "pilote_delai", "conclusion", "ordre"]
        widgets = {
            "description_action": forms.Textarea(attrs={"class": "form-control", "rows": 2}),
            "pilote_delai": forms.TextInput(attrs={"class": "form-control", "placeholder": "Pilote - Délai"}),
            "conclusion": forms.Textarea(attrs={"class": "form-control", "rows": 2}),
            "ordre": forms.NumberInput(attrs={"class": "form-control"}),
        }

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.fields["ordre"].required = False
        self.fields["description_action"].required = False

    def clean(self):
        cleaned_data = super().clean()
        desc = cleaned_data.get("description_action")
        pilote = cleaned_data.get("pilote_delai")
        conclusion = cleaned_data.get("conclusion")
        if (pilote or conclusion) and not desc:
            self.add_error("description_action", "La description de l'action test est obligatoire.")
        if not cleaned_data.get("ordre"):
            cleaned_data["ordre"] = 1
        return cleaned_data

    def has_changed(self):
        if not self.instance.pk:
            desc = str(self.data.get(self.add_prefix("description_action")) or "").strip()
            pilote = str(self.data.get(self.add_prefix("pilote_delai")) or "").strip()
            conclusion = str(self.data.get(self.add_prefix("conclusion")) or "").strip()
            if not desc and not pilote and not conclusion:
                return False
        return super().has_changed()


ActionTestD5FormSet = inlineformset_factory(
    ReclamationClient,
    ActionTestD5,
    form=ActionTestD5Form,
    extra=0,
    can_delete=True,
)


class ActionPermanenteD6Form(forms.ModelForm):
    class Meta:
        model = ActionCorrective
        fields = [
            "axe", "cause_racine", "description", "pilote", "delai",
            "date_realisation", "date_verification", "statut",
            "efficace", "audit_poste_doc37", "ordre",
        ]
        widgets = {
            "axe": forms.Select(attrs={"class": "form-control"}),
            "cause_racine": forms.Textarea(attrs={"class": "form-control", "rows": 2, "placeholder": "Cause racine identifiée..."}),
            "description": forms.Textarea(attrs={"class": "form-control", "rows": 2, "placeholder": "Description de l'action..."}),
            "pilote": forms.TextInput(attrs={"class": "form-control", "placeholder": "Pilote"}),
            "delai": DateInput(attrs={"class": "form-control"}),
            "date_realisation": DateInput(attrs={"class": "form-control"}),
            "date_verification": DateInput(attrs={"class": "form-control"}),
            "statut": forms.Select(attrs={"class": "form-control"}),
            "efficace": forms.Select(choices=[(None, "— Non évalué —"), (True, "Oui (Efficace)"), (False, "Non (Inefficace)")], attrs={"class": "form-control"}),
            "audit_poste_doc37": forms.CheckboxInput(attrs={"class": "form-check-input"}),
            "ordre": forms.NumberInput(attrs={"class": "form-control"}),
        }

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.fields["ordre"].required = False
        self.fields["description"].required = False

    def clean(self):
        cleaned_data = super().clean()
        desc = cleaned_data.get("description")
        pilote = cleaned_data.get("pilote")
        cause = cleaned_data.get("cause_racine")
        delai = cleaned_data.get("delai")
        date_realisation = cleaned_data.get("date_realisation")
        date_verification = cleaned_data.get("date_verification")
        has_any = any([desc, pilote, cause, delai, date_realisation, date_verification])
        if has_any and not desc:
            self.add_error("description", "La description de l'action permanente est obligatoire.")
        if not cleaned_data.get("ordre"):
            cleaned_data["ordre"] = 1
        return cleaned_data

    def has_changed(self):
        if not self.instance.pk:
            desc = str(self.data.get(self.add_prefix("description")) or "").strip()
            pilote = str(self.data.get(self.add_prefix("pilote")) or "").strip()
            cause = str(self.data.get(self.add_prefix("cause_racine")) or "").strip()
            delai = str(self.data.get(self.add_prefix("delai")) or "").strip()
            date_real = str(self.data.get(self.add_prefix("date_realisation")) or "").strip()
            date_verif = str(self.data.get(self.add_prefix("date_verification")) or "").strip()
            if not any([desc, pilote, cause, delai, date_real, date_verif]):
                return False
        return super().has_changed()


ActionPermanenteD6FormSet = inlineformset_factory(
    ReclamationClient,
    ActionCorrective,
    form=ActionPermanenteD6Form,
    extra=0,
    can_delete=True,
)


class CapitalisationSMQSD7Form(forms.ModelForm):
    """Métadonnées D7 ; les documents sont gérés par la liste JSON dédiée."""

    class Meta:
        model = CapitalisationSMQSD7
        fields = []


class DocumentSMQSD7Form(forms.ModelForm):
    """Formulaire de référence pour un document D7 libre."""

    class Meta:
        model = DocumentSMQSD7
        fields = ["nom_reference", "mis_a_jour", "commentaire", "fichier"]


class ClotureRecevabiliteD8Form(forms.ModelForm):
    """Décision de recevabilité & Clôture D8."""

    class Meta:
        model = ClotureRecevabiliteD8
        fields = [
            "statut_recevabilite", "motif_decision_factuel",
            "feliciter_equipe", "date_felicitations", "date_envoi_8d_final",
        ]
        widgets = {
            "statut_recevabilite": forms.Select(attrs={"class": "form-control"}),
            "motif_decision_factuel": forms.Textarea(attrs={"class": "form-control", "rows": 4, "placeholder": "Explication factuelle détaillée de la décision de recevabilité ou du refus..."}),
            "feliciter_equipe": forms.CheckboxInput(attrs={"class": "form-check-input"}),
            "date_felicitations": DateInput(attrs={"class": "form-control"}),
            "date_envoi_8d_final": DateInput(attrs={"class": "form-control"}),
        }


class FicheIncidentDoc05Form(forms.ModelForm):
    """Formulaire d'édition de la Fiche Incident Client (I) et Fiche d'Amélioration Interne (AI) - Doc 05."""

    class Meta:
        model = FicheIncidentDoc05
        fields = [
            "redacteur", "date_detection", "date_ouverture", "site_concerne",
            "evenement_qualite", "evenement_securite", "evenement_environnement",
            "quoi_reponse", "qui_reponse", "ou_reponse", "quand_reponse",
            "comment_reponse", "combien_reponse", "autre_reponse",
            "motif_non_conformite", "deja_signale", "deja_signale_details",
            "particularites_changements", "particularites_details",
            "risque_similaire", "risque_similaire_details", "date_cloture",
        ]
        widgets = {
            "date_detection": DateInput(attrs={"class": "form-control"}),
            "date_ouverture": DateInput(attrs={"class": "form-control"}),
            "date_cloture": DateInput(attrs={"class": "form-control"}),
            "redacteur": forms.TextInput(attrs={"class": "form-control", "placeholder": "Nom du rédacteur de la fiche"}),
            "site_concerne": forms.TextInput(attrs={"class": "form-control", "placeholder": "Ex : 117 - Sovab"}),
            "evenement_qualite": forms.CheckboxInput(attrs={"class": "form-check-input"}),
            "evenement_securite": forms.CheckboxInput(attrs={"class": "form-check-input"}),
            "evenement_environnement": forms.CheckboxInput(attrs={"class": "form-check-input"}),
            "quoi_reponse": forms.Textarea(attrs={"class": "form-control", "rows": 2, "placeholder": "Description de la nature du problème / dysfonctionnement"}),
            "qui_reponse": forms.Textarea(attrs={"class": "form-control", "rows": 2, "placeholder": "Qui rencontre / détecte / subit le problème"}),
            "ou_reponse": forms.Textarea(attrs={"class": "form-control", "rows": 2, "placeholder": "Où détecté / site / secteur / poste"}),
            "quand_reponse": forms.Textarea(attrs={"class": "form-control", "rows": 2, "placeholder": "Quand détecté / étape des opérations"}),
            "comment_reponse": forms.Textarea(attrs={"class": "form-control", "rows": 2, "placeholder": "Comment se manifeste le problème"}),
            "combien_reponse": forms.Textarea(attrs={"class": "form-control", "rows": 2, "placeholder": "Quantité concernée / fréquence"}),
            "autre_reponse": forms.Textarea(attrs={"class": "form-control", "rows": 3, "placeholder": "Références, Désignation, Fournisseur, Défaut..."}),
            "motif_non_conformite": forms.Textarea(attrs={"class": "form-control", "rows": 2, "placeholder": "Motif de la non-conformité"}),
            "deja_signale": forms.CheckboxInput(attrs={"class": "form-check-input"}),
            "deja_signale_details": forms.TextInput(attrs={"class": "form-control", "placeholder": "Si OUI Date/période"}),
            "particularites_changements": forms.CheckboxInput(attrs={"class": "form-check-input"}),
            "particularites_details": forms.Textarea(attrs={"class": "form-control", "rows": 2, "placeholder": "Si OUI lesquels"}),
            "risque_similaire": forms.CheckboxInput(attrs={"class": "form-check-input"}),
            "risque_similaire_details": forms.TextInput(attrs={"class": "form-control", "placeholder": "Si OUI où"}),
        }
