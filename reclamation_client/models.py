"""Modèles du module Réclamation Client (P05 & Doc.83 Rapport 8D)."""

import logging
from datetime import timedelta
from django.db import models
from django.utils import timezone
from django.urls import reverse

logger = logging.getLogger(__name__)


class ReclamationClient(models.Model):
    """Fiche principale d'une réclamation / incident client (Procédure P05)."""

    TYPE_RECLAMATION = "R"
    TYPE_INCIDENT = "I"
    TYPE_AMELIORATION = "AI"
    TYPE_CHOICES = [
        (TYPE_RECLAMATION, "Réclamation (R)"),
        (TYPE_INCIDENT, "Incident (I)"),
        (TYPE_AMELIORATION, "Amélioration (AI)"),
    ]

    MODE_8D = "8D"
    MODE_DOC05 = "DOC05"
    MODE_DOC05_FAI = "DOC05_FAI"
    MODE_CHOICES = [
        (MODE_8D, "Rapport 8D"),
        (MODE_DOC05, "Fiche d'incident (Doc 05)"),
        (MODE_DOC05_FAI, "Fiche d'incident / FAI"),
    ]

    @classmethod
    def get_mode_for_type(cls, type_sig):
        if type_sig == cls.TYPE_RECLAMATION:
            return cls.MODE_8D
        elif type_sig == cls.TYPE_AMELIORATION:
            return cls.MODE_DOC05_FAI
        else:
            return cls.MODE_DOC05

    STATUT_BROUILLON = "brouillon"
    STATUT_D1_D3 = "d1_d3"
    STATUT_D4_D6 = "d4_d6"
    STATUT_D7_D8 = "d7_d8"
    STATUT_CLOTURE = "cloture"
    STATUT_CHOICES = [
        (STATUT_BROUILLON, "Brouillon"),
        (STATUT_D1_D3, "D1-D3 : Prise en charge & Sécurisation"),
        (STATUT_D4_D6, "D4-D6 : Analyse & Plan d'actions"),
        (STATUT_D7_D8, "D7-D8 : Capitalisation & Clôture"),
        (STATUT_CLOTURE, "Clôturé"),
    ]

    # ── Identifiant auto ──────────────────────────────────────────────────────
    reference = models.CharField(
        max_length=30, unique=True, blank=True,
        verbose_name="Référence",
        help_text="Généré automatiquement : REC + AAMMM + séquence (ex : REC2511001)",
    )
    numero_interne = models.CharField(
        max_length=50, blank=True, verbose_name="N° Interne",
    )
    numero_reclamation_client = models.CharField(
        max_length=100, blank=True, verbose_name="N° Réclamation Client",
    )

    # ── Classification P05 ────────────────────────────────────────────────────
    type_signalement = models.CharField(
        max_length=5, choices=TYPE_CHOICES, default=TYPE_RECLAMATION,
        verbose_name="Type de signalement",
    )
    mode_traitement = models.CharField(
        max_length=10, choices=MODE_CHOICES, default=MODE_8D,
        verbose_name="Support de traitement",
    )
    statut = models.CharField(
        max_length=20, choices=STATUT_CHOICES, default=STATUT_D1_D3,
        verbose_name="Statut du dossier",
    )

    # ── Organisation & Client ─────────────────────────────────────────────────
    societe = models.ForeignKey(
        "accounts.Societe", on_delete=models.PROTECT, related_name="reclamations_clients",
        verbose_name="Société",
    )
    section = models.ForeignKey(
        "accounts.Section", on_delete=models.SET_NULL, null=True, blank=True,
        related_name="reclamations_clients", verbose_name="Section",
    )
    site = models.ForeignKey(
        "accounts.Site", on_delete=models.SET_NULL, null=True, blank=True,
        related_name="reclamations_clients", verbose_name="Site concerné",
    )
    client_nom = models.CharField(max_length=200, verbose_name="Client")
    contact_client = models.CharField(max_length=200, blank=True, verbose_name="Contact client")

    # ── Produit / Prestation ──────────────────────────────────────────────────
    description_piece = models.CharField(max_length=255, blank=True, verbose_name="Description pièce / prestation")
    reference_piece = models.CharField(max_length=100, blank=True, verbose_name="Référence pièce")
    quantite_impactee = models.PositiveIntegerField(default=0, verbose_name="Quantité impactée")
    est_probleme_repetitif = models.BooleanField(default=False, verbose_name="Problème répétitif ?")

    # ── Dates clés P05 ────────────────────────────────────────────────────────
    date_alerte_client = models.DateField(default=timezone.now, verbose_name="Date d'alerte client")
    date_ouverture = models.DateField(default=timezone.now, verbose_name="Date d'ouverture fiche")
    date_mise_a_jour = models.DateField(auto_now=True, verbose_name="Date de mise à jour")
    date_incident = models.DateField(null=True, blank=True, verbose_name="Date de l'incident")
    date_envoi_d1_d3 = models.DateField(null=True, blank=True, verbose_name="Date envoi D1-D3 au client")

    # Accusé de réception obligatoire P05
    accuse_reception_envoye = models.BooleanField(default=False, verbose_name="Accusé de réception écrit envoyé au client")
    date_accuse_reception = models.DateField(null=True, blank=True, verbose_name="Date d'accusé de réception")

    # ── Métadonnées ──────────────────────────────────────────────────────────
    created_by = models.ForeignKey(
        "accounts.User", on_delete=models.SET_NULL, null=True, blank=True,
        related_name="reclamations_creees", verbose_name="Créé par",
    )
    updated_by = models.ForeignKey(
        "accounts.User", on_delete=models.SET_NULL, null=True, blank=True,
        related_name="reclamations_modifiees", verbose_name="Modifié par",
    )
    created_at = models.DateTimeField(auto_now_add=True, verbose_name="Créé le")
    updated_at = models.DateTimeField(auto_now=True, verbose_name="Modifié le")

    class Meta:
        verbose_name = "Réclamation Client"
        verbose_name_plural = "Réclamations Clients"
    def save(self, *args, **kwargs):
        if not self.mode_traitement:
            self.mode_traitement = self.get_mode_for_type(self.type_signalement)
        if not self.reference:
            prefix = (
                self.date_alerte_client.strftime("REC%y%m")
                if self.date_alerte_client
                else timezone.now().strftime("REC%y%m")
            )
            last = (
                ReclamationClient.objects.filter(reference__startswith=prefix)
                .order_by("-reference")
                .values_list("reference", flat=True)
                .first()
            )
            next_num = int(last[-3:]) + 1 if last else 1
            self.reference = f"{prefix}{next_num:03d}"
            logger.info("Référence réclamation générée : %s", self.reference)
        super().save(*args, **kwargs)

    def get_absolute_url(self):
        return reverse("reclamation:detail", kwargs={"pk": self.pk})

    def __str__(self):
        return f"{self.reference} - {self.client_nom} ({self.type_signalement})"

    @property
    def statut_badge(self):
        return {
            self.STATUT_BROUILLON: "secondary",
            self.STATUT_D1_D3: "warning",
            self.STATUT_D4_D6: "info",
            self.STATUT_D7_D8: "primary",
            self.STATUT_CLOTURE: "success",
        }.get(self.statut, "secondary")


class Participant8D(models.Model):
    """Participant à l'équipe 8D (D1)."""

    reclamation = models.ForeignKey(
        ReclamationClient, on_delete=models.CASCADE, related_name="participants",
        verbose_name="Réclamation",
    )
    user = models.ForeignKey(
        "accounts.User", on_delete=models.SET_NULL, null=True, blank=True,
        related_name="participations_8d", verbose_name="Utilisateur interne",
    )
    nom_externe = models.CharField(max_length=200, blank=True, verbose_name="Nom externe")
    fonction = models.CharField(max_length=200, verbose_name="Fonction")
    est_pilote = models.BooleanField(default=False, verbose_name="Pilote de la réclamation")

    class Meta:
        verbose_name = "Participant 8D"
        verbose_name_plural = "Participants 8D"

    def __str__(self):
        name = self.user.get_full_name() if self.user else self.nom_externe
        return f"{name} - {self.fonction}"


class DescriptionQQOQCCP(models.Model):
    """Description détaillée du problème (D2 - Matrice Le problème EST / N'EST PAS)."""

    reclamation = models.OneToOneField(
        ReclamationClient, on_delete=models.CASCADE, related_name="qqoqccp",
        verbose_name="Réclamation",
    )
    description_client = models.TextField(blank=True, verbose_name="Description du problème par le client")

    # 7 Axes QQOQCCP : EST vs N'EST PAS
    quoi_est = models.TextField(blank=True, verbose_name="QUOI (Objet / Défaillance) - EST")
    quoi_nest_pas = models.TextField(blank=True, verbose_name="QUOI - N'EST PAS")

    qui_est = models.TextField(blank=True, verbose_name="QUI (Rencontre le problème) - EST")
    qui_nest_pas = models.TextField(blank=True, verbose_name="QUI - N'EST PAS")

    ou_est = models.TextField(blank=True, verbose_name="OÙ (Secteur / Site) - EST")
    ou_nest_pas = models.TextField(blank=True, verbose_name="OÙ - N'EST PAS")

    quand_est = models.TextField(blank=True, verbose_name="QUAND (Détecté quand / par qui) - EST")
    quand_nest_pas = models.TextField(blank=True, verbose_name="QUAND - N'EST PAS")

    comment_est = models.TextField(blank=True, verbose_name="COMMENT (Se manifeste le problème) - EST")
    comment_nest_pas = models.TextField(blank=True, verbose_name="COMMENT - N'EST PAS")

    combien_est = models.TextField(blank=True, verbose_name="COMBIEN (Combien de pièces) - EST")
    combien_nest_pas = models.TextField(blank=True, verbose_name="COMBIEN - N'EST PAS")

    pourquoi_est = models.TextField(blank=True, verbose_name="POURQUOI (Est-ce un problème) - EST")
    pourquoi_nest_pas = models.TextField(blank=True, verbose_name="POURQUOI - N'EST PAS")

    class Meta:
        verbose_name = "Description QQOQCCP D2"
        verbose_name_plural = "Descriptions QQOQCCP D2"


class MesureConservatoireD3(models.Model):
    """Action conservatoire ou de sécurisation (D3)."""

    TYPE_CHOICES = [
        ("tri_interne", "Tri stock interne"),
        ("tri_externe", "Tri stock externe"),
        ("repere_unitaire", "Repère unitaire"),
        ("autre", "Autre action"),
    ]

    reclamation = models.ForeignKey(
        ReclamationClient, on_delete=models.CASCADE, related_name="mesures_conservatoires",
        verbose_name="Réclamation",
    )
    type_mesure = models.CharField(max_length=30, choices=TYPE_CHOICES, verbose_name="Type de mesure")
    selectionne = models.BooleanField(default=False, verbose_name="Appliquée ?")
    quantite_triee = models.PositiveIntegerField(default=0, verbose_name="Quantité triée")
    quantite_nok = models.PositiveIntegerField(default=0, verbose_name="Quantité NOK")
    commentaires = models.TextField(blank=True, verbose_name="Commentaires")

    class Meta:
        verbose_name = "Mesure conservatoire D3"
        verbose_name_plural = "Mesures conservatoires D3"

    def __str__(self):
        return f"{self.get_type_mesure_display()} ({self.reclamation.reference})"


class AnalyseCausesDoubleAxeD4(models.Model):
    """Analyse des causes 5 Pourquoi à Double Axe (D4.1 Non-détection & D4.2 Cause Technique)."""

    reclamation = models.OneToOneField(
        ReclamationClient, on_delete=models.CASCADE, related_name="analyse_causes_d4",
        verbose_name="Réclamation",
    )
    cause_principale_non_detection = models.TextField(blank=True, verbose_name="Synthèse cause principale de non-détection (D4.1)")
    cause_principale_technique = models.TextField(blank=True, verbose_name="Synthèse cause principale technique / non-conformité (D4.2)")

    # Même contrat que AT.arbre_causes : {"causes": [{"label": str,
    # "branches": [{"pourquoi": [p1, p2, p3, p4, p5]}]}]}
    pourquoi_non_detection = models.JSONField(default=dict, blank=True, verbose_name="5 Pourquoi Non-Détection (D4.1)")
    pourquoi_technique = models.JSONField(default=dict, blank=True, verbose_name="5 Pourquoi Cause Technique (D4.2)")

    class Meta:
        verbose_name = "Analyse des causes D4"
        verbose_name_plural = "Analyses des causes D4"


class ActionTestD5(models.Model):
    """Action test planifiée (D5)."""

    reclamation = models.ForeignKey(
        ReclamationClient, on_delete=models.CASCADE, related_name="actions_tests",
        verbose_name="Réclamation",
    )
    description_action = models.TextField(verbose_name="Action test")
    pilote_delai = models.CharField(max_length=200, blank=True, verbose_name="Pilote - Délai")
    conclusion = models.TextField(blank=True, verbose_name="Conclusion du test")
    ordre = models.PositiveIntegerField(default=1)

    class Meta:
        ordering = ["ordre"]
        verbose_name = "Action test D5"
        verbose_name_plural = "Actions tests D5"


class ActionPermanenteD6(models.Model):
    """Action corrective / préventive permanente (D6)."""

    AXE_CHOICES = [
        ("non_detection", "D4.1 - Non Détection"),
        ("technique", "D4.2 - Cause Technique"),
        ("autre", "Autre"),
    ]

    STATUT_CHOICES = [
        ("non_demarre", "Non démarré"),
        ("en_cours", "En cours"),
        ("realise", "Réalisé"),
        ("verifie", "Vérifié"),
    ]

    reclamation = models.ForeignKey(
        ReclamationClient, on_delete=models.CASCADE, related_name="actions_permanentes",
        verbose_name="Réclamation",
    )
    axe = models.CharField(max_length=20, choices=AXE_CHOICES, default="technique", verbose_name="Axe d'analyse")
    cause_racine = models.TextField(blank=True, verbose_name="Cause racine associée")
    description = models.TextField(verbose_name="Action corrective / préventive")
    pilote = models.CharField(max_length=200, blank=True, verbose_name="Pilote")
    delai = models.DateField(null=True, blank=True, verbose_name="Délai")
    date_realisation = models.DateField(null=True, blank=True, verbose_name="Date de réalisation")
    date_verification = models.DateField(null=True, blank=True, verbose_name="Date de vérification")
    statut = models.CharField(max_length=20, choices=STATUT_CHOICES, default="non_demarre", verbose_name="Statut")
    efficace = models.BooleanField(null=True, verbose_name="Action efficace ?")
    audit_poste_doc37 = models.BooleanField(default=False, verbose_name="Audit de poste Doc 37 réalisé ?")
    ordre = models.PositiveIntegerField(default=1)

    class Meta:
        ordering = ["ordre"]
        verbose_name = "Action permanente D6"
        verbose_name_plural = "Actions permanentes D6"


class CapitalisationSMQSD7(models.Model):
    """Capitalisation et mise à jour des standards SMQS (D7)."""

    reclamation = models.OneToOneField(
        ReclamationClient, on_delete=models.CASCADE, related_name="capitalisation_d7",
        verbose_name="Réclamation",
    )

    # Documents SMQS obligatoires Doc.83
    doc01_instruction = models.BooleanField(default=False, verbose_name="Doc.01 Instruction de travail")
    doc01_pilote_delai = models.CharField(max_length=150, blank=True)

    doc5_24_competences = models.BooleanField(default=False, verbose_name="Doc 5-24 Tableau de compétences")
    doc5_24_pilote_delai = models.CharField(max_length=150, blank=True)

    doc21_formation = models.BooleanField(default=False, verbose_name="Doc.21 Formation nouvel arrivant")
    doc21_pilote_delai = models.CharField(max_length=150, blank=True)

    doc34_habilitation_indiv = models.BooleanField(default=False, verbose_name="Doc 34 Habilitation individuelle")
    doc34_pilote_delai = models.CharField(max_length=150, blank=True)

    doc38_habilitation_poste = models.BooleanField(default=False, verbose_name="Doc 38 Habilitation au poste")
    doc38_pilote_delai = models.CharField(max_length=150, blank=True)

    doc12_gammes = models.BooleanField(default=False, verbose_name="Doc 12 Gamme de travail")
    doc12_pilote_delai = models.CharField(max_length=150, blank=True)
    precisez_gammes = models.TextField(blank=True, verbose_name="Précisez les Gammes")

    doc50_ok_demarrage = models.BooleanField(default=False, verbose_name="Doc 50 OK démarrage")
    doc50_pilote_delai = models.CharField(max_length=150, blank=True)

    # Liste libre des documents D7 ajoutés par l'utilisateur. Les anciens
    # champs fixes restent conservés pour ne pas altérer les données existantes,
    # mais ne sont plus affichés ni utilisés comme documents par défaut.
    documents_smqs = models.JSONField(
        null=True,
        blank=True,
        default=None,
        verbose_name="Documents SMQS D7 personnalisés",
    )

    class Meta:
        verbose_name = "Capitalisation SMQS D7"
        verbose_name_plural = "Capitalisations SMQS D7"


class DocumentSMQSD7(models.Model):
    """Document libre ajouté dans l'étape D7 d'un Rapport 8D."""

    capitalisation_d7 = models.ForeignKey(
        CapitalisationSMQSD7,
        on_delete=models.CASCADE,
        related_name="documents_d7",
        verbose_name="Capitalisation D7",
    )
    nom_reference = models.CharField(max_length=255, blank=True, verbose_name="Nom / Référence")
    mis_a_jour = models.BooleanField(default=False, verbose_name="Mis à jour ?")
    commentaire = models.TextField(blank=True, verbose_name="Commentaire")
    fichier = models.FileField(
        upload_to="reclamation_client/d7/%Y/%m/",
        blank=True,
        verbose_name="Fichier",
    )

    def __str__(self):
        return self.nom_reference or self.fichier.name or f"Document D7 #{self.pk}"

    def delete(self, *args, **kwargs):
        fichier_name = self.fichier.name
        storage = self.fichier.storage
        result = super().delete(*args, **kwargs)
        if fichier_name and storage.exists(fichier_name):
            storage.delete(fichier_name)
        return result


class ClotureRecevabiliteD8(models.Model):
    """Décision de recevabilité et fermeture du 8D (D8 - P05 §5)."""

    RECEVABILITE_RECEVABLE = "recevable"
    RECEVABILITE_NON_RECEVABLE = "non_recevable"
    RECEVABILITE_PARTIEL = "partiel"
    RECEVABILITE_CHOICES = [
        (RECEVABILITE_RECEVABLE, "Recevable (Responsabilité AB Serve avérée)"),
        (RECEVABILITE_NON_RECEVABLE, "Non Recevable (Refus justifié)"),
        (RECEVABILITE_PARTIEL, "Partiellement Recevable"),
    ]

    reclamation = models.OneToOneField(
        ReclamationClient, on_delete=models.CASCADE, related_name="cloture_d8",
        verbose_name="Réclamation",
    )
    statut_recevabilite = models.CharField(
        max_length=20, choices=RECEVABILITE_CHOICES, default=RECEVABILITE_RECEVABLE,
        verbose_name="Recevabilité",
    )
    motif_decision_factuel = models.TextField(
        blank=True, verbose_name="Motif de la décision (Justification factuelle obligatoire en cas de refus)",
    )
    feliciter_equipe = models.BooleanField(default=False, verbose_name="Féliciter l'équipe ?")
    date_felicitations = models.DateField(null=True, blank=True, verbose_name="Date félicitations")
    date_envoi_8d_final = models.DateField(null=True, blank=True, verbose_name="Date d'envoi du 8D final au client")

    class Meta:
        verbose_name = "Clôture & Recevabilité D8"
        verbose_name_plural = "Clôtures & Recevabilités D8"


class FicheIncidentDoc05(models.Model):
    """Données spécifiques à la Fiche d'Incident Client (I) et Fiche d'Amélioration Interne (AI) - Doc.05."""

    reclamation = models.OneToOneField(
        ReclamationClient, on_delete=models.CASCADE, related_name="fiche_doc05",
        verbose_name="Réclamation / Incident",
    )
    redacteur = models.CharField(max_length=200, blank=True, verbose_name="Rédacteur de la fiche")
    date_detection = models.DateField(null=True, blank=True, verbose_name="Date de détection la non-conformité")
    date_ouverture = models.DateField(null=True, blank=True, verbose_name="Date de l'ouverture de la fiche")
    site_concerne = models.CharField(max_length=200, blank=True, verbose_name="Site concerné")

    # Evènement
    evenement_qualite = models.BooleanField(default=True, verbose_name="Qualité")
    evenement_securite = models.BooleanField(default=False, verbose_name="Sécurité")
    evenement_environnement = models.BooleanField(default=False, verbose_name="Environnement")

    # QQOQCC Answers
    quoi_reponse = models.TextField(blank=True, verbose_name="QUOI - Réponse pour décrire le problème")
    qui_reponse = models.TextField(blank=True, verbose_name="QUI - Réponse pour décrire le problème")
    ou_reponse = models.TextField(blank=True, verbose_name="OÙ - Réponse pour décrire le problème")
    quand_reponse = models.TextField(blank=True, verbose_name="QUAND - Réponse pour décrire le problème")
    comment_reponse = models.TextField(blank=True, verbose_name="COMMENT - Réponse pour décrire le problème")
    combien_reponse = models.TextField(blank=True, verbose_name="COMBIEN - Réponse pour décrire le problème")
    autre_reponse = models.TextField(blank=True, verbose_name="AUTRE - Informations utiles")

    # 5 Pourquoi
    motif_non_conformite = models.TextField(blank=True, verbose_name="Motif de la non-conformité")
    pourquoi_chains = models.JSONField(default=list, blank=True, verbose_name="5 Pourquoi Chains (Doc 05)")

    # Repetitive / Context Questions
    deja_signale = models.BooleanField(default=False, verbose_name="Ce problème a-t-il déjà été signalé ?")
    deja_signale_details = models.CharField(max_length=255, blank=True, verbose_name="Date / Période si déjà signalé")

    particularites_changements = models.BooleanField(default=False, verbose_name="Particularités / changements intervenus ?")
    particularites_details = models.TextField(blank=True, verbose_name="Lesquels si particularités")

    risque_similaire = models.BooleanField(default=False, verbose_name="Risque similaire sur autre produit/secteur ?")
    risque_similaire_details = models.CharField(max_length=255, blank=True, verbose_name="Où si risque similaire")

    # Actions Doc.05
    mesures_immediates = models.JSONField(default=list, blank=True, verbose_name="Mesures immédiates (Doc 05)")
    actions_correctives = models.JSONField(default=list, blank=True, verbose_name="Actions correctives retenues (Doc 05)")

    # Clôture
    date_cloture = models.DateField(null=True, blank=True, verbose_name="Date de clôture")

    class Meta:
        verbose_name = "Fiche Incident / FAI Doc 05"
        verbose_name_plural = "Fiches Incidents / FAI Doc 05"

    def __str__(self):
        return f"Doc.05 {self.reclamation.reference}"
