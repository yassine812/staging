"""Administration du module gestion documentaire."""

from django.contrib import admin, messages
from django.core.mail import send_mail
from django.utils import timezone

from .models import (
    Document,
    DossierDocumentaire,
    FichierBibliotheque,
    Indicateur,
    IndicateurQuotidien,
    MesureIndicateur,
    ObjectifIndicateur,
    Processus,
    RealiseConsolideIndicateur,
    SuiviIndicateurQuotidien,
    ValidationDocument,
    VersionDocument,
)

admin.site.register(DossierDocumentaire)
admin.site.register(FichierBibliotheque)
admin.site.register(IndicateurQuotidien)
admin.site.register(SuiviIndicateurQuotidien)


class VersionDocumentInline(admin.TabularInline):
    """Versions rattachées à un document."""

    model = VersionDocument
    extra = 0
    readonly_fields = ("date_creation", "date_modification")


class ValidationDocumentInline(admin.TabularInline):
    """Traçabilité des validations/actions documentaire."""

    model = ValidationDocument
    extra = 0
    readonly_fields = ("date_action",)
    can_delete = False


@admin.register(Document)
class DocumentAdmin(admin.ModelAdmin):
    list_display = (
        "code_documentaire",
        "titre",
        "type_document",
        "processus",
        "statut",
        "date_application",
        "date_retrait",
        "est_supprime",
    )
    list_filter = ("type_document", "statut", "processus", "est_supprime")
    search_fields = ("code_documentaire", "titre", "reference_documentaire")
    readonly_fields = ("code_documentaire", "date_creation", "date_modification", "date_suppression")
    inlines = [VersionDocumentInline, ValidationDocumentInline]
    actions = ["action_archiver_documents", "action_notifier_diffusion"]

    @admin.action(description="Archiver les documents sélectionnés")
    def action_archiver_documents(self, request, queryset):
        archived = 0
        skipped = 0
        for document in queryset:
            if document.statut != Document.Statut.APPLICABLE:
                skipped += 1
                continue
            try:
                document.transitionner_statut(
                    Document.Statut.ARCHIVE,
                    utilisateur=request.user,
                    commentaire="Archivage massif depuis l'admin.",
                )
                ValidationDocument.objects.create(
                    document=document,
                    type_action=ValidationDocument.TypeAction.ARCHIVAGE,
                    utilisateur=request.user,
                    commentaire="Archivage massif depuis l'admin.",
                    ancien_statut=Document.Statut.APPLICABLE,
                    nouveau_statut=Document.Statut.ARCHIVE,
                )
                archived += 1
            except Exception:
                skipped += 1

        if archived:
            self.message_user(request, f"{archived} document(s) archivé(s).", level=messages.SUCCESS)
        if skipped:
            self.message_user(request, f"{skipped} document(s) ignoré(s).", level=messages.WARNING)

    @admin.action(description="Notifier la diffusion (email) pour les documents sélectionnés")
    def action_notifier_diffusion(self, request, queryset):
        notified = 0
        for document in queryset.filter(statut=Document.Statut.APPLICABLE, est_supprime=False):
            recipients = []
            if document.cree_par and document.cree_par.email:
                recipients.append(document.cree_par.email)

            # Notifie au moins le créateur; extensible aux groupes métier.
            if not recipients:
                continue

            send_mail(
                subject=f"[QSE] Diffusion document {document.code_documentaire}",
                message=(
                    f"Le document {document.code_documentaire} - {document.titre} "
                    f"est applicable au {document.date_application or timezone.localdate()}."
                ),
                from_email=None,
                recipient_list=recipients,
                fail_silently=True,
            )
            ValidationDocument.objects.create(
                document=document,
                type_action=ValidationDocument.TypeAction.DIFFUSION,
                utilisateur=request.user,
                commentaire="Notification de diffusion envoyée depuis l'admin.",
                ancien_statut=document.statut,
                nouveau_statut=document.statut,
            )
            notified += 1

        self.message_user(request, f"Notification envoyée pour {notified} document(s).", level=messages.SUCCESS)


@admin.register(VersionDocument)
class VersionDocumentAdmin(admin.ModelAdmin):
    list_display = (
        "document",
        "version",
        "indice",
        "statut",
        "redacteur",
        "copie_non_maitrisee",
        "date_creation",
    )
    list_filter = ("statut", "copie_non_maitrisee", "document__type_document")
    search_fields = ("document__code_documentaire", "document__titre", "resume_changements")


@admin.register(ValidationDocument)
class ValidationDocumentAdmin(admin.ModelAdmin):
    list_display = (
        "document",
        "version_document",
        "type_action",
        "utilisateur",
        "ancien_statut",
        "nouveau_statut",
        "date_action",
    )
    list_filter = ("type_action", "ancien_statut", "nouveau_statut", "date_action")
    search_fields = ("document__code_documentaire", "commentaire", "utilisateur__username")
    readonly_fields = (
        "document",
        "version_document",
        "type_action",
        "utilisateur",
        "commentaire",
        "ancien_statut",
        "nouveau_statut",
        "donnees_action",
        "date_action",
    )


# ============================================================
# MODULE TABLEAU DE BORD SMQS
# Administration des modèles du Tableau de Bord
# ============================================================


@admin.register(Processus)
class ProcessusAdmin(admin.ModelAdmin):
    list_display = ("code", "nom", "societe", "is_active")
    list_filter = ("societe", "is_active")
    search_fields = ("code", "nom")
    filter_horizontal = ("RO", "RS", "CE")


@admin.register(Indicateur)
class IndicateurAdmin(admin.ModelAdmin):
    list_display = ("code", "nom", "processus", "periodicite", "mode_agregation", "sens_objectif", "mode_calcul", "is_active")
    list_filter = ("processus", "periodicite", "sens_objectif", "mode_calcul", "is_active")
    search_fields = ("code", "nom")


@admin.register(ObjectifIndicateur)
class ObjectifIndicateurAdmin(admin.ModelAdmin):
    list_display = ("indicateur", "annee", "valeur_objectif")
    list_filter = ("annee",)


@admin.register(MesureIndicateur)
class MesureIndicateurAdmin(admin.ModelAdmin):
    list_display = ("indicateur", "annee", "mois", "valeur", "saisie_par")
    list_filter = ("annee", "mois")
    search_fields = ("indicateur__code", "indicateur__nom")


@admin.register(RealiseConsolideIndicateur)
class RealiseConsolideIndicateurAdmin(admin.ModelAdmin):
    list_display = ("indicateur", "annee_reference", "mois_reference", "valeur", "saisie_par", "updated_at")
    list_filter = ("annee_reference", "mois_reference")
    search_fields = ("indicateur__code", "indicateur__nom")



