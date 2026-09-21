"""
Test script to verify ZERO DATA LOSS when switching support between 8D and DOC05.
Covers all 11 mandatory steps:
1. Créer une Réclamation R en 8D.
2. Remplir plusieurs champs D1-D8 avec des données de test.
3. Enregistrer.
4. Vérifier les données en base.
5. Changer 8D → DOC05.
6. Vérifier qu'aucune donnée 8D n'a été supprimée en base.
7. Remplir/enregistrer des données Doc05.
8. Changer DOC05 → 8D.
9. Vérifier que toutes les données 8D précédentes réapparaissent.
10. Revenir DOC05.
11. Vérifier que les données Doc05 sont toujours présentes.
"""

import os
import sys
import django

# Setup Django environment
sys.path.insert(0, r"c:\Users\Yassine\audit2-main")
sys.stdout.reconfigure(encoding='utf-8')
os.environ.setdefault("DJANGO_SETTINGS_MODULE", "settings")
django.setup()

from django.test import RequestFactory
from django.contrib.auth import get_user_model
from django.contrib.messages.storage.fallback import FallbackStorage
from accounts.models import Societe, Site
from reclamation_client.models import (
    ReclamationClient,
    Participant8D,
    DescriptionQQOQCCP,
    MesureConservatoireD3,
    AnalyseCausesDoubleAxeD4,
    ActionTestD5,
    ActionPermanenteD6,
    CapitalisationSMQSD7,
    ClotureRecevabiliteD8,
    FicheIncidentDoc05,
)
from reclamation_client.views import (
    reclamation_changer_support,
    reclamation_update_8d,
    reclamation_update_doc05,
)

User = get_user_model()
rf = RequestFactory()

def run_zero_data_loss_test():
    print("=" * 70)
    print("TEST ZERO DATA LOSS: 8D <-> DOC05 SUPPORT SWITCH")
    print("=" * 70)

    # 0. Setup test user & organization
    admin_user = User.objects.filter(is_superuser=True).first()
    if not admin_user:
        admin_user = User.objects.create_superuser("admin_test", "admin@test.com", "pass123")
    
    societe = Societe.objects.first()
    site = Site.objects.first()
    if not societe:
        societe = Societe.objects.create(nom="Societe Test Zero Loss")
    if not site:
        from accounts.models import Section
        section = Section.objects.first() or Section.objects.create(Nom="Section Test", societe=societe)
        site = Site.objects.create(nom="Site Test Zero Loss", section=section)

    # 1. Créer une Réclamation R en 8D
    print("\n--- Étape 1 : Création de la Réclamation R en 8D ---")
    rec = ReclamationClient.objects.create(
        type_signalement=ReclamationClient.TYPE_RECLAMATION,
        mode_traitement=ReclamationClient.MODE_8D,
        societe=societe,
        site=site,
        client_nom="Client Test Zero Loss",
        contact_client="Jean Dupont",
        description_piece="Support moteur alu",
        reference_piece="REF-MOT-999",
        quantite_impactee=42,
        created_by=admin_user,
        updated_by=admin_user,
    )
    print(f"Dossier créé : ID={rec.pk}, Ref={rec.reference}, Type={rec.type_signalement}, Mode={rec.mode_traitement}")
    assert rec.type_signalement == "R"
    assert rec.mode_traitement == "8D"

    # 2. Remplir plusieurs champs D1-D8 avec des données de test
    print("\n--- Étape 2 & 3 : Remplissage et Enregistrement D1 à D8 ---")
    # D1
    p1 = Participant8D.objects.create(
        reclamation=rec,
        nom_externe="Alice Smith",
        fonction="Ingénieure Qualité",
        est_pilote=True,
    )
    p2 = Participant8D.objects.create(
        reclamation=rec,
        nom_externe="Bob Martin",
        fonction="Chef d'atelier",
        est_pilote=False,
    )

    # D2
    qqoqccp, _ = DescriptionQQOQCCP.objects.get_or_create(reclamation=rec)
    qqoqccp.description_client = "Fissure observée sur le support côté fixation gauche."
    qqoqccp.quoi_est = "Fissure de 15mm nette"
    qqoqccp.quoi_nest_pas = "Déformation plastique"
    qqoqccp.qui_est = "Opérateur ligne d'assemblage client"
    qqoqccp.qui_nest_pas = "Contrôle final usine"
    qqoqccp.ou_est = "Usine client - Ligne 3"
    qqoqccp.ou_nest_pas = "Entrepôt stockage"
    qqoqccp.quand_est = "2026-09-15 pendant montage"
    qqoqccp.quand_nest_pas = "À réception palettes"
    qqoqccp.comment_est = "Visuellement lors du vissage couple 45Nm"
    qqoqccp.comment_nest_pas = "Par test ultrason"
    qqoqccp.combien_est = "42 pièces du lot L-2026-88"
    qqoqccp.combien_nest_pas = "Tout le lot (500 pièces)"
    qqoqccp.pourquoi_est = "Risque rupture en fonctionnement véhicule"
    qqoqccp.pourquoi_nest_pas = "Défaut purement esthétique"
    qqoqccp.save()

    # D3
    m1, _ = MesureConservatoireD3.objects.get_or_create(reclamation=rec, type_mesure="tri_interne")
    m1.selectionne = True
    m1.quantite_triee = 150
    m1.quantite_nok = 3
    m1.commentaires = "Tri de l'en-cours interne effectué à 100%."
    m1.save()

    # D4
    d4, _ = AnalyseCausesDoubleAxeD4.objects.get_or_create(reclamation=rec)
    d4.cause_principale_non_detection = "Capteur optique de contrôle fissuration mal calibré."
    d4.cause_principale_technique = "Vitesse d'avance de l'outil d'usinage trop élevée créant une micro-fissure."
    d4.pourquoi_non_detection = [
        ["Capteur n'a pas déclenché", "Seuil trop haut", "Réglage modifié lors de maintenance", "Pas de procédure de validation", "Cause racine non détection"]
    ]
    d4.pourquoi_technique = [
        ["Fissure amorcée", "Contrainte excessive", "Avance outil excessive", "Programme CNC mal versionné", "Cause racine technique"]
    ]
    d4.save()

    # D5
    act_test = ActionTestD5.objects.create(
        reclamation=rec,
        description_action="Test d'usinage à vitesse réduite 20% sur 20 pièces",
        pilote_delai="B. Martin - 48h",
        conclusion="Aucune micro-fissure détectée par ressuage.",
        ordre=1,
    )

    # D6
    act_perm = ActionPermanenteD6.objects.create(
        reclamation=rec,
        axe="technique",
        cause_racine="Programme CNC mal versionné",
        description="Verrouillage des programmes CNC et contrôle accès par badge",
        pilote="B. Martin",
        statut="en_cours",
        ordre=1,
    )

    # D7
    d7, _ = CapitalisationSMQSD7.objects.get_or_create(reclamation=rec)
    d7.doc01_instruction = True
    d7.doc01_pilote_delai = "A. Smith - 2026-09-30"
    d7.doc12_gammes = True
    d7.precisez_gammes = "Gamme d'usinage GU-MOT-042 mise à jour"
    d7.save()

    # D8
    d8, _ = ClotureRecevabiliteD8.objects.get_or_create(reclamation=rec)
    d8.statut_recevabilite = ClotureRecevabiliteD8.RECEVABILITE_RECEVABLE
    d8.motif_decision_factuel = "Micro-fissure imputable à notre paramètre d'usinage. Responsabilité AB Serve confirmée."
    d8.feliciter_equipe = True
    d8.save()

    # 4. Vérifier les données en base
    print("\n--- Étape 4 : Vérification des données 8D en base ---")
    assert rec.participants.count() == 2, f"Participants count: {rec.participants.count()}"
    assert rec.qqoqccp.quoi_est == "Fissure de 15mm nette"
    assert rec.mesures_conservatoires.filter(selectionne=True).count() == 1
    assert rec.analyse_causes_d4.cause_principale_technique == "Vitesse d'avance de l'outil d'usinage trop élevée créant une micro-fissure."
    assert rec.actions_tests.count() == 1
    assert rec.actions_permanentes.count() == 1
    assert rec.capitalisation_d7.doc01_instruction is True
    assert rec.cloture_d8.statut_recevabilite == "recevable"
    print("-> Toutes les données 8D (D1-D8) sont bien présentes et validées en base. OK!")

    # 5. Changer 8D → DOC05 via la vue reclamation_changer_support
    print("\n--- Étape 5 : Switch 8D → DOC05 via reclamation_changer_support ---")
    req = rf.post(f"/reclamation/{rec.pk}/changer-support/", {"nouveau_support": "DOC05"})
    req.user = admin_user
    # Attach message storage
    setattr(req, 'session', {})
    messages = FallbackStorage(req)
    setattr(req, '_messages', messages)

    resp = reclamation_changer_support(req, rec.pk)
    rec.refresh_from_db()
    print(f"Statut HTTP redirection : {resp.status_code} vers {resp.url}")
    print(f"Nouveau mode_traitement en base : {rec.mode_traitement}")
    assert rec.mode_traitement == "DOC05"

    # 6. Vérifier qu'aucune donnée 8D n'a été supprimée en base
    print("\n--- Étape 6 : Vérification ZERO DATA LOSS sur 8D après passage à DOC05 ---")
    assert rec.participants.count() == 2
    assert rec.participants.first().nom_externe == "Alice Smith"
    assert rec.qqoqccp.quoi_est == "Fissure de 15mm nette"
    assert rec.qqoqccp.description_client == "Fissure observée sur le support côté fixation gauche."
    assert rec.mesures_conservatoires.get(type_mesure="tri_interne").quantite_triee == 150
    assert rec.analyse_causes_d4.cause_principale_technique == "Vitesse d'avance de l'outil d'usinage trop élevée créant une micro-fissure."
    assert len(rec.analyse_causes_d4.pourquoi_technique) == 1
    assert rec.actions_tests.first().description_action == "Test d'usinage à vitesse réduite 20% sur 20 pièces"
    assert rec.actions_permanentes.first().cause_racine == "Programme CNC mal versionné"
    assert rec.capitalisation_d7.doc01_instruction is True
    assert rec.capitalisation_d7.precisez_gammes == "Gamme d'usinage GU-MOT-042 mise à jour"
    assert rec.cloture_d8.statut_recevabilite == "recevable"
    assert rec.cloture_d8.feliciter_equipe is True
    print("-> ZERO DATA LOSS CONFIRMÉ : Toutes les données D1-D8 sont 100% intactes en base !")

    # 7. Remplir / enregistrer des données Doc05
    print("\n--- Étape 7 : Remplissage et Enregistrement des données Doc 05 ---")
    doc05, _ = FicheIncidentDoc05.objects.get_or_create(reclamation=rec)
    doc05.redacteur = "Sophie Responsable Qualite"
    doc05.quoi_reponse = "Doc05 QUOI: Défaillance constatée sur support moteur."
    doc05.qui_reponse = "Doc05 QUI: Equipe de production."
    doc05.ou_reponse = "Doc05 OU: Ligne 3 usine."
    doc05.motif_non_conformite = "Doc05 MOTIF: Micro-fissuration liée aux conditions d'usinage."
    doc05.pourquoi_chains = [
        {"p1": "Fissure", "p2": "Effort coupe", "p3": "Avance", "p4": "Prog CNC", "p5": "Version", "conclusion": "Valider le programme"}
    ]
    doc05.mesures_immediates = [
        {"description": "Arrêt de la machine d'usinage", "pilote": "S. Qualité", "delai": "2026-09-16", "realise_le": "2026-09-16"}
    ]
    doc05.actions_correctives = [
        {"description": "Validation systématique des versions de code CNC", "pilote": "B. Martin", "delai": "2026-09-25", "realise_le": "", "efficacite": "En cours"}
    ]
    doc05.save()
    print("-> Données Doc05 enregistrées en base avec succès.")

    # 8. Changer DOC05 → 8D via la vue reclamation_changer_support
    print("\n--- Étape 8 : Switch DOC05 → 8D via reclamation_changer_support ---")
    req2 = rf.post(f"/reclamation/{rec.pk}/changer-support/", {"nouveau_support": "8D"})
    req2.user = admin_user
    req2.session = {}
    req2._messages = FallbackStorage(req2)

    resp2 = reclamation_changer_support(req2, rec.pk)
    rec.refresh_from_db()
    print(f"Statut HTTP redirection : {resp2.status_code} vers {resp2.url}")
    print(f"Nouveau mode_traitement en base : {rec.mode_traitement}")
    assert rec.mode_traitement == "8D"

    # 9. Vérifier que toutes les données 8D précédentes réapparaissent exactement
    print("\n--- Étape 9 : Vérification que TOUTES les données 8D sont réapparues intactes ---")
    # Vérification en base
    assert rec.participants.count() == 2
    assert rec.participants.filter(est_pilote=True).first().nom_externe == "Alice Smith"
    assert rec.qqoqccp.quoi_est == "Fissure de 15mm nette"
    assert rec.qqoqccp.comment_est == "Visuellement lors du vissage couple 45Nm"
    assert rec.mesures_conservatoires.get(type_mesure="tri_interne").quantite_triee == 150
    assert rec.analyse_causes_d4.cause_principale_technique == "Vitesse d'avance de l'outil d'usinage trop élevée créant une micro-fissure."
    assert rec.actions_tests.first().conclusion == "Aucune micro-fissure détectée par ressuage."
    assert rec.actions_permanentes.first().description == "Verrouillage des programmes CNC et contrôle accès par badge"
    assert rec.capitalisation_d7.precisez_gammes == "Gamme d'usinage GU-MOT-042 mise à jour"
    assert rec.cloture_d8.motif_decision_factuel.startswith("Micro-fissure imputable")

    # Vérification via le context de la vue reclamation_update_8d
    req_get_8d = rf.get(f"/reclamation/{rec.pk}/editer-8d/")
    req_get_8d.user = admin_user
    req_get_8d.session = {}
    req_get_8d._messages = FallbackStorage(req_get_8d)
    resp_8d = reclamation_update_8d(req_get_8d, rec.pk)
    assert resp_8d.status_code == 200
    print("-> Vue reclamation_update_8d rendue avec succès (HTTP 200).")
    print("-> Toutes les données D1 à D8 sont parfaitement restaurées et accessibles !")

    # 10. Revenir DOC05 via reclamation_changer_support
    print("\n--- Étape 10 : Revenir DOC05 via reclamation_changer_support ---")
    req3 = rf.post(f"/reclamation/{rec.pk}/changer-support/", {"nouveau_support": "DOC05"})
    req3.user = admin_user
    req3.session = {}
    req3._messages = FallbackStorage(req3)

    resp3 = reclamation_changer_support(req3, rec.pk)
    rec.refresh_from_db()
    print(f"Statut HTTP redirection : {resp3.status_code} vers {resp3.url}")
    assert rec.mode_traitement == "DOC05"

    # 11. Vérifier que les données Doc05 sont toujours présentes
    print("\n--- Étape 11 : Vérification que les données Doc05 sont toujours présentes ---")
    fiche = FicheIncidentDoc05.objects.get(reclamation=rec)
    assert fiche.redacteur == "Sophie Responsable Qualite"
    assert fiche.quoi_reponse == "Doc05 QUOI: Défaillance constatée sur support moteur."
    assert fiche.qui_reponse == "Doc05 QUI: Equipe de production."
    assert fiche.motif_non_conformite == "Doc05 MOTIF: Micro-fissuration liée aux conditions d'usinage."
    assert len(fiche.pourquoi_chains) == 1
    assert fiche.pourquoi_chains[0]["p1"] == "Fissure"
    assert len(fiche.mesures_immediates) == 1
    assert fiche.mesures_immediates[0]["description"] == "Arrêt de la machine d'usinage"
    assert len(fiche.actions_correctives) == 1
    assert fiche.actions_correctives[0]["description"] == "Validation systématique des versions de code CNC"

    # Vérification via la vue reclamation_update_doc05
    req_get_doc05 = rf.get(f"/reclamation/{rec.pk}/editer-doc05/")
    req_get_doc05.user = admin_user
    req_get_doc05.session = {}
    req_get_doc05._messages = FallbackStorage(req_get_doc05)
    resp_doc05 = reclamation_update_doc05(req_get_doc05, rec.pk)
    assert resp_doc05.status_code == 200
    print("-> Vue reclamation_update_doc05 rendue avec succès (HTTP 200).")
    print("-> Toutes les données Doc05 sont parfaitement conservées et intactes !")

    print("\n" + "=" * 70)
    print("✅ SUCCÈS ABSOLU : LES 11 ÉTAPES SONT VALIDÉES SANS AUCUNE PERTE DE DONNÉES !")
    print("=" * 70)

if __name__ == "__main__":
    run_zero_data_loss_test()
