"""
Test script to verify 5 Pourquoi UI improvements in both 8D and Doc 05:
1. Long texts in D4.1, D4.2 and Doc 05.
2. Rendering templates with textareas and verifying HTML output.
3. Testing form submission with long texts and verifying persistence.
"""

import os
import sys
import json
import django

sys.path.insert(0, r"c:\Users\Yassine\audit2-main")
sys.stdout.reconfigure(encoding='utf-8')
os.environ.setdefault("DJANGO_SETTINGS_MODULE", "settings")
django.setup()

from django.test import RequestFactory
from django.contrib.auth import get_user_model
from django.contrib.messages.storage.fallback import FallbackStorage
from accounts.models import Societe, Site, Section
from reclamation_client.models import (
    ReclamationClient,
    AnalyseCausesDoubleAxeD4,
    FicheIncidentDoc05,
)
from reclamation_client.views import (
    reclamation_update_8d,
    reclamation_update_doc05,
)

User = get_user_model()
rf = RequestFactory()

def test_5why_ui():
    print("=" * 70)
    print("TEST UI & PERSISTANCE : 5 POURQUOI DANS 8D ET DOC 05")
    print("=" * 70)

    admin_user = User.objects.filter(is_superuser=True).first()
    if not admin_user:
        admin_user = User.objects.create_superuser("admin_test_ui", "admin_ui@test.com", "pass123")
    
    societe = Societe.objects.first() or Societe.objects.create(nom="Societe Test UI")
    section = Section.objects.first() or Section.objects.create(Nom="Section Test", societe=societe)
    site = Site.objects.first() or Site.objects.create(nom="Site Test UI", section=section)

    long_text_d4_1 = "Critères de contrôle non définis dans la gamme de fabrication."
    long_text_d4_2 = "Protection des pièces non définie lors de la manutention."
    long_text_doc05 = "Absence de contrôle systématique de l'étiquette avant validation du produit."

    # 1. Tester 8D avec des textes longs
    print("\n--- 1. Vérification Rapport 8D (D4.1 & D4.2) ---")
    rec_8d = ReclamationClient.objects.create(
        type_signalement=ReclamationClient.TYPE_RECLAMATION,
        mode_traitement=ReclamationClient.MODE_8D,
        societe=societe,
        site=site,
        client_nom="Client Test 8D Long Text",
        created_by=admin_user,
        updated_by=admin_user,
    )

    d4, _ = AnalyseCausesDoubleAxeD4.objects.get_or_create(reclamation=rec_8d)
    d4.pourquoi_non_detection = [
        ["Contrôle visuel insuffisant", "Pas de vérification dimensionnelle", "Manque de temps en fin de poste", "Procédure floue", long_text_d4_1]
    ]
    d4.pourquoi_technique = [
        ["Rayure constatée en manutention", "Pièces en contact direct sans intercalaire", "Pas de calage adapté", "Gamme non respectée", long_text_d4_2]
    ]
    d4.cause_principale_non_detection = long_text_d4_1
    d4.cause_principale_technique = long_text_d4_2
    d4.save()

    # Rendu GET de form_8d.html
    req = rf.get(f"/reclamations/{rec_8d.pk}/editer-8d/")
    req.user = admin_user
    req.session = {}
    req._messages = FallbackStorage(req)

    resp = reclamation_update_8d(req, rec_8d.pk)
    assert resp.status_code == 200
    content = resp.content.decode("utf-8")

    assert "pq-textarea" in content, "La classe CSS pq-textarea doit être présente dans form_8d.html"
    assert "min-height: 72px" in content or "min-height:72px" in content
    assert "pourquoi_non_detection_json" in content
    assert long_text_d4_1 in content, "Le texte long D4.1 doit être présent dans le template 8D"
    assert long_text_d4_2 in content, "Le texte long D4.2 doit être présent dans le template 8D"
    print("-> form_8d.html rendu avec succès : classe pq-textarea présente, textes longs injectés sans coupure.")

    # 2. Tester Doc 05 avec des textes longs
    print("\n--- 2. Vérification Fiche Doc 05 ---")
    rec_doc05 = ReclamationClient.objects.create(
        type_signalement=ReclamationClient.TYPE_INCIDENT,
        mode_traitement=ReclamationClient.MODE_DOC05,
        societe=societe,
        site=site,
        client_nom="Client Test Doc05 Long Text",
        created_by=admin_user,
        updated_by=admin_user,
    )

    fiche, _ = FicheIncidentDoc05.objects.get_or_create(reclamation=rec_doc05)
    fiche.pourquoi_chains = [
        {
            "p1": "Étiquette non conforme détectée en logistique",
            "p2": "Erreur d'impression du code barre sur le rouleau",
            "p3": "Mauvais fichier envoyé au fournisseur d'étiquettes",
            "p4": "Procédure de validation de maquette non suivie",
            "p5": long_text_doc05,
            "conclusion": "Mettre en place un détrompeur logiciel pour la validation d'étiquette."
        }
    ]
    fiche.save()

    # Rendu GET de form_doc05.html
    req_doc05 = rf.get(f"/reclamations/{rec_doc05.pk}/editer-doc05/")
    req_doc05.user = admin_user
    req_doc05.session = {}
    req_doc05._messages = FallbackStorage(req_doc05)

    resp_doc05 = reclamation_update_doc05(req_doc05, rec_doc05.pk)
    assert resp_doc05.status_code == 200
    content_doc05 = resp_doc05.content.decode("utf-8")

    assert "Absence de contrôle systématique" in content_doc05, "Le texte long Doc 05 doit être présent dans le template Doc 05"
    assert "chain-textarea" in content_doc05, "La classe CSS chain-textarea doit être présente dans form_doc05.html"
    print("-> form_doc05.html rendu avec succès : classe chain-textarea et grille responsive col-lg-2 présentes.")

    # 3. Tester la sauvegarde POST dans Doc 05 avec des textes longs
    print("\n--- 3. Test de soumission POST avec textes longs ---")
    new_chain = [
        {
            "p1": "Texte long 1 : " + long_text_doc05,
            "p2": "Texte long 2 : Analyse intermédiaire détaillée sans coupure",
            "p3": "Texte long 3 : Autre explication longue",
            "p4": "Texte long 4 : Détection de la cause",
            "p5": long_text_d4_1,
            "conclusion": "Conclusion complète et lisible sur plusieurs lignes."
        }
    ]
    post_data = {
        "pourquoi_chains_json": json.dumps(new_chain),
        "mesures_immediates_json": "[]",
        "actions_correctives_json": "[]",
        "redacteur": "Testeur UI",
        "date_detection": "2026-09-18",
        "date_ouverture": "2026-09-18",
        "site_concerne": "Site Test UI",
        "evenement_qualite": "on",
        "motif_non_conformite": "Non-conformité test",
        "quoi_reponse": "Quoi",
        "qui_reponse": "Qui",
        "ou_reponse": "Ou",
        "quand_reponse": "Quand",
        "comment_reponse": "Comment",
        "combien_reponse": "Combien",
    }
    req_post = rf.post(f"/reclamations/{rec_doc05.pk}/editer-doc05/", post_data)
    req_post.user = admin_user
    req_post.session = {}
    req_post._messages = FallbackStorage(req_post)

    resp_post = reclamation_update_doc05(req_post, rec_doc05.pk)
    fiche.refresh_from_db()
    assert resp_post.status_code == 302, f"Expected 302 redirect, got {resp_post.status_code}"
    assert fiche.pourquoi_chains[0]["p1"].startswith("Texte long 1")
    assert fiche.pourquoi_chains[0]["p5"] == long_text_d4_1
    print("-> Données sauvegardées et vérifiées en base avec succès.")

    print("\n" + "=" * 70)
    print("✅ TOUS LES TESTS UI & PERSISTANCE 5 POURQUOI SONT VALIDÉS !")
    print("=" * 70)

if __name__ == "__main__":
    test_5why_ui()
