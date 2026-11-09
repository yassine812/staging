from unittest.mock import patch
import uuid

from django.db import IntegrityError
from django.test import Client, SimpleTestCase, TestCase
from django.urls import reverse

from accounts.models import Section, Societe, User
from .models import ClientAccountModule, CreatedClientAccount
from .countries import resolve_country


class CountryResolutionTests(SimpleTestCase):
    def test_free_text_names_and_common_spellings(self):
        for name, iso in [
            ("Maroc", "MA"), ("Morocco", "MA"), ("  CANADA  ", "CA"),
            ("Cote d'Ivoire", "CI"), ("Côte d’Ivoire", "CI"), ("USA", "US"),
            ("Etats Unis", "US"), ("Deutschland", "DE"), ("Polska", "PL"),
            ("المغرب", "MA"), ("Brasil", "BR"), ("Royaume Uni", "GB"),
        ]:
            with self.subTest(country=name):
                self.assertEqual(resolve_country(name)["iso"], iso)

    def test_capital_timezone_for_countries_with_multiple_zones(self):
        for name, timezone in [
            ("États-Unis", "America/New_York"), ("Canada", "America/Toronto"),
            ("Australie", "Australia/Sydney"), ("Brésil", "America/Sao_Paulo"),
            ("Russie", "Europe/Moscow"), ("Maroc", "Africa/Casablanca"),
        ]:
            with self.subTest(country=name):
                self.assertEqual(resolve_country(name)["timezone"], timezone)

    def test_all_dataset_codes_are_recognized_and_zones_are_valid(self):
        import csv
        from pathlib import Path
        import pytz
        with Path(__file__).with_name("data").joinpath("countries.csv").open(encoding="utf-8") as file:
            countries = list(csv.DictReader(file))
        self.assertEqual(len(countries), 250)
        for country in countries:
            with self.subTest(country=country["iso"]):
                self.assertEqual(resolve_country(country["iso"]), country)
                if country["timezone"]:
                    self.assertIn(country["timezone"], pytz.all_timezones_set)
        self.assertIsNone(resolve_country("pays inventé"))


class ClientAccountModuleTests(TestCase):
    def setUp(self):
        self.company = Societe.objects.create(nom="Société A")
        self.other_company = Societe.objects.create(nom="Société B")
        self.section = Section.objects.create(Nom="405 F SCANIA", societe=self.company)
        self.other_section = Section.objects.create(Nom="405 Autre site", societe=self.other_company)
        self.admin = User.objects.create_user(username="admin", is_superuser=True)
        self.rs = User.objects.create_user(username="rs", is_RS=True, societe=self.company)
        self.outsider = User.objects.create_user(username="rs-b", is_RS=True, societe=self.other_company)
        self.configure_url = reverse("client_accounts:configure", args=[self.company.pk])
        self.client.force_login(self.admin)
        self.client.post(self.configure_url, {"action": "activate"})
        self.module = ClientAccountModule.objects.get(admin=self.admin, societe=self.company)
        self.form_url = reverse("client_accounts:form", args=[self.module.token])
        self.search_url = reverse("client_accounts:sections", args=[self.module.token])
        self.create_url = reverse("client_accounts:create", args=[self.module.token])
        self.data = {
            "first_name": "Artur", "last_name": "Witus", "email": "artur@example.test",
            "pays": "Pologne", "section": self.section.pk,
        }
        self.client.force_login(self.rs)

    def test_creates_real_client_with_required_fields(self):
        response = self.client.post(self.create_url, self.data)
        self.assertEqual(response.status_code, 201, response.content)
        user = User.objects.get(username="AWitus")
        record = CreatedClientAccount.objects.get(user=user)
        self.assertEqual(response.json()["username"], user.username)
        self.assertRegex(record.matricule, r"^CLT405PL[0-9]{4}$")
        self.assertEqual(user.section, self.section)
        self.assertEqual(user.societe.nom, "Client")
        self.assertEqual(user.timezone, "Europe/Warsaw")
        self.assertTrue(user.is_active and user.is_CLT and user.has_usable_password())
        self.assertFalse(user.is_staff or user.is_superuser or user.is_RS)
        self.assertIsNone(user.customer_id)
        self.assertIsNone(user.cout_horaire)
        self.assertEqual(list(user.groups.values_list("name", flat=True)), ["CLT"])
        self.assertNotIn("password", response.json())

    def test_admin_module_and_rs_form_render_with_live_urls(self):
        response = self.client.get(self.form_url)
        self.assertContains(response, self.search_url)
        self.assertContains(response, self.create_url)
        self.assertContains(response, 'name="csrfmiddlewaretoken"')
        self.assertNotContains(response, 'nav-sidebar')
        self.assertNotContains(response, reverse("administration:utilisateurs"))
        self.client.force_login(self.admin)
        response = self.client.get(reverse("client_accounts:manage"))
        self.assertContains(response, self.form_url)
        self.assertContains(response, 'Création de comptes clients')
        self.assertContains(response, 'class="nav-link active"')
        self.assertContains(self.client.get(reverse("home")), reverse("client_accounts:manage"))

    def test_shared_form_does_not_grant_administration_access(self):
        self.assertEqual(self.client.get(self.form_url).status_code, 200)
        for name in ("administration:dashboard", "administration:utilisateurs",
                     "client_accounts:manage"):
            with self.subTest(page=name):
                self.assertEqual(self.client.get(reverse(name)).status_code, 403)
        self.rs.refresh_from_db()
        self.assertFalse(self.rs.is_superuser or self.rs.is_staff)
        self.assertEqual(str(self.client.session["_auth_user_id"]), str(self.rs.pk))

    def test_duplicate_email_keeps_a_single_account(self):
        self.assertEqual(self.client.post(self.create_url, self.data).status_code, 201)
        self.data["email"] = "ARTUR@EXAMPLE.TEST"
        response = self.client.post(self.create_url, self.data)
        self.assertEqual(response.status_code, 400)
        self.assertIn("email", response.json()["errors"])
        self.assertEqual(CreatedClientAccount.objects.count(), 1)

    def test_client_destination_company_cannot_publish_a_form(self):
        destination = Societe.objects.get(nom="Client")
        legacy_module = ClientAccountModule.objects.create(
            admin=self.admin, societe=destination, enabled=True,
        )
        self.client.force_login(self.admin)
        response = self.client.get(reverse("client_accounts:manage"))
        self.assertEqual([row["societe"] for row in response.context["rows"]],
                         [self.company, self.other_company])
        self.assertEqual(self.client.post(
            reverse("client_accounts:configure", args=[destination.pk]),
            {"action": "activate"},
        ).status_code, 404)
        self.client.logout()
        for name in ("form", "sections", "create"):
            url = reverse(f"client_accounts:{name}", args=[legacy_module.token])
            with self.subTest(endpoint=name):
                response = self.client.post(url, self.data) if name == "create" else self.client.get(url)
                self.assertEqual(response.status_code, 404)
        self.assertFalse(CreatedClientAccount.objects.exists())
        self.assertTrue(Societe.objects.filter(pk=destination.pk).exists())

    def test_existing_account_email_is_rejected(self):
        User.objects.create_user(username="legacy", email="ARTUR@example.test")
        response = self.client.post(self.create_url, self.data)
        self.assertEqual(response.status_code, 400)
        self.assertFalse(CreatedClientAccount.objects.exists())

    def test_existing_username_with_different_case_gets_a_suffix(self):
        User.objects.create_user(username="awitus")
        response = self.client.post(self.create_url, self.data)
        self.assertEqual(response.status_code, 201, response.content)
        self.assertEqual(response.json()["username"], "AWitus1")

    @patch("client_accounts.creation.secrets.randbelow", return_value=32)
    def test_identifier_collisions_choose_next_available_values(self, random_suffix):
        first = self.client.post(self.create_url, self.data)
        self.data["email"] = "another@example.test"
        second = self.client.post(self.create_url, self.data)
        self.assertEqual(first.json()["matricule"], "CLT405PL0032")
        self.assertEqual(second.json()["matricule"], "CLT405PL0033")
        self.assertEqual(second.json()["username"], "AWitus1")

    def test_search_uses_current_company_data_and_exact_code(self):
        Section.objects.create(Nom="4050", societe=self.company)
        second = Section.objects.create(Nom="405 Deuxième", societe=self.company)
        results = self.client.get(self.search_url, {"code": "405"}).json()["sections"]
        self.assertEqual({item["id"] for item in results}, {str(self.section.pk), str(second.pk)})
        self.data["section"] = self.other_section.pk
        self.assertEqual(self.client.post(self.create_url, self.data).status_code, 400)
        self.assertFalse(CreatedClientAccount.objects.exists())

    def test_management_stays_admin_only(self):
        self.assertEqual(self.client.get(reverse("client_accounts:manage")).status_code, 403)
        self.assertEqual(self.client.post(self.configure_url, {"action": "activate"}).status_code, 403)
        self.client.logout()
        self.assertEqual(self.client.get(reverse("client_accounts:manage")).status_code, 302)
        self.assertEqual(self.client.post(self.configure_url, {"action": "activate"}).status_code, 302)

    def test_anonymous_link_creates_client_without_logging_visitor_in(self):
        client = Client(enforce_csrf_checks=True)
        response = client.get(self.form_url)
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response["Referrer-Policy"], "no-referrer")
        self.assertNotContains(response, 'nav-sidebar')
        results = client.get(self.search_url, {"code": "405"}).json()["sections"]
        self.assertEqual([item["id"] for item in results], [str(self.section.pk)])
        csrf = client.cookies["csrftoken"].value
        response = client.post(self.create_url, self.data, HTTP_X_CSRFTOKEN=csrf)
        self.assertEqual(response.status_code, 201, response.content)
        record = CreatedClientAccount.objects.get()
        self.assertIsNone(record.created_by)
        self.assertFalse(record.user.is_staff or record.user.is_superuser or record.user.is_RS)
        self.assertNotIn("_auth_user_id", client.session)
        for name in ("administration:dashboard", "administration:utilisateurs",
                     "client_accounts:manage"):
            with self.subTest(page=name):
                self.assertEqual(client.get(reverse(name)).status_code, 302)
        self.assertEqual(client.post(self.configure_url, {"action": "deactivate"},
                                     HTTP_X_CSRFTOKEN=csrf).status_code, 302)
        self.module.refresh_from_db()
        self.assertTrue(self.module.enabled)

    def test_anonymous_visitor_cannot_select_another_company_or_grant_roles(self):
        self.client.logout()
        self.data["section"] = self.other_section.pk
        self.assertEqual(self.client.post(self.create_url, self.data).status_code, 400)
        self.data.update(section=self.section.pk, is_staff=True, is_superuser=True,
                         is_RS=True, societe=self.other_company.pk)
        self.assertEqual(self.client.post(self.create_url, self.data).status_code, 201)
        user = CreatedClientAccount.objects.get().user
        self.assertFalse(user.is_staff or user.is_superuser or user.is_RS)
        self.assertEqual(user.societe.nom, "Client")

    def test_unknown_or_inactive_owner_link_is_rejected(self):
        self.client.logout()
        token = uuid.uuid4()
        self.assertEqual(self.client.get(reverse("client_accounts:form", args=[token])).status_code, 404)
        self.assertEqual(self.client.get(reverse("client_accounts:sections", args=[token]), {"code": "405"}).status_code, 404)
        self.assertEqual(self.client.post(reverse("client_accounts:create", args=[token]), self.data).status_code, 404)
        self.admin.is_active = False
        self.admin.save(update_fields=["is_active"])
        self.assertEqual(self.client.get(self.form_url).status_code, 404)
        self.assertEqual(self.client.get(self.search_url, {"code": "405"}).status_code, 404)
        self.assertEqual(self.client.post(self.create_url, self.data).status_code, 404)
        self.assertFalse(CreatedClientAccount.objects.exists())

    def test_disabled_and_reactivated_module_revokes_old_links(self):
        self.client.force_login(self.admin)
        self.client.post(self.configure_url, {"action": "deactivate"})
        self.client.logout()
        self.assertEqual(self.client.get(self.form_url).status_code, 404)
        self.assertEqual(self.client.get(self.search_url, {"code": "405"}).status_code, 404)
        self.assertEqual(self.client.post(self.create_url, self.data).status_code, 404)
        self.client.force_login(self.admin)
        self.client.post(self.configure_url, {"action": "activate"})
        self.client.logout()
        self.assertEqual(self.client.get(self.form_url).status_code, 404)
        self.assertFalse(CreatedClientAccount.objects.exists())

    def test_creation_requires_csrf(self):
        client = Client(enforce_csrf_checks=True)
        self.assertEqual(client.post(self.create_url, self.data).status_code, 403)

    @patch("client_accounts.creation.CreatedClientAccount.objects.create", side_effect=IntegrityError)
    def test_partial_failure_rolls_back_the_user(self, create_record):
        self.assertEqual(self.client.post(self.create_url, self.data).status_code, 409)
        self.assertFalse(User.objects.filter(username="AWitus").exists())

    def test_invalid_country_does_not_create_a_user(self):
        self.data["pays"] = "inconnu"
        self.assertEqual(self.client.post(self.create_url, self.data).status_code, 400)
        self.assertFalse(CreatedClientAccount.objects.exists())

    def test_new_countries_create_accounts_from_typed_names(self):
        for country, code, timezone in [
            ("Maroc", "MA", "Africa/Casablanca"),
            ("CANADA", "CA", "America/Toronto"),
            ("Germany", "GR", "Europe/Berlin"),
        ]:
            with self.subTest(country=country):
                self.data.update(pays=country, email=f"client-{code}@example.test")
                response = self.client.post(self.create_url, self.data)
                self.assertEqual(response.status_code, 201, response.content)
                user = User.objects.get(username=response.json()["username"])
                self.assertEqual(user.pays, country)
                self.assertEqual(user.timezone, timezone)
                self.assertTrue(response.json()["matricule"].startswith(f"CLT405{code}"))
