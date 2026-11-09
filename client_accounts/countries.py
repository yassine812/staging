import csv
import unicodedata
from functools import lru_cache
from pathlib import Path

from babel import Locale


ALIASES = {
    "US": ("USA", "United States of America", "États-Unis d’Amérique"),
    "GB": ("UK", "Great Britain", "Grande-Bretagne"),
    "AE": ("UAE", "EAU"),
    "CI": ("Ivory Coast",),
    "CD": ("RDC", "DRC", "République démocratique du Congo", "Congo Kinshasa"),
    "CG": ("République du Congo", "Congo Brazzaville"),
    "CZ": ("Czech Republic", "République tchèque"),
    "TR": ("Turkey", "Türkiye"),
    "SZ": ("Swaziland",),
    "CV": ("Cape Verde", "Cap-Vert"),
}


def normalize_country(value):
    value = unicodedata.normalize("NFKD", value.casefold())
    return "".join(character for character in value if character.isalnum())


@lru_cache(maxsize=1)
def _country_names():
    locales = [Locale.parse(language) for language in ("fr", "en", "de", "pl", "ar", "es", "pt")]
    names = {}
    with Path(__file__).with_name("data").joinpath("countries.csv").open(encoding="utf-8", newline="") as file:
        for country in csv.DictReader(file):
            iso = country["iso"]
            aliases = [iso, country["iso3"], country["name"], *ALIASES.get(iso, ())]
            aliases.extend(locale.territories.get(iso, "") for locale in locales)
            for alias in aliases:
                key = normalize_country(alias)
                if not key:
                    continue
                if key in names and names[key] != country:
                    names[key] = None  # Require clarification for ambiguous names.
                else:
                    names[key] = country
    return names


def resolve_country(value):
    return _country_names().get(normalize_country(value))
