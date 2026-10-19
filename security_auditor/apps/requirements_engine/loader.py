"""Load the 137-requirement catalogue and the requirement->scanner mapping.

Requirements are first-class data (spec 40): adding a requirement means
adding it to the catalogue and re-generating, never code changes.
"""
from __future__ import annotations

from pathlib import Path
from typing import Optional

import yaml

ROOT = Path(__file__).resolve().parents[2]
DEFAULT_REQUIREMENTS_PATH = ROOT / "requirements" / "django_137_requirements.yml"
DEFAULT_MAPPING_PATH = ROOT / "rules" / "requirement_mapping.yml"


class Requirement:
    """First-class requirement object (spec 6)."""

    __slots__ = ("id", "name", "description", "category", "severity",
                 "verification_method", "automation_level", "scanner_mapping",
                 "cwe", "owasp", "test_definition", "remediation")

    def __init__(self, data: dict):
        self.id = data["id"]
        self.name = data["name"]
        self.description = data.get("description", "")
        self.category = data["category"]
        self.severity = data["severity"]
        self.verification_method = list(data.get("verification_method") or data.get("verification") or [])
        self.automation_level = data["automation_level"]
        self.scanner_mapping = data.get("scanner_mapping", {}) or {}
        self.cwe = list(data.get("cwe", []))
        self.owasp = data.get("owasp", "")
        self.test_definition = data.get("test_definition", [])
        self.remediation = data.get("remediation", "")

    @property
    def is_manual(self) -> bool:
        # "manual" among verification methods only adds review notes; the
        # automation_level is authoritative (spec 42).
        return self.automation_level in ("MANUAL", "NOT_AUTOMATABLE")

    def to_dict(self) -> dict:
        return {slot: getattr(self, slot) for slot in self.__slots__}


def load_requirements(path: Optional[str] = None) -> list[Requirement]:
    p = Path(path) if path else DEFAULT_REQUIREMENTS_PATH
    data = yaml.safe_load(p.read_text(encoding="utf-8"))
    reqs = [Requirement(item) for item in data]
    ids = [r.id for r in reqs]
    if len(ids) != len(set(ids)):
        raise ValueError("duplicate requirement ids in catalogue")
    return reqs


def load_mapping(path: Optional[str] = None) -> dict:
    p = Path(path) if path else DEFAULT_MAPPING_PATH
    return yaml.safe_load(p.read_text(encoding="utf-8")) or {}
