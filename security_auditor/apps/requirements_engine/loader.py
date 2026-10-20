"""Load the 137-requirement catalogue and the requirement->scanner mapping.

Requirements are first-class data (spec 40): adding a requirement means
adding it to the catalogue and re-generating, never code changes.
"""
from __future__ import annotations

import os
from pathlib import Path
from typing import Optional

import yaml

ROOT = Path(__file__).resolve().parents[2]
DEFAULT_REQUIREMENTS_PATH = ROOT / "django_137_requirements.yml"
DEFAULT_MAPPING_PATH = ROOT / "rules" / "requirement_mapping.yml"
OVERRIDES_PATH = Path(os.environ.get(
    "SECURITY_AUDITOR_REQUIREMENTS_OVERRIDES",
    str(ROOT / "requirements_overrides.yml"),
))


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


def _base_records(path: Optional[str] = None) -> list[dict]:
    p = Path(path) if path else DEFAULT_REQUIREMENTS_PATH
    data = yaml.safe_load(p.read_text(encoding="utf-8")) or []
    if isinstance(data, dict):
        data = data.get("requirements", [])
    return [dict(item) for item in data]


def _read_overrides() -> dict:
    if not OVERRIDES_PATH.exists():
        return {"overrides": {}, "added": [], "deleted": []}
    data = yaml.safe_load(OVERRIDES_PATH.read_text(encoding="utf-8")) or {}
    return {
        "overrides": data.get("overrides", {}) or {},
        "added": data.get("added", []) or [],
        "deleted": data.get("deleted", []) or [],
    }


def _write_overrides(data: dict) -> None:
    OVERRIDES_PATH.parent.mkdir(parents=True, exist_ok=True)
    temporary = OVERRIDES_PATH.with_suffix(OVERRIDES_PATH.suffix + ".tmp")
    temporary.write_text(yaml.safe_dump(data, allow_unicode=True, sort_keys=False), encoding="utf-8")
    temporary.replace(OVERRIDES_PATH)


def _clear_axis_cache() -> None:
    # The axis module caches the catalogue mapping for scan speed.  An
    # administrator change must become visible to the next page/scan in the
    # same process as well.
    try:
        from security_auditor.apps.audits.axes import _catalogue_axes, _catalogue_axes_all
        _catalogue_axes.cache_clear()
        _catalogue_axes_all.cache_clear()
    except Exception:  # noqa: BLE001 - catalogue writes must not fail on an optional cache
        pass


def catalogue_records() -> list[dict]:
    """Return the effective catalogue, including administrator changes."""
    records = {str(item.get("id")): item for item in _base_records()}
    changes = _read_overrides()
    for req_id in changes["deleted"]:
        records.pop(str(req_id), None)
    for req_id, item in changes["overrides"].items():
        records[str(req_id)] = dict(item)
    for item in changes["added"]:
        records[str(item.get("id"))] = dict(item)
    return list(records.values())


def load_requirements(path: Optional[str] = None) -> list[Requirement]:
    records = _base_records(path) if path else catalogue_records()
    reqs = [Requirement(item) for item in records]
    ids = [r.id for r in reqs]
    if len(ids) != len(set(ids)):
        raise ValueError("duplicate requirement ids in catalogue")
    return reqs


def _normalise_record(data: dict, existing: dict | None = None) -> dict:
    merged = dict(existing or {})
    merged.update({key: value for key, value in data.items() if value is not None})
    required = ("id", "name", "category", "severity", "automation_level")
    missing = [key for key in required if not str(merged.get(key, "")).strip()]
    if missing:
        raise ValueError("Champs obligatoires manquants : " + ", ".join(missing))
    merged["id"] = str(merged["id"]).strip()
    merged["verification_method"] = list(merged.get("verification_method") or [])
    merged["cwe"] = list(merged.get("cwe") or [])
    merged["scanner_mapping"] = dict(merged.get("scanner_mapping") or {})
    merged["test_definition"] = list(merged.get("test_definition") or [])
    # Validate the same shape used by the scanner before persisting it.
    Requirement(merged)
    return merged


def save_catalogue_requirement(data: dict, requirement_id: str | None = None) -> dict:
    """Create or update one requirement without editing the shipped catalogue."""
    changes = _read_overrides()
    effective = {item["id"]: item for item in catalogue_records()}
    old_id = str(requirement_id or data.get("id") or "").strip()
    existing = effective.get(old_id)
    record = _normalise_record(data, existing)
    new_id = record["id"]
    if requirement_id and old_id != new_id:
        raise ValueError("L'identifiant d'une exigence existante ne peut pas être modifié")
    if not existing and new_id in effective:
        raise ValueError("Cet identifiant d'exigence existe déjà")
    base_ids = {item["id"] for item in _base_records()}
    changes["deleted"] = [item for item in changes["deleted"] if str(item) != new_id]
    if existing and old_id in base_ids:
        changes["overrides"][new_id] = record
    elif existing:
        changes["added"] = [item for item in changes["added"] if item.get("id") != new_id]
        changes["added"].append(record)
    else:
        changes["added"].append(record)
    _write_overrides(changes)
    _clear_axis_cache()
    return record


def delete_catalogue_requirement(requirement_id: str) -> None:
    """Hide a shipped requirement or remove an administrator-added one."""
    req_id = str(requirement_id).strip()
    effective = {item["id"]: item for item in catalogue_records()}
    if req_id not in effective:
        raise KeyError(req_id)
    changes = _read_overrides()
    base_ids = {item["id"] for item in _base_records()}
    if req_id in base_ids:
        if req_id not in changes["deleted"]:
            changes["deleted"].append(req_id)
        changes["overrides"].pop(req_id, None)
    else:
        changes["added"] = [item for item in changes["added"] if item.get("id") != req_id]
    _write_overrides(changes)
    _clear_axis_cache()


def load_mapping(path: Optional[str] = None) -> dict:
    p = Path(path) if path else DEFAULT_MAPPING_PATH
    return yaml.safe_load(p.read_text(encoding="utf-8")) or {}
