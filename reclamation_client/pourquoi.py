"""Helpers for keeping the Doc.83 5-Pourquoi data compatible with AT."""


def _as_text(value):
    return "" if value is None else str(value)


def _normalise_branch(raw):
    """Return one AT-compatible branch containing exactly five values."""
    if isinstance(raw, dict):
        if isinstance(raw.get("pourquoi"), list):
            values = raw["pourquoi"]
        elif "pourquoi" in raw and "justification" in raw:
            values = [raw.get("pourquoi", ""), "", "", "", raw.get("justification", "")]
        elif "pourquoi" in raw:
            values = [raw.get("pourquoi", "")]
        elif isinstance(raw.get("chain"), list):
            values = raw["chain"]
        else:
            # Legacy D4 records used {etape, pourquoi, justification}.
            values = [raw.get("pourquoi", ""), "", "", "", raw.get("justification", "")]
    elif isinstance(raw, list):
        values = raw
    else:
        values = [raw]

    result = []
    for value in values[:5]:
        if isinstance(value, dict):
            value = value.get("pourquoi", "")
        result.append(_as_text(value))
    result.extend([""] * (5 - len(result)))
    return result[:5]


def normalise_arbre(raw, cause_label=""):
    """Convert legacy Doc.83 values to the exact AT tree shape.

    This function is read-time compatibility only: it does not write anything
    to the database. Empty new analyses remain empty (no example branch).
    """
    if isinstance(raw, dict) and isinstance(raw.get("causes"), list):
        return raw

    if isinstance(raw, dict) and isinstance(raw.get("branches"), list):
        return {
            "causes": [{
                "label": _as_text(raw.get("label", cause_label)),
                "branches": [_normalise_branch(branch) for branch in raw["branches"]],
            }]
        }

    if not isinstance(raw, list) or not raw:
        return {"causes": []}

    branches = [_normalise_branch(item) for item in raw]
    return {
        "causes": [{
            "label": _as_text(cause_label),
                "branches": [{"pourquoi": branch} for branch in branches],
        }]
    }


def arbre_has_content(arbre):
    """Whether an AT-shaped tree contains a non-empty user value."""
    if not isinstance(arbre, dict):
        return False
    for cause in arbre.get("causes", []):
        if str(cause.get("label", "")).strip():
            return True
        for branch in cause.get("branches", []):
            if any(str(value or "").strip() for value in branch.get("pourquoi", [])):
                return True
    return False


def selected_root_causes(arbre):
    """Return only explicitly selected, non-empty P5 values from a Doc.83 tree."""
    selected = []
    tree = normalise_arbre(arbre)
    for cause in tree.get("causes", []):
        if not isinstance(cause, dict):
            continue
        for branch in cause.get("branches", []):
            if not isinstance(branch, dict) or branch.get("pdf_selected") is not True:
                continue
            values = branch.get("pourquoi") or []
            if isinstance(values, list) and len(values) >= 5:
                p5 = _as_text(values[4]).strip()
                if p5:
                    selected.append(p5)
    return selected
