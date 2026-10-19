"""Project discovery: build a profile of the target without executing its code.

Detects Django presence and version, Python version, database, DRF/GraphQL,
frontend stack, authentication approach, deployment, workers, cache, storage
and dependencies (spec 5).  Purely static - the target's code is never run
during discovery.
"""
from __future__ import annotations

import re
from pathlib import Path

EXCLUDED_DIRS = {
    ".git", ".hg", ".svn", "__pycache__", "node_modules", ".venv", "venv",
    "env", ".tox", ".nox", ".mypy_cache", ".pytest_cache", "dist", "build",
    ".next", "site-packages", ".idea", ".vscode",
}

MARKER_FILES = [
    "manage.py", "settings.py", "requirements.txt", "pyproject.toml",
    "Pipfile", "poetry.lock", "urls.py", "apps.py", "models.py", "views.py",
    "serializers.py", "permissions.py", "Dockerfile", "docker-compose.yml",
    "docker-compose.yaml", ".env", "setup.py", "setup.cfg",
]

_REQ_LINE = re.compile(r"^\s*([A-Za-z0-9][A-Za-z0-9._-]*)\s*(\[[^\]]*\])?\s*(.*)$")


def _read(path: Path, limit: int = 400_000) -> str:
    try:
        return path.read_text(encoding="utf-8", errors="replace")[:limit]
    except OSError:
        return ""


def walk_source(source_dir: str):
    """Yield Path objects, skipping excluded directories and binary-ish files."""
    root = Path(source_dir)
    for path in sorted(root.rglob("*")):
        if path.is_dir():
            continue
        parts = set(path.relative_to(root).parts[:-1])
        if parts & EXCLUDED_DIRS:
            continue
        if path.stat().st_size > 2_000_000:
            continue
        yield path


def parse_requirements_txt(text: str, base_dir: Path, seen: set | None = None) -> list[dict]:
    """Parse requirements.txt (with -r includes) into [{name, specifier, line}]."""
    seen = seen or set()
    deps: list[dict] = []
    for raw in text.splitlines():
        line = raw.split("#", 1)[0].strip()
        if not line:
            continue
        if line.startswith(("-r", "--requirement")):
            target = line.split(None, 1)[1].strip()
            inc = (base_dir / target).resolve()
            try:
                inc.relative_to(base_dir.resolve())
            except ValueError:
                continue
            if inc.is_file() and str(inc) not in seen:
                seen.add(str(inc))
                deps.extend(parse_requirements_txt(_read(inc), inc.parent, seen))
            continue
        if line.startswith(("-e", "--", "git+", "http://", "https://")):
            name = line.rsplit("/", 1)[-1].split(".git")[0] or line
            deps.append({"name": name, "specifier": "(vcs/editable)", "line": raw})
            continue
        m = _REQ_LINE.match(line)
        if m:
            deps.append({"name": m.group(1), "specifier": (m.group(3) or "").strip().split(";")[0].strip(),
                         "line": raw})
    return deps


def _deps_from_pyproject(text: str) -> list[dict]:
    try:
        import tomllib
        data = tomllib.loads(text)
    except Exception:
        return []
    deps = []
    project = data.get("project", {}) or {}
    for entry in project.get("dependencies", []) or []:
        m = _REQ_LINE.match(entry)
        if m:
            deps.append({"name": m.group(1), "specifier": (m.group(3) or "").strip(), "line": entry})
    for group in (data.get("dependency-groups", {}) or {}).values():
        for entry in group or []:
            if isinstance(entry, str):
                m = _REQ_LINE.match(entry)
                if m:
                    deps.append({"name": m.group(1), "specifier": (m.group(3) or "").strip(), "line": entry})
    poetry = (data.get("tool", {}) or {}).get("poetry", {}) or {}
    for section in ("dependencies", "dev-dependencies"):
        for name, spec in (poetry.get(section, {}) or {}).items():
            if name.lower() == "python":
                continue
            deps.append({"name": name, "specifier": spec if isinstance(spec, str) else str(spec),
                         "line": f"{name} (poetry)"})
    return deps


def _detect(names_lower: set, text_blob: str, *needles: str) -> bool:
    return any(n in names_lower for n in needles) or any(n in text_blob for n in needles)


def discover_project(source_dir: str) -> dict:
    root = Path(source_dir)
    profile: dict = {
        "path": str(root.resolve()),
        "is_django": False,
        "django_version_hint": None,
        "python_version_hint": None,
        "databases": [],
        "api": [],
        "frontend": [],
        "auth": [],
        "deployment": [],
        "workers": [],
        "cache": [],
        "storage": [],
        "dependencies": [],
        "markers": [],
        "settings_files": [],
        "urls_files": [],
        "stats": {"python_files": 0, "template_files": 0, "lines_of_python": 0},
    }
    if not root.is_dir():
        return profile

    dep_names: set[str] = set()
    dep_blob: list[dict] = []

    # ---- dependency manifests -------------------------------------------
    for req_file in list(root.glob("requirements.txt")) + list(root.glob("requirements/*.txt")):
        if req_file.is_file():
            dep_blob.extend(parse_requirements_txt(_read(req_file), req_file.parent))
    pyproject = root / "pyproject.toml"
    if pyproject.is_file():
        dep_blob.extend(_deps_from_pyproject(_read(pyproject)))
    pipfile = root / "Pipfile"
    if pipfile.is_file():
        for line in _read(pipfile).splitlines():
            m = re.match(r'^\s*"?([A-Za-z0-9._-]+)"?\s*=\s*"?([^"#\n]*)', line)
            if m and m.group(1).lower() not in ("python_version", "url", "verify_ssl",
                                                 "name", "requires", "packages", "dev-packages"):
                dep_blob.append({"name": m.group(1), "specifier": m.group(2).strip('*"= '), "line": line})
    # dedupe by name keeping first
    seen: set[str] = set()
    for dep in dep_blob:
        key = dep["name"].lower()
        if key in seen:
            continue
        seen.add(key)
        profile["dependencies"].append(dep)
    dep_names = {d["name"].lower() for d in profile["dependencies"]}

    # ---- walk tree --------------------------------------------------------
    settings_text = ""
    for path in walk_source(source_dir):
        rel = path.relative_to(root)
        name = path.name
        if name in MARKER_FILES and len(rel.parts) <= 4:
            profile["markers"].append(str(rel))
        if name == "manage.py" and not profile["is_django"]:
            profile["is_django"] = True
        if name.endswith(".py"):
            profile["stats"]["python_files"] += 1
            if "settings" in name:
                profile["settings_files"].append(str(rel))
                settings_text += "\n" + _read(path)
            if name == "urls.py":
                profile["urls_files"].append(str(rel))
        if path.suffix in (".html", ".jinja", ".jinja2") and "template" not in str(rel).lower():
            profile["stats"]["template_files"] += 1
        elif path.suffix in (".html",):
            profile["stats"]["template_files"] += 1

    # manage.py check fallback: settings module reference anywhere
    if not profile["is_django"]:
        profile["is_django"] = bool(profile["settings_files"] and profile["urls_files"]) or \
            any(m.endswith("manage.py") for m in profile["markers"])

    # ---- settings.py is the richest signal ------------------------------
    blob = settings_text.lower()
    for dep in profile["dependencies"]:
        if dep["name"].lower() == "django":
            profile["django_version_hint"] = dep["specifier"] or None

    def has(*needles):
        return any(n in blob for n in needles)

    if has("postgresql", "psycopg"):
        profile["databases"].append("PostgreSQL")
    if has("mysql", "pymysql"):
        profile["databases"].append("MySQL")
    if has("sqlite3", "sqlite"):
        profile["databases"].append("SQLite")
    if has("oracle", "mssql"):
        profile["databases"].append("Other RDBMS")

    if "rest_framework" in blob or "djangorestframework" in dep_names:
        profile["api"].append("Django REST Framework")
    if "graphene" in dep_names or "strawberry" in dep_names or "graphene" in blob:
        profile["api"].append("GraphQL")
    if "simplejwt" in dep_names or "jwt" in blob:
        profile["auth"].append("JWT")
    if "allauth" in dep_names or "oauth" in blob:
        profile["auth"].append("OAuth/social")
    if "session" in blob and "authentication" in blob or profile["is_django"]:
        profile["auth"].append("Session (Django default)")
    if "axes" in dep_names:
        profile["auth"].append("django-axes brute-force protection")

    pkg_json = root / "package.json"
    if pkg_json.is_file():
        pj = _read(pkg_json)
        if "react" in pj:
            profile["frontend"].append("React")
        if "vue" in pj:
            profile["frontend"].append("Vue")
        if "angular" in pj:
            profile["frontend"].append("Angular")
    if profile["stats"]["template_files"]:
        profile["frontend"].append("Django templates")

    if (root / "Dockerfile").exists() or any(m.endswith("Dockerfile") for m in profile["markers"]):
        profile["deployment"].append("Docker")
    if (root / "docker-compose.yml").exists() or (root / "docker-compose.yaml").exists():
        profile["deployment"].append("Docker Compose")
    if _detect(dep_names, blob, "gunicorn"):
        profile["deployment"].append("Gunicorn")
    if _detect(dep_names, blob, "uvicorn"):
        profile["deployment"].append("Uvicorn")
    if any(root.glob("**/nginx*.conf")):
        profile["deployment"].append("Nginx config present")

    if _detect(dep_names, blob, "celery"):
        profile["workers"].append("Celery")
    if _detect(dep_names, blob, "django-rq", "rq"):
        profile["workers"].append("RQ")
    if _detect(dep_names, blob, "dramatiq"):
        profile["workers"].append("Dramatiq")

    if _detect(dep_names, blob, "redis"):
        profile["cache"].append("Redis")
    if _detect(dep_names, blob, "memcached", "pymemcache"):
        profile["cache"].append("Memcached")

    if _detect(dep_names, blob, "boto3", "django-storages"):
        profile["storage"].append("S3-compatible")
    if _detect(dep_names, blob, "minio"):
        profile["storage"].append("MinIO")
    if profile["is_django"]:
        profile["storage"].append("Local filesystem (default)")

    # python version hints
    for fname in ("runtime.txt", ".python-version"):
        f = root / fname
        if f.is_file():
            profile["python_version_hint"] = _read(f).strip().replace("python-", "")
            break

    return profile
