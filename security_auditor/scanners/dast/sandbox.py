"""Isolated application startup for DAST (spec 12).

Strategy:
  Local Django runtime: ``python manage.py runserver 127.0.0.1:<free-port>``
  bound to loopback only - never exposed publicly.

The sandbox never exposes the app beyond 127.0.0.1 and always enforces a
timeout.  A startup failure returns a clear reason so the pipeline can mark
DAST-dependent requirements NOT TESTED instead of pretending success (spec 36).
"""
from __future__ import annotations

import os
import shutil
import socket
import subprocess
import sys
import time
import urllib.error
import urllib.request
from dataclasses import dataclass
from pathlib import Path

IS_WINDOWS = os.name == "nt"


@dataclass
class StartupResult:
    started: bool
    base_url: str | None = None
    method: str | None = None
    reason: str = ""
    process: subprocess.Popen | None = None


def _free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def _wait_http(url: str, timeout: float = 60.0) -> bool:
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            req = urllib.request.Request(url, method="GET")
            with urllib.request.urlopen(req, timeout=2) as resp:
                if resp.status:
                    return True
        except urllib.error.HTTPError:
            return True                       # any HTTP answer: app is up
        except (urllib.error.URLError, OSError, TimeoutError):
            time.sleep(0.5)
    return False


SKIP_DIR_NAMES = {
    ".git", "node_modules", ".venv", "venv", "env", "__pycache__", ".tox",
    ".mypy_cache", ".pytest_cache", "dist", "build", ".next", "site-packages",
    "staticfiles", "vendor", "migrations",
}


def _find_manage_py(project: Path, max_depth: int = 4) -> Path | None:
    """BFS for the nearest directory containing manage.py (breadth-first so the
    shallowest Django project root wins).  Handles repos where the Django
    project lives in a subfolder (e.g. ``repo/Module_Audit/manage.py``)."""
    queue: list[tuple[Path, int]] = [(project, 0)]
    while queue:
        cur, depth = queue.pop(0)
        if (cur / "manage.py").is_file():
            return cur
        if depth >= max_depth:
            continue
        try:
            children = sorted(cur.iterdir(), key=lambda p: p.name)
        except OSError:
            continue
        for child in children:
            if (child.is_dir() and child.name not in SKIP_DIR_NAMES
                    and not child.name.startswith(".")):
                queue.append((child, depth + 1))
    return None


def _has_django(python: str) -> bool:
    try:
        return subprocess.run([python, "-c", "import django"], capture_output=True,
                              timeout=20).returncode == 0
    except (OSError, subprocess.TimeoutExpired, ValueError):
        return False


def _venv_pythons(*roots: Path):
    for root in roots:
        for rel in (".venv/bin/python", "venv/bin/python",
                    ".venv/Scripts/python.exe", "venv/Scripts/python.exe"):
            cand = root / rel
            if cand.exists():
                yield str(cand)


def _build_isolated_venv(django_version: str | None, drf: bool,
                         databases: list | None = None,
                         project_root: Path | None = None) -> str | None:
    """Best-effort isolated venv with the detected Django version (+DRF, +DB
    drivers), so a project with no usable venv can still be started for DAST.
    Never touches the auditor's or the project's environment."""
    import tempfile
    dest = Path(tempfile.mkdtemp(prefix="audit-sandbox-")) / "venv"
    try:
        subprocess.run([sys.executable, "-m", "venv", str(dest)],
                       capture_output=True, timeout=180, check=True)
    except Exception:  # noqa: BLE001
        return None
    pip = dest / ("Scripts/pip.exe" if IS_WINDOWS else "bin/pip")
    pkgs = [f"django=={django_version}" if django_version else "django"]
    if drf:
        pkgs.append("djangorestframework")
    for db in (databases or []):
        db = (db or "").lower()
        if "postgres" in db:
            pkgs.append("psycopg2-binary")
        elif "mysql" in db or "mariadb" in db:
            pkgs.append("pymysql")
    try:
        subprocess.run([str(pip), "install", "--disable-pip-version-check", "-q", *pkgs],
                       capture_output=True, timeout=420, check=True)
    except Exception:  # noqa: BLE001
        return None

    # Best-effort: also install the project's declared requirements so its
    # imports resolve.  A failing manifest falls back to per-package installs.
    if project_root is not None:
        for manifest in _find_manifests(project_root):
            r = subprocess.run([str(pip), "install", "--disable-pip-version-check",
                                "-q", "-r", str(manifest)],
                               capture_output=True, timeout=420)
            if r.returncode != 0:
                for spec in _manifest_specs(manifest):
                    subprocess.run([str(pip), "install", "--disable-pip-version-check",
                                    "-q", spec], capture_output=True, timeout=120)

    py = str(dest / ("Scripts/python.exe" if IS_WINDOWS else "bin/python"))
    return py if _has_django(py) else None


def _find_manifests(project_root: Path, max_depth: int = 3) -> list[Path]:
    out: list[Path] = []
    queue: list[tuple[Path, int]] = [(project_root, 0)]
    while queue and len(out) < 3:
        cur, depth = queue.pop(0)
        out.extend(sorted(cur.glob("requirements*.txt")))
        if depth < max_depth:
            try:
                children = [c for c in sorted(cur.iterdir(), key=lambda p: p.name)
                            if c.is_dir() and c.name not in SKIP_DIR_NAMES
                            and not c.name.startswith(".")]
            except OSError:
                children = []
            queue.extend((c, depth + 1) for c in children)
    return out


def _manifest_specs(manifest: Path) -> list[str]:
    specs = []
    try:
        for line in manifest.read_text(errors="replace").splitlines():
            line = line.split("#", 1)[0].strip()
            if not line or line.startswith(("-", "git+", "http")):
                continue
            specs.append(line)
            if len(specs) >= 40:
                break
    except OSError:
        pass
    return specs


def _pick_python(project: Path, manage_root: Path, profile: dict | None) -> tuple[str, str]:
    """Return (python, note).  Prefer an interpreter that can import django."""
    candidates = list(_venv_pythons(manage_root, project))
    candidates += [p for p in (shutil.which("python3"), shutil.which("python"),
                               sys.executable) if p]
    for cand in candidates:
        if _has_django(cand):
            return cand, "project/system interpreter with django"
    # No interpreter has django: build an isolated venv with detected version.
    ver = (profile or {}).get("django_version_hint") or None
    if ver:
        import re
        ver = re.sub(r"^[^0-9]+", "", ver).strip() or None   # '==4.2.1' -> '4.2.1'
    drf = bool((profile or {}).get("api"))
    dbs = (profile or {}).get("databases") or []
    iso = _build_isolated_venv(ver, drf, dbs, project_root=manage_root)
    if iso:
        return iso, "isolated venv (auto-installed django)"
    return candidates[0], "no interpreter with django found"


def start_application(source_dir: str, config: dict, source_type: str = "local",
                      wait_timeout: float = 45.0,
                      profile: dict | None = None) -> StartupResult:
    project = Path(source_dir)
    dast_cfg = (config or {}).get("dast", {}) or {}
    allow_runserver = dast_cfg.get("allow_local_runserver", True)
    # ---- local Django runserver --------------------------------------------
    if not allow_runserver:
        return StartupResult(False, reason="local runserver fallback disabled by configuration")

    manage_root = _find_manage_py(project)
    if manage_root is None:
        return StartupResult(False, reason=(
            "no manage.py found within 4 directory levels - cannot start the "
            "application (point the audit at the folder containing manage.py, "
            "or at a parent of it)"))

    port = _free_port()
    env = dict(os.environ)
    env.setdefault("PYTHONUNBUFFERED", "1")
    env.setdefault("DJANGO_ALLOWED_HOSTS", "127.0.0.1,localhost")
    # operator-provided env for the sandboxed app (e.g. point it at a test DB)
    for k, v in (dast_cfg.get("env") or {}).items():
        env[str(k)] = str(v)
    python, py_note = _pick_python(project, manage_root, profile)
    # --skip-checks: DAST needs the app *served*; blocking on config system
    # checks (admin.E403 etc.) would refuse to boot apps we still want to probe.
    cmd = [python, "manage.py", "runserver", f"127.0.0.1:{port}", "--noreload",
           "--skip-checks"]
    log_path = manage_root / ".audit-runserver.log"
    try:
        logf = open(log_path, "wb")
        popen_kwargs = {}
        if IS_WINDOWS:
            # Detach into its own process group so it survives this process and
            # can be killed as a tree (start_new_session is POSIX-only).
            popen_kwargs["creationflags"] = subprocess.CREATE_NEW_PROCESS_GROUP
        else:
            popen_kwargs["start_new_session"] = True
        proc = subprocess.Popen(cmd, cwd=manage_root, stdout=logf,
                                stderr=subprocess.STDOUT, env=env, **popen_kwargs)
    except (OSError, ValueError) as exc:
        return StartupResult(False, reason=f"could not launch runserver: {exc}")

    base = f"http://127.0.0.1:{port}"
    if _wait_http(base, wait_timeout):
        return StartupResult(True, base, f"runserver ({py_note})", process=proc)

    # failed: collect tail of log for the report
    _terminate(proc)
    tail = ""
    try:
        tail = log_path.read_text(errors="replace")[-800:]
    except OSError:
        pass
    return StartupResult(False, reason=f"application did not become reachable: {tail.strip()}",
                         process=None)


def _terminate(proc: subprocess.Popen | None) -> None:
    """Best-effort termination of the app process (and its tree on Windows)."""
    if proc is None:
        return
    try:
        if IS_WINDOWS:
            # Kill the whole process tree (runserver may spawn children).
            subprocess.run(["taskkill", "/F", "/T", "/PID", str(proc.pid)],
                           capture_output=True, timeout=15)
        else:
            proc.terminate()
        proc.wait(timeout=10)
    except Exception:  # noqa: BLE001
        try:
            proc.kill()
        except Exception:  # noqa: BLE001
            pass


def stop_application(startup: StartupResult) -> None:
    _terminate(startup.process)
