"""Project source acquisition: GitHub clone, ZIP extraction, local folder.

Each audit works on its own isolated workspace copy (spec 22); the original
location is never modified.
"""
from __future__ import annotations

import re
import shutil
import subprocess
from pathlib import Path

from security_auditor.apps.audits.utils import safe_extract_zip


def _mask_url(url: str) -> str:
    return re.sub(r"https?://[^@/]+:[^@/]+@", "https://***:***@", url)


def acquire_github(repo_url: str, dest_dir: str, branch: str | None = None,
                   commit: str | None = None, token: str | None = None,
                   timeout: int = 600) -> dict:
    """Clone a repository into the audit workspace. Supports public and
    token-authenticated private repos plus branch selection."""
    dest = Path(dest_dir)
    dest.mkdir(parents=True, exist_ok=True)
    url = repo_url.strip().rstrip("/")
    if url.endswith(".git"):
        url = url[:-4]
    clone_url = url
    if token:
        clone_url = re.sub(r"^https://", f"https://x-access-token:{token}@", url)

    cmd = ["git", "clone", "--quiet"]
    if branch:
        cmd += ["--branch", branch]
    cmd += ["--depth", "50", clone_url, str(dest / "source")]
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
    except subprocess.TimeoutExpired:
        raise RuntimeError("git clone timed out")
    if proc.returncode != 0:
        err = (proc.stderr or "").replace(token or "\x00", "***") if token else (proc.stderr or "")
        raise RuntimeError(f"git clone failed for {_mask_url(url)}: {err.strip()[:300]}")

    src = dest / "source"
    sha = subprocess.run(["git", "rev-parse", "HEAD"], cwd=src, capture_output=True,
                         text=True).stdout.strip()
    actual_branch = subprocess.run(["git", "rev-parse", "--abbrev-ref", "HEAD"], cwd=src,
                                   capture_output=True, text=True).stdout.strip()
    if commit:
        fetch = subprocess.run(["git", "fetch", "--depth", "100", "origin", commit],
                               cwd=src, capture_output=True, text=True)
        co = subprocess.run(["git", "checkout", "--quiet", commit], cwd=src,
                            capture_output=True, text=True)
        if fetch.returncode == 0 and co.returncode == 0:
            sha = commit
    return {"path": str(src), "repo_url": url, "branch": actual_branch or branch,
            "commit_sha": sha}


def acquire_zip(zip_path: str, dest_dir: str) -> dict:
    dest = Path(dest_dir)
    dest.mkdir(parents=True, exist_ok=True)
    src = dest / "source"
    members = safe_extract_zip(zip_path, str(src))
    # if the archive has a single top-level directory, descend into it
    tops = {m.split("/", 1)[0] for m in members}
    root = src
    if len(tops) == 1 and (src / list(tops)[0]).is_dir():
        root = src / list(tops)[0]
    return {"path": str(root), "archive": str(zip_path), "members": len(members)}


def acquire_local(path: str, dest_dir: str | None = None) -> dict:
    p = Path(path).expanduser().resolve()
    if not p.is_dir():
        raise RuntimeError(f"local project folder not found: {path}")
    return {"path": str(p)}


def copy_to_workspace(path: str, dest_dir: str) -> str:
    """Copy a local project into the isolated workspace (skip VCS/venv)."""
    dest = Path(dest_dir) / "source"
    if dest.exists():
        shutil.rmtree(dest)

    def ignore(directory, names):
        return [n for n in names if n in {".git", "node_modules", ".venv", "venv",
                                          "__pycache__", ".tox", ".mypy_cache"}]
    shutil.copytree(path, dest, ignore=ignore, symlinks=False)
    return str(dest)
