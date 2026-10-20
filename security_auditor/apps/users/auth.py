"""Platform authentication/RBAC + audit logging (spec 34, 38).

Users are stored in <workdir>/users.json with scrypt-hashed passwords and
role-based access (admin / analyst / viewer).  Session tokens are random
32-byte hex strings stored *hashed* (SHA-256) in users.json with a 12 h
expiry, so logins survive server restarts.  All mutating API calls are
audit-logged.
"""
from __future__ import annotations

import hashlib
import json
import os
import secrets
import time
from pathlib import Path

ROLES = ("admin", "analyst", "viewer")
ROLE_PERMISSIONS = {
    "admin": {"read", "create_audit", "retest", "delete_audit", "manage_users", "manage_requirements"},
    "analyst": {"read", "create_audit", "retest"},
    "viewer": {"read"},
}
TOKEN_TTL = 12 * 3600          # 12 hours


class AuthError(Exception):
    pass


class UserStore:
    def __init__(self, workdir: str):
        self.path = Path(workdir) / "users.json"
        self.log_path = Path(workdir) / "audit.log"
        self.path.parent.mkdir(parents=True, exist_ok=True)
        if not self.path.exists():
            self._write({"users": {}})

    # ------------------------------------------------------------------
    def _read(self) -> dict:
        return json.loads(self.path.read_text(encoding="utf-8"))

    def _write(self, data: dict) -> None:
        self.path.write_text(json.dumps(data, indent=2), encoding="utf-8")
        try:
            os.chmod(self.path, 0o600)
        except OSError:
            pass

    def create_user(self, username: str, password: str, role: str = "analyst") -> None:
        if role not in ROLES:
            raise AuthError(f"invalid role {role}")
        data = self._read()
        salt = secrets.token_bytes(16)
        digest = hashlib.scrypt(password.encode(), salt=salt, n=2 ** 14, r=8, p=1)
        data["users"][username] = {"role": role, "salt": salt.hex(), "hash": digest.hex()}
        self._write(data)
        self.audit_log("user.create", {"username": username, "role": role})

    def set_password(self, username: str, password: str) -> None:
        data = self._read()
        user = data["users"].get(username)
        if not user:
            raise AuthError("unknown user")
        salt = secrets.token_bytes(16)
        digest = hashlib.scrypt(password.encode(), salt=salt, n=2 ** 14, r=8, p=1)
        user["salt"] = salt.hex()
        user["hash"] = digest.hex()
        self._write(data)
        self.audit_log("user.password_change", {"username": username})

    def verify(self, username: str, password: str) -> str:
        data = self._read()
        user = data["users"].get(username)
        if not user:
            raise AuthError("invalid credentials")
        digest = hashlib.scrypt(password.encode(), salt=bytes.fromhex(user["salt"]),
                                n=2 ** 14, r=8, p=1)
        if not secrets.compare_digest(digest.hex(), user["hash"]):
            raise AuthError("invalid credentials")
        return self._issue_token(data, username)

    def create_token(self, username: str) -> str:
        data = self._read()
        if username not in data["users"]:
            raise AuthError("unknown user")
        return self._issue_token(data, username)

    def _issue_token(self, data: dict, username: str) -> str:
        """Persist a hashed session token (survives restarts, expires in 12h)."""
        token = secrets.token_hex(32)
        sha = hashlib.sha256(token.encode()).hexdigest()
        now = time.time()
        tokens = [t for t in data.get("tokens", []) if t.get("expires", 0) > now]
        tokens.append({"sha": sha, "user": username, "expires": now + TOKEN_TTL})
        data["tokens"] = tokens
        self._write(data)
        return token

    def user_for_token(self, token: str) -> tuple[str, str]:
        sha = hashlib.sha256(token.encode()).hexdigest()
        data = self._read()
        now = time.time()
        for t in data.get("tokens", []):
            if secrets.compare_digest(t.get("sha", ""), sha) and t.get("expires", 0) > now:
                username = t["user"]
                role = data["users"].get(username, {}).get("role", "viewer")
                return username, role
        raise AuthError("invalid or expired token")

    def require(self, token: str | None, permission: str) -> tuple[str, str]:
        if not token:
            raise AuthError("missing bearer token")
        username, role = self.user_for_token(token)
        if permission not in ROLE_PERMISSIONS.get(role, set()):
            raise AuthError(f"role '{role}' lacks permission '{permission}'")
        return username, role

    def audit_log(self, action: str, detail: dict) -> None:
        from security_auditor.apps.audits.models import now_iso
        with open(self.log_path, "a", encoding="utf-8") as fh:
            fh.write(json.dumps({"ts": now_iso(), "action": action, **detail}) + "\n")
