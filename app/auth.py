"""Local authentication, session tokens, and role-based user management for Arbiter.

User records are stored in ``wazuh.app_settings`` (key ``auth_users``) with
PBKDF2-HMAC-SHA256 password digests encrypted at rest via ``app.secure_store``.
Session tokens are encrypted with the local Fernet secret key.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import os
import re
import secrets
import time
from datetime import datetime, timezone
from typing import Any

from app.secure_store import SecretStoreError, decrypt_text, encrypt_text, is_encrypted
from app.settings import load_document, save_document

AUTH_USERS_KEY = "auth_users"
SESSION_COOKIE_NAME = "arbiter_session"
SESSION_TTL_SECONDS = 12 * 3600  # 12 hours
VALID_ROLES = {"admin", "analyst"}
_USERNAME_RE = re.compile(r"^[A-Za-z0-9_.-]{3,50}$")


def _default_admin_credentials() -> tuple[str, str]:
    user = (os.getenv("ARBITER_ADMIN_USER") or "admin").strip() or "admin"
    password = os.getenv("ARBITER_ADMIN_PASSWORD") or "arbiter123"
    return user, password


def _hash_password(password: str, salt: str | None = None) -> str:
    salt_hex = salt or secrets.token_hex(16)
    dk = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt_hex.encode("ascii"), 120_000)
    raw = f"pbkdf2_sha256${salt_hex}${dk.hex()}"
    return encrypt_text(raw)


def _verify_password(password: str, stored_secret: str) -> bool:
    if not stored_secret or not isinstance(stored_secret, str):
        return False
    raw = stored_secret
    if is_encrypted(stored_secret):
        try:
            raw = decrypt_text(stored_secret)
        except SecretStoreError:
            return False
    parts = raw.split("$")
    if len(parts) != 3 or parts[0] != "pbkdf2_sha256":
        return False
    _, salt_hex, expected_hex = parts
    dk = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt_hex.encode("ascii"), 120_000)
    return hmac.compare_digest(dk.hex(), expected_hex)


def sanitize_user(record: dict[str, Any]) -> dict[str, Any]:
    username = str(record.get("username") or "").strip()
    role = str(record.get("role") or "analyst").strip().lower()
    if role not in VALID_ROLES:
        role = "analyst"
    return {
        "username": username,
        "display_name": str(record.get("display_name") or username).strip() or username,
        "role": role,
        "created_at": str(record.get("created_at") or ""),
        "updated_at": str(record.get("updated_at") or ""),
    }


def _load_raw_users(conn) -> list[dict[str, Any]]:
    doc = load_document(conn, AUTH_USERS_KEY, None)
    users = doc.get("users") if isinstance(doc, dict) else None
    if isinstance(users, list) and users:
        valid = [u for u in users if isinstance(u, dict) and str(u.get("username") or "").strip()]
        if valid:
            return valid

    # Seed initial default admin account
    admin_user, admin_pass = _default_admin_credentials()
    now = datetime.now(timezone.utc).isoformat()
    seeded = [{
        "username": admin_user,
        "display_name": "Administrator",
        "role": "admin",
        "password_hash": _hash_password(admin_pass),
        "created_at": now,
        "updated_at": now,
    }]
    try:
        save_document(conn, AUTH_USERS_KEY, {"users": seeded})
    except Exception:
        pass
    return seeded


def _save_raw_users(conn, users: list[dict[str, Any]]) -> None:
    save_document(conn, AUTH_USERS_KEY, {"users": users})


def list_users(conn) -> list[dict[str, Any]]:
    users = _load_raw_users(conn)
    return [sanitize_user(u) for u in users]


def get_user(conn, username: str) -> dict[str, Any] | None:
    target = str(username or "").strip().lower()
    if not target:
        return None
    for user in _load_raw_users(conn):
        if str(user.get("username") or "").strip().lower() == target:
            return sanitize_user(user)
    return None


def authenticate_user(conn, username: str, password: str) -> dict[str, Any] | None:
    target = str(username or "").strip().lower()
    if not target or not password:
        return None
    users = _load_raw_users(conn)
    for user in users:
        if str(user.get("username") or "").strip().lower() == target:
            if _verify_password(password, str(user.get("password_hash") or "")):
                return sanitize_user(user)
            return None
    return None


def create_user(
    conn,
    *,
    username: str,
    password: str,
    role: str = "analyst",
    display_name: str = "",
) -> dict[str, Any]:
    clean_username = str(username or "").strip()
    if not _USERNAME_RE.match(clean_username):
        raise ValueError("Username harus 3–50 karakter (huruf, angka, titik, garis bawah, atau strip).")
    if not isinstance(password, str) or len(password) < 6:
        raise ValueError("Password minimal 6 karakter.")
    if len(password) > 200:
        raise ValueError("Password terlalu panjang.")
    clean_role = str(role or "analyst").strip().lower()
    if clean_role not in VALID_ROLES:
        raise ValueError("Role harus 'admin' atau 'analyst'.")
    clean_display = str(display_name or "").strip()[:100] or clean_username

    users = _load_raw_users(conn)
    if any(str(u.get("username") or "").strip().lower() == clean_username.lower() for u in users):
        raise ValueError(f"Username '{clean_username}' sudah terdaftar.")

    now = datetime.now(timezone.utc).isoformat()
    record = {
        "username": clean_username,
        "display_name": clean_display,
        "role": clean_role,
        "password_hash": _hash_password(password),
        "created_at": now,
        "updated_at": now,
    }
    users.append(record)
    _save_raw_users(conn, users)
    return sanitize_user(record)


def update_user(
    conn,
    username: str,
    *,
    password: str | None = None,
    role: str | None = None,
    display_name: str | None = None,
) -> dict[str, Any]:
    target = str(username or "").strip().lower()
    if not target:
        raise ValueError("Username tidak valid.")
    users = _load_raw_users(conn)
    idx = next((i for i, u in enumerate(users) if str(u.get("username") or "").strip().lower() == target), None)
    if idx is None:
        raise ValueError("Pengguna tidak ditemukan.")

    record = dict(users[idx])
    if role is not None and str(role).strip() != "":
        clean_role = str(role).strip().lower()
        if clean_role not in VALID_ROLES:
            raise ValueError("Role harus 'admin' atau 'analyst'.")
        if record.get("role") == "admin" and clean_role != "admin":
            admin_count = sum(1 for u in users if str(u.get("role") or "") == "admin")
            if admin_count <= 1:
                raise ValueError("Tidak dapat mengubah role admin terakhir.")
        record["role"] = clean_role

    if display_name is not None:
        clean_display = str(display_name).strip()[:100]
        record["display_name"] = clean_display or record["username"]

    if password is not None and str(password) != "":
        if len(password) < 6:
            raise ValueError("Password baru minimal 6 karakter.")
        if len(password) > 200:
            raise ValueError("Password terlalu panjang.")
        record["password_hash"] = _hash_password(password)

    record["updated_at"] = datetime.now(timezone.utc).isoformat()
    users[idx] = record
    _save_raw_users(conn, users)
    return sanitize_user(record)


def delete_user(conn, username: str, *, actor_username: str = "") -> bool:
    target = str(username or "").strip().lower()
    if not target:
        raise ValueError("Username tidak valid.")
    if actor_username and target == actor_username.strip().lower():
        raise ValueError("Anda tidak dapat menghapus akun yang sedang digunakan login.")
    users = _load_raw_users(conn)
    idx = next((i for i, u in enumerate(users) if str(u.get("username") or "").strip().lower() == target), None)
    if idx is None:
        raise ValueError("Pengguna tidak ditemukan.")
    if str(users[idx].get("role") or "") == "admin":
        admin_count = sum(1 for u in users if str(u.get("role") or "") == "admin")
        if admin_count <= 1:
            raise ValueError("Tidak dapat menghapus akun admin terakhir.")
    users.pop(idx)
    _save_raw_users(conn, users)
    return True


def create_session_token(user: dict[str, Any], ttl_seconds: int = SESSION_TTL_SECONDS) -> str:
    now = int(time.time())
    payload = {
        "u": str(user["username"]),
        "r": str(user.get("role") or "analyst"),
        "d": str(user.get("display_name") or user["username"]),
        "iat": now,
        "exp": now + int(ttl_seconds),
    }
    return encrypt_text(json.dumps(payload, separators=(",", ":")))


def verify_session_token(token: str | None) -> dict[str, Any] | None:
    if not token or not isinstance(token, str):
        return None
    try:
        raw = decrypt_text(token.strip())
        data = json.loads(raw)
    except (SecretStoreError, ValueError, TypeError):
        return None
    if not isinstance(data, dict):
        return None
    exp = data.get("exp")
    if not isinstance(exp, (int, float)) or int(time.time()) > int(exp):
        return None
    username = str(data.get("u") or "").strip()
    role = str(data.get("r") or "analyst").strip().lower()
    if not username or role not in VALID_ROLES:
        return None
    return {
        "username": username,
        "role": role,
        "display_name": str(data.get("d") or username).strip() or username,
    }

