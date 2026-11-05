"""Local encryption for credentials at rest.

The key is never part of the repository. It comes from ``ARBITER_SECRET_KEY``
(or ``ARBITER_SECRET_KEY_FILE``), otherwise a 0600 key file is generated under
the user's data directory. Only ciphertext is written to PostgreSQL.
"""

from __future__ import annotations

import base64
import hashlib
import os
from pathlib import Path

from cryptography.fernet import Fernet, InvalidToken

PREFIX = "fernet:v1:"


class SecretStoreError(RuntimeError):
    """Raised when local credential encryption cannot be performed."""


def _key_path() -> Path:
    explicit = os.getenv("ARBITER_SECRET_KEY_FILE", "").strip()
    if explicit:
        return Path(explicit).expanduser()
    base = os.getenv("XDG_DATA_HOME", "").strip()
    root = Path(base).expanduser() if base else Path.home() / ".local" / "share"
    return root / "arbiter" / "secret.key"


def _read_or_create_key_file() -> str:
    path = _key_path()
    if path.exists():
        try:
            return path.read_text(encoding="utf-8").strip()
        except OSError as error:
            raise SecretStoreError("Kunci enkripsi lokal tidak dapat dibaca.") from error
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        raw = Fernet.generate_key().decode("ascii")
        descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
            handle.write(raw)
        return raw
    except FileExistsError:
        try:
            return path.read_text(encoding="utf-8").strip()
        except OSError as error:
            raise SecretStoreError("Kunci enkripsi lokal tidak dapat dibaca.") from error
    except OSError as error:
        raise SecretStoreError("Kunci enkripsi lokal tidak dapat dibuat.") from error


def _fernet() -> Fernet:
    raw = os.getenv("ARBITER_SECRET_KEY", "").strip()
    if not raw:
        raw = _read_or_create_key_file()
    try:
        return Fernet(raw.encode("utf-8"))
    except (ValueError, TypeError):
        # Accept a passphrase as well as a generated Fernet key.
        digest = hashlib.sha256(raw.encode("utf-8")).digest()
        return Fernet(base64.urlsafe_b64encode(digest))


def encrypt_text(value: str) -> str:
    text = str(value or "")
    if not text:
        return ""
    try:
        token = _fernet().encrypt(text.encode("utf-8")).decode("ascii")
    except SecretStoreError:
        raise
    except Exception as error:
        raise SecretStoreError("Kredensial tidak dapat dienkripsi.") from error
    return PREFIX + token


def is_encrypted(value: str) -> bool:
    return isinstance(value, str) and value.startswith(PREFIX)


def decrypt_text(value: str) -> str:
    text = str(value or "")
    if not text:
        return ""
    if not is_encrypted(text):
        return text
    try:
        return _fernet().decrypt(text[len(PREFIX):].encode("ascii")).decode("utf-8")
    except InvalidToken as error:
        raise SecretStoreError("Kunci enkripsi lokal tidak cocok dengan kredensial tersimpan.") from error
    except SecretStoreError:
        raise
    except Exception as error:
        raise SecretStoreError("Kredensial tersimpan tidak dapat didekripsi.") from error
