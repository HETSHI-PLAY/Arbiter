"""Workspace settings: Wazuh Indexer connection and realtime monitor preferences.

Settings are stored locally in PostgreSQL (``wazuh.app_settings``) and are never
sent to a remote service. Secrets are stored server-side only and are redacted
from every API response.
"""

from __future__ import annotations

import base64
import copy
import ipaddress
import json
import re
import ssl
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime
from typing import Any

from app.secure_store import SecretStoreError, decrypt_text, encrypt_text, is_encrypted

SETTINGS_KEY = "app"
MIN_RULE_LEVEL = 7

DEFAULT_SETTINGS: dict[str, Any] = {
    "wazuh": {
        "enabled": False,
        "indexer_url": "",
        "username": "",
        "index_pattern": "wazuh-alerts-*",
        "verify_tls": True,
    },
    "realtime": {
        "enabled": False,
        "interval_seconds": 30,
        "mode": "interval",
        "last_pull_at": "",
        "max_alerts": 500,
        "min_rule_level": 7,
        "max_rule_level": None,
    },
    "ai": {
        "enabled": False,
        "base_url": "http://127.0.0.1:11434",
        "model": "hf.co/XHToken/Spark-X2.6-4B-GGUF:Q4_K_M",
        "timeout_seconds": 90,
    },
    "intel": {
        "web_url": "http://localhost:3001",
    },
    "ui": {
        "sidebar_default": "expanded",
    },
}

_SIDEBAR_VALUES = {"expanded", "collapsed"}
_INDEX_PATTERN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._*,-]*$")
_URL = re.compile(r"^https?://[^\s]+$", re.IGNORECASE)
_OLLAMA_PATH_SUFFIX_RE = re.compile(
    r"/(?:api(?:/(?:generate|chat|tags|pull|show|embeddings|embed|version))?|v1(?:/chat/completions|/completions|/models)?)/?$",
    re.IGNORECASE,
)
_LOCAL_HOST_SUFFIXES = (".local", ".lan", ".internal", ".home", ".lab", ".corp", ".intranet", ".localdomain")


def normalize_ollama_base_url(value: Any) -> str:
    """Normalize an Ollama base URL (stripping /api/generate etc.) and verify it is loopback or private LAN."""
    raw = str(value or "").strip() or "http://127.0.0.1:11434"
    cleaned = raw.rstrip("/")
    cleaned = _OLLAMA_PATH_SUFFIX_RE.sub("", cleaned).rstrip("/")
    parsed = urllib.parse.urlparse(cleaned)
    host = (parsed.hostname or "").strip().lower()
    if parsed.scheme not in {"http", "https"} or not host:
        raise ValueError("AI lokal hanya boleh memakai http://localhost, IP loopback, atau IP jaringan lokal (LAN).")

    allowed = False
    if host in {"localhost", "127.0.0.1", "::1"}:
        allowed = True
    else:
        try:
            ip = ipaddress.ip_address(host)
            cgnat = ipaddress.ip_network("100.64.0.0/10")
            if ip.is_loopback or ip.is_private or ip.is_link_local or (isinstance(ip, ipaddress.IPv4Address) and ip in cgnat):
                allowed = True
        except ValueError:
            # Hostname: allow single-label internal hostnames (e.g. Docker service `ollama`) or local LAN suffixes
            if "." not in host or host.endswith(_LOCAL_HOST_SUFFIXES):
                allowed = True

    if not allowed:
        raise ValueError("AI lokal hanya boleh memakai http://localhost, IP loopback, atau IP jaringan lokal (LAN).")
    return cleaned


def default_settings() -> dict[str, Any]:
    return copy.deepcopy(DEFAULT_SETTINGS)


def _deep_merge(base: dict[str, Any], override: dict[str, Any]) -> dict[str, Any]:
    result = copy.deepcopy(base)
    for key, value in override.items():
        if isinstance(value, dict) and isinstance(result.get(key), dict):
            result[key] = _deep_merge(result[key], value)
        else:
            result[key] = value
    return result


def _boolean(value: Any, field: str) -> bool:
    if isinstance(value, bool):
        return value
    if value in (0, 1):
        return bool(value)
    raise ValueError(f"{field} harus berupa boolean (true/false).")


def _text(value: Any, field: str, limit: int = 500) -> str:
    if value is None:
        return ""
    if not isinstance(value, (str, int, float)):
        raise ValueError(f"{field} tidak valid.")
    text = str(value).strip()
    if len(text) > limit:
        raise ValueError(f"{field} terlalu panjang (maksimal {limit} karakter).")
    return text


def validate_settings(payload: dict[str, Any], current: dict[str, Any] | None = None) -> dict[str, Any]:
    """Validate a partial settings payload and merge it over ``current``."""
    if not isinstance(payload, dict):
        raise ValueError("Payload pengaturan tidak valid.")
    base = _deep_merge(default_settings(), current or {})
    settings = _deep_merge(base, payload)

    wazuh = settings.get("wazuh")
    if not isinstance(wazuh, dict):
        raise ValueError("Bagian wazuh tidak valid.")
    url = _text(wazuh.get("indexer_url"), "wazuh.indexer_url")
    if url and not _URL.match(url):
        raise ValueError("URL Wazuh Indexer harus diawali http:// atau https:// dan tanpa spasi.")
    wazuh["indexer_url"] = url.rstrip("/")
    wazuh["username"] = _text(wazuh.get("username"), "wazuh.username", 200)
    wazuh["index_pattern"] = _text(wazuh.get("index_pattern"), "wazuh.index_pattern", 200) or "wazuh-alerts-*"
    if not _INDEX_PATTERN.match(wazuh["index_pattern"]):
        raise ValueError("Pola indeks hanya boleh berisi huruf, angka, titik, garis bawah, tanda hubung, koma, dan bintang.")
    wazuh["verify_tls"] = _boolean(wazuh.get("verify_tls", True), "wazuh.verify_tls")
    wazuh["enabled"] = _boolean(wazuh.get("enabled", False), "wazuh.enabled")
    password = wazuh.pop("password", None)
    if password is not None:
        if not isinstance(password, str):
            raise ValueError("wazuh.password tidak valid.")
        if len(password) > 500:
            raise ValueError("wazuh.password terlalu panjang.")
        # Never keep plaintext in the settings document; store local ciphertext.
        wazuh["password_enc"] = encrypt_text(password) if password else ""
    wazuh.setdefault("password_enc", "")
    if not isinstance(wazuh["password_enc"], str):
        raise ValueError("wazuh.password_enc tidak valid.")

    realtime = settings.get("realtime")
    if not isinstance(realtime, dict):
        raise ValueError("Bagian realtime tidak valid.")
    realtime["enabled"] = _boolean(realtime.get("enabled", False), "realtime.enabled")
    try:
        interval = int(realtime.get("interval_seconds", 30))
    except (TypeError, ValueError):
        raise ValueError("realtime.interval_seconds harus berupa angka.") from None
    if not 10 <= interval <= 300:
        raise ValueError("Interval realtime harus antara 10 dan 300 detik.")
    realtime["interval_seconds"] = interval
    mode = _text(realtime.get("mode"), "realtime.mode", 20) or "interval"
    if mode not in ("interval", "daily"):
        raise ValueError("realtime.mode harus interval atau daily.")
    realtime["mode"] = mode
    realtime["last_pull_at"] = _text(realtime.get("last_pull_at"), "realtime.last_pull_at", 40)
    try:
        max_alerts = int(realtime.get("max_alerts", 500))
    except (TypeError, ValueError):
        raise ValueError("realtime.max_alerts harus berupa angka.") from None
    if not 1 <= max_alerts <= 5000:
        raise ValueError("realtime.max_alerts harus antara 1 dan 5000.")
    realtime["max_alerts"] = max_alerts

    raw_min_level = realtime.get("min_rule_level", MIN_RULE_LEVEL)
    try:
        min_rule_level = int(MIN_RULE_LEVEL if raw_min_level is None or raw_min_level == "" else raw_min_level)
    except (TypeError, ValueError):
        raise ValueError("realtime.min_rule_level harus berupa angka.") from None
    if not 0 <= min_rule_level <= 16:
        raise ValueError("realtime.min_rule_level harus antara 0 dan 16.")
    realtime["min_rule_level"] = min_rule_level

    raw_max_level = realtime.get("max_rule_level")
    if raw_max_level is None or str(raw_max_level).strip() == "":
        max_rule_level: int | None = None
    else:
        try:
            max_rule_level = int(raw_max_level)
        except (TypeError, ValueError):
            raise ValueError("realtime.max_rule_level harus berupa angka.") from None
        if not 0 <= max_rule_level <= 16 or max_rule_level < min_rule_level:
            raise ValueError("realtime.max_rule_level tidak valid.")
    realtime["max_rule_level"] = max_rule_level

    prev_rt = (current or {}).get("realtime") if isinstance(current, dict) else None
    rt_payload = payload.get("realtime") if isinstance(payload.get("realtime"), dict) else {}
    if isinstance(prev_rt, dict) and "last_pull_at" not in rt_payload:
        prev_min = prev_rt.get("min_rule_level", MIN_RULE_LEVEL)
        prev_max = prev_rt.get("max_rule_level", None)
        if (min_rule_level, max_rule_level) != (prev_min, prev_max):
            realtime["last_pull_at"] = ""

    ai = settings.get("ai")
    if not isinstance(ai, dict):
        raise ValueError("Bagian ai tidak valid.")
    ai["enabled"] = _boolean(ai.get("enabled", False), "ai.enabled")
    base_url = _text(ai.get("base_url"), "ai.base_url", 300) or "http://127.0.0.1:11434"
    ai["base_url"] = normalize_ollama_base_url(base_url)
    ai["model"] = _text(ai.get("model"), "ai.model", 200) or DEFAULT_SETTINGS["ai"]["model"]
    try:
        ai_timeout = int(ai.get("timeout_seconds", 90))
    except (TypeError, ValueError):
        raise ValueError("ai.timeout_seconds harus berupa angka.") from None
    if not 10 <= ai_timeout <= 180:
        raise ValueError("Timeout AI harus antara 10 dan 180 detik.")
    ai["timeout_seconds"] = ai_timeout

    intel = settings.get("intel")
    if not isinstance(intel, dict):
        raise ValueError("Bagian intel tidak valid.")
    web_url = _text(intel.get("web_url"), "intel.web_url", 300) or "http://localhost:3001"
    if not _URL.match(web_url):
        raise ValueError("URL IP Intel harus diawali http:// atau https:// dan tanpa spasi.")
    intel["web_url"] = re.sub(r"/ip/?$", "", web_url.rstrip("/"), flags=re.IGNORECASE).rstrip("/") or "http://localhost:3001"
    abuse_key = intel.pop("abuseipdb_api_key", None)
    if abuse_key is not None:
        if not isinstance(abuse_key, str):
            raise ValueError("intel.abuseipdb_api_key tidak valid.")
        if len(abuse_key) > 500:
            raise ValueError("intel.abuseipdb_api_key terlalu panjang.")
        intel["abuseipdb_key_enc"] = encrypt_text(abuse_key.strip()) if abuse_key.strip() else ""
    intel.setdefault("abuseipdb_key_enc", "")
    if not isinstance(intel["abuseipdb_key_enc"], str):
        raise ValueError("intel.abuseipdb_key_enc tidak valid.")

    ui = settings.get("ui")
    if not isinstance(ui, dict):
        raise ValueError("Bagian ui tidak valid.")
    sidebar = _text(ui.get("sidebar_default"), "ui.sidebar_default", 20) or "expanded"
    if sidebar not in _SIDEBAR_VALUES:
        raise ValueError("ui.sidebar_default harus expanded atau collapsed.")
    ui["sidebar_default"] = sidebar

    return settings


def redact_settings(settings: dict[str, Any]) -> dict[str, Any]:
    """Return a client-safe view; passwords never leave the server."""
    result = copy.deepcopy(settings)
    wazuh = result.setdefault("wazuh", {})
    password_enc = wazuh.pop("password_enc", "") or ""
    wazuh.pop("password", None)
    wazuh.pop("_legacy_plaintext", None)
    wazuh["password_set"] = bool(password_enc)
    wazuh["auth_configured"] = bool(result["wazuh"].get("indexer_url"))
    intel = result.setdefault("intel", {"web_url": "http://localhost:3001"})
    abuse_key_enc = intel.pop("abuseipdb_key_enc", "") or ""
    intel.pop("abuseipdb_api_key", None)
    intel["abuseipdb_key_set"] = bool(abuse_key_enc)
    return result


def load_document(conn, key: str, default: Any = None) -> Any:
    """Read one local JSON document from wazuh.app_settings."""
    try:
        row = conn.execute(
            "SELECT value FROM wazuh.app_settings WHERE key = %s", (key,)
        ).fetchone()
    except Exception:
        return default
    if not row:
        return default
    value = row["value"] if isinstance(row, dict) else row[0]
    if isinstance(value, str):
        try:
            value = json.loads(value)
        except ValueError:
            return default
    return value if value is not None else default


def save_document(conn, key: str, value: Any) -> None:
    conn.execute(
        """
        INSERT INTO wazuh.app_settings (key, value, updated_at)
        VALUES (%s, %s::jsonb, now())
        ON CONFLICT (key) DO UPDATE SET value = EXCLUDED.value, updated_at = now()
        """,
        (key, json.dumps(value)),
    )


def load_settings(conn) -> dict[str, Any]:
    """Load stored settings; missing rows fall back to defaults.

    Legacy plaintext passwords are converted to local ciphertext in memory and
    flagged so the caller can migrate them on the next write.
    """
    value = load_document(conn, SETTINGS_KEY, None)
    if not isinstance(value, dict):
        return default_settings()
    stored = value.get("wazuh")
    legacy_password = ""
    if isinstance(stored, dict):
        legacy_password = stored.pop("password", "") or ""
    try:
        settings = validate_settings(value, default_settings())
    except ValueError:
        return default_settings()
    wazuh = settings["wazuh"]
    if legacy_password:
        if is_encrypted(legacy_password):
            wazuh["password_enc"] = legacy_password
        else:
            wazuh["password_enc"] = encrypt_text(legacy_password)
            wazuh["_legacy_plaintext"] = True
    return settings


def migrate_settings(conn) -> bool:
    """Encrypt a legacy plaintext password if one is still stored."""
    settings = load_settings(conn)
    if not settings.get("wazuh", {}).get("_legacy_plaintext"):
        return False
    settings["wazuh"].pop("_legacy_plaintext", None)
    save_settings(conn, settings)
    return True


def save_settings(conn, settings: dict[str, Any]) -> dict[str, Any]:
    payload = copy.deepcopy(settings)
    wazuh = payload.setdefault("wazuh", {})
    wazuh.pop("password", None)
    wazuh.pop("_legacy_plaintext", None)
    password_enc = wazuh.get("password_enc", "") or ""
    if password_enc and not is_encrypted(password_enc):
        # Defensive: never persist plaintext, even if a caller bypassed validation.
        wazuh["password_enc"] = encrypt_text(password_enc)
    save_document(conn, SETTINGS_KEY, payload)
    return payload


def wazuh_password(settings: dict[str, Any]) -> str:
    """Decrypt the stored password in memory only; never log or return it."""
    wazuh = settings.get("wazuh", {})
    encrypted = str(wazuh.get("password_enc") or "")
    if not encrypted:
        return ""
    try:
        return decrypt_text(encrypted)
    except SecretStoreError:
        return ""


def intel_abuseipdb_key(settings: dict[str, Any]) -> str:
    """Decrypt the stored AbuseIPDB API key in memory only; never log or return it."""
    intel = settings.get("intel", {})
    encrypted = str(intel.get("abuseipdb_key_enc") or "")
    if not encrypted:
        return ""
    try:
        return decrypt_text(encrypted)
    except SecretStoreError:
        return ""


def wazuh_alert_query(
    min_rule_level: int = MIN_RULE_LEVEL,
    max_rule_level: int | None = None,
) -> dict[str, Any]:
    """Scope used for Wazuh Indexer read/count with configurable severity range."""
    level_range: dict[str, int] = {"gte": int(min_rule_level)}
    if max_rule_level is not None:
        level_range["lte"] = int(max_rule_level)
    return {"query": {"range": {"rule.level": level_range}}}


def _normalize_wazuh_timestamp(value: str) -> str:
    """Convert an ISO or human timestamp to the form Wazuh Indexer's date field accepts.

    Python's ``datetime.isoformat()`` emits ``+00:00``; Wazuh alert documents
    (and the indexer's strict date parser) use ``+0000``. A colon in the offset
    makes the range query fail with HTTP 400, so collapse it here.
    Also accepts ``DD/MM/YYYY HH:MM(:SS)``, ``DD/MM/YYYY HH.MM(.SS)``, and
    naive ``YYYY-MM-DDTHH:MM(:SS)`` (assumed WIB ``+0700``).
    """
    text = str(value or "").strip()
    if not text:
        return ""
    if text.lower() == "now":
        return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S+0000")

    # Match DD/MM/YYYY [HH[:.]MM([:.]SS)]
    m_dmy = re.match(
        r"^(\d{1,2})[/\-](\d{1,2})[/\-](\d{4})(?:[T\s]+(\d{1,2})[:.](\d{2})(?:[:.](\d{2}))?)?(?:\s*(?:WIB|UTC|Z|[+-]\d{2}:?\d{2}))?$",
        text,
        re.IGNORECASE,
    )
    if m_dmy:
        day, month, year = int(m_dmy.group(1)), int(m_dmy.group(2)), int(m_dmy.group(3))
        hour = int(m_dmy.group(4) or 0)
        minute = int(m_dmy.group(5) or 0)
        second = int(m_dmy.group(6) or 0)
        tz_suffix = "+0700"
        tz_match = re.search(r"(Z|[+-]\d{2}:?\d{2})$", text, re.IGNORECASE)
        if tz_match:
            raw_tz = tz_match.group(1).upper()
            tz_suffix = "+0000" if raw_tz == "Z" else raw_tz.replace(":", "")
        elif text.upper().endswith("UTC"):
            tz_suffix = "+0000"
        return f"{year:04d}-{month:02d}-{day:02d}T{hour:02d}:{minute:02d}:{second:02d}{tz_suffix}"

    # Match naive YYYY-MM-DD[T ]HH:MM(:SS) (from <input type="datetime-local"> or manual input)
    m_iso_naive = re.match(
        r"^(\d{4})-(\d{2})-(\d{2})[T\s](\d{2})[:.](\d{2})(?:[:.](\d{2}))?$",
        text,
    )
    if m_iso_naive:
        year_s, month_s, day_s, hour_s, min_s = m_iso_naive.groups()[:5]
        sec_s = m_iso_naive.group(6) or "00"
        return f"{year_s}-{month_s}-{day_s}T{hour_s}:{min_s}:{sec_s}+0700"

    text = re.sub(r"([+-]\d{2}):(\d{2})$", r"\1\2", text)
    return text


def _valid_timestamp(value: str) -> bool:
    """True when the value parses as a real instant (guards against sending a
    garbage string that would 400 the indexer)."""
    text = _normalize_wazuh_timestamp(value)
    if not text:
        return False
    iso_candidate = re.sub(r"([+-]\d{2})(\d{2})$", r"\1:\2", text)
    try:
        datetime.fromisoformat(iso_candidate.replace("Z", "+00:00"))
        return True
    except ValueError:
        return False


def test_wazuh_connection(
    *,
    indexer_url: str,
    username: str,
    password: str,
    index_pattern: str,
    verify_tls: bool,
    min_rule_level: int = MIN_RULE_LEVEL,
    max_rule_level: int | None = None,
    timeout: float = 5.0,
) -> dict[str, Any]:
    """Probe the Wazuh Indexer with a single scoped count request."""
    base = str(indexer_url or "").strip().rstrip("/")
    if not base or not _URL.match(base):
        raise ValueError("URL Wazuh Indexer belum diatur atau tidak valid.")
    pattern = str(index_pattern or "wazuh-alerts-*").strip()
    if not _INDEX_PATTERN.match(pattern):
        raise ValueError("Pola indeks tidak valid.")
    target = f"{base}/{urllib.parse.quote(pattern, safe='*-._,')}/_count"
    body = json.dumps(wazuh_alert_query(min_rule_level=min_rule_level, max_rule_level=max_rule_level)).encode("utf-8")
    request = urllib.request.Request(
        target,
        data=body,
        method="POST",
        headers={"Accept": "application/json", "Content-Type": "application/json"},
    )
    if username:
        token = base64.b64encode(f"{username}:{password}".encode()).decode()
        request.add_header("Authorization", f"Basic {token}")

    context = None
    if target.lower().startswith("https://"):
        context = ssl.create_default_context()
        if not verify_tls:
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE

    opener = urllib.request.build_opener(
        urllib.request.ProxyHandler({}),
        *([urllib.request.HTTPSHandler(context=context)] if context else []),
    )
    try:
        with opener.open(request, timeout=timeout) as response:
            body = response.read(1024 * 1024)
            status = response.status
    except urllib.error.HTTPError as error:
        detail = _http_error_reason(error)
        if error.code in (401, 403):
            raise ValueError("Autentikasi Wazuh Indexer ditolak. Periksa username dan password.") from None
        if error.code == 404:
            raise ValueError("Indeks tidak ditemukan. Periksa pola indeks Wazuh.") from None
        raise ValueError(f"Wazuh Indexer menolak permintaan (HTTP {error.code}).{detail}") from None
    except urllib.error.URLError as error:
        reason = str(getattr(error, "reason", ""))
        if isinstance(getattr(error, "reason", None), ssl.SSLError) or "certificate" in reason.lower():
            raise ValueError("TLS gagal diverifikasi. Periksa sertifikat atau matikan verifikasi TLS untuk lab lokal.") from None
        raise ValueError("Tidak dapat terhubung ke Wazuh Indexer. Periksa URL dan jaringan.") from None
    except TimeoutError:
        raise ValueError("Koneksi ke Wazuh Indexer melebihi batas waktu.") from None

    try:
        parsed = json.loads(body.decode("utf-8") or "{}")
    except ValueError:
        raise ValueError("Respons Wazuh Indexer bukan JSON yang valid.") from None
    count = parsed.get("count") if isinstance(parsed, dict) else None
    return {
        "ok": True,
        "status": status,
        "count": int(count) if isinstance(count, (int, float)) else None,
        "index_pattern": pattern,
        "min_rule_level": int(min_rule_level),
        "max_rule_level": int(max_rule_level) if max_rule_level is not None else None,
    }


def _wazuh_opener(indexer_url: str, username: str, password: str, verify_tls: bool):
    """Build a ProxyHandler-free opener with optional basic auth + TLS control."""
    context = None
    if indexer_url.lower().startswith("https://"):
        context = ssl.create_default_context()
        if not verify_tls:
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
    return urllib.request.build_opener(
        urllib.request.ProxyHandler({}),
        *([urllib.request.HTTPSHandler(context=context)] if context else []),
    )


def _wazuh_request(opener, request, timeout: float) -> tuple[int, bytes]:
    """Open a Wazuh request and translate transport errors into user-safe ValueErrors."""
    try:
        with opener.open(request, timeout=timeout) as response:
            return response.status, response.read(64 * 1024 * 1024)
    except urllib.error.HTTPError as error:
        detail = _http_error_reason(error)
        if error.code in (401, 403):
            raise ValueError("Autentikasi Wazuh Indexer ditolak. Periksa username dan password.") from None
        if error.code == 404:
            raise ValueError("Indeks tidak ditemukan. Periksa pola indeks Wazuh.") from None
        raise ValueError(f"Wazuh Indexer menolak permintaan (HTTP {error.code}).{detail}") from None
    except urllib.error.URLError as error:
        reason = str(getattr(error, "reason", ""))
        if isinstance(getattr(error, "reason", None), ssl.SSLError) or "certificate" in reason.lower():
            raise ValueError("TLS gagal diverifikasi. Periksa sertifikat atau matikan verifikasi TLS untuk lab lokal.") from None
        raise ValueError("Tidak dapat terhubung ke Wazuh Indexer. Periksa URL dan jaringan.") from None
    except TimeoutError:
        raise ValueError("Koneksi ke Wazuh Indexer melebihi batas waktu.") from None


def _http_error_reason(error: urllib.error.HTTPError) -> str:
    """Extract a short, safe reason from an upstream HTTP error body.

    Returns '' when the body is missing or not JSON. Never echoes credentials —
    the body is the indexer's own error payload.
    """
    try:
        raw = error.read(64 * 1024).decode("utf-8", "replace")
    except Exception:
        return ""
    if not raw:
        return ""
    try:
        parsed = json.loads(raw)
    except ValueError:
        snippet = re.sub(r"\s+", " ", raw).strip()[:200]
        return f" ({snippet})" if snippet else ""
    if not isinstance(parsed, dict):
        return ""
    reason = parsed.get("error", {}).get("reason") if isinstance(parsed.get("error"), dict) else parsed.get("error")
    if isinstance(reason, str) and reason.strip():
        return f" {reason.strip()[:300]}"
    return ""


def wazuh_search(
    *,
    indexer_url: str,
    username: str,
    password: str,
    index_pattern: str,
    verify_tls: bool,
    size: int = 500,
    since: str = "",
    until: str = "",
    min_rule_level: int = MIN_RULE_LEVEL,
    max_rule_level: int | None = None,
    timeout: float = 10.0,
) -> list[dict[str, Any]]:
    """Pull alert documents from the Wazuh Indexer within the configured severity range.

    Returns a list of raw ``_source`` documents (newest first). ``since`` and ``until``
    are optional timestamp bounds on the alert ``timestamp`` field.
    """
    base = str(indexer_url or "").strip().rstrip("/")
    if not base or not _URL.match(base):
        raise ValueError("URL Wazuh Indexer belum diatur atau tidak valid.")
    pattern = str(index_pattern or "wazuh-alerts-*").strip()
    if not _INDEX_PATTERN.match(pattern):
        raise ValueError("Pola indeks tidak valid.")
    if not 1 <= int(size) <= 5000:
        raise ValueError("Ukuran pencarian Wazuh harus antara 1 dan 5000.")

    level_range: dict[str, int] = {"gte": int(min_rule_level)}
    if max_rule_level is not None:
        level_range["lte"] = int(max_rule_level)
    must_clauses: list[dict[str, Any]] = [{"range": {"rule.level": level_range}}]
    ts_range: dict[str, str] = {}
    if since and str(since).strip():
        ts_since = _normalize_wazuh_timestamp(str(since))
        if _valid_timestamp(ts_since):
            ts_range["gte"] = ts_since
    if until and str(until).strip():
        ts_until = _normalize_wazuh_timestamp(str(until))
        if _valid_timestamp(ts_until):
            ts_range["lte"] = ts_until
    if ts_range:
        must_clauses.append({"range": {"timestamp": ts_range}})
    query_obj: dict[str, Any] = (
        must_clauses[0] if len(must_clauses) == 1 else {"bool": {"must": must_clauses}}
    )
    payload = {
        "size": int(size),
        "query": query_obj,
        "sort": [{"timestamp": {"order": "desc"}}],
    }
    target = f"{base}/{urllib.parse.quote(pattern, safe='*-._,')}/_search"
    request = urllib.request.Request(
        target,
        data=json.dumps(payload).encode("utf-8"),
        method="POST",
        headers={"Accept": "application/json", "Content-Type": "application/json"},
    )
    if username:
        token = base64.b64encode(f"{username}:{password}".encode()).decode()
        request.add_header("Authorization", f"Basic {token}")
    opener = _wazuh_opener(base, username, password, verify_tls)
    status, raw = _wazuh_request(opener, request, timeout)
    try:
        parsed = json.loads(raw.decode("utf-8") or "{}")
    except ValueError:
        raise ValueError("Respons Wazuh Indexer bukan JSON yang valid.") from None
    hits = parsed.get("hits", {}) if isinstance(parsed, dict) else {}
    outer = hits.get("hits", []) if isinstance(hits, dict) else []
    docs: list[dict[str, Any]] = []
    for hit in outer:
        if isinstance(hit, dict) and isinstance(hit.get("_source"), dict):
            docs.append(hit["_source"])
    return docs
