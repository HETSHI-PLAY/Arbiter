"""PostgreSQL database layer and schema migration for Arbiter."""

from __future__ import annotations

import json
from contextlib import contextmanager
from typing import Any, Generator

import psycopg
from fastapi import HTTPException
from psycopg.rows import dict_row

from app.config import DATABASE_URL, REMOTE_DATABASE_URL, ACTIVE_DB_PROFILE

SCHEMA_SQL = """
CREATE SCHEMA IF NOT EXISTS wazuh;

CREATE TABLE IF NOT EXISTS wazuh.alerts (
    id BIGSERIAL PRIMARY KEY,
    alert_id TEXT NOT NULL DEFAULT '',
    timestamp TEXT,
    tenant TEXT NOT NULL DEFAULT 'Default',
    agent_name TEXT,
    agent_ip TEXT,
    rule_id TEXT,
    rule_level INTEGER,
    description TEXT NOT NULL DEFAULT '',
    rule_groups JSONB NOT NULL DEFAULT '[]',
    decoder TEXT,
    location TEXT,
    source_ip TEXT,
    mitre_ids JSONB NOT NULL DEFAULT '[]',
    cve TEXT,
    data JSONB NOT NULL DEFAULT '{}',
    raw JSONB NOT NULL,
    log_signature TEXT DEFAULT '',
    hit_count INTEGER DEFAULT 1,
    first_seen TEXT,
    last_seen TEXT,
    wazuh_ids JSONB DEFAULT '[]',
    duplicate_instances JSONB DEFAULT '[]',
    parsed_details JSONB DEFAULT '{}',
    is_reviewed BOOLEAN NOT NULL DEFAULT false,
    reviewed_at TIMESTAMPTZ,
    reviewer_notes TEXT DEFAULT '',
    imported_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE(alert_id, timestamp, agent_name, rule_id)
);

CREATE TABLE IF NOT EXISTS wazuh.analysis_groups (
    id UUID PRIMARY KEY,
    title TEXT NOT NULL,
    category TEXT NOT NULL DEFAULT '',
    analysis TEXT NOT NULL DEFAULT '',
    conclusion TEXT NOT NULL DEFAULT '',
    recommendation TEXT NOT NULL DEFAULT '',
    status TEXT NOT NULL DEFAULT 'open',
    severity TEXT NOT NULL DEFAULT 'medium',
    source TEXT NOT NULL DEFAULT 'human',
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS wazuh.alert_group_members (
    alert_pk BIGINT REFERENCES wazuh.alerts(id) ON DELETE CASCADE,
    group_id UUID REFERENCES wazuh.analysis_groups(id) ON DELETE CASCADE,
    PRIMARY KEY(alert_pk, group_id)
);

-- Fallback mock table for public.ip_intel_cache so open-source users without IP Intel don't crash
CREATE TABLE IF NOT EXISTS public.ip_intel_cache (
    ip TEXT PRIMARY KEY,
    abuse_score INTEGER,
    vt_malicious INTEGER,
    country_code TEXT,
    isp TEXT,
    attack_types TEXT[] DEFAULT '{}',
    total_alert_count INTEGER DEFAULT 1,
    last_seen TIMESTAMPTZ DEFAULT now()
);

-- Performance indices
CREATE INDEX IF NOT EXISTS idx_wazuh_alerts_source_ip ON wazuh.alerts(source_ip);
CREATE INDEX IF NOT EXISTS idx_wazuh_alerts_rule_id ON wazuh.alerts(rule_id);
CREATE INDEX IF NOT EXISTS idx_wazuh_alerts_timestamp ON wazuh.alerts(timestamp);
CREATE INDEX IF NOT EXISTS idx_wazuh_alerts_tenant ON wazuh.alerts(tenant);
CREATE INDEX IF NOT EXISTS idx_wazuh_alerts_sig ON wazuh.alerts(tenant, log_signature);
CREATE INDEX IF NOT EXISTS idx_wazuh_alerts_reviewed ON wazuh.alerts(is_reviewed);
-- Scoped stats and triage performance indices
CREATE INDEX IF NOT EXISTS idx_wazuh_alerts_tenant_timestamp ON wazuh.alerts(tenant, timestamp);
CREATE INDEX IF NOT EXISTS idx_wazuh_alerts_rule_level ON wazuh.alerts(rule_level);
CREATE INDEX IF NOT EXISTS idx_wazuh_alerts_agent_name ON wazuh.alerts(agent_name);
CREATE INDEX IF NOT EXISTS idx_wazuh_alerts_status ON wazuh.alerts((parsed_details->>'status'));
-- Note: highly-cardinal user_agent, url_path, referer, and arbitrary text pattern
-- dimensions intentionally do not carry broad btree indexes to prevent bloat on high-volume ingest.
"""


import secrets
import threading
import time
from urllib.parse import urlparse, urlunparse, unquote

_preview_lock = threading.Lock()
_profile_lock = threading.RLock()
_preview_registry: dict[str, dict[str, Any]] = {}
PREVIEW_TOKEN_TTL = 60.0
MAX_PREVIEW_REGISTRY_SIZE = 500


def _clean_expired_previews_locked(now: float) -> None:
    expired = [tok for tok, item in _preview_registry.items() if now > item.get("expires_at", 0)]
    for tok in expired:
        _preview_registry.pop(tok, None)


def create_preview_token(kind: str, profile_id: str, criteria: dict[str, Any], count: int) -> str:
    with _preview_lock:
        now = time.time()
        _clean_expired_previews_locked(now)
        # Cap registry capacity (LRU / FIFO eviction of oldest tokens if full)
        if len(_preview_registry) >= MAX_PREVIEW_REGISTRY_SIZE:
            oldest_tokens = sorted(_preview_registry.keys(), key=lambda k: _preview_registry[k].get("created_at", 0))
            num_to_evict = len(_preview_registry) - MAX_PREVIEW_REGISTRY_SIZE + 1
            for tok in oldest_tokens[:num_to_evict]:
                _preview_registry.pop(tok, None)

        token = secrets.token_hex(16)
        _preview_registry[token] = {
            "kind": kind,
            "profile_id": profile_id,
            "criteria": criteria,
            "count": count,
            "created_at": now,
            "expires_at": now + PREVIEW_TOKEN_TTL,
        }
        return token


def validate_and_consume_preview_token(token: str | None, kind: str, profile_id: str, criteria: dict[str, Any]) -> dict[str, Any]:
    if not token or not str(token).strip():
        raise HTTPException(
            status_code=400,
            detail="Eksekusi pembersihan memerlukan server-side preview_token yang valid. Buat pratinjau terlebih dahulu."
        )
    token_str = str(token).strip()
    with _preview_lock:
        now = time.time()
        _clean_expired_previews_locked(now)
        # Atomic single-use consumption: exactly one thread gets entry, others get None
        entry = _preview_registry.pop(token_str, None)

    if not entry:
        raise HTTPException(
            status_code=400,
            detail="Preview token tidak valid, telah kedaluwarsa (berlaku 60 detik), atau sudah digunakan (single-use). Lakukan pratinjau ulang."
        )
    if now > entry["expires_at"]:
        raise HTTPException(
            status_code=400,
            detail="Preview token telah kedaluwarsa (berlaku 60 detik). Lakukan pratinjau ulang."
        )
    if entry["profile_id"] != profile_id:
        raise HTTPException(
            status_code=409,
            detail=f"Target profil database telah berubah dari '{entry['profile_id']}' menjadi '{profile_id}'. Eksekusi dibatalkan demi keamanan."
        )
    if entry["kind"] != kind:
        raise HTTPException(
            status_code=400,
            detail=f"Preview token tidak sesuai jenis operasi ({entry['kind']} != {kind})."
        )
    if entry["criteria"] != criteria:
        raise HTTPException(
            status_code=400,
            detail="Kriteria pembersihan tidak cocok dengan pratinjau yang disetujui. Lakukan pratinjau ulang."
        )
    return entry


_active_profile = ACTIVE_DB_PROFILE
_db_profiles: dict[str, dict[str, Any]] = {
    "local": {
        "id": "local",
        "name": "Laptop (Lokal)",
        "url": DATABASE_URL,
        "mode": "read_write",
        "description": "PostgreSQL lokal di laptop. Workspace operasional SOC utama.",
    },
    "remote": {
        "id": "remote",
        "name": "PC Intel (Remote)",
        "url": REMOTE_DATABASE_URL,
        "mode": "read_only",
        "description": "PostgreSQL pada host IP Intel. Sumber cache reputasi dan telemetri sekunder.",
    },
}


def mask_connection_url(url: str) -> str:
    """Masks password in connection URI for safe UI display."""
    try:
        parsed = urlparse(url)
        if parsed.password:
            netloc = f"{parsed.username or ''}:***@{parsed.hostname or ''}"
            if parsed.port:
                netloc += f":{parsed.port}"
            return urlunparse(parsed._replace(netloc=netloc))
        return url
    except Exception:
        return "postgresql://***"


def get_active_profile_id() -> str:
    return _active_profile


def get_active_profile() -> dict[str, Any]:
    prof = _db_profiles.get(_active_profile, _db_profiles["local"])
    return {
        "id": prof["id"],
        "name": prof["name"],
        "mode": prof["mode"],
        "description": prof["description"],
        "masked_url": mask_connection_url(prof["url"]),
    }


def set_active_profile(profile_id: str) -> dict[str, Any]:
    global _active_profile
    with _profile_lock:
        if profile_id not in _db_profiles:
            raise HTTPException(status_code=400, detail=f"Database profile '{profile_id}' not found.")
        _active_profile = profile_id
        return get_active_profile()


def update_profile_url(profile_id: str, new_url: str) -> dict[str, Any]:
    if profile_id not in _db_profiles:
        raise HTTPException(status_code=400, detail=f"Database profile '{profile_id}' not found.")
    new_url = str(new_url).strip()
    if not (new_url.startswith("postgresql://") or new_url.startswith("postgres://")):
        raise HTTPException(status_code=400, detail="Connection URL must start with postgresql://")
    if unquote(urlparse(new_url).password or "") == "***":
        raise HTTPException(status_code=400, detail="Masked URI is display-only. Enter a complete replacement URI.")
    _db_profiles[profile_id]["url"] = new_url
    return get_active_profile()


def test_db_connection(url: str | None = None, *, profile_id: str | None = None) -> dict[str, Any]:
    if profile_id is not None and profile_id not in _db_profiles:
        raise HTTPException(status_code=400, detail="Unknown database profile.")
    target_url = url or _db_profiles[profile_id or _active_profile]["url"]
    start_t = time.perf_counter()
    try:
        with psycopg.connect(target_url, connect_timeout=4, row_factory=dict_row) as conn:
            row = conn.execute("SELECT version() AS v").fetchone()
            ver = row["v"] if row else "PostgreSQL"
            elapsed = time.perf_counter() - start_t
            return {
                "ok": True,
                "latency_ms": round(elapsed * 1000, 1),
                "version": ver.split(",")[0] if ver else "PostgreSQL",
            }
    except Exception as exc:
        elapsed = time.perf_counter() - start_t
        return {
            "ok": False,
            "latency_ms": round(elapsed * 1000, 1),
            "error": str(exc),
        }


def get_db_connection(profile_id: str | None = None):
    """Returns a psycopg connection with dictionary row formatting for the active profile."""
    with _profile_lock:
        target_pid = profile_id or _active_profile
        prof = _db_profiles.get(target_pid, _db_profiles["local"])
    try:
        conn = psycopg.connect(prof["url"], row_factory=dict_row)
        try:
            conn._arbiter_profile_id = prof["id"]
            conn._arbiter_profile_mode = prof["mode"]
        except (AttributeError, TypeError):
            pass
        return conn
    except Exception as exc:
        raise HTTPException(
            status_code=503,
            detail=f"Database connection error ({prof['name']}): {exc}",
        ) from exc


def get_database_status(conn: psycopg.Connection | Any | None = None) -> dict[str, Any]:
    """Returns comprehensive database details, health metrics, and tenant distribution."""
    active_conn = conn if conn is not None else get_db_connection()
    own_conn = conn is None
    try:
        alerts_n = active_conn.execute("SELECT count(*) AS n FROM wazuh.alerts").fetchone()["n"]
        groups_n = active_conn.execute("SELECT count(*) AS n FROM wazuh.analysis_groups").fetchone()["n"]
        intel_n = 0
        try:
            intel_n = active_conn.execute("SELECT count(*) AS n FROM public.ip_intel_cache").fetchone()["n"]
        except Exception:
            pass

        time_range = active_conn.execute("""
            SELECT min(timestamp) AS earliest, max(timestamp) AS latest
            FROM wazuh.alerts
        """).fetchone()

        tenants = active_conn.execute("""
            SELECT tenant, count(*) AS count
            FROM wazuh.alerts
            GROUP BY tenant
            ORDER BY count DESC, tenant ASC
        """).fetchall()

        table_sizes = {}
        try:
            alerts_size = active_conn.execute("SELECT pg_size_pretty(pg_total_relation_size('wazuh.alerts')) AS sz").fetchone()["sz"]
            groups_size = active_conn.execute("SELECT pg_size_pretty(pg_total_relation_size('wazuh.analysis_groups')) AS sz").fetchone()["sz"]
            table_sizes = {"wazuh.alerts": alerts_size, "wazuh.analysis_groups": groups_size}
        except Exception:
            table_sizes = {"wazuh.alerts": "N/A (Local SQLite/Memory)", "wazuh.analysis_groups": "N/A"}

        profiles_info = []
        for pid, pdata in _db_profiles.items():
            profiles_info.append({
                "id": pid,
                "name": pdata["name"],
                "mode": pdata["mode"],
                "description": pdata["description"],
                "masked_url": mask_connection_url(pdata["url"]),
                "is_active": pid == _active_profile,
            })

        return {
            "status": "ok",
            "active_profile": get_active_profile(),
            "profiles": profiles_info,
            "stats": {
                "alerts": alerts_n,
                "groups": groups_n,
                "ip_intel_records": intel_n,
                "earliest_telemetry": time_range["earliest"] if time_range else None,
                "latest_telemetry": time_range["latest"] if time_range else None,
            },
            "tenants": tenants or [],
            "table_sizes": table_sizes,
        }
    finally:
        if own_conn:
            active_conn.close()


def purge_alerts(
    conn: psycopg.Connection,
    *,
    older_than_days: int | None = None,
    time_from: str | None = None,
    time_to: str | None = None,
    tenant: str = "all",
    dry_run: bool = True,
    preview_token: str | None = None,
    expected_profile: str | None = None,
) -> dict[str, Any]:
    raw_pid = getattr(conn, "_arbiter_profile_id", None)
    conn_pid = raw_pid if isinstance(raw_pid, str) else None
    with _profile_lock:
        current_active = _active_profile
        if conn_pid and conn_pid != current_active:
            raise HTTPException(
                status_code=409,
                detail=f"Profil database beralih di tengah pemrosesan ('{conn_pid}' -> '{current_active}'). Permintaan dibatalkan.",
            )
        active = _db_profiles.get(conn_pid or current_active, _db_profiles["local"])

    if expected_profile and str(expected_profile).strip() != active["id"]:
        raise HTTPException(
            status_code=409,
            detail=f"Target profil database tidak cocok (aktif: '{active['id']}', diharapkan: '{expected_profile}').",
        )
    if not dry_run and active["mode"] == "read_only":
        raise HTTPException(
            status_code=403,
            detail=f"Database '{active['name']}' dalam mode Read-Only. Beralih ke profil Laptop (Lokal) untuk pembersihan data.",
        )

    criteria = {
        "tenant": tenant or "all",
        "older_than_days": older_than_days,
        "time_from": str(time_from).strip() if time_from else "",
        "time_to": str(time_to).strip() if time_to else "",
    }

    clauses: list[str] = []
    params: list[Any] = []
    if tenant and tenant != "all":
        clauses.append("tenant = %s")
        params.append(tenant)
    if older_than_days is not None:
        if older_than_days <= 0 or older_than_days > 36500:
            raise HTTPException(status_code=400, detail="Parameter older_than_days harus berupa bilangan bulat positif.")
        from datetime import datetime, timezone, timedelta
        cutoff = (datetime.now(timezone.utc) - timedelta(days=older_than_days)).strftime("%Y-%m-%dT%H:%M:%SZ")
        clauses.append("timestamp < %s")
        params.append(cutoff)
    if time_from and str(time_from).strip():
        clauses.append("timestamp >= %s")
        params.append(str(time_from).strip())
    if time_to and str(time_to).strip():
        clauses.append("timestamp <= %s")
        params.append(str(time_to).strip())

    if not clauses:
        raise HTTPException(status_code=400, detail="Tentukan minimal satu filter pembersihan (rentang waktu, hari, atau tenant).")

    where_sql = "WHERE " + " AND ".join(clauses)
    count_sql = f"SELECT count(*) AS n FROM wazuh.alerts {where_sql}"
    matching = conn.execute(count_sql, params).fetchone()["n"]

    if dry_run:
        token = create_preview_token("alerts", active["id"], criteria, matching)
        return {"dry_run": True, "count": matching, "preview_token": token, "profile": active["id"]}

    validate_and_consume_preview_token(preview_token, "alerts", active["id"], criteria)
    cur = conn.execute(f"DELETE FROM wazuh.alerts {where_sql}", params)
    actual_deleted = cur.rowcount if (cur and hasattr(cur, "rowcount") and cur.rowcount is not None and cur.rowcount >= 0) else matching
    return {"dry_run": False, "deleted": actual_deleted}


def purge_incidents(
    conn: psycopg.Connection,
    *,
    status_filter: str = "closed_only",
    dry_run: bool = True,
    preview_token: str | None = None,
    expected_profile: str | None = None,
) -> dict[str, Any]:
    raw_pid = getattr(conn, "_arbiter_profile_id", None)
    conn_pid = raw_pid if isinstance(raw_pid, str) else None
    with _profile_lock:
        current_active = _active_profile
        if conn_pid and conn_pid != current_active:
            raise HTTPException(
                status_code=409,
                detail=f"Profil database beralih di tengah pemrosesan ('{conn_pid}' -> '{current_active}'). Permintaan dibatalkan.",
            )
        active = _db_profiles.get(conn_pid or current_active, _db_profiles["local"])

    if expected_profile and str(expected_profile).strip() != active["id"]:
        raise HTTPException(
            status_code=409,
            detail=f"Target profil database tidak cocok (aktif: '{active['id']}', diharapkan: '{expected_profile}').",
        )
    if not dry_run and active["mode"] == "read_only":
        raise HTTPException(
            status_code=403,
            detail=f"Database '{active['name']}' dalam mode Read-Only. Beralih ke profil Laptop (Lokal) untuk pembersihan data.",
        )

    valid_statuses = {"closed_only", "all", "closed", "resolved", "open", "in_progress"}
    if status_filter not in valid_statuses:
        raise HTTPException(status_code=400, detail=f"Kriteria kasus '{status_filter}' tidak valid.")

    criteria = {"status_filter": status_filter}

    clauses: list[str] = []
    params: list[Any] = []
    if status_filter == "closed_only":
        clauses.append("status IN ('closed', 'resolved')")
    elif status_filter == "all":
        pass
    else:
        clauses.append("status = %s")
        params.append(status_filter)

    where_sql = ("WHERE " + " AND ".join(clauses)) if clauses else ""
    count_sql = f"SELECT count(*) AS n FROM wazuh.analysis_groups {where_sql}"
    matching = conn.execute(count_sql, params).fetchone()["n"]

    if dry_run:
        token = create_preview_token("incidents", active["id"], criteria, matching)
        return {"dry_run": True, "count": matching, "preview_token": token, "profile": active["id"]}

    validate_and_consume_preview_token(preview_token, "incidents", active["id"], criteria)
    cur = conn.execute(f"DELETE FROM wazuh.analysis_groups {where_sql}", params)
    actual_deleted = cur.rowcount if (cur and hasattr(cur, "rowcount") and cur.rowcount is not None and cur.rowcount >= 0) else matching
    return {"dry_run": False, "deleted": actual_deleted}


@contextmanager
def get_db() -> Generator[psycopg.Connection, None, None]:
    conn = get_db_connection()
    try:
        yield conn
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()


def init_database() -> None:
    """Executes schema migrations and ensures indices exist."""
    with get_db() as conn:
        conn.execute(SCHEMA_SQL)


def ingest_alert_with_dedup(conn: psycopg.Connection, a: dict[str, Any]) -> tuple[bool, bool]:
    """Ingests an alert with safeguard against identical Wazuh IDs and signature-based hit aggregation.

    Returns:
        (inserted, deduplicated)
    """
    alert_id = str(a.get("alert_id") or a.get("id") or "").strip()
    wazuh_id = str(a.get("wazuh_id") or alert_id).strip()
    tenant = a.get("tenant") or "Default"
    sig = a.get("log_signature") or ""
    timestamp = a.get("timestamp") or ""

    # Safeguard 1: Exact alert already exists by alert_id or contained in wazuh_ids
    existing_by_id = conn.execute(
        """SELECT id FROM wazuh.alerts 
           WHERE (alert_id = %s OR wazuh_ids @> %s::jsonb) AND tenant = %s 
           LIMIT 1""",
        (alert_id, json.dumps([wazuh_id]), tenant),
    ).fetchone()
    if existing_by_id:
        return False, False  # Exactly the same alert already in DB, safe ignore

    # Safeguard 2: Signature deduplication across identical recurring logs
    instance_meta = {
        "id": alert_id or wazuh_id,
        "timestamp": timestamp,
        "agent_name": a.get("agent_name"),
        "agent_ip": a.get("agent_ip"),
        "location": a.get("location"),
        "full_log": a.get("full_log"),
    }

    if sig:
        existing_sig = conn.execute(
            """SELECT id, hit_count, first_seen, last_seen, wazuh_ids, duplicate_instances 
               FROM wazuh.alerts 
               WHERE tenant = %s AND log_signature = %s AND log_signature != '' 
               LIMIT 1""",
            (tenant, sig),
        ).fetchone()

        if existing_sig:
            pk = existing_sig["id"]
            current_count = existing_sig["hit_count"] or 1
            existing_w_ids = existing_sig["wazuh_ids"] or []
            existing_instances = existing_sig["duplicate_instances"] or []

            if wazuh_id and wazuh_id not in existing_w_ids:
                existing_w_ids.append(wazuh_id)
            existing_instances.append(instance_meta)

            # Update time bounds
            times = [t for t in (existing_sig["first_seen"], existing_sig["last_seen"], timestamp) if t]
            first_t = min(times) if times else timestamp
            last_t = max(times) if times else timestamp

            conn.execute(
                """UPDATE wazuh.alerts 
                   SET hit_count = %s,
                       first_seen = %s,
                       last_seen = %s,
                       wazuh_ids = %s::jsonb,
                       duplicate_instances = %s::jsonb
                   WHERE id = %s""",
                (
                    current_count + 1,
                    first_t,
                    last_t,
                    json.dumps(existing_w_ids),
                    json.dumps(existing_instances, ensure_ascii=False),
                    pk,
                ),
            )
            return False, True  # Deduplicated into existing row

    # New distinct alert row
    wazuh_ids = [wazuh_id] if wazuh_id else []
    instances = [instance_meta]

    values = (
        alert_id,
        timestamp,
        tenant,
        a.get("agent_name"),
        a.get("agent_ip"),
        a.get("rule_id"),
        a.get("rule_level"),
        a.get("description"),
        json.dumps(a.get("rule_groups") or []),
        a.get("decoder"),
        a.get("location"),
        a.get("source_ip"),
        json.dumps(a.get("mitre_ids") or []),
        a.get("cve"),
        json.dumps(a.get("data") or {}),
        json.dumps(a.get("raw") or {}, ensure_ascii=False),
        sig,
        1,
        timestamp,
        timestamp,
        json.dumps(wazuh_ids),
        json.dumps(instances, ensure_ascii=False),
        json.dumps(a.get("parsed_details") or {}),
        False,
        "",
    )

    cur = conn.execute(
        """INSERT INTO wazuh.alerts(
            alert_id, timestamp, tenant, agent_name, agent_ip, rule_id, rule_level,
            description, rule_groups, decoder, location, source_ip, mitre_ids,
            cve, data, raw, log_signature, hit_count, first_seen, last_seen,
            wazuh_ids, duplicate_instances, parsed_details, is_reviewed, reviewer_notes
        ) VALUES(
            %s, %s, %s, %s, %s, %s, %s, %s, %s::jsonb, %s, %s, %s, %s::jsonb,
            %s, %s::jsonb, %s::jsonb, %s, %s, %s, %s, %s::jsonb, %s::jsonb, %s::jsonb, %s, %s
        ) ON CONFLICT(alert_id, timestamp, agent_name, rule_id) DO NOTHING RETURNING id""",
        values,
    )

    if cur.fetchone():
        return True, False
    return False, False
