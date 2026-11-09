"""Threat intelligence enrichment and database caching for Arbiter & IP Intel."""

from __future__ import annotations

import ipaddress
import json
import logging
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.parse import quote
from urllib.request import Request, urlopen

import os

try:
    import app.config as _cfg
    ABUSEIPDB_API_KEY = getattr(_cfg, "ABUSEIPDB_API_KEY", "")
    REMOTE_DATABASE_URL = getattr(_cfg, "REMOTE_DATABASE_URL", "")
except (ImportError, AttributeError):
    ABUSEIPDB_API_KEY = os.getenv("ABUSEIPDB_API_KEY", "")
    REMOTE_DATABASE_URL = os.getenv("REMOTE_DATABASE_URL", "")

logger = logging.getLogger("arbiter.intel")


def is_valid_ip(ip: str) -> bool:
    """Validates IPv4 and IPv6 addresses."""
    if not isinstance(ip, str) or not ip.strip():
        return False
    clean = ip.strip()
    try:
        ipaddress.ip_address(clean)
        return True
    except ValueError:
        return False


def is_private_ip(ip: str) -> bool:
    """Checks if IP belongs to private/RFC1918, loopback, or link-local range."""
    try:
        obj = ipaddress.ip_address(ip.strip())
        return (
            obj.is_private
            or obj.is_loopback
            or obj.is_link_local
            or obj.is_multicast
            or obj.is_reserved
        )
    except ValueError:
        return False


def query_abuseipdb(ip: str, api_key: str | None = None) -> dict[str, Any]:
    """Queries AbuseIPDB API v2 check endpoint."""
    key = api_key or ABUSEIPDB_API_KEY
    if not key:
        raise ValueError("AbuseIPDB API key not configured")

    url = f"https://api.abuseipdb.com/api/v2/check?ipAddress={quote(ip)}&maxAgeInDays=90&verbose"
    req = Request(
        url,
        headers={
            "Key": key,
            "Accept": "application/json",
            "User-Agent": "Arbiter-SOC/2.0",
        },
    )
    try:
        with urlopen(req, timeout=10) as resp:
            data = json.loads(resp.read().decode("utf-8"))
            return data.get("data") or {}
    except HTTPError as exc:
        err_msg = f"HTTP {exc.code}"
        try:
            body = json.loads(exc.read().decode("utf-8"))
            if body.get("errors"):
                err_msg = body["errors"][0].get("detail", err_msg)
        except Exception:
            pass
        raise RuntimeError(f"AbuseIPDB error: {err_msg}") from exc
    except (URLError, TimeoutError) as exc:
        raise RuntimeError(f"AbuseIPDB network error: {exc}") from exc


def _resolve_remote_db_url() -> str:
    """Resolve the active remote IP Intel database URL (including runtime overrides from #/database)."""
    try:
        import app.database as _db_mod
        prof = getattr(_db_mod, "_db_profiles", {}).get("remote", {})
        url = str(prof.get("url") or "").strip()
        if url:
            return url
    except Exception:
        pass
    return str(REMOTE_DATABASE_URL or "").strip()


def lookup_remote_ip_cache(ip: str, remote_url: str | None = None) -> dict[str, Any] | None:
    """Look up an existing IP record in the remote IP Intel PostgreSQL database."""
    target_url = str(remote_url or _resolve_remote_db_url()).strip()
    if not target_url:
        return None
    try:
        import psycopg  # type: ignore
        from psycopg.rows import dict_row  # type: ignore
        with psycopg.connect(target_url, connect_timeout=3, row_factory=dict_row) as rconn:
            row = rconn.execute(
                "SELECT ip, abuse_score, vt_malicious, country_code, isp FROM public.ip_intel_cache WHERE ip = %s",
                (ip,),
            ).fetchone()
            if row and row.get("abuse_score") is not None:
                return {
                    "ip": ip,
                    "status": "enriched",
                    "abuse_score": int(row.get("abuse_score") or 0),
                    "vt_malicious": int(row.get("vt_malicious") or 0),
                    "country_code": row.get("country_code"),
                    "isp": row.get("isp") or "Unknown ISP",
                    "domain": None,
                    "usage_type": None,
                    "total_reports": 0,
                    "reputation_source": "ip_intel_db",
                    "is_private": False,
                }
    except Exception as exc:
        logger.debug("Remote IP Intel DB lookup skipped: %s", exc)
    return None


def enrich_ip(ip: str, api_key: str | None = None, remote_url: str | None = None) -> dict[str, Any]:
    """Enriches a single IP address with threat intelligence."""
    clean_ip = ip.strip()
    if not is_valid_ip(clean_ip):
        return {
            "ip": clean_ip,
            "status": "invalid",
            "error": "Bukan format IPv4/IPv6 yang valid.",
            "abuse_score": None,
        }

    # Private IP check: keep telemetry private and airgapped
    if is_private_ip(clean_ip):
        return {
            "ip": clean_ip,
            "status": "private",
            "abuse_score": 0,
            "vt_malicious": 0,
            "country_code": "LAN",
            "isp": "Private Local Network (RFC1918)",
            "domain": None,
            "usage_type": "Private / Intranet",
            "total_reports": 0,
            "reputation_source": "local_private",
            "is_private": True,
        }

    effective_key = (api_key or ABUSEIPDB_API_KEY or "").strip()
    if effective_key:
        try:
            data = query_abuseipdb(clean_ip, effective_key)
            score = int(data.get("abuseConfidenceScore") or 0)
            return {
                "ip": clean_ip,
                "status": "enriched",
                "abuse_score": score,
                "vt_malicious": 0,
                "country_code": data.get("countryCode"),
                "isp": data.get("isp") or "Unknown ISP",
                "domain": data.get("domain"),
                "usage_type": data.get("usageType"),
                "total_reports": int(data.get("totalReports") or 0),
                "reputation_source": "abuseipdb",
                "is_private": False,
            }
        except Exception as exc:
            remote_cached = lookup_remote_ip_cache(clean_ip, remote_url)
            if remote_cached:
                return remote_cached
            return {
                "ip": clean_ip,
                "status": "error",
                "error": str(exc),
                "abuse_score": None,
            }

    # If no AbuseIPDB API key is configured, pull directly from the remote IP Intel database cache
    remote_cached = lookup_remote_ip_cache(clean_ip, remote_url)
    if remote_cached:
        return remote_cached

    return {
        "ip": clean_ip,
        "status": "error",
        "error": "AbuseIPDB API key belum diatur di Pengaturan dan IP belum ditemukan di database PC Intel (Remote).",
        "abuse_score": None,
    }


def upsert_ip_cache(conn: Any, enriched: dict[str, Any]) -> None:
    """Upserts enriched IP telemetry into public.ip_intel_cache."""
    ip = enriched.get("ip")
    if not ip or enriched.get("status") in ("invalid", "error"):
        return

    sql = """
    INSERT INTO public.ip_intel_cache (
        ip, abuse_score, vt_malicious, country_code, isp
    ) VALUES (%s, %s, %s, %s, %s)
    ON CONFLICT (ip) DO UPDATE SET
        abuse_score = EXCLUDED.abuse_score,
        vt_malicious = COALESCE(EXCLUDED.vt_malicious, ip_intel_cache.vt_malicious),
        country_code = COALESCE(EXCLUDED.country_code, ip_intel_cache.country_code),
        isp = COALESCE(EXCLUDED.isp, ip_intel_cache.isp)
    """
    conn.execute(
        sql,
        (
            ip,
            enriched.get("abuse_score"),
            enriched.get("vt_malicious", 0),
            enriched.get("country_code"),
            enriched.get("isp"),
        ),
    )


def sync_remote_cache(enriched_list: list[dict[str, Any]], remote_url: str | None = None) -> None:
    """Attempts best-effort mirror to remote IP Intel database if reachable."""
    target_url = str(remote_url or _resolve_remote_db_url()).strip()
    if not target_url or not enriched_list:
        return
    try:
        import psycopg  # type: ignore
        with psycopg.connect(target_url, connect_timeout=3) as rconn:
            with rconn.cursor() as cur:
                for item in enriched_list:
                    if item.get("status") not in ("invalid", "error"):
                        upsert_ip_cache(cur, item)
            rconn.commit()
    except Exception as exc:
        logger.debug("Remote cache sync skipped or unreachable: %s", exc)
