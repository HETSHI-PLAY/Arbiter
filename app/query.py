"""Shared parameterized alert predicates; no database or configuration imports."""
from __future__ import annotations

import json
import re
from collections.abc import Sequence
from datetime import datetime, timedelta, timezone
from typing import Any
from urllib.parse import unquote

from fastapi import HTTPException


def validated_group_id(value: str | None) -> str | None:
    if value is not None and not re.fullmatch(r"[0-9a-fA-F]{8}(?:-[0-9a-fA-F]{4}){3}-[0-9a-fA-F]{12}", value):
        raise HTTPException(status_code=422, detail="group_id must be a UUID.")
    return value


# These names are an API contract, not client-provided SQL.
# PIVOT_DEFINITIONS is a closed, immutable whitelist of supported dimensions.
PIVOT_DEFINITIONS: dict[str, dict[str, str]] = {
    "rule_description": {
        "label": "Deskripsi rule",
        "sql": "COALESCE(NULLIF(a.description, ''), 'Wazuh Alert')",
    },
    "rule_id": {
        "label": "Rule ID",
        "sql": "COALESCE(NULLIF(a.rule_id, ''), '-')",
    },
    "severity": {
        "label": "Severity",
        "sql": (
            "CASE "
            "WHEN a.rule_level >= 12 THEN 'critical' "
            "WHEN a.rule_level >= 10 THEN 'high' "
            "WHEN a.rule_level >= 7 THEN 'medium' "
            "ELSE 'low' END"
        ),
    },
    "source_ip": {
        "label": "Source IP",
        "sql": "COALESCE(NULLIF(a.source_ip, ''), 'Tanpa IP')",
    },
    "agent": {
        "label": "Host / Agent",
        "sql": "COALESCE(NULLIF(a.agent_name, ''), 'Tidak diketahui')",
    },
    "referer": {
        "label": "Referer",
        "sql": "COALESCE(NULLIF(a.parsed_details->>'referer', ''), 'Tidak tersedia')",
    },
    "http_status": {
        "label": "HTTP status",
        "sql": (
            "COALESCE("
            "NULLIF(a.data->>'status', ''), "
            "NULLIF(a.data->>'id', ''), "
            "NULLIF(a.parsed_details->>'status', ''), "
            "NULLIF(a.parsed_details->>'http_status', ''), "
            "'Tidak tersedia')"
        ),
    },
    "http_method": {
        "label": "HTTP Method",
        "sql": "COALESCE(NULLIF(UPPER(a.parsed_details->>'method'), ''), 'Tidak tersedia')",
    },
    "url_path": {
        "label": "URL / Path",
        "sql": (
            "CASE "
            "WHEN COALESCE("
            "NULLIF(a.data->>'url', ''), "
            "NULLIF(a.data->>'uri', ''), "
            "NULLIF(a.parsed_details->>'path', ''), "
            "NULLIF(a.parsed_details->>'uri', ''), "
            "NULLIF(a.parsed_details->>'url_path', ''), "
            "'') = '' THEN 'Tidak tersedia' "
            "WHEN split_part(COALESCE(NULLIF(a.data->>'url', ''), NULLIF(a.data->>'uri', ''), NULLIF(a.parsed_details->>'path', ''), NULLIF(a.parsed_details->>'uri', ''), NULLIF(a.parsed_details->>'url_path', ''), ''), '?', 1) IN ('', '/') "
            "AND COALESCE(NULLIF(a.data->>'url', ''), NULLIF(a.data->>'uri', ''), NULLIF(a.parsed_details->>'path', ''), NULLIF(a.parsed_details->>'uri', ''), NULLIF(a.parsed_details->>'url_path', ''), '') LIKE '%%?%%' "
            "THEN COALESCE(NULLIF(a.data->>'url', ''), NULLIF(a.data->>'uri', ''), NULLIF(a.parsed_details->>'path', ''), NULLIF(a.parsed_details->>'uri', ''), NULLIF(a.parsed_details->>'url_path', ''), '') "
            "WHEN split_part(COALESCE(NULLIF(a.data->>'url', ''), NULLIF(a.data->>'uri', ''), NULLIF(a.parsed_details->>'path', ''), NULLIF(a.parsed_details->>'uri', ''), NULLIF(a.parsed_details->>'url_path', ''), ''), '?', 1) = '/index.php' "
            "AND COALESCE(NULLIF(a.data->>'url', ''), NULLIF(a.data->>'uri', ''), NULLIF(a.parsed_details->>'path', ''), NULLIF(a.parsed_details->>'uri', ''), NULLIF(a.parsed_details->>'url_path', ''), '') LIKE '%%?%%' "
            "THEN COALESCE(NULLIF(a.data->>'url', ''), NULLIF(a.data->>'uri', ''), NULLIF(a.parsed_details->>'path', ''), NULLIF(a.parsed_details->>'uri', ''), NULLIF(a.parsed_details->>'url_path', ''), '') "
            "WHEN COALESCE(NULLIF(a.data->>'url', ''), NULLIF(a.data->>'uri', ''), NULLIF(a.parsed_details->>'path', ''), NULLIF(a.parsed_details->>'uri', ''), NULLIF(a.parsed_details->>'url_path', ''), '') LIKE '%%rest_route=%%' "
            "THEN COALESCE(NULLIF(a.data->>'url', ''), NULLIF(a.data->>'uri', ''), NULLIF(a.parsed_details->>'path', ''), NULLIF(a.parsed_details->>'uri', ''), NULLIF(a.parsed_details->>'url_path', ''), '') "
            "ELSE COALESCE(NULLIF(split_part(COALESCE(NULLIF(a.data->>'url', ''), NULLIF(a.data->>'uri', ''), NULLIF(a.parsed_details->>'path', ''), NULLIF(a.parsed_details->>'uri', ''), NULLIF(a.parsed_details->>'url_path', ''), ''), '?', 1), ''), '/') "
            "END"
        ),
    },
    "user_agent": {
        "label": "User-Agent",
        "sql": "COALESCE(NULLIF(a.parsed_details->>'ua', ''), NULLIF(a.parsed_details->>'user_agent', ''), 'Tidak tersedia')",
    },
    "pattern": {
        "label": "Pola teks",
        "sql": "",
    },
    "tenant": {
        "label": "Tenant",
        "sql": "COALESCE(NULLIF(a.tenant, ''), 'Default')",
    },
}

FACET_COLUMNS = {k: v["sql"] for k, v in PIVOT_DEFINITIONS.items() if v["sql"]}


def normalize_tenants(values: str | Sequence[str] | None) -> tuple[str, ...]:
    """Return the canonical exact tenant set; an empty tuple represents all."""
    if values is None:
        return ()
    raw_values = [values] if isinstance(values, str) else list(values)
    if not raw_values:
        return ()
    tenants = [str(value).strip() for value in raw_values]
    if any(not value for value in tenants):
        raise HTTPException(status_code=422, detail="tenant must not be blank.")
    unique = tuple(sorted(set(tenants)))
    if "all" in unique:
        if len(unique) != 1:
            raise HTTPException(status_code=422, detail="tenant=all cannot be combined with named tenants.")
        return ()
    return unique


def tenant_clause(alias: str, values: str | Sequence[str] | None) -> tuple[str, list[Any]]:
    """Build a bound exact-set tenant predicate for a trusted query alias."""
    if not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", alias):
        raise ValueError("SQL alias must be a simple identifier.")
    tenants = normalize_tenants(values)
    return (f"{alias}.tenant = ANY(%s)", [list(tenants)]) if tenants else ("", [])


def positive_ids(values: list[Any]) -> list[int]:
    """Validate every explicit ID; never silently discard a bad selection."""
    result = []
    for value in values:
        token = str(value)
        if not token.isascii() or not token.isdecimal() or int(token) < 1:
            raise ValueError("Alert IDs must be positive integers.")
        number = int(token)
        if number > 9_223_372_036_854_775_807:
            raise ValueError("Alert ID exceeds the supported integer range.")
        if number not in result:
            result.append(number)
    return result


def alert_where(
    *, q: str = "", tenant: str | Sequence[str] | None = "all", status: str = "all",
    group_id: str | None = None, filter_preset: str = "",
    review_status: str = "all",
    time_preset: str = "",
    time_from: str | None = None, time_to: str | None = None,
    facet: str = "", facet_value: str = "",
    secondary_facet: str = "", secondary_facet_value: str = "",
    alert_ids: str | Sequence[int | str] | None = None,
) -> tuple[str, list[Any]]:
    group_id = validated_group_id(group_id)
    clauses: list[str] = []
    params: list[Any] = []
    if alert_ids is not None and str(alert_ids).strip() != "":
        raw_ids = (
            [tok.strip() for tok in str(alert_ids).split(",") if tok.strip()]
            if isinstance(alert_ids, str)
            else [tok for tok in alert_ids if str(tok).strip()]
        )
        if raw_ids:
            try:
                parsed_ids = positive_ids(raw_ids)
            except ValueError as exc:
                raise HTTPException(status_code=422, detail=str(exc)) from exc
            clauses.append("a.id = ANY(%s)")
            params.append(parsed_ids)
    if q:
        columns = (
            "a.alert_id", "a.agent_name", "a.agent_ip", "a.rule_id", "a.description",
            "a.source_ip", "a.cve", "a.tenant", "a.location", "a.decoder", "a.raw::text",
        )
        clauses.append("(" + " OR ".join(f"{column} ILIKE %s" for column in columns) + ")")
        params.extend([f"%{q}%"] * len(columns))
    tenant_sql, tenant_params = tenant_clause("a", tenant)
    if tenant_sql:
        clauses.append(tenant_sql)
        params.extend(tenant_params)
    if status in {"grouped", "ungrouped"}:
        prefix = "NOT " if status == "ungrouped" else ""
        clauses.append(prefix + "EXISTS (SELECT 1 FROM wazuh.alert_group_members m WHERE m.alert_pk = a.id)")
    if group_id and group_id.strip():
        clauses.append("EXISTS (SELECT 1 FROM wazuh.alert_group_members m WHERE m.alert_pk = a.id AND m.group_id = %s::uuid)")
        params.append(group_id.strip())
    if review_status in {"reviewed", "unreviewed"}:
        clauses.append("a.is_reviewed = " + ("true" if review_status == "reviewed" else "false"))
    if filter_preset in {"403", "404"}:
        clauses.append("(a.raw::text ILIKE %s OR a.parsed_details->>'status' = %s)")
        params.extend([f"% {filter_preset} %", filter_preset])
    elif filter_preset == "repeating":
        clauses.append("a.hit_count > 1")
    elif filter_preset == "bot":
        clauses.append("(a.description ILIKE %s OR a.raw::text ILIKE %s)")
        params.extend(["%bot%", "%bot%"])
    elif filter_preset == "curl":
        clauses.append("a.raw::text ILIKE %s")
        params.append("%curl%")
    elif filter_preset == "non_http":
        clauses.append("a.parsed_details->>'log_type' != 'http'")
    if time_preset and not (time_from and str(time_from).strip()):
        deltas = {
            "1h": timedelta(hours=1),
            "24h": timedelta(hours=24),
            "7d": timedelta(days=7),
            "30d": timedelta(days=30),
        }
        if time_preset in deltas:
            time_from = (datetime.now(timezone.utc) - deltas[time_preset]).strftime("%Y-%m-%dT%H:%M:%SZ")
    if time_from and str(time_from).strip():
        clauses.append("a.timestamp >= %s")
        params.append(str(time_from).strip())
    if time_to and str(time_to).strip():
        clauses.append("a.timestamp <= %s")
        params.append(str(time_to).strip())
    if facet or facet_value:
        if facet not in FACET_COLUMNS or not str(facet_value).strip():
            raise HTTPException(status_code=422, detail="facet and facet_value must use a supported exact facet.")
        val = str(facet_value).strip()
        if facet == "severity" and val.isdigit():
            clauses.append("a.rule_level = %s")
            params.append(int(val))
        else:
            clauses.append(f"{FACET_COLUMNS[facet]} = %s")
            params.append(val)
    if secondary_facet or secondary_facet_value:
        if secondary_facet not in FACET_COLUMNS or not str(secondary_facet_value).strip():
            raise HTTPException(status_code=422, detail="secondary_facet and secondary_facet_value must use a supported exact facet.")
        sec_val = str(secondary_facet_value).strip()
        if secondary_facet == "severity" and sec_val.isdigit():
            clauses.append("a.rule_level = %s")
            params.append(int(sec_val))
        else:
            clauses.append(f"{FACET_COLUMNS[secondary_facet]} = %s")
            params.append(sec_val)
    return ("WHERE " + " AND ".join(clauses) if clauses else ""), params


MALICIOUS_URI_RX = re.compile(
    r'(?i)(?:'
    r'(?:\.|%2e|%252e){2}(?:/|\\|%2f|%5c)|'
    r'/cgi-bin/|'
    r'/etc/(?:passwd|hosts|shadow|issue|group)|'
    r'/\.(?!well-known[/?#]|$)[a-zA-Z0-9_.-]+|'
    r'/(?:[^/]+/)*(?:gcp|firebase|google-(?:services|key)|aws|boto|azure-pipelines|bitbucket-pipelines|docker-compose|service-account|appsettings|_?env\d*)[^/]*\.(?:json|ya?ml|cfg|properties|template)|'
    r'^/[^/]+\.(?:json|ya?ml|cfg|properties|template|key|boto|htpasswd)(?:\?|$)|'
    r'/(?:db|database|websql|dbweb|geoserver|jmx-console|web-console|jboss|invoker|coldfusion|cfide|cobbler(?:_api)?|uploadedfiles?|filemanager|cache_template|esp/cms_changeDeviceContext|avi/avigui)(?:/|$)|'
    r'/(?:icons/|custom_403\.html)|'
    r'\.(?:js|png|jpg|gif|css|txt|tpl)\.php(?:\?|$)|'
    r'/(?:info|debug|test|configuration|web\.config|xmlrpc)\.php(?:\?|$)|'
    r'^/[a-zA-Z0-9_-]{10,}(?:\?|$)'
    r')'
)

MALICIOUS_QUERY_RX = re.compile(
    r'(?i)(?:'
    r'(?:\.|%2e|%252e){2}(?:/|\\|%2f|%5c)|'
    r'%22|%27|%3C|%3E|%7C|[\"\'<>]|\|s\.|'
    r'rest_route=|'
    r'author=\d+|'
    r'phpinfo=|'
    r'^/index\.php\?(?:lang|id|file|page)=|'
    r'\b1337\b'
    r')'
)

MALICIOUS_METHOD_RX = re.compile(
    r'(?i)(?:'
    r'^POST\s+(?:/|/(?:account|avi/)[^\s]*|/index\.php/sebatik)(?:\s+HTTP/|$)|'
    r'\"POST\s+(?:/|/(?:account|avi/)[^\s]*|/index\.php/sebatik)\s+HTTP/'
    r')'
)

MALICIOUS_UA_RX = re.compile(
    r'(?i)(?:'
    r'zgrab|Go Web Pentest Tool|masscan|nuclei|nikto|sqlmap|nmap|'
    r'lkx-|traversalplugin|apache2449|leakix|'
    r'^-+$|^Mozilla/5\.0 \(compatible\)$|^Mozilla/5\.0 \([^)]+\) AppleWebKit/[0-9.]+$|'
    r'Firefox/3\.|Linux i686'
    r')'
)

BENIGN_WHITELIST_RX = re.compile(
    r'(?i)(?:'
    r'^/index\.php/(?:sebatik|informatika|snsebatik2018|index)(?:/[^\s?#\"\'%|<>]*|$)|'
    r'^/plugins/generic/pdfJsViewer/|'
    r'^/lib/pkp/|'
    r'^/\.well-known/|'
    r'^/(?:sitemap\.xml|ads\.txt|robots\.txt|favicon\.ico)(?:\?|$)'
    r')'
)


def is_malicious_alert_record(row: dict[str, Any]) -> bool:
    data = row.get("data") or {}
    if isinstance(data, str):
        try:
            data = json.loads(data)
        except Exception:
            data = {}
    parsed = row.get("parsed_details") or {}
    if isinstance(parsed, str):
        try:
            parsed = json.loads(parsed)
        except Exception:
            parsed = {}
    raw = row.get("raw") or {}
    if isinstance(raw, str):
        try:
            raw_obj = json.loads(raw)
            full_log = raw_obj.get("full_log") or raw
        except Exception:
            full_log = raw
    else:
        full_log = raw.get("full_log") or ""

    url = str(data.get("url") or data.get("uri") or parsed.get("path") or parsed.get("uri") or "").strip()
    if not url and full_log:
        m = re.search(r'\"(?:GET|POST|HEAD|PUT|DELETE)\s+([^\s]+)\s+HTTP/', full_log)
        if m:
            url = m.group(1)

    method = str(parsed.get("method") or "").strip().upper()
    if not method and full_log:
        m = re.search(r'\"([A-Z]+)\s+[^\s]+\s+HTTP/', full_log)
        if m:
            method = m.group(1)

    ua = str(parsed.get("ua") or parsed.get("user_agent") or "").strip()
    if not ua and full_log:
        parts = re.findall(r'\"([^\"]*)\"', full_log)
        if len(parts) >= 3:
            ua = parts[-1]

    decoded_url = unquote(url)

    # 1. Suspicious HTTP Method
    if method == "POST" and (url in ("/", "/account", "/index.php/sebatik") or url.startswith("/avi/")):
        return True
    if full_log and MALICIOUS_METHOD_RX.search(full_log):
        return True

    # 2. Scanner / Anomalous User Agent
    if ua and MALICIOUS_UA_RX.search(ua):
        return True

    # 3. Query injection / fuzzing (overrides whitelist)
    if MALICIOUS_QUERY_RX.search(url) or MALICIOUS_QUERY_RX.search(decoded_url) or (full_log and MALICIOUS_QUERY_RX.search(full_log)):
        return True

    # 4. Legitimate Whitelist Guardrail
    if BENIGN_WHITELIST_RX.match(url) or BENIGN_WHITELIST_RX.match(decoded_url):
        return False

    # 5. Malicious URI / path
    if MALICIOUS_URI_RX.search(url) or MALICIOUS_URI_RX.search(decoded_url):
        return True

    return False
