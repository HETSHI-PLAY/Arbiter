"""FastAPI Application Server for Arbiter — SOC Telemetry & Incident Workspace."""

from __future__ import annotations

import csv
import io
import json
import uuid
from contextlib import asynccontextmanager
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any
from urllib.parse import quote

from fastapi import Depends, FastAPI, File, HTTPException, Query, Response, UploadFile
from fastapi.responses import FileResponse, HTMLResponse, StreamingResponse
from fastapi.staticfiles import StaticFiles

from app.config import HOST, PORT
from app.ai_triage import safe_alerts, test_ollama, triage_with_fallback
from app.core import normalize_alert, suggestions_with_fallback
from app.intel import enrich_ip, is_valid_ip, sync_remote_cache, upsert_ip_cache
import app.database as db_module
from app.database import get_db, init_database, ingest_alert_with_dedup
from app.exports import (
    generate_docx_landscape_report,
    generate_gdocs_html_report,
    generate_markdown_report,
    generate_tsv_table,
    generate_xlsx_workbook,
)
from app.parser import parse_export
from app.privacy import sanitize_text
from app.query import alert_where, normalize_tenants, positive_ids, tenant_clause, validated_group_id, PIVOT_DEFINITIONS, FACET_COLUMNS, is_malicious_alert_record
from app.settings import (
    load_settings,
    migrate_settings,
    redact_settings,
    save_settings,
    test_wazuh_connection,
    validate_settings,
    wazuh_password,
    wazuh_search,
)


@asynccontextmanager
async def lifespan(app: FastAPI):
    # Ensure tables, schemas, and indices are fully initialized on startup
    init_database()
    try:
        with get_db() as conn:
            migrate_settings(conn)
    except Exception:
        # Startup must not fail if legacy credential migration is not possible.
        pass
    yield


app = FastAPI(
    title="Arbiter — SOC Telemetry & Incident Workspace",
    version="2.0.0",
    lifespan=lifespan,
)
app.mount("/static", StaticFiles(directory=Path(__file__).with_name("static"), check_dir=False), name="static")


@app.get("/favicon.ico", include_in_schema=False)
def favicon():
    fav_path = Path(__file__).with_name("static") / "img" / "favicon.svg"
    return FileResponse(fav_path, media_type="image/svg+xml")


@app.get("/api/health")
def health_check():
    with get_db() as conn:
        alerts_n = conn.execute("SELECT count(*) AS n FROM wazuh.alerts").fetchone()["n"]
        groups_n = conn.execute("SELECT count(*) AS n FROM wazuh.analysis_groups").fetchone()["n"]
        intel_n = 0
        try:
            intel_n = conn.execute("SELECT count(*) AS n FROM public.ip_intel_cache").fetchone()["n"]
        except Exception:
            pass

    return {
        "status": "ok",
        "app": "Arbiter",
        "alerts": alerts_n,
        "groups": groups_n,
        "ip_intel_records": intel_n,
        "privacy": "airgapped_local",
    }


@app.get("/health", include_in_schema=False)
def health_alias():
    """Lightweight liveness probe for reverse proxies and monitors.

    Full workspace aggregates remain at /api/health.
    """
    return {"status": "ok", "app": "Arbiter"}


@app.get("/api/tenants")
def get_tenants():
    with get_db() as conn:
        rows = conn.execute(
            """SELECT tenant, count(*) as count 
               FROM wazuh.alerts 
               GROUP BY tenant 
               ORDER BY count DESC, tenant ASC"""
        ).fetchall()
    return {"tenants": rows}


def _process_alerts_ingest(raw_alerts: list[dict[str, Any]]) -> dict[str, int]:
    inserted_count = 0
    dedup_count = 0
    with get_db() as conn:
        for item in raw_alerts:
            normalized = normalize_alert(item)
            inserted, deduped = ingest_alert_with_dedup(conn, normalized)
            if inserted:
                inserted_count += 1
            elif deduped:
                dedup_count += 1
    return {
        "parsed": len(raw_alerts),
        "inserted": inserted_count,
        "deduplicated": dedup_count,
    }


def _scope_tenant_value(tenant: str | list[str] | tuple[str, ...] | None) -> str | list[str]:
    """Normalize a request scope while retaining the legacy single-tenant echo."""
    tenants = normalize_tenants(tenant)
    if not tenants:
        return "all"
    return tenants[0] if len(tenants) == 1 else list(tenants)


def _tenant_label(tenant: str | list[str] | tuple[str, ...] | None) -> str:
    tenants = normalize_tenants(tenant)
    return ", ".join(tenants) if tenants else "Semua Tenant"


@app.post("/api/import")
async def import_file(file: UploadFile = File(...)):
    raw_bytes = await file.read()
    try:
        content = raw_bytes.decode("utf-8-sig")
    except UnicodeDecodeError as exc:
        raise HTTPException(status_code=400, detail="File must be UTF-8 encoded text/JSON") from exc

    try:
        alerts, warnings = parse_export(content)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc

    stats = _process_alerts_ingest(alerts)
    return {**stats, "warnings": warnings}


@app.post("/api/import-text")
def import_text(payload: dict[str, Any]):
    content = str(payload.get("content") or payload.get("text") or "").strip()
    if not content:
        raise HTTPException(status_code=400, detail="Content cannot be empty.")
    try:
        alerts, warnings = parse_export(content)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc

    stats = _process_alerts_ingest(alerts)
    return {**stats, "warnings": warnings}


@app.get("/api/alerts")
def list_alerts(
    q: str = "",
    tenant: list[str] = Query(default=["all"]),
    status: str = "all",
    group_id: str | None = None,
    filter_preset: str = "",
    review_status: str = "all",
    time_preset: str = "",
    time_from: str = "",
    time_to: str = "",
    facet: str = "",
    facet_value: str = "",
    secondary_facet: str = "",
    secondary_facet_value: str = "",
    sort: str = "desc",
    sort_by: str = "timestamp",
    limit: int = 500,
    offset: int = 0,
    summary: bool = False,
):
    if offset < 0:
        raise HTTPException(status_code=422, detail="offset must be zero or greater.")
    limit = min(max(limit, 1), 10000)
    where_sql, params = alert_where(
        q=q, tenant=tenant, status=status, group_id=group_id,
        filter_preset=filter_preset, review_status=review_status,
        time_preset=time_preset, time_from=time_from, time_to=time_to,
        facet=facet, facet_value=facet_value,
        secondary_facet=secondary_facet, secondary_facet_value=secondary_facet_value,
    )

    # Sort order
    order_dir = "ASC" if str(sort).lower() == "asc" else "DESC"
    if sort_by == "hits":
        order_col = f"a.hit_count {order_dir} NULLS LAST, a.timestamp {order_dir} NULLS LAST, a.id {order_dir}"
    elif sort_by == "severity":
        order_col = f"a.rule_level {order_dir} NULLS LAST, a.timestamp {order_dir} NULLS LAST, a.id {order_dir}"
    else:
        order_col = f"a.timestamp {order_dir} NULLS LAST, a.id {order_dir}"

    projection = """a.id, a.alert_id, a.timestamp, a.tenant, a.agent_name, a.agent_ip,
        a.rule_id, a.rule_level, a.description, a.rule_groups, a.decoder, a.location,
        a.source_ip, a.mitre_ids, a.cve, a.hit_count, a.first_seen, a.last_seen, a.is_reviewed"""
    if not summary:
        projection += """, a.data, a.raw, a.wazuh_ids, a.duplicate_instances,
        a.parsed_details, a.reviewer_notes,
        COALESCE(a.raw->>'full_log', '') AS full_log,
        COALESCE(a.raw->>'previous_output', '') AS previous_output"""
    sql = f"""
    SELECT {projection},
        ipc.abuse_score,
        ipc.vt_malicious,
        ipc.country_code,
        ipc.isp,
        ipc.attack_types,
        COALESCE(
            json_agg(json_build_object('id', g.id, 'title', g.title, 'category', g.category))
            FILTER (WHERE g.id IS NOT NULL),
            '[]'
        ) AS groups
    FROM wazuh.alerts a
    LEFT JOIN public.ip_intel_cache ipc ON a.source_ip = ipc.ip
    LEFT JOIN wazuh.alert_group_members m ON m.alert_pk = a.id
    LEFT JOIN wazuh.analysis_groups g ON g.id = m.group_id
    {where_sql}
    GROUP BY 
        a.id, ipc.abuse_score, ipc.vt_malicious, ipc.country_code, ipc.isp, ipc.attack_types
    ORDER BY {order_col}
    LIMIT %s OFFSET %s
    """
    count_sql = f"SELECT count(DISTINCT a.id) AS n FROM wazuh.alerts a {where_sql}"

    with get_db() as conn:
        rows = conn.execute(sql, params + [limit, offset]).fetchall()
        total = conn.execute(count_sql, params).fetchone()["n"]

    return {"items": rows, "total": total}


@app.get("/api/alerts/{alert_id}")
def get_alert_detail(alert_id: int, tenant: list[str] = Query(default=["all"])):
    where = "a.id = %s"
    params: list[Any] = [alert_id]
    tenant_sql, tenant_params = tenant_clause("a", tenant)
    if tenant_sql:
        where += " AND " + tenant_sql
        params.extend(tenant_params)
    with get_db() as conn:
        row = conn.execute(
            f"""SELECT a.*, COALESCE(a.raw->>'full_log', '') AS full_log,
                       COALESCE(a.raw->>'previous_output', '') AS previous_output,
                       ipc.abuse_score, ipc.vt_malicious, ipc.country_code, ipc.isp,
                       ipc.attack_types,
                       COALESCE(json_agg(json_build_object('id', g.id, 'title', g.title, 'category', g.category))
                                FILTER (WHERE g.id IS NOT NULL), '[]') AS groups
                FROM wazuh.alerts a
                LEFT JOIN public.ip_intel_cache ipc ON a.source_ip = ipc.ip
                LEFT JOIN wazuh.alert_group_members m ON m.alert_pk = a.id
                LEFT JOIN wazuh.analysis_groups g ON g.id = m.group_id
                WHERE {where}
                GROUP BY a.id, ipc.abuse_score, ipc.vt_malicious, ipc.country_code, ipc.isp, ipc.attack_types""",
            params,
        ).fetchone()
    if row is None:
        raise HTTPException(status_code=404, detail="Alert not found in this scope.")
    return row


@app.put("/api/alerts/{alert_id}/review")
def update_alert_review(alert_id: int, payload: dict[str, Any], tenant: list[str] = Query(default=["all"])):
    is_reviewed = bool(payload.get("is_reviewed", True))
    notes = str(payload.get("reviewer_notes") or "").strip()
    with get_db() as conn:
        _validate_membership(conn, [alert_id], tenant)
        conn.execute(
            """UPDATE wazuh.alerts
               SET is_reviewed = %s,
                   reviewed_at = CASE WHEN %s THEN now() ELSE NULL END,
                   reviewer_notes = %s
               WHERE id = %s""",
            (is_reviewed, is_reviewed, notes, alert_id),
        )
    return {"status": "ok", "id": alert_id, "is_reviewed": is_reviewed}


@app.post("/api/alerts/batch-review")
def batch_update_review(payload: dict[str, Any], tenant: list[str] = Query(default=["all"])):
    normalize_tenants(tenant)
    alert_ids = payload.get("alert_ids") or []
    is_reviewed = bool(payload.get("is_reviewed", True))
    if not alert_ids:
        raise HTTPException(status_code=400, detail="No valid alert IDs provided.")
    with get_db() as conn:
        clean_pks = _validate_membership(conn, alert_ids, tenant)
        conn.execute(
            """UPDATE wazuh.alerts
               SET is_reviewed = %s,
                   reviewed_at = CASE WHEN %s THEN now() ELSE NULL END
               WHERE id = ANY(%s)""",
            (is_reviewed, is_reviewed, clean_pks),
        )
    return {"status": "ok", "count": len(clean_pks), "is_reviewed": is_reviewed}


@app.post("/api/intel/enrich")
def enrich_intel(payload: dict[str, Any], tenant: list[str] = Query(default=["all"])):
    normalize_tenants(tenant)
    raw_ips = payload.get("ips") or []
    if isinstance(raw_ips, str):
        raw_ips = [raw_ips]
    alert_ids = payload.get("alert_ids") or []
    if isinstance(alert_ids, (int, str)):
        alert_ids = [alert_ids]

    target_ips: list[str] = [str(x).strip() for x in raw_ips if str(x).strip()]

    if alert_ids:
        clean_pks = positive_ids(alert_ids)
        if clean_pks:
            with get_db() as conn:
                where_clause = "WHERE a.id = ANY(%s)"
                params: list[Any] = [clean_pks]
                tenant_sql, tenant_params = tenant_clause("a", tenant)
                if tenant_sql:
                    where_clause += " AND " + tenant_sql
                    params.extend(tenant_params)
                rows = conn.execute(
                    f"SELECT DISTINCT a.source_ip FROM wazuh.alerts a {where_clause} AND a.source_ip IS NOT NULL AND a.source_ip != ''",
                    params,
                ).fetchall()
                for r in rows:
                    ip_val = (r["source_ip"] or "").strip()
                    if ip_val and ip_val not in target_ips:
                        target_ips.append(ip_val)

    unique_ips = list(dict.fromkeys(ip for ip in target_ips if is_valid_ip(ip)))[:50]
    if not unique_ips:
        raise HTTPException(status_code=400, detail="Tidak ada alamat IPv4/IPv6 valid yang diberikan untuk di-enrich.")

    results = []
    with get_db() as conn:
        for ip in unique_ips:
            res = enrich_ip(ip)
            if res.get("status") not in ("invalid", "error"):
                upsert_ip_cache(conn, res)
            results.append(res)
        if hasattr(conn, "commit"):
            conn.commit()

    sync_remote_cache(results)

    return {
        "status": "ok",
        "count": len(results),
        "enriched": results,
    }


def _scoped_groups(conn, tenant: str | list[str] | tuple[str, ...] | None = "all", group_id: str | None = None):
    group_id = validated_group_id(group_id)
    clauses: list[str] = []
    params: list[Any] = []
    tenant_sql, tenant_params = tenant_clause("a", tenant)
    if tenant_sql:
        clauses.append(tenant_sql)
        params.extend(tenant_params)
    if group_id:
        clauses.append("g.id = %s")
        params.append(group_id)
    where = "WHERE " + " AND ".join(clauses) if clauses else ""
    return conn.execute(
        f"""SELECT g.*,
                   COALESCE(array_agg(DISTINCT a.id) FILTER (WHERE a.id IS NOT NULL), '{{}}') AS alert_pks,
                   count(DISTINCT a.id) AS alert_count,
                   COALESCE(array_agg(DISTINCT a.tenant) FILTER (WHERE a.tenant IS NOT NULL), '{{}}') AS tenants
            FROM wazuh.analysis_groups g
            LEFT JOIN wazuh.alert_group_members m ON m.group_id = g.id
            LEFT JOIN wazuh.alerts a ON a.id = m.alert_pk
            {where}
            GROUP BY g.id
            ORDER BY g.created_at DESC, g.id DESC""",
        params,
    ).fetchall()


@app.get("/api/groups")
def list_groups(tenant: list[str] = Query(default=["all"])):
    with get_db() as conn:
        return _scoped_groups(conn, tenant)


@app.get("/api/groups/{group_id}")
def get_group_detail(group_id: str, tenant: list[str] = Query(default=["all"])):
    with get_db() as conn:
        rows = _scoped_groups(conn, tenant, group_id)
    if not rows:
        raise HTTPException(status_code=404, detail="Incident group not found in this scope.")
    return rows[0]


@app.post("/api/groups")
def create_group(payload: dict[str, Any], tenant: list[str] = Query(default=["all"])):
    normalize_tenants(tenant)
    title = str(payload.get("title", "")).strip()
    if not title:
        raise HTTPException(status_code=400, detail="Group / Incident title is required.")
    if normalize_tenants(tenant) and not payload.get("alert_pks"):
        raise HTTPException(status_code=400, detail="Pilih minimal satu bukti untuk tenant ini, atau buat kasus kosong dari scope Semua tenant.")
    group_id = uuid.uuid4()
    with get_db() as conn:
        pks = _validate_membership(conn, payload.get("alert_pks", []), tenant)
        conn.execute(
            """INSERT INTO wazuh.analysis_groups(
                id, title, category, analysis, conclusion, recommendation, status, severity, source
            ) VALUES(%s, %s, %s, %s, %s, %s, %s, %s, %s)""",
            (
                group_id,
                title,
                payload.get("category", "General Incident"),
                payload.get("analysis", ""),
                payload.get("conclusion", ""),
                payload.get("recommendation", ""),
                payload.get("status", "open"),
                payload.get("severity", "medium"),
                payload.get("source", "human"),
            ),
        )
        for pk in pks:
            conn.execute(
                "INSERT INTO wazuh.alert_group_members(alert_pk, group_id) VALUES(%s, %s) ON CONFLICT DO NOTHING",
                (pk, group_id),
            )
    return {"id": str(group_id), "title": title}


@app.put("/api/groups/{group_id}")
def update_group(group_id: str, payload: dict[str, Any], tenant: list[str] = Query(default=["all"])):
    normalize_tenants(tenant)
    validated_group_id(group_id)
    if "title" in payload and not str(payload["title"] or "").strip():
        raise HTTPException(status_code=400, detail="Judul insiden wajib diisi.")
    with get_db() as conn:
        if not _scoped_groups(conn, tenant, group_id):
            raise HTTPException(status_code=404, detail="Incident group not found in this scope.")
        cur = conn.execute(
            """UPDATE wazuh.analysis_groups
               SET title = COALESCE(%s, title),
                   category = COALESCE(%s, category),
                   analysis = COALESCE(%s, analysis),
                   conclusion = COALESCE(%s, conclusion),
                   recommendation = COALESCE(%s, recommendation),
                   status = COALESCE(%s, status),
                   severity = COALESCE(%s, severity),
                   updated_at = now()
               WHERE id = %s RETURNING id""",
            (
                payload.get("title"),
                payload.get("category"),
                payload.get("analysis"),
                payload.get("conclusion"),
                payload.get("recommendation"),
                payload.get("status"),
                payload.get("severity"),
                group_id,
            ),
        )
        if not cur.fetchone():
            raise HTTPException(status_code=404, detail="Incident group not found.")
    return {"status": "ok"}


@app.delete("/api/groups/{group_id}")
def delete_group(group_id: str, tenant: list[str] = Query(default=["all"])):
    normalize_tenants(tenant)
    validated_group_id(group_id)
    with get_db() as conn:
        if not _scoped_groups(conn, tenant, group_id):
            raise HTTPException(status_code=404, detail="Incident group not found in this scope.")
        conn.execute("DELETE FROM wazuh.analysis_groups WHERE id = %s", (group_id,))
    return {"status": "ok"}


@app.post("/api/groups/{group_id}/members")
def add_group_members(group_id: str, payload: dict[str, Any], tenant: list[str] = Query(default=["all"])):
    normalize_tenants(tenant)
    validated_group_id(group_id)
    with get_db() as conn:
        if not _scoped_groups(conn, tenant, group_id):
            raise HTTPException(status_code=404, detail="Incident group not found in this scope.")
        pks = _validate_membership(conn, payload.get("alert_pks", []), tenant)
        for pk in pks:
            conn.execute(
                "INSERT INTO wazuh.alert_group_members(alert_pk, group_id) VALUES(%s, %s) ON CONFLICT DO NOTHING",
                (pk, group_id),
            )
    return {"status": "ok"}


def _validate_membership(conn, values, tenant: str | list[str] | tuple[str, ...] | None) -> list[int]:
    if not isinstance(values, list):
        raise HTTPException(status_code=422, detail="alert_pks must be a list.")
    try:
        pks = positive_ids(values)
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    if pks:
        where = "id = ANY(%s)"
        params: list[Any] = [pks]
        tenant_sql, tenant_params = tenant_clause("a", tenant)
        if tenant_sql:
            where += " AND " + tenant_sql
            params.extend(tenant_params)
        rows = conn.execute(f"SELECT a.id FROM wazuh.alerts a WHERE {where}", params).fetchall()
        if {row["id"] for row in rows} != set(pks):
            raise HTTPException(status_code=400, detail="Selected alerts are missing or outside the active tenant.")
    return pks


@app.delete("/api/groups/{group_id}/members/{alert_pk}")
def remove_group_member(group_id: str, alert_pk: int, tenant: list[str] = Query(default=["all"])):
    validated_group_id(group_id)
    with get_db() as conn:
        _validate_membership(conn, [alert_pk], tenant)
        groups = _scoped_groups(conn, tenant, group_id)
        if not groups:
            raise HTTPException(status_code=404, detail="Incident group not found in this scope.")
        if normalize_tenants(tenant) and alert_pk in groups[0]["alert_pks"] and groups[0]["alert_count"] <= 1:
            raise HTTPException(status_code=409, detail="Bukti terakhir tenant tidak dapat dilepas dari scope ini. Gunakan Semua tenant untuk meninjau kasus sebelum melepasnya.")
        conn.execute(
            "DELETE FROM wazuh.alert_group_members WHERE group_id = %s AND alert_pk = %s",
            (group_id, alert_pk),
        )
    return {"status": "ok"}


@app.get("/api/stats")
def get_stats(
    pivot_by: str = "rule_description",
    secondary_pivot: str | None = None,
    compare: str = "",
    metric: str = "alerts",
    top_n: int = 8,
    chart: str = "bar",
    chart_scale: str = "normal",
    bucket: str = "auto",
    pattern: str = "",
    other_details: bool = False,
    q: str = "",
    tenant: list[str] = Query(default=["all"]),
    status: str = "all",
    group_id: str | None = None,
    filter_preset: str = "",
    review_status: str = "all",
    time_preset: str = "",
    time_from: str = "",
    time_to: str = "",
    facet: str = "",
    facet_value: str = "",
    secondary_facet: str = "",
    secondary_facet_value: str = "",
):
    if pivot_by not in PIVOT_DEFINITIONS:
        raise HTTPException(
            status_code=422,
            detail=f"Invalid pivot_by '{pivot_by}'. Supported pivots: {', '.join(PIVOT_DEFINITIONS.keys())}",
        )
    if secondary_pivot and (secondary_pivot not in PIVOT_DEFINITIONS or secondary_pivot == "pattern"):
        raise HTTPException(
            status_code=422,
            detail=f"Invalid secondary_pivot '{secondary_pivot}'. Must be a supported non-pattern dimension.",
        )
    if metric not in {"alerts", "events"}:
        raise HTTPException(status_code=422, detail="metric must be 'alerts' or 'events'.")
    if not (1 <= top_n <= 1000):
        raise HTTPException(status_code=422, detail="top_n must be between 1 and 1000.")
    if bucket not in {"auto", "minute", "hour", "day"}:
        raise HTTPException(status_code=422, detail="bucket must be one of: auto, minute, hour, day.")
    if pivot_by == "pattern":
        pat = pattern.strip()
        if not (1 <= len(pat) <= 120):
            raise HTTPException(
                status_code=422,
                detail="pattern parameter (1-120 chars) is required when pivot_by is 'pattern'.",
            )
    if time_from and time_to and str(time_from).strip() > str(time_to).strip():
        raise HTTPException(status_code=422, detail="time_from must be before or equal to time_to.")

    where_sql, base_params = alert_where(
        q=q,
        tenant=tenant,
        status=status,
        group_id=group_id,
        filter_preset=filter_preset,
        review_status=review_status,
        time_preset=time_preset,
        time_from=time_from,
        time_to=time_to,
        facet=facet,
        facet_value=facet_value,
        secondary_facet=secondary_facet,
        secondary_facet_value=secondary_facet_value,
    )
    parent_where_sql, parent_base_params = alert_where(
        q=q,
        tenant=tenant,
        status=status,
        group_id=group_id,
        filter_preset=filter_preset,
        review_status=review_status,
        time_preset=time_preset,
        time_from=time_from,
        time_to=time_to,
        facet=facet,
        facet_value=facet_value,
    )
    workspace_where_sql, workspace_base_params = alert_where(
        q=q,
        tenant=tenant,
        status=status,
        group_id=group_id,
        filter_preset=filter_preset,
        review_status=review_status,
        time_preset=time_preset,
        time_from=time_from,
        time_to=time_to,
    )

    metric_expr = "COUNT(*)" if metric == "alerts" else "COALESCE(SUM(COALESCE(a.hit_count, 1)), 0)"

    if pivot_by == "pattern":
        dim_sql = (
            "CASE WHEN ("
            "a.description ILIKE %s OR a.raw::text ILIKE %s OR a.parsed_details::text ILIKE %s"
            ") THEN 'Cocok pola' ELSE 'Tidak cocok pola' END"
        )
        dim_params = [f"%{pattern.strip()}%"] * 3
    else:
        dim_sql = PIVOT_DEFINITIONS[pivot_by]["sql"]
        dim_params = []

    with get_db() as conn:
        total_row = conn.execute(
            f"""SELECT COUNT(*) AS total_alerts,
                       COALESCE(SUM(COALESCE(a.hit_count, 1)), 0) AS total_events
                FROM wazuh.alerts a {where_sql}""",
            base_params,
        ).fetchone()
        total_alerts = int(total_row["total_alerts"] or 0)
        total_events = int(total_row["total_events"] or 0)
        total = total_alerts if metric == "alerts" else total_events

        fetch_limit = min(max(top_n, 1), 1000)
        grouped_sql = f"""
            SELECT {dim_sql} AS k, {metric_expr} AS n
            FROM wazuh.alerts a {where_sql}
            GROUP BY 1
            ORDER BY 2 DESC, 1 ASC
            LIMIT %s
        """
        top_rows = conn.execute(grouped_sql, dim_params + base_params + [fetch_limit]).fetchall()

        items = []
        for r in top_rows:
            cnt = int(r["n"] or 0)
            pct = round((cnt / total * 100.0), 2) if total > 0 else 0.0
            items.append({
                "key": str(r["k"] if r["k"] is not None else "Tidak tersedia"),
                "count": cnt,
                "percentage": pct,
            })

        other_count = 0
        other_percentage = 0.0
        other_items = []

        secondary_distribution = None
        secondary_breakdown = None

        parent_total = None
        workspace_total = None
        primary_percentage_of_total = None
        secondary_percentage_of_parent = None
        secondary_percentage_of_total = None

        if facet and facet_value:
            p_row = conn.execute(
                f"""SELECT COUNT(*) AS total_alerts,
                           COALESCE(SUM(COALESCE(a.hit_count, 1)), 0) AS total_events
                    FROM wazuh.alerts a {parent_where_sql}""",
                parent_base_params,
            ).fetchone()
            parent_total = int(p_row["total_alerts"] or 0) if metric == "alerts" else int(p_row["total_events"] or 0)

            w_row = conn.execute(
                f"""SELECT COUNT(*) AS total_alerts,
                           COALESCE(SUM(COALESCE(a.hit_count, 1)), 0) AS total_events
                    FROM wazuh.alerts a {workspace_where_sql}""",
                workspace_base_params,
            ).fetchone()
            workspace_total = int(w_row["total_alerts"] or 0) if metric == "alerts" else int(w_row["total_events"] or 0)

            if workspace_total > 0:
                primary_percentage_of_total = round((parent_total / workspace_total * 100.0), 2)
            else:
                primary_percentage_of_total = 0.0

            if secondary_facet and secondary_facet_value:
                if parent_total > 0:
                    secondary_percentage_of_parent = round((total / parent_total * 100.0), 2)
                else:
                    secondary_percentage_of_parent = 0.0

                if workspace_total > 0:
                    secondary_percentage_of_total = round((total / workspace_total * 100.0), 2)
                else:
                    secondary_percentage_of_total = 0.0

        if secondary_pivot:
            sec_dim_sql = PIVOT_DEFINITIONS[secondary_pivot]["sql"]
            sec_sql = f"""
                SELECT {dim_sql} AS k1, {sec_dim_sql} AS k2, {metric_expr} AS n
                FROM wazuh.alerts a {where_sql}
                GROUP BY 1, 2
                ORDER BY 3 DESC
                LIMIT 500
            """
            sec_rows = conn.execute(sec_sql, dim_params + base_params).fetchall()
            sec_dist: dict[str, list[dict[str, Any]]] = {}
            for r in sec_rows:
                k1 = str(r["k1"] if r["k1"] is not None else "Tidak tersedia")
                k2 = str(r["k2"] if r["k2"] is not None else "Tidak tersedia")
                if k1 not in sec_dist:
                    sec_dist[k1] = []
                sec_dist[k1].append({"key": k2, "count": int(r["n"] or 0)})
            secondary_distribution = sec_dist

            # When primary facet is active, secondary_breakdown provides the complete breakdown of secondary dimension
            # within the parent facet scope (using parent_where_sql so all sub-categories remain visible)
            if facet and facet_value:
                sec_break_sql = f"""
                    SELECT {sec_dim_sql} AS k, {metric_expr} AS n
                    FROM wazuh.alerts a {parent_where_sql}
                    GROUP BY 1
                    ORDER BY 2 DESC, 1 ASC
                    LIMIT 500
                """
                sec_break_rows = conn.execute(sec_break_sql, parent_base_params).fetchall()
                base_calc_total = parent_total if (parent_total and parent_total > 0) else total
                break_items = []
                for r in sec_break_rows:
                    cnt = int(r["n"] or 0)
                    pct = round((cnt / base_calc_total * 100.0), 2) if base_calc_total > 0 else 0.0
                    break_items.append({
                        "key": str(r["k"] if r["k"] is not None else "Tidak tersedia"),
                        "count": cnt,
                        "percentage": pct,
                    })
                secondary_breakdown = break_items

        granularity = bucket
        if granularity == "auto":
            time_bounds = conn.execute(
                f"""SELECT MIN(NULLIF(a.timestamp, '')) AS earliest,
                           MAX(NULLIF(a.timestamp, '')) AS latest
                    FROM wazuh.alerts a {where_sql}""",
                base_params,
            ).fetchone()
            earliest = time_bounds["earliest"] if time_bounds else None
            latest = time_bounds["latest"] if time_bounds else None
            if earliest and latest and len(earliest) >= 10 and len(latest) >= 10:
                if earliest[:10] == latest[:10]:
                    granularity = "minute"
                elif earliest[:7] == latest[:7]:
                    granularity = "hour"
                else:
                    granularity = "day"
            else:
                granularity = "hour"

        if granularity == "minute":
            bucket_sql = "substr(a.timestamp, 1, 16) || ':00Z'"
        elif granularity == "day":
            bucket_sql = "substr(a.timestamp, 1, 10)"
        else:
            bucket_sql = "substr(a.timestamp, 1, 13) || ':00:00Z'"

        ts_where = (where_sql + " AND " if where_sql else "WHERE ") + "(a.timestamp IS NOT NULL AND a.timestamp != '')"
        ts_sql = f"""
            SELECT {bucket_sql} AS b, {dim_sql} AS k, {metric_expr} AS n
            FROM wazuh.alerts a {ts_where}
            GROUP BY 1, 2
            ORDER BY 1 ASC
        """
        ts_rows = conn.execute(ts_sql, dim_params + base_params).fetchall()

        top_keys = [it["key"] for it in items]
        buckets_dict: dict[str, dict[str, Any]] = {}
        for r in ts_rows:
            b_key = str(r["b"])
            k_key = str(r["k"] if r["k"] is not None else "Tidak tersedia")
            cnt = int(r["n"] or 0)
            if b_key not in buckets_dict:
                buckets_dict[b_key] = {
                    "bucket": b_key,
                    "total": 0,
                    "series": {tk: 0 for tk in top_keys},
                    "above_average": False,
                }
            buckets_dict[b_key]["total"] += cnt
            if k_key in top_keys:
                buckets_dict[b_key]["series"][k_key] += cnt

        time_series = list(buckets_dict.values())
        if time_series:
            avg_val = sum(b["total"] for b in time_series) / len(time_series)
            threshold = avg_val * 1.5
            for b in time_series:
                b["above_average"] = bool(b["total"] > threshold and b["total"] > 1)

    res_data = {
        "pivot_by": pivot_by,
        "secondary_pivot": secondary_pivot,
        "secondary_distribution": secondary_distribution,
        "secondary_breakdown": secondary_breakdown,
        "metric": metric,
        "total": total,
        "total_alerts": total_alerts,
        "total_events": total_events,
        "top_n": top_n,
        "granularity": granularity,
        "items": items,
        "other_count": other_count,
        "other_percentage": other_percentage,
        "other_items": other_items,
        "time_series": time_series,
        "scope": {
            "tenant": list(normalize_tenants(tenant)),
            "q": q,
            "status": status,
            "group_id": group_id,
            "filter_preset": filter_preset,
            "review_status": review_status,
            "time_from": time_from,
            "time_to": time_to,
            "facet": facet,
            "facet_value": facet_value,
            "secondary_facet": secondary_facet,
            "secondary_facet_value": secondary_facet_value,
        },
    }
    if parent_total is not None:
        res_data["parent_total"] = parent_total
    if workspace_total is not None:
        res_data["workspace_total"] = workspace_total
    if primary_percentage_of_total is not None:
        res_data["primary_percentage_of_total"] = primary_percentage_of_total
    if secondary_percentage_of_parent is not None:
        res_data["secondary_percentage_of_parent"] = secondary_percentage_of_parent
    if secondary_percentage_of_total is not None:
        res_data["secondary_percentage_of_total"] = secondary_percentage_of_total
    return res_data


@app.post("/api/stats/facet-alert-ids")
def get_facet_alert_ids(payload: dict[str, Any]):
    tenant = payload.get("tenant", ["all"])
    if isinstance(tenant, str):
        tenant = [tenant]
    q = payload.get("q", "")
    status = payload.get("status", "all")
    group_id = payload.get("group_id")
    filter_preset = payload.get("filter_preset", "")
    review_status = payload.get("review_status", "all")
    time_preset = payload.get("time_preset", "")
    time_from = payload.get("time_from", "")
    time_to = payload.get("time_to", "")
    facet = payload.get("facet", "")
    facet_value = payload.get("facet_value", "")
    secondary_facet = payload.get("secondary_facet", "")
    secondary_facet_values = payload.get("secondary_facet_values", [])
    spotter_mode = str(payload.get("spotter_mode", "all")).strip().lower()

    if not isinstance(secondary_facet_values, list):
        raise HTTPException(status_code=422, detail="secondary_facet_values must be a list.")

    where_sql, params = alert_where(
        q=q, tenant=tenant, status=status, group_id=group_id,
        filter_preset=filter_preset, review_status=review_status,
        time_preset=time_preset, time_from=time_from, time_to=time_to,
        facet=facet, facet_value=facet_value,
    )

    if secondary_facet and secondary_facet_values:
        if secondary_facet not in FACET_COLUMNS:
            raise HTTPException(status_code=422, detail="Invalid secondary_facet.")
        sec_col = FACET_COLUMNS[secondary_facet]
        where_sql += (" AND " if where_sql else "WHERE ") + f"{sec_col} = ANY(%s)"
        params.append(secondary_facet_values)

    with get_db() as conn:
        rows = conn.execute(
            f"SELECT a.id, a.data, a.parsed_details, a.raw FROM wazuh.alerts a {where_sql} ORDER BY a.rule_id ASC NULLS LAST, a.timestamp ASC NULLS LAST, a.id ASC LIMIT 10000",
            params,
        ).fetchall()

    filtered_ids = []
    for r in rows:
        row_dict = dict(r)
        if spotter_mode == "malicious":
            if is_malicious_alert_record(row_dict):
                filtered_ids.append(int(r["id"]))
        elif spotter_mode == "benign":
            if not is_malicious_alert_record(row_dict):
                filtered_ids.append(int(r["id"]))
        else:
            filtered_ids.append(int(r["id"]))

    return {
        "alert_pks": filtered_ids,
        "total": len(filtered_ids),
        "spotter_mode": spotter_mode,
        "raw_total": len(rows),
    }


@app.get("/api/triage/summary")
def triage_summary(
    q: str = "",
    secondary_facet: str = "",
    secondary_facet_value: str = "",
    tenant: list[str] = Query(default=["all"]),
    status: str = "all",
    group_id: str | None = None,
    filter_preset: str = "",
    review_status: str = "all",
    time_preset: str = "",
    time_from: str = "",
    time_to: str = "",
    facet: str = "",
    facet_value: str = "",
):
    where_sql, params = alert_where(
        q=q,
        tenant=tenant,
        status=status,
        group_id=group_id,
        filter_preset=filter_preset,
        review_status=review_status,
        time_preset=time_preset,
        time_from=time_from,
        time_to=time_to,
        facet=facet,
        facet_value=facet_value,
        secondary_facet=secondary_facet,
        secondary_facet_value=secondary_facet_value,
    )

    with get_db() as conn:
        counts = conn.execute(
            f"""SELECT COUNT(*) AS alerts,
                       COALESCE(SUM(COALESCE(a.hit_count, 1)), 0) AS events,
                       COUNT(DISTINCT NULLIF(a.source_ip, '')) AS unique_source_ips,
                       COUNT(DISTINCT NULLIF(a.agent_name, '')) AS unique_agents,
                       MIN(NULLIF(a.timestamp, '')) AS earliest,
                       MAX(NULLIF(a.timestamp, '')) AS latest
                FROM wazuh.alerts a {where_sql}""",
            params,
        ).fetchone()

        sev_rows = conn.execute(
            f"""SELECT
                    CASE
                        WHEN a.rule_level >= 12 THEN 'critical'
                        WHEN a.rule_level >= 10 THEN 'high'
                        WHEN a.rule_level >= 7 THEN 'medium'
                        ELSE 'low'
                    END AS sev,
                    COUNT(*) AS n
                FROM wazuh.alerts a {where_sql}
                GROUP BY 1""",
            params,
        ).fetchall()

        sev_map = {"critical": 0, "high": 0, "medium": 0, "low": 0}
        for r in sev_rows:
            k = str(r["sev"]).lower()
            if k in sev_map:
                sev_map[k] = int(r["n"] or 0)

        group_row = conn.execute(
            f"""SELECT COUNT(DISTINCT m.group_id) AS n
                FROM wazuh.alert_group_members m
                JOIN wazuh.alerts a ON a.id = m.alert_pk
                {where_sql}""",
            params,
        ).fetchone()
        incident_cases = int(group_row["n"] or 0) if group_row else 0

        top_rule_row = conn.execute(
            f"""SELECT
                    COALESCE(NULLIF(a.rule_id, ''), '-') AS rule_id,
                    COALESCE(NULLIF(a.description, ''), 'Wazuh Alert') AS description,
                    COUNT(*) AS n
                FROM wazuh.alerts a {where_sql}
                GROUP BY 1, 2
                ORDER BY 3 DESC, 1 ASC
                LIMIT 1""",
            params,
        ).fetchone()

        top_rule = None
        if top_rule_row and int(top_rule_row["n"] or 0) > 0:
            top_rule = {
                "rule_id": str(top_rule_row["rule_id"]),
                "description": str(top_rule_row["description"]),
                "count": int(top_rule_row["n"]),
            }

    return {
        "alerts": int(counts["alerts"] or 0) if counts else 0,
        "events": int(counts["events"] or 0) if counts else 0,
        "unique_source_ips": int(counts["unique_source_ips"] or 0) if counts else 0,
        "unique_agents": int(counts["unique_agents"] or 0) if counts else 0,
        "severity": sev_map,
        "incident_cases": incident_cases,
        "time_range": {
            "earliest": counts["earliest"] if counts else None,
            "latest": counts["latest"] if counts else None,
        },
        "top_rule": top_rule,
    }


@app.get("/api/suggestions")
def get_suggestions(
    use_local_ai: bool = False, tenant: list[str] = Query(default=["all"]), q: str = "",
    review_status: str = "all", filter_preset: str = "", status: str = "all",
    group_id: str | None = None, time_from: str = "", time_to: str = "",
):
    where, params = alert_where(
        tenant=tenant, q=q, review_status=review_status, filter_preset=filter_preset,
        status=status, group_id=group_id, time_from=time_from, time_to=time_to,
    )
    with get_db() as conn:
        rows = conn.execute(
            f"""SELECT a.id, a.alert_id, a.timestamp, a.tenant, a.agent_name, a.agent_ip, a.rule_id, a.rule_level,
                       a.description, a.rule_groups, a.decoder, a.location, a.source_ip, a.mitre_ids, a.cve,
                       a.log_signature, a.raw
                FROM wazuh.alerts a {where}
                ORDER BY a.timestamp DESC NULLS LAST, a.id DESC LIMIT 300""",
            params,
        ).fetchall()
    candidate_alerts = [{**r, "id": str(r["id"])} for r in rows]
    groups_list, mode, warning = suggestions_with_fallback(candidate_alerts, enabled=use_local_ai)
    return {"mode": mode, "warning": warning, "suggestions": groups_list}


@app.get("/api/realtime/count")
def api_realtime_count():
    """Count Medium+ Wazuh alerts without downloading or storing any alert."""
    with get_db() as conn:
        stored = load_settings(conn)
    wazuh = stored.get("wazuh", {})
    if not wazuh.get("indexer_url"):
        raise HTTPException(status_code=400, detail="Wazuh Indexer belum dikonfigurasi di halaman Pengaturan.")
    try:
        result = test_wazuh_connection(
            indexer_url=wazuh.get("indexer_url", ""),
            username=wazuh.get("username", ""),
            password=wazuh_password(stored),
            index_pattern=wazuh.get("index_pattern", "wazuh-alerts-*"),
            verify_tls=bool(wazuh.get("verify_tls", True)),
        )
    except ValueError as error:
        raise HTTPException(status_code=502, detail=str(error)) from None
    return {**result, "checked_at": datetime.now(timezone.utc).isoformat()}


@app.post("/api/realtime/pull")
def api_realtime_pull():
    """Pull Medium+ alerts from the Wazuh Indexer and ingest them into the active DB.

    Interval mode pulls on demand; daily mode only pulls once every 24 hours
    (enforced server-side via ``realtime.last_pull_at``). Never downloads more
    than ``realtime.max_alerts`` documents per call.
    """
    now = datetime.now(timezone.utc)
    with get_db() as conn:
        stored = load_settings(conn)
    wazuh = stored.get("wazuh", {})
    realtime = stored.get("realtime", {})
    if not wazuh.get("indexer_url"):
        raise HTTPException(status_code=400, detail="Wazuh Indexer belum dikonfigurasi di halaman Pengaturan.")

    mode = str(realtime.get("mode") or "interval")
    last_pull_at = str(realtime.get("last_pull_at") or "").strip()
    if mode == "daily" and last_pull_at:
        try:
            last = datetime.fromisoformat(last_pull_at.replace("Z", "+00:00"))
            if last.tzinfo is None:
                last = last.replace(tzinfo=timezone.utc)
            elapsed = now - last
            if elapsed.total_seconds() < 24 * 3600:
                next_pull = last + timedelta(hours=24)
                return {
                    "status": "skipped",
                    "reason": "Pull harian hanya dijalankan sekali setiap 24 jam.",
                    "last_pull_at": last_pull_at,
                    "next_pull_at": next_pull.isoformat(),
                }
        except ValueError:
            pass  # Unparseable timestamp: treat as never pulled.

    try:
        docs = wazuh_search(
            indexer_url=wazuh.get("indexer_url", ""),
            username=wazuh.get("username", ""),
            password=wazuh_password(stored),
            index_pattern=wazuh.get("index_pattern", "wazuh-alerts-*"),
            verify_tls=bool(wazuh.get("verify_tls", True)),
            size=int(realtime.get("max_alerts") or 500),
            since=last_pull_at,
        )
    except ValueError as error:
        raise HTTPException(status_code=502, detail=str(error)) from None

    inserted = 0
    deduplicated = 0
    with get_db() as conn:
        for item in docs:
            normalized = normalize_alert(item)
            did_insert, did_dedup = ingest_alert_with_dedup(conn, normalized)
            if did_insert:
                inserted += 1
            elif did_dedup:
                deduplicated += 1
        # Persist the pull timestamp so daily gating and the next `since` window work.
        stored["realtime"]["last_pull_at"] = now.isoformat()
        save_settings(conn, stored)

    return {
        "status": "pulled",
        "pulled_at": now.isoformat(),
        "searched": len(docs),
        "inserted": inserted,
        "deduplicated": deduplicated,
        "min_rule_level": 7,
        "index_pattern": wazuh.get("index_pattern", "wazuh-alerts-*"),
    }


@app.post("/api/ai/test")
def api_ai_test(payload: dict[str, Any]):
    with get_db() as conn:
        stored = load_settings(conn)
    ai = stored.get("ai", {})
    base_url = str(payload.get("base_url") or ai.get("base_url") or "http://127.0.0.1:11434").strip()
    model = str(payload.get("model") or ai.get("model") or "").strip()
    if not model:
        raise HTTPException(status_code=400, detail="Model AI belum diatur.")
    try:
        return test_ollama(base_url=base_url, model=model)
    except ValueError as error:
        raise HTTPException(status_code=502, detail=str(error)) from None


@app.post("/api/ai/triage")
def api_ai_triage(payload: dict[str, Any]):
    if not isinstance(payload, dict):
        raise HTTPException(status_code=400, detail="Payload AI triage tidak valid.")
    try:
        limit = int(payload.get("limit") or 40)
        min_rule_level = int(payload.get("min_rule_level") or 7)
    except (TypeError, ValueError):
        raise HTTPException(status_code=400, detail="limit dan min_rule_level harus berupa angka.") from None
    if not 5 <= limit <= 100:
        raise HTTPException(status_code=400, detail="limit harus antara 5 dan 100.")
    if not 0 <= min_rule_level <= 15:
        raise HTTPException(status_code=400, detail="min_rule_level harus antara 0 dan 15.")

    tenant = payload.get("tenant") or ["all"]
    where, params = alert_where(tenant=tenant, review_status=str(payload.get("review_status") or "unreviewed"))
    level_clause = "a.rule_level >= %s"
    if where:
        where = f"{where} AND {level_clause}"
    else:
        where = f"WHERE {level_clause}"
    query_params = list(params) + [min_rule_level, limit]
    with get_db() as conn:
        rows = conn.execute(
            f"""SELECT a.id, a.alert_id, a.timestamp, a.tenant, a.agent_name, a.agent_ip,
                       a.rule_id, a.rule_level, a.description, a.rule_groups, a.source_ip,
                       a.mitre_ids, a.cve, a.hit_count, a.log_signature
                FROM wazuh.alerts a {where}
                ORDER BY a.rule_level DESC NULLS LAST, a.timestamp DESC NULLS LAST, a.id DESC
                LIMIT %s""",
            query_params,
        ).fetchall()
        stored = load_settings(conn)
    alerts = [{**row, "id": str(row["id"])} for row in rows]
    ai = stored.get("ai", {})
    groups, mode, warning = triage_with_fallback(
        alerts,
        enabled=bool(ai.get("enabled")),
        model=str(ai.get("model") or ""),
        base_url=str(ai.get("base_url") or "http://127.0.0.1:11434"),
        timeout=float(ai.get("timeout_seconds") or 90),
    )
    if not ai.get("enabled") and not warning:
        warning = "AI Triage belum diaktifkan di Pengaturan; hasil memakai heuristik lokal."
    return {
        "mode": mode,
        "warning": warning,
        "model": ai.get("model"),
        "alert_count": len(alerts),
        "min_rule_level": min_rule_level,
        "alerts": safe_alerts(alerts),
        "groups": groups,
    }


@app.post("/api/ai/triage/save")
def api_ai_triage_save(payload: dict[str, Any]):
    """Persist an AI triage result as editable incident groups (source='ai').

    Each group becomes an ``analysis_groups`` row with its TP/FP/needs_review
    verdict, the model's reasoning, and its member alerts. The analyst can then
    add/remove alerts or delete the group from the Insiden page.
    """
    if not isinstance(payload, dict):
        raise HTTPException(status_code=400, detail="Payload penyimpanan triage tidak valid.")
    groups = payload.get("groups")
    if not isinstance(groups, list) or not groups:
        raise HTTPException(status_code=400, detail="Tidak ada grup triage untuk disimpan.")
    tenant = payload.get("tenant") or ["all"]
    normalize_tenants(tenant)

    allowed_verdicts = {"tp", "fp", "needs_review"}
    saved: list[dict[str, Any]] = []
    with get_db() as conn:
        for index, group in enumerate(groups):
            if not isinstance(group, dict):
                continue
            verdict = str(group.get("verdict") or "needs_review").strip().lower()
            if verdict not in allowed_verdicts:
                verdict = "needs_review"
            title = str(group.get("title") or f"AI Triage {index + 1}").strip()[:200] or f"AI Triage {index + 1}"
            category = str(group.get("category") or "AI Triage")[:120]
            reason = str(group.get("reason") or "")[:400]
            group_id = uuid.uuid4()
            pks = _validate_membership(conn, group.get("alert_ids") or [], tenant)
            severity = {"tp": "high", "fp": "low", "needs_review": "medium"}.get(verdict, "medium")
            conn.execute(
                """INSERT INTO wazuh.analysis_groups(
                    id, title, category, analysis, conclusion, recommendation, status, severity, source, verdict
                ) VALUES(%s, %s, %s, %s, %s, %s, %s, %s, %s, %s)""",
                (group_id, title, category, reason, "", "", "open", severity, "ai", verdict),
            )
            for pk in pks:
                conn.execute(
                    "INSERT INTO wazuh.alert_group_members(alert_pk, group_id) VALUES(%s, %s) ON CONFLICT DO NOTHING",
                    (pk, group_id),
                )
            saved.append({"id": str(group_id), "title": title, "verdict": verdict, "alert_count": len(pks)})
    if not saved:
        raise HTTPException(status_code=400, detail="Tidak ada grup valid untuk disimpan.")
    return {"saved": saved, "count": len(saved)}


# A bounded, complete export is returned, or an explicit 413; never a partial file.
MAX_EXPORT_ALERTS = 10_000


def _get_alerts_for_export(
    group_id: str | None = None, alert_ids: str | None = None, tenant: str | list[str] | tuple[str, ...] | None = "all",
    q: str = "", review_status: str = "all", filter_preset: str = "", status: str = "all",
    time_preset: str = "", time_from: str = "", time_to: str = "",
    facet: str = "", facet_value: str = "",
    secondary_facet: str = "", secondary_facet_value: str = "",
) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    where, params = alert_where(
        q=q, tenant=tenant, review_status=review_status, filter_preset=filter_preset,
        status=status, group_id=group_id, time_preset=time_preset, time_from=time_from, time_to=time_to,
        facet=facet, facet_value=facet_value,
        secondary_facet=secondary_facet, secondary_facet_value=secondary_facet_value,
    )
    clean_pks: list[int] = []
    if alert_ids:
        clean_pks = positive_ids(alert_ids.split(","))
        where += (" AND " if where else "WHERE ") + "a.id = ANY(%s)"
        params.append(clean_pks)
    meta: dict[str, Any] = {
        "title": "SOC Security Telemetry Report", "category": "Incident Investigation",
        "severity": "Medium", "status": "Triage", "analysis": "", "conclusion": "", "recommendation": "",
    }
    with get_db() as conn:
        if group_id and not alert_ids:
            groups = _scoped_groups(conn, tenant, group_id)
            if not groups:
                raise HTTPException(status_code=404, detail="Incident group not found in this scope.")
            meta = dict(groups[0])
        alerts = conn.execute(
            f"""SELECT a.*, ipc.abuse_score, ipc.vt_malicious, ipc.country_code, ipc.isp
                FROM wazuh.alerts a
                LEFT JOIN public.ip_intel_cache ipc ON a.source_ip = ipc.ip
                {where}
                ORDER BY a.rule_id ASC NULLS LAST, a.timestamp ASC NULLS LAST, a.id ASC
                LIMIT %s""",
            params + [MAX_EXPORT_ALERTS + 1],
        ).fetchall()
    if len(alerts) > MAX_EXPORT_ALERTS:
        raise HTTPException(status_code=413, detail=f"Export exceeds {MAX_EXPORT_ALERTS} alerts. Narrow the scope and retry.")
    if alert_ids and {row["id"] for row in alerts} != set(clean_pks):
        raise HTTPException(status_code=409, detail="Sebagian pilihan tidak tersedia pada tenant ini. Pilih ulang; tidak ada laporan parsial dibuat.")
    if alert_ids:
        meta["title"] = f"Investigasi Kasus ({len(alerts)} Alert Terpilih)"
    elif not group_id:
        tenant_tag = f"Tenant: {_tenant_label(tenant)}" if normalize_tenants(tenant) else "Semua Tenant"
        meta["title"] = f"Laporan Rekapitulasi Triage ({tenant_tag})"
    return alerts, meta


def export_scope(
    group_id: str | None = None, alert_ids: str | None = None, tenant: list[str] = Query(default=["all"]),
    q: str = "", review_status: str = "all", filter_preset: str = "", status: str = "all",
    time_preset: str = "", time_from: str = "", time_to: str = "",
    facet: str = "", facet_value: str = "",
    secondary_facet: str = "", secondary_facet_value: str = "",
) -> dict[str, Any]:
    normalize_tenants(tenant)
    # Explicit selection replaces triage filters, never tenant context.
    if alert_ids is not None:
        try:
            alert_ids = ",".join(str(pk) for pk in positive_ids(alert_ids.split(",")))
        except ValueError as exc:
            raise HTTPException(status_code=422, detail=str(exc)) from exc
        group_id, q, review_status, filter_preset, status, time_preset, time_from, time_to, facet, facet_value, secondary_facet, secondary_facet_value = None, "", "all", "", "all", "", "", "", "", "", "", ""
    return dict(group_id=group_id, alert_ids=alert_ids, tenant=_scope_tenant_value(tenant), q=q,
                review_status=review_status, filter_preset=filter_preset, status=status,
                time_preset=time_preset, time_from=time_from, time_to=time_to,
                facet=facet, facet_value=facet_value,
                secondary_facet=secondary_facet, secondary_facet_value=secondary_facet_value)


@app.get("/api/export/preview")
def export_preview(scope: dict[str, Any] = Depends(export_scope)):
    alerts, meta = _get_alerts_for_export(**scope)
    return {"count": len(alerts), "meta": meta, "scope": scope,
            "html": generate_gdocs_html_report(alerts, meta), "truncated": False}


@app.get("/api/export/report-html", response_class=HTMLResponse)
def export_gdocs_html(scope: dict[str, Any] = Depends(export_scope)):
    alerts, meta = _get_alerts_for_export(**scope)
    html_content = generate_gdocs_html_report(alerts, meta)
    return HTMLResponse(content=html_content, headers={"X-Arbiter-Count": str(len(alerts))})


@app.get("/api/export/docx")
def export_docx(scope: dict[str, Any] = Depends(export_scope)):
    alerts, meta = _get_alerts_for_export(**scope)
    buf = generate_docx_landscape_report(alerts, meta)
    filename = f"Arbiter-Report-{meta.get('title', 'SOC')[:24].replace(' ', '_')}.docx"
    return StreamingResponse(
        buf,
        media_type="application/vnd.openxmlformats-officedocument.wordprocessingml.document",
        headers={"Content-Disposition": "attachment; filename=Arbiter-Report.docx; filename*=UTF-8''" + quote(filename, safe=""), "X-Arbiter-Count": str(len(alerts))},
    )


@app.get("/api/export/xlsx")
def export_xlsx(scope: dict[str, Any] = Depends(export_scope)):
    alerts, _ = _get_alerts_for_export(**scope)
    buf = generate_xlsx_workbook(alerts)
    filename = "Arbiter-Alerts-Export.xlsx"
    return StreamingResponse(
        buf,
        media_type="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
        headers={"Content-Disposition": f'attachment; filename="{filename}"', "X-Arbiter-Count": str(len(alerts))},
    )


@app.get("/api/export/tsv")
def export_tsv(scope: dict[str, Any] = Depends(export_scope)):
    alerts, _ = _get_alerts_for_export(**scope)
    tsv_content = generate_tsv_table(alerts)
    return Response(content=tsv_content, media_type="text/tab-separated-values; charset=utf-8",
                    headers={"X-Arbiter-Count": str(len(alerts))})


@app.get("/api/export/markdown")
def export_markdown(scope: dict[str, Any] = Depends(export_scope)):
    alerts, meta = _get_alerts_for_export(**scope)
    md_content = generate_markdown_report(alerts, meta)
    return Response(content=md_content, media_type="text/markdown; charset=utf-8",
                    headers={"X-Arbiter-Count": str(len(alerts))})


@app.get("/api/export.csv")
def export_csv(scope: dict[str, Any] = Depends(export_scope)):
    alerts, _ = _get_alerts_for_export(**scope)
    output = io.StringIO()
    fields = [
        "alert_id", "timestamp", "tenant", "agent_name", "agent_ip", "rule_id", "rule_level",
        "description", "source_ip", "abuse_score", "vt_malicious", "country_code",
        "hit_count", "location", "decoder", "cve", "mitre_ids", "is_reviewed"
    ]
    writer = csv.DictWriter(output, fieldnames=fields, extrasaction="ignore")
    writer.writeheader()
    for a in alerts:
        row = dict(a)
        row["mitre_ids"] = ", ".join(row.get("mitre_ids") or [])
        writer.writerow(row)
    return StreamingResponse(
        iter([output.getvalue()]),
        media_type="text/csv; charset=utf-8",
        headers={"Content-Disposition": "attachment; filename=arbiter-alerts.csv", "X-Arbiter-Count": str(len(alerts))},
    )


@app.post("/api/sanitize-logs")
def api_sanitize_logs(payload: dict[str, Any]):
    text = str(payload.get("text") or "").strip()
    return {"sanitized": sanitize_text(text)}


@app.get("/api/settings")
def api_get_settings():
    with get_db() as conn:
        stored = load_settings(conn)
    return {"settings": redact_settings(stored)}


@app.put("/api/settings")
def api_put_settings(payload: dict[str, Any]):
    with get_db() as conn:
        current = load_settings(conn)
        try:
            updated = validate_settings(payload, current)
        except ValueError as error:
            raise HTTPException(status_code=400, detail=str(error)) from None
        save_settings(conn, updated)
    return {"settings": redact_settings(updated)}


@app.post("/api/settings/wazuh/test")
def api_test_wazuh(payload: dict[str, Any]):
    if not isinstance(payload, dict):
        raise HTTPException(status_code=400, detail="Payload pengujian tidak valid.")
    with get_db() as conn:
        stored = load_settings(conn)
    wazuh = stored.get("wazuh", {})
    url = str(payload.get("indexer_url", wazuh.get("indexer_url", "")) or "").strip()
    username = str(payload.get("username", wazuh.get("username", "")) or "").strip()
    password = payload.get("password")
    if password is None or password == "":
        password = wazuh_password(stored)
    pattern = str(payload.get("index_pattern", wazuh.get("index_pattern", "wazuh-alerts-*")) or "").strip()
    verify_tls = payload.get("verify_tls", wazuh.get("verify_tls", True))
    if not isinstance(verify_tls, bool):
        raise HTTPException(status_code=400, detail="verify_tls harus berupa boolean (true/false).")
    try:
        return test_wazuh_connection(
            indexer_url=url,
            username=username,
            password=str(password or ""),
            index_pattern=pattern,
            verify_tls=verify_tls,
        )
    except ValueError as error:
        raise HTTPException(status_code=502, detail=str(error)) from None


@app.get("/api/database/status")
def api_database_status():
    if hasattr(db_module, "get_database_status"):
        with get_db() as conn:
            return db_module.get_database_status(conn)
    with get_db() as conn:
        alerts_n = conn.execute("SELECT count(*) AS n FROM wazuh.alerts").fetchone()["n"]
        groups_n = conn.execute("SELECT count(*) AS n FROM wazuh.analysis_groups").fetchone()["n"]
        intel_n = 0
        try:
            intel_n = conn.execute("SELECT count(*) AS n FROM public.ip_intel_cache").fetchone()["n"]
        except Exception:
            pass
        tenants = conn.execute("SELECT tenant, count(*) AS count FROM wazuh.alerts GROUP BY tenant").fetchall()
        return {
            "status": "ok",
            "active_profile": {"id": "local", "name": "Laptop (Lokal)", "mode": "read_write", "masked_url": "postgresql://arbiter:***@127.0.0.1:5432/abuseip"},
            "profiles": [
                {"id": "local", "name": "Laptop (Lokal)", "mode": "read_write", "description": "PostgreSQL lokal di laptop. Workspace operasional SOC utama.", "masked_url": "postgresql://arbiter:***@127.0.0.1:5432/abuseip", "is_active": True},
                {"id": "remote", "name": "PC Intel (Remote)", "mode": "read_only", "description": "PostgreSQL pada host IP Intel. Sumber cache reputasi dan telemetri sekunder.", "masked_url": "postgresql://arbiter:***@192.168.1.50:5432/abuseip", "is_active": False},
            ],
            "stats": {"alerts": alerts_n, "groups": groups_n, "ip_intel_records": intel_n},
            "tenants": tenants or [],
            "table_sizes": {"wazuh.alerts": "N/A", "wazuh.analysis_groups": "N/A"},
        }


@app.post("/api/database/switch")
def api_database_switch(payload: dict[str, Any]):
    profile = str(payload.get("profile") or "").strip()
    if hasattr(db_module, "set_active_profile"):
        return db_module.set_active_profile(profile)
    return {"id": profile, "status": "switched"}


@app.post("/api/database/test")
def api_database_test(payload: dict[str, Any]):
    url = payload.get("url")
    if hasattr(db_module, "test_db_connection"):
        if "profile" in payload:
            return db_module.test_db_connection(url, profile_id=str(payload["profile"]).strip())
        return db_module.test_db_connection(url)
    return {"ok": True, "latency_ms": 1.0, "version": "PostgreSQL Mock"}


@app.post("/api/database/config")
def api_database_config(payload: dict[str, Any]):
    profile = str(payload.get("profile") or "remote").strip()
    url = str(payload.get("url") or "").strip()
    if hasattr(db_module, "update_profile_url"):
        return db_module.update_profile_url(profile, url)
    return {"status": "ok"}


@app.post("/api/database/purge-alerts")
def api_database_purge_alerts(payload: dict[str, Any]):
    older_than_days = payload.get("older_than_days")
    if older_than_days is not None and str(older_than_days).strip() != "":
        try:
            older_than_days = int(older_than_days)
            if older_than_days <= 0 or older_than_days > 36500:
                raise ValueError()
        except (ValueError, TypeError):
            raise HTTPException(status_code=400, detail="Parameter older_than_days harus berupa bilangan bulat positif.")
    else:
        older_than_days = None

    time_from = payload.get("time_from")
    if time_from and str(time_from).strip():
        time_from = str(time_from).strip()
        try:
            from datetime import datetime
            datetime.fromisoformat(time_from.replace("Z", "+00:00"))
        except Exception:
            raise HTTPException(status_code=400, detail="Format time_from tidak valid (gunakan ISO 8601).")
    else:
        time_from = ""

    time_to = payload.get("time_to")
    if time_to and str(time_to).strip():
        time_to = str(time_to).strip()
        try:
            from datetime import datetime
            datetime.fromisoformat(time_to.replace("Z", "+00:00"))
        except Exception:
            raise HTTPException(status_code=400, detail="Format time_to tidak valid (gunakan ISO 8601).")
    else:
        time_to = ""

    if time_from and time_to and time_from > time_to:
        raise HTTPException(status_code=400, detail="Rentang waktu tidak valid: time_from harus sebelum atau sama dengan time_to.")

    tenant = str(payload.get("tenant") or "all").strip()

    if "dry_run" in payload:
        if not isinstance(payload["dry_run"], bool):
            raise HTTPException(status_code=400, detail="Parameter dry_run harus berupa boolean (true/false).")
        dry_run = payload["dry_run"]
    else:
        dry_run = True

    preview_token = payload.get("preview_token")
    if not dry_run and (preview_token is None or not str(preview_token).strip()):
        raise HTTPException(
            status_code=400,
            detail="Eksekusi pembersihan memerlukan server-side preview_token yang valid. Lakukan pratinjau terlebih dahulu."
        )

    expected_profile = payload.get("expected_profile") or payload.get("profile")

    with get_db() as conn:
        if hasattr(db_module, "purge_alerts"):
            return db_module.purge_alerts(
                conn, older_than_days=older_than_days, time_from=time_from,
                time_to=time_to, tenant=tenant, dry_run=dry_run,
                preview_token=preview_token, expected_profile=expected_profile,
            )
        return {"dry_run": dry_run, "count": 0}


@app.post("/api/database/purge-incidents")
def api_database_purge_incidents(payload: dict[str, Any]):
    status_filter = str(payload.get("status") or "closed_only").strip()
    valid_statuses = {"closed_only", "all", "closed", "resolved", "open", "in_progress"}
    if status_filter not in valid_statuses:
        raise HTTPException(status_code=400, detail=f"Kriteria status insiden '{status_filter}' tidak valid.")

    if "dry_run" in payload:
        if not isinstance(payload["dry_run"], bool):
            raise HTTPException(status_code=400, detail="Parameter dry_run harus berupa boolean (true/false).")
        dry_run = payload["dry_run"]
    else:
        dry_run = True

    preview_token = payload.get("preview_token")
    if not dry_run and (preview_token is None or not str(preview_token).strip()):
        raise HTTPException(
            status_code=400,
            detail="Eksekusi pembersihan memerlukan server-side preview_token yang valid. Lakukan pratinjau terlebih dahulu."
        )

    expected_profile = payload.get("expected_profile") or payload.get("profile")

    with get_db() as conn:
        if hasattr(db_module, "purge_incidents"):
            return db_module.purge_incidents(
                conn, status_filter=status_filter, dry_run=dry_run,
                preview_token=preview_token, expected_profile=expected_profile,
            )
        return {"dry_run": dry_run, "count": 0}


@app.get("/", response_class=HTMLResponse)
def index_page():
    html_path = Path(__file__).with_name("index.html")
    return HTMLResponse(content=html_path.read_text(encoding="utf-8"))
