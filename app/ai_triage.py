"""Local AI triage: TP/FP classification plus evidence grouping.

Only sanitized structured fields are sent to the loopback Ollama endpoint.
Raw logs, ``raw``/``data`` blobs, and full_log content never leave the process.
"""

from __future__ import annotations

import json
import re
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, timedelta, timezone
from typing import Any

from app.core import LocalAIUnavailable, ollama_request
from app.settings import normalize_ollama_base_url
from app.wazuh_intel import classify_alert, correlate_alerts

WIB = timezone(timedelta(hours=7))
WIB_CUTOFF_HOUR = 17
AI_TRIAGE_STATE_KEY = "ai_triage_state"

SAFE_FIELDS = (
    "id",
    "alert_id",
    "timestamp",
    "tenant",
    "agent_name",
    "agent_ip",
    "rule_id",
    "rule_level",
    "description",
    "source_ip",
    "rule_groups",
    "mitre_ids",
    "cve",
    "hit_count",
)

MAX_ALERTS = 40
VERDICTS = {"tp", "fp", "needs_review"}
VERDICT_LABELS = {"tp": "True Positive", "fp": "False Positive", "needs_review": "Perlu ditinjau"}


def safe_alerts(alerts: list[dict[str, Any]], limit: int = MAX_ALERTS) -> list[dict[str, Any]]:
    result = []
    for alert in alerts[:limit]:
        record = {}
        for field in SAFE_FIELDS:
            value = alert.get(field)
            if isinstance(value, str) and field == "description":
                value = value[:300]
            record[field] = value
        record["id"] = str(alert.get("id") or alert.get("alert_id") or "")
        record["rule_level"] = int(alert.get("rule_level") or 0)
        record["hit_count"] = int(alert.get("hit_count") or 1)
        result.append(record)
    return result


def _heuristic_verdict(alert: dict[str, Any]) -> tuple[str, str]:
    """Deterministic fallback verdict with an auditable rule/context reason."""
    intel = classify_alert(alert)
    return str(intel["verdict"]), str(intel["reason"])


def _intel_summary(alert: dict[str, Any]) -> dict[str, Any]:
    intel = classify_alert(alert)
    return {
        "confidence": intel.get("confidence"),
        "priority": intel.get("priority"),
        "role": intel.get("role"),
        "signals": intel.get("signals") or [],
    }


GROUP_BY_MODES = {"host_rule", "rule_description"}


def wib_window_key(value: Any = None) -> str:
    """Return the 17:00 WIB cutoff window identifier ('YYYY-MM-DDT17:00+07:00').

    Alerts/events occurring strictly before 17:00 WIB on day D belong to
    'D T17:00+07:00'. Alerts/events at or after 17:00 WIB on day D belong to
    '(D+1) T17:00+07:00'. Returns '' if value is empty or unparseable.
    """
    if value is None or value == "":
        return ""
    if isinstance(value, datetime):
        dt = value
    else:
        text = str(value).strip()
        if not text:
            return ""
        if len(text) == 10 and text[4:5] == "-" and text[7:8] == "-":
            text = f"{text}T00:00:00+07:00"
        else:
            if text.endswith("Z") or text.endswith("z"):
                text = text[:-1] + "+00:00"
            text = re.sub(r"([+-]\d{2})(\d{2})$", r"\1:\2", text)
        try:
            dt = datetime.fromisoformat(text)
        except ValueError:
            return ""
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=WIB)
    dt_wib = dt.astimezone(WIB)
    cutoff_date = dt_wib.date()
    if (dt_wib.hour, dt_wib.minute, dt_wib.second, dt_wib.microsecond) >= (WIB_CUTOFF_HOUR, 0, 0, 0):
        cutoff_date = cutoff_date + timedelta(days=1)
    return f"{cutoff_date.isoformat()}T17:00+07:00"


def current_wib_window_key(now: datetime | None = None) -> str:
    return wib_window_key(now or datetime.now(WIB))


def format_wib_window_label(window_key: str) -> str:
    """Human-readable label for a 17:00 WIB window key, e.g. '2026-11-08 17:00 WIB'."""
    text = str(window_key or "").strip()
    if len(text) >= 16 and "T17:00" in text:
        return f"{text[:10]} 17:00 WIB"
    return text


def _alert_tenant(alert: dict[str, Any]) -> str:
    return str(alert.get("tenant") or "Default").strip() or "Default"


def _partition_by_tenant(alerts: list[dict[str, Any]]) -> list[tuple[str, bool, list[dict[str, Any]]]]:
    """Partition alerts by tenant so a single group never mixes two or more tenants."""
    buckets: dict[str, list[dict[str, Any]]] = {}
    explicit: dict[str, bool] = {}
    for alert in alerts:
        raw_t = str(alert.get("tenant") or "").strip()
        tenant = raw_t or "Default"
        buckets.setdefault(tenant, []).append(alert)
        if raw_t:
            explicit[tenant] = True
    return [(tenant, explicit.get(tenant, False), items) for tenant, items in buckets.items()]


def _group_by_rule_description(
    tenant: str,
    has_explicit_tenant: bool,
    multi_tenant: bool,
    alerts: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    buckets: dict[tuple[str, str], list[dict[str, Any]]] = {}
    windows_per_desc: dict[str, set[str]] = {}
    for alert in alerts:
        aid = str(alert.get("id") or alert.get("alert_id") or "")
        desc = str(alert.get("description") or "").strip()
        rule_id = str(alert.get("rule_id") or "").strip()
        desc_key = desc.lower() if desc else (f"rule:{rule_id}" if rule_id else f"id:{aid}")
        win_key = wib_window_key(alert.get("timestamp"))
        buckets.setdefault((desc_key, win_key), []).append(alert)
        windows_per_desc.setdefault(desc_key, set()).add(win_key)

    groups: list[dict[str, Any]] = []
    for (desc_key, win_key), members in buckets.items():
        ids = list(dict.fromkeys(
            str(a.get("id") or a.get("alert_id"))
            for a in members
            if (a.get("id") or a.get("alert_id")) is not None
        ))
        if not ids:
            continue
        strongest = max(members, key=lambda a: int(a.get("rule_level") or 0))
        rule_id = str(strongest.get("rule_id") or "")
        rule_level = int(strongest.get("rule_level") or 0)
        desc = str(strongest.get("description") or f"Rule {rule_id or ids[0]}").strip()
        source_ips = sorted({
            str(a.get("source_ip") or "")
            for a in members
            if a.get("source_ip") and a.get("source_ip") != "-"
        })
        agent_names = sorted({
            str(a.get("agent_name") or "")
            for a in members
            if a.get("agent_name") and a.get("agent_name") != "-"
        })
        total_hits = sum(int(a.get("hit_count") or 1) for a in members)
        intels = [classify_alert(a) for a in members]
        verdicts = [(str(info["verdict"]), str(info["reason"]), str(info.get("source") or "")) for info in intels]
        strongest_verdict, base_reason = _heuristic_verdict(strongest)
        payload_tp = next(((v, r) for v, r, src in verdicts if v == "tp" and src == "payload_indicator"), None)
        any_tp = next(((v, r) for v, r, _ in verdicts if v == "tp"), None)
        if payload_tp:
            verdict, base_reason = payload_tp
        elif any_tp:
            verdict, base_reason = any_tp
        elif any(v == "needs_review" for v, _, _ in verdicts):
            verdict = "needs_review"
        else:
            verdict = strongest_verdict

        multi_window = len(windows_per_desc.get(desc_key, set())) > 1
        title_suffix = f" ({tenant})" if (has_explicit_tenant and multi_tenant) else ""
        win_suffix = f" [≤ {format_wib_window_label(win_key)}]" if (multi_window and win_key) else ""
        title = f"{desc}{title_suffix}{win_suffix}"[:200]
        agent_tag = f" · {len(agent_names)} agent" if len(agent_names) > 1 else (f" · {agent_names[0]}" if len(agent_names) == 1 else "")
        category = (f"Rule description · {tenant}{agent_tag}" if has_explicit_tenant else f"Rule description{agent_tag}")[:120]
        agent_note = f" pada {len(agent_names)} agent ({', '.join(agent_names[:4])}{'…' if len(agent_names) > 4 else ''})" if agent_names else ""
        tenant_note = f" di tenant '{tenant}'" if has_explicit_tenant else ""
        win_note = f" (batas grup {format_wib_window_label(win_key)})" if win_key else ""
        reason = f"Dikelompokkan berdasarkan rule description{tenant_note}{win_note}: {len(ids)} alert ({total_hits} hits){agent_note}. {base_reason}"[:400]
        group_key = f"{tenant}::rule_description::{desc_key}::{win_key}"
        groups.append({
            "tenant": tenant,
            "window_key": win_key,
            "group_key": group_key,
            "lock_tp": bool(payload_tp),
            "heuristic_reason": reason,
            "category": category,
            "title": title,
            "verdict": verdict,
            "reason": reason,
            "alert_ids": ids,
            "rule_id": rule_id[:80],
            "rule_level": rule_level,
            "description": desc[:300],
            "source_ips": source_ips[:8],
            "agent_names": agent_names[:8],
            "alert_count": len(ids),
            "total_hits": total_hits,
            "chain": [],
            "response_alert_ids": [],
            **_intel_summary(strongest),
        })
    return groups


def heuristic_triage(alerts: list[dict[str, Any]], *, group_by: str = "host_rule") -> list[dict[str, Any]]:
    """Deterministic fallback, clearly labelled as rules rather than AI."""
    partitions = _partition_by_tenant(alerts)
    multi_tenant = len(partitions) > 1
    if group_by == "rule_description":
        result: list[dict[str, Any]] = []
        for tenant, has_explicit, tenant_alerts in partitions:
            for item in _group_by_rule_description(tenant, has_explicit, multi_tenant, tenant_alerts):
                result.append({
                    "tenant": item["tenant"],
                    "window_key": item["window_key"],
                    "group_key": item["group_key"],
                    "category": item["category"],
                    "title": item["title"],
                    "verdict": item["verdict"],
                    "reason": item["reason"],
                    "alert_ids": item["alert_ids"],
                    "chain": item["chain"],
                    "response_alert_ids": item["response_alert_ids"],
                    "confidence": item.get("confidence"),
                    "priority": item.get("priority"),
                    "role": item.get("role"),
                    "signals": item.get("signals") or [],
                })
        return result

    groups: list[dict[str, Any]] = []
    for tenant, has_explicit, tenant_alerts in partitions:
        win_buckets: dict[str, list[dict[str, Any]]] = {}
        for alert in tenant_alerts:
            win_buckets.setdefault(wib_window_key(alert.get("timestamp")), []).append(alert)
        multi_window = len(win_buckets) > 1
        for win_key, win_alerts in win_buckets.items():
            by_id = {str(a.get("id") or a.get("alert_id")): a for a in win_alerts}
            covered: set[str] = set()
            win_suffix = f" [≤ {format_wib_window_label(win_key)}]" if (multi_window and win_key) else ""
            for group in correlate_alerts(win_alerts):
                ids = [str(item) for item in group.get("alert_ids", []) if str(item) in by_id]
                if not ids:
                    continue
                members = [by_id[item] for item in ids]
                strongest = max(members, key=lambda a: int(a.get("rule_level") or 0))
                verdict, reason = _heuristic_verdict(strongest)
                for m_alert in members:
                    m_info = classify_alert(m_alert)
                    if m_info.get("source") == "payload_indicator" or (m_info["verdict"] == "tp" and verdict != "tp"):
                        verdict = str(m_info["verdict"])
                        reason = str(m_info["reason"])
                        if m_info.get("source") == "payload_indicator":
                            break
                covered.update(ids)
                base_title = group.get("title") or "Kelompok heuristik"
                title = f"{base_title}{f' ({tenant})' if (has_explicit and multi_tenant) else ''}{win_suffix}"[:200]
                base_cat = group.get("category") or "Heuristik lokal"
                category = f"{base_cat} · {tenant}" if (has_explicit and multi_tenant) else base_cat
                sig_key = f"{base_cat}:{base_title}".lower()
                groups.append({
                    "tenant": tenant,
                    "window_key": win_key,
                    "group_key": f"{tenant}::host_rule::{sig_key}::{win_key}",
                    "category": category,
                    "title": title,
                    "verdict": verdict,
                    "reason": reason,
                    "alert_ids": ids,
                    "chain": group.get("chain") or [],
                    "response_alert_ids": group.get("response_alert_ids") or [],
                    **_intel_summary(strongest),
                })
            for alert_id, alert in by_id.items():
                if alert_id in covered:
                    continue
                verdict, reason = _heuristic_verdict(alert)
                base_title = str(alert.get("description") or f"Alert {alert_id}")[:160]
                title = f"{base_title}{f' ({tenant})' if (has_explicit and multi_tenant) else ''}{win_suffix}"[:200]
                sig_key = f"single:{alert.get('agent_name') or ''}:{alert.get('rule_id') or base_title}".lower()
                groups.append({
                    "tenant": tenant,
                    "window_key": win_key,
                    "group_key": f"{tenant}::host_rule::{sig_key}::{win_key}",
                    "category": f"Heuristik lokal · {tenant}" if (has_explicit and multi_tenant) else "Heuristik lokal",
                    "title": title,
                    "verdict": verdict,
                    "reason": reason,
                    "alert_ids": [alert_id],
                })
    return groups


def _cluster_alerts(alerts: list[dict[str, Any]], *, group_by: str = "host_rule") -> list[dict[str, Any]]:
    """Stage 1 — deterministic grouping (no LLM, no network).

    Each cluster is strictly scoped to a single tenant and 17:00 WIB window so two
    or more tenants or post-17:00 WIB windows are never combined into one case group.
    """
    partitions = _partition_by_tenant(alerts)
    multi_tenant = len(partitions) > 1
    if group_by == "rule_description":
        clusters: list[dict[str, Any]] = []
        for tenant, has_explicit, tenant_alerts in partitions:
            for item in _group_by_rule_description(tenant, has_explicit, multi_tenant, tenant_alerts):
                clusters.append({
                    "tenant": item["tenant"],
                    "window_key": item["window_key"],
                    "group_key": item["group_key"],
                    "lock_tp": bool(item.get("lock_tp")),
                    "heuristic_reason": item.get("heuristic_reason") or item.get("reason") or "",
                    "alert_ids": item["alert_ids"],
                    "title": item["title"][:200],
                    "category": item["category"][:120],
                    "rule_id": item["rule_id"],
                    "rule_level": item["rule_level"],
                    "description": item["description"],
                    "source_ips": item["source_ips"],
                    "agent_names": item["agent_names"],
                    "alert_count": item["alert_count"],
                    "total_hits": item["total_hits"],
                    "chain": [],
                    "confidence": item.get("confidence"),
                    "response_alert_ids": [],
                })
        return clusters

    clusters = []
    for tenant, has_explicit, tenant_alerts in partitions:
        win_buckets: dict[str, list[dict[str, Any]]] = {}
        for alert in tenant_alerts:
            win_buckets.setdefault(wib_window_key(alert.get("timestamp")), []).append(alert)
        multi_window = len(win_buckets) > 1
        for win_key, win_alerts in win_buckets.items():
            by_id = {str(a.get("id") or a.get("alert_id")): a for a in win_alerts}
            covered: set[str] = set()
            win_suffix = f" [≤ {format_wib_window_label(win_key)}]" if (multi_window and win_key) else ""
            for group in correlate_alerts(win_alerts):
                ids = [str(item) for item in group.get("alert_ids", []) if str(item) in by_id and str(item) not in covered]
                if not ids:
                    continue
                covered.update(ids)
                members = [by_id[i] for i in ids]
                payload_info = next((classify_alert(a) for a in members if classify_alert(a).get("source") == "payload_indicator"), None)
                source_ips = sorted({str(a.get("source_ip") or "") for a in members if a.get("source_ip")})
                agent_names = sorted({str(a.get("agent_name") or "") for a in members if a.get("agent_name") and a.get("agent_name") != "-"})
                base_title = str(group.get("title") or "Cluster")
                title = f"{base_title}{f' ({tenant})' if (has_explicit and multi_tenant) else ''}{win_suffix}"[:200]
                base_cat = str(group.get("category") or "")
                category = (f"{base_cat} · {tenant}" if (has_explicit and multi_tenant and base_cat) else base_cat)[:120]
                sig_key = f"{base_cat}:{base_title}".lower()
                clusters.append({
                    "tenant": tenant,
                    "window_key": win_key,
                    "group_key": f"{tenant}::host_rule::{sig_key}::{win_key}",
                    "lock_tp": bool(payload_info),
                    "heuristic_reason": str(payload_info["reason"]) if payload_info else "",
                    "alert_ids": ids,
                    "title": title,
                    "category": category,
                    "rule_id": str(group.get("rule_id") or "")[:80],
                    "rule_level": int(group.get("rule_level") or 0),
                    "description": str(group.get("description") or "")[:300],
                    "source_ips": source_ips[:8],
                    "agent_names": agent_names[:8],
                    "alert_count": len(ids),
                    "total_hits": int(group.get("total_hits") or 0),
                    "chain": group.get("chain") or [],
                    "confidence": group.get("confidence"),
                    "response_alert_ids": group.get("response_alert_ids") or [],
                })
            for alert_id, alert in by_id.items():
                if alert_id in covered:
                    continue
                a_info = classify_alert(alert)
                is_payload_tp = a_info.get("source") == "payload_indicator"
                base_title = str(alert.get("description") or f"Alert {alert_id}")
                title = f"{base_title}{f' ({tenant})' if (has_explicit and multi_tenant) else ''}{win_suffix}"[:200]
                sig_key = f"single:{alert.get('agent_name') or ''}:{alert.get('rule_id') or base_title}".lower()
                clusters.append({
                    "tenant": tenant,
                    "window_key": win_key,
                    "group_key": f"{tenant}::host_rule::{sig_key}::{win_key}",
                    "lock_tp": bool(is_payload_tp),
                    "heuristic_reason": str(a_info["reason"]) if is_payload_tp else "",
                    "alert_ids": [alert_id],
                    "title": title,
                    "category": f"Tunggal · {tenant}" if (has_explicit and multi_tenant) else "Tunggal",
                    "rule_id": str(alert.get("rule_id") or "")[:80],
                    "rule_level": int(alert.get("rule_level") or 0),
                    "description": str(alert.get("description") or "")[:300],
                    "source_ips": [str(alert.get("source_ip"))] if alert.get("source_ip") else [],
                    "agent_names": [str(alert.get("agent_name"))] if alert.get("agent_name") else [],
                    "alert_count": 1,
                    "total_hits": int(alert.get("hit_count") or 1),
                })
    return clusters


def _cluster_prompt(clusters: list[dict[str, Any]]) -> str:
    """Build a compact prompt: one sanitized summary per cluster, indexed.

    The model never sees alert ids or raw logs — it classifies by cluster index,
    so hallucinated ids are structurally impossible to feed back.
    """
    payload = [
        {
            "index": index,
            "rule_id": cluster["rule_id"],
            "rule_level": cluster["rule_level"],
            "description": cluster["description"],
            "source_ips": cluster["source_ips"],
            "agent_names": cluster["agent_names"],
            "alert_count": cluster["alert_count"],
            "total_hits": cluster["total_hits"],
        }
        for index, cluster in enumerate(clusters)
    ]
    return (
        "You are a SOC triage assistant working fully offline. Each item below is a cluster of similar "
        "alerts already grouped by rule_id, source IP, CVE, or log signature. Do not regroup them. "
        "Classify each cluster as tp (true positive: real suspicious activity), fp (false positive: "
        "expected/benign, e.g. routine administrative noise), or needs_review (insufficient evidence). "
        "Use ONLY the cluster data; do not invent facts, hosts, IPs, or ids. Return STRICT JSON: "
        '{"verdicts":[{"index":int,"verdict":"tp"|"fp"|"needs_review","reason":string}]}. '
        "One verdict per cluster, same indices as input. Keep reasons under 240 characters. Clusters: "
        + json.dumps(payload, ensure_ascii=False)
    )


def _validate_cluster_verdicts(value: Any, clusters: list[dict[str, Any]]) -> list[dict[str, Any]]:
    if not isinstance(value, dict) or not isinstance(value.get("verdicts"), list):
        raise LocalAIUnavailable("Model AI tidak mengembalikan struktur verdict yang valid.")
    by_index = {index: cluster for index, cluster in enumerate(clusters)}
    groups: list[dict[str, Any]] = []
    seen_indexes: set[int] = set()
    for item in value["verdicts"]:
        if not isinstance(item, dict):
            continue
        try:
            index = int(item.get("index"))
        except (TypeError, ValueError):
            continue
        cluster = by_index.get(index)
        if cluster is None or index in seen_indexes:
            continue
        seen_indexes.add(index)
        verdict = str(item.get("verdict") or "needs_review").strip().lower()
        if verdict not in VERDICTS:
            verdict = "needs_review"
        reason = str(item.get("reason") or "Tanpa alasan dari model.")[:400]
        if cluster.get("lock_tp") and verdict != "tp":
            verdict = "tp"
            reason = str(cluster.get("heuristic_reason") or reason)[:400]
        groups.append({
            "tenant": cluster.get("tenant") or "Default",
            "window_key": cluster.get("window_key") or "",
            "group_key": cluster.get("group_key") or "",
            "category": cluster["category"] or "AI lokal",
            "title": cluster["title"] or f"Cluster {index}",
            "verdict": verdict,
            "reason": reason,
            "alert_ids": cluster["alert_ids"],
        })
    # Any cluster the model skipped still needs a verdict.
    for index, cluster in enumerate(clusters):
        if index in seen_indexes:
            continue
        locked = bool(cluster.get("lock_tp"))
        groups.append({
            "tenant": cluster.get("tenant") or "Default",
            "window_key": cluster.get("window_key") or "",
            "group_key": cluster.get("group_key") or "",
            "category": cluster["category"] or "Belum diklasifikasikan",
            "title": cluster["title"] or f"Cluster {index}",
            "verdict": "tp" if locked else "needs_review",
            "reason": str(cluster.get("heuristic_reason") if locked else "Model tidak mengembalikan verdict untuk cluster ini; tinjau manual.")[:400],
            "alert_ids": cluster["alert_ids"],
        })
    if not groups:
        raise LocalAIUnavailable("Model AI tidak menghasilkan verdict yang dapat dipakai.")
    return groups


def merge_triage_groups(
    existing_groups: list[dict[str, Any]],
    incoming_groups: list[dict[str, Any]],
    alerts_by_id: dict[str, dict[str, Any]],
) -> list[dict[str, Any]]:
    """Merge new triage groups into existing groups within the same tenant and 17:00 WIB window."""
    merged: list[dict[str, Any]] = []
    by_match_key: dict[tuple[str, str, str], dict[str, Any]] = {}
    covered_ids: set[str] = set()
    verdict_rank = {"tp": 3, "needs_review": 2, "fp": 1}

    for group in existing_groups:
        if not isinstance(group, dict):
            continue
        raw_ids = group.get("alert_ids") or []
        ids = list(dict.fromkeys(str(aid) for aid in raw_ids if str(aid) in alerts_by_id))
        if not ids:
            continue
        first_alert = alerts_by_id[ids[0]]
        tenant = str(group.get("tenant") or _alert_tenant(first_alert)).strip() or "Default"
        ids = [aid for aid in ids if _alert_tenant(alerts_by_id[aid]) == tenant]
        if not ids:
            continue
        win_key = str(group.get("window_key") or wib_window_key(first_alert.get("timestamp")) or "")
        g_key = str(group.get("group_key") or f"{tenant}::{str(group.get('title') or '').lower()}::{win_key}")
        verdict = str(group.get("verdict") or "needs_review")
        reason = str(group.get("reason") or "")
        for aid in ids:
            a_info = classify_alert(alerts_by_id[aid])
            if a_info.get("source") == "payload_indicator" and verdict != "tp":
                verdict = "tp"
                reason = str(a_info["reason"])
                break
        item = {
            **group,
            "tenant": tenant,
            "window_key": win_key,
            "group_key": g_key,
            "verdict": verdict,
            "reason": reason,
            "alert_ids": ids,
        }
        covered_ids.update(ids)
        merged.append(item)
        by_match_key[(tenant, g_key, win_key)] = item

    for inc in incoming_groups:
        if not isinstance(inc, dict):
            continue
        raw_ids = inc.get("alert_ids") or []
        ids = list(dict.fromkeys(str(aid) for aid in raw_ids if str(aid) in alerts_by_id))
        if not ids:
            continue
        first_alert = alerts_by_id[ids[0]]
        tenant = str(inc.get("tenant") or _alert_tenant(first_alert)).strip() or "Default"
        ids = [aid for aid in ids if _alert_tenant(alerts_by_id[aid]) == tenant]
        if not ids:
            continue
        win_key = str(inc.get("window_key") or wib_window_key(first_alert.get("timestamp")) or "")
        g_key = str(inc.get("group_key") or f"{tenant}::{str(inc.get('title') or '').lower()}::{win_key}")
        mkey = (tenant, g_key, win_key)
        target = by_match_key.get(mkey)
        if target is not None:
            new_ids = [aid for aid in ids if aid not in target["alert_ids"] and aid not in covered_ids]
            if new_ids:
                target["alert_ids"] = list(dict.fromkeys([*target["alert_ids"], *new_ids]))
                covered_ids.update(new_ids)
                prev_new = [str(x) for x in (target.get("new_alert_ids") or []) if str(x) in alerts_by_id]
                target["new_alert_ids"] = list(dict.fromkeys([*prev_new, *new_ids]))
                inc_verdict = str(inc.get("verdict") or "needs_review")
                cur_verdict = str(target.get("verdict") or "needs_review")
                if verdict_rank.get(inc_verdict, 0) > verdict_rank.get(cur_verdict, 0):
                    target["verdict"] = inc_verdict
        else:
            unassigned = [aid for aid in ids if aid not in covered_ids]
            if unassigned:
                covered_ids.update(unassigned)
                new_item = {
                    **inc,
                    "tenant": tenant,
                    "window_key": win_key,
                    "group_key": g_key,
                    "alert_ids": unassigned,
                }
                merged.append(new_item)
                by_match_key[mkey] = new_item

    return merged


def ai_triage(
    alerts: list[dict[str, Any]],
    *,
    model: str,
    base_url: str,
    timeout: float = 90,
    group_by: str = "host_rule",
) -> list[dict[str, Any]]:
    """Two-stage triage: deterministic clustering, then LLM classification per cluster.

    The model receives only sanitized cluster summaries (rule_id, level, description,
    IP/host lists, counts) — never raw logs, ``data``, ``full_log``, or alert ids.
    """
    clusters = _cluster_alerts(alerts, group_by=group_by)
    if not clusters:
        return []
    text = ollama_request(_cluster_prompt(clusters), model=model, base_url=base_url, timeout=timeout)
    try:
        value = json.loads(text)
    except (ValueError, TypeError) as error:
        raise LocalAIUnavailable("Model AI mengembalikan JSON yang tidak valid.") from error
    return _validate_cluster_verdicts(value, clusters)


def triage_with_fallback(
    alerts: list[dict[str, Any]],
    *,
    enabled: bool,
    model: str,
    base_url: str,
    timeout: float = 90,
    group_by: str = "host_rule",
) -> tuple[list[dict[str, Any]], str, str | None]:
    if not enabled:
        return heuristic_triage(alerts, group_by=group_by), "local_rules", None
    try:
        return ai_triage(alerts, model=model, base_url=base_url, timeout=timeout, group_by=group_by), "local_ai", None
    except Exception as error:
        return heuristic_triage(alerts, group_by=group_by), "local_rules_fallback", str(error)


def test_ollama(*, base_url: str, model: str, timeout: float = 8) -> dict[str, Any]:
    normalized_base = normalize_ollama_base_url(base_url)
    target = normalized_base.rstrip("/") + "/api/tags"
    request = urllib.request.Request(target, method="GET", headers={"Accept": "application/json"})
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
    try:
        with opener.open(request, timeout=timeout) as response:
            body = response.read(2 * 1024 * 1024)
    except urllib.error.URLError:
        raise ValueError("Ollama tidak dapat dihubungi di alamat tersebut. Pastikan layanan berjalan.") from None
    except TimeoutError:
        raise ValueError("Ollama tidak merespons dalam batas waktu.") from None
    try:
        payload = json.loads(body.decode("utf-8") or "{}")
    except ValueError:
        raise ValueError("Respons Ollama bukan JSON yang valid.") from None
    models = payload.get("models") if isinstance(payload, dict) else []
    names = [str(item.get("name") or "") for item in models if isinstance(item, dict)]
    available = model in names
    if not available:
        raise ValueError(f"Model '{model}' belum tersedia di Ollama. Jalankan: ollama pull {model}")
    return {"ok": True, "model": model, "models": names}
