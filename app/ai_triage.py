"""Local AI triage: TP/FP classification plus evidence grouping.

Only sanitized structured fields are sent to the loopback Ollama endpoint.
Raw logs, ``raw``/``data`` blobs, and full_log content never leave the process.
"""

from __future__ import annotations

import json
import urllib.error
import urllib.parse
import urllib.request
from typing import Any

from app.core import LocalAIUnavailable, ollama_request, suggest_groups

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

_TP_HINTS = ("attack", "exploit", "brute", "malicious", "scan", "injection", "overflow", "denied", "failure", "unauthorized", "traversal", "shell", "malware")
_FP_HINTS = ("successful", "session opened", "session closed", "audit", "informational", "normal")


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
    level = int(alert.get("rule_level") or 0)
    text = f"{alert.get('description') or ''} {alert.get('rule_groups') or ''}".lower()
    if any(hint in text for hint in _FP_HINTS) and level < 10:
        return "fp", f"Level {level}; pola aktivitas rutin/administratif. Verifikasi manual tetap diperlukan."
    if level >= 10 or any(hint in text for hint in _TP_HINTS):
        return "tp", f"Level {level} dengan indikasi aktivitas mencurigakan pada rule/description."
    return "needs_review", f"Level {level}; bukti belum cukup untuk memastikan TP atau FP."


def heuristic_triage(alerts: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Deterministic fallback, clearly labelled as rules rather than AI."""
    by_id = {str(a.get("id") or a.get("alert_id")): a for a in alerts}
    groups = []
    covered: set[str] = set()
    for group in suggest_groups(alerts):
        ids = [str(item) for item in group.get("alert_ids", []) if str(item) in by_id]
        if not ids:
            continue
        strongest = max((by_id[item] for item in ids), key=lambda a: int(a.get("rule_level") or 0))
        verdict, reason = _heuristic_verdict(strongest)
        covered.update(ids)
        groups.append({
            "category": group.get("category") or "Heuristik lokal",
            "title": group.get("title") or "Kelompok heuristik",
            "verdict": verdict,
            "reason": reason,
            "alert_ids": ids,
        })
    for alert_id, alert in by_id.items():
        if alert_id in covered:
            continue
        verdict, reason = _heuristic_verdict(alert)
        groups.append({
            "category": "Heuristik lokal",
            "title": str(alert.get("description") or f"Alert {alert_id}")[:160],
            "verdict": verdict,
            "reason": reason,
            "alert_ids": [alert_id],
        })
    return groups


def _cluster_alerts(alerts: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Stage 1 — deterministic grouping (no LLM, no network).

    Reuses ``suggest_groups`` (rule_id + source_ip / agent / CVE / log_signature)
    to collapse N alerts into K clusters, then attaches sanitized summary fields
    that are safe to send to the model. Unmatched alerts become singleton clusters.
    """
    by_id = {str(a.get("id") or a.get("alert_id")): a for a in alerts}
    clusters: list[dict[str, Any]] = []
    covered: set[str] = set()
    for group in suggest_groups(alerts):
        # Priority order (source+rule > agent+rule > CVE > signature): keep each
        # alert in only its first matching cluster so the model never sees the
        # same alert classified twice.
        ids = [str(item) for item in group.get("alert_ids", []) if str(item) in by_id and str(item) not in covered]
        if not ids:
            continue
        covered.update(ids)
        members = [by_id[i] for i in ids]
        source_ips = sorted({str(a.get("source_ip") or "") for a in members if a.get("source_ip")})
        agent_names = sorted({str(a.get("agent_name") or "") for a in members if a.get("agent_name") and a.get("agent_name") != "-"})
        clusters.append({
            "alert_ids": ids,
            "title": str(group.get("title") or "Cluster")[:200],
            "category": str(group.get("category") or "")[:120],
            "rule_id": str(group.get("rule_id") or "")[:80],
            "rule_level": int(group.get("rule_level") or 0),
            "description": str(group.get("description") or "")[:300],
            "source_ips": source_ips[:8],
            "agent_names": agent_names[:8],
            "alert_count": len(ids),
            "total_hits": int(group.get("total_hits") or 0),
        })
    for alert_id, alert in by_id.items():
        if alert_id in covered:
            continue
        clusters.append({
            "alert_ids": [alert_id],
            "title": str(alert.get("description") or f"Alert {alert_id}")[:200],
            "category": "Tunggal",
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
        groups.append({
            "category": cluster["category"] or "AI lokal",
            "title": cluster["title"] or f"Cluster {index}",
            "verdict": verdict,
            "reason": str(item.get("reason") or "Tanpa alasan dari model.")[:400],
            "alert_ids": cluster["alert_ids"],
        })
    # Any cluster the model skipped still needs a verdict.
    for index, cluster in enumerate(clusters):
        if index in seen_indexes:
            continue
        groups.append({
            "category": cluster["category"] or "Belum diklasifikasikan",
            "title": cluster["title"] or f"Cluster {index}",
            "verdict": "needs_review",
            "reason": "Model tidak mengembalikan verdict untuk cluster ini; tinjau manual.",
            "alert_ids": cluster["alert_ids"],
        })
    if not groups:
        raise LocalAIUnavailable("Model AI tidak menghasilkan verdict yang dapat dipakai.")
    return groups


def ai_triage(
    alerts: list[dict[str, Any]],
    *,
    model: str,
    base_url: str,
    timeout: float = 90,
) -> list[dict[str, Any]]:
    """Two-stage triage: deterministic clustering, then LLM classification per cluster.

    The model receives only sanitized cluster summaries (rule_id, level, description,
    IP/host lists, counts) — never raw logs, ``data``, ``full_log``, or alert ids.
    """
    clusters = _cluster_alerts(alerts)
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
) -> tuple[list[dict[str, Any]], str, str | None]:
    if not enabled:
        return heuristic_triage(alerts), "local_rules", None
    try:
        return ai_triage(alerts, model=model, base_url=base_url, timeout=timeout), "local_ai", None
    except Exception as error:
        return heuristic_triage(alerts), "local_rules_fallback", str(error)


def test_ollama(*, base_url: str, model: str, timeout: float = 8) -> dict[str, Any]:
    parsed = urllib.parse.urlparse(base_url)
    if parsed.scheme != "http" or parsed.hostname not in {"localhost", "127.0.0.1", "::1"}:
        raise ValueError("AI lokal hanya boleh memakai http://localhost atau IP loopback.")
    target = base_url.rstrip("/") + "/api/tags"
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
