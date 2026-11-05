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


def _prompt(alerts: list[dict[str, Any]]) -> str:
    return (
        "You are a SOC triage assistant working fully offline. Classify and group the alerts below. "
        "Use ONLY the provided alert ids. Do not invent facts, hosts, or IPs. A false positive means the "
        "activity is expected/benign (for example routine administrative noise). Use needs_review when the "
        "evidence is insufficient. Return STRICT JSON with this shape: "
        '{"groups":[{"category":string,"title":string,"verdict":"tp"|"fp"|"needs_review",'
        '"reason":string,"alert_ids":[string,...]}]}. '
        "Every alert must appear in at least one group. Keep reasons under 240 characters. Alerts: "
        + json.dumps(alerts, ensure_ascii=False)
    )


def _validate_ai_groups(value: Any, alerts: list[dict[str, Any]]) -> list[dict[str, Any]]:
    if not isinstance(value, dict) or not isinstance(value.get("groups"), list):
        raise LocalAIUnavailable("Model AI tidak mengembalikan struktur grup yang valid.")
    valid_ids = {str(a.get("id")) for a in alerts}
    seen: set[str] = set()
    groups = []
    for item in value["groups"]:
        if not isinstance(item, dict) or not isinstance(item.get("alert_ids"), list):
            continue
        ids = []
        for raw in item["alert_ids"]:
            alert_id = str(raw)
            if alert_id in valid_ids and alert_id not in seen:
                ids.append(alert_id)
                seen.add(alert_id)
        if not ids:
            continue
        verdict = str(item.get("verdict") or "needs_review").strip().lower()
        if verdict not in VERDICTS:
            verdict = "needs_review"
        groups.append({
            "category": str(item.get("category") or "AI lokal")[:120],
            "title": str(item.get("title") or "Kelompok AI lokal")[:200],
            "verdict": verdict,
            "reason": str(item.get("reason") or "Tanpa alasan dari model.")[:400],
            "alert_ids": ids,
        })
    missing = [alert_id for alert_id in valid_ids if alert_id not in seen]
    if missing:
        groups.append({
            "category": "Belum dikelompokkan",
            "title": "Alert yang belum diklasifikasikan model",
            "verdict": "needs_review",
            "reason": "Model tidak menempatkan alert ini pada grup mana pun; tinjau manual.",
            "alert_ids": missing,
        })
    if not groups:
        raise LocalAIUnavailable("Model AI tidak menghasilkan grup yang dapat dipakai.")
    return groups


def ai_triage(
    alerts: list[dict[str, Any]],
    *,
    model: str,
    base_url: str,
    timeout: float = 90,
) -> list[dict[str, Any]]:
    safe = safe_alerts(alerts)
    if not safe:
        return []
    text = ollama_request(_prompt(safe), model=model, base_url=base_url, timeout=timeout)
    try:
        value = json.loads(text)
    except (ValueError, TypeError) as error:
        raise LocalAIUnavailable("Model AI mengembalikan JSON yang tidak valid.") from error
    return _validate_ai_groups(value, safe)


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
