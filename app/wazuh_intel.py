"""Deterministic Wazuh event intelligence: read, classify, and correlate.

This module is deliberately local and rule-based. It does not call an LLM,
does not perform network I/O, and never transmits raw telemetry.

Three responsibilities:

1. **Read nested Wazuh structures.** Active Response alerts embed the alert
   that triggered them inside ``data.parameters.alert`` (and sometimes inside a
   JSON payload in ``full_log``). Vulnerability Detector alerts embed their
   metadata in ``data.vulnerability``.
2. **Classify with auditable signals.** Rule semantics, Wazuh groups, severity,
   and optional context (known-bad source, repetition, first occurrence) produce
   a verdict, role, priority, confidence, and a human-readable reason. Unknown
   rules stay ``needs_review``; the classifier never declares an alert "safe".
3. **Correlate.** Active-Response events are linked back to their origin alert,
   and primary alerts are clustered by target host + rule while collecting all
   source IPs and containment events as facets.

The rule priors below are calibrated from the 738 labelled Wazuh alerts used
during design. They are **not** a model trained on production data: every rule
profile is explicit and every output includes the signals that produced it.
"""

from __future__ import annotations

import json
import re
from datetime import datetime, timezone
from typing import Any
from urllib.parse import unquote

from app.parser import as_dict, clean_val, parse_to_datetime, valid_ip

VERDICTS = {"tp", "fp", "needs_review"}
ROLES = {"indicator", "response", "context", "unknown"}
PRIORITIES = {"low", "medium", "high", "critical"}
PRIORITY_ORDER = {"low": 0, "medium": 1, "high": 2, "critical": 3}

# Rule profiles are keyed by Wazuh's stable built-in rule IDs. Each profile is
# intentionally explicit; no profile is inferred from a production database.
#   family, role, verdict, confidence, reason
RULE_PROFILES: dict[str, tuple[str, str, str, float, str]] = {
    # Active Response is a containment side effect, not an independent attack.
    "651": (
        "active_response", "response", "fp", 0.99,
        "Active Response 'add' adalah tindakan containment turunan; tautkan ke alert asal, jangan dinilai sebagai serangan mandiri.",
    ),
    "652": (
        "active_response", "response", "fp", 0.99,
        "Active Response 'delete' adalah tindakan pemulihan turunan; tautkan ke alert asal, jangan dinilai sebagai serangan mandiri.",
    ),
    # Credential access and web probing seen as true positives in the curated set.
    "5710": (
        "credential_access", "indicator", "tp", 0.95,
        "Percobaan login SSH dengan user tidak ada/invalid menunjukkan credential guessing.",
    ),
    "31101": (
        "web_probe", "indicator", "tp", 0.88,
        "Error 400/404 berulang pada web server menunjukkan probing atau request malformed.",
    ),
    "2833": (
        "persistence", "indicator", "tp", 0.92,
        "Perubahan crontab root adalah jalur persistensi/eksekusi terjadwal yang perlu ditinjau.",
    ),
    "5762": (
        "recon", "indicator", "tp", 0.72,
        "Koneksi SSH direset sebelum autentikasi; indikasi scan atau klien yang gagal pada tahap awal.",
    ),
    "5740": (
        "recon", "indicator", "tp", 0.70,
        "Kegagalan pertukaran kunci SSH (kex) dapat berasal dari scan atau implementasi klien tidak lazim.",
    ),
    "31303": (
        "tls_probe", "indicator", "tp", 0.78,
        "Pesan kritis Nginx pada TLS handshake menunjukkan klien bermasalah atau probing TLS.",
    ),
    # Vulnerability lifecycle and routine administration: context, not an attack.
    "23502": (
        "vulnerability_lifecycle", "context", "fp", 0.97,
        "Notifikasi CVE 'Solved' adalah perubahan status kerentanan, bukan aktivitas serangan.",
    ),
    "591": (
        "maintenance", "context", "fp", 0.98,
        "Rotasi file log adalah operasi rutin sistem.",
    ),
    "5501": (
        "expected_admin", "context", "fp", 0.82,
        "Sesi PAM dibuka untuk user yang sah; konteks administratif, bukan bukti serangan.",
    ),
    "5502": (
        "expected_admin", "context", "fp", 0.82,
        "Sesi PAM ditutup untuk user yang sah; konteks administratif, bukan bukti serangan.",
    ),
    "5715": (
        "expected_admin", "context", "fp", 0.80,
        "Autentikasi SSH berhasil; perlu dikorelasikan dengan login gagal sebelumnya, bukan otomatis dianggap aman.",
    ),
    "5402": (
        "expected_admin", "context", "fp", 0.80,
        "Sudo berhasil ke root; perlu dikorelasikan dengan aktivitas user dan perintah yang dijalankan.",
    ),
    "11": (
        "baseline_anomaly", "context", "needs_review", 0.55,
        "Lonjakan volume log adalah anomali baseline; penyebabnya belum dapat dipastikan dari alert ini.",
    ),
}

_TP_KEYWORDS = (
    "invalid user", "non-existent user", "nonexistent user", "brute", "attack",
    "exploit", "scan", "injection", "traversal", "malware", "ransomware",
    "exfiltration", "credential dump", "lateral movement", "unauthorized",
    "forbidden file", "400 error", "connection reset", "critical message",
    "failed password", "authentication failure",
)
_FP_KEYWORDS = (
    "log file rotated", "session opened", "session closed", "authentication success",
    "successful sudo", "was solved", "agent connected", "agent reconnected",
    "agent disconnected", "openscap: pass", "audit: successful", "routine",
)

_ACTIVE_RESPONSE_RE = re.compile(r"active-response/[^\s:]+:\s*(\{.*\})\s*$", re.S)

_TRAVERSAL_PAYLOAD_RE = re.compile(
    r"(?i)(?:"
    r"(?:\.|%2e|%252e){2}(?:/|\\|%2f|%5c|%252f|%255c)|"
    r"/cgi-bin/(?:[^\s\"']*?(?:\.|%2e)|setup\.cgi)|"
    r"/(?:etc/(?:passwd|hosts|shadow|issue|group)|proc/self|bin/(?:sh|bash)|windows/win\.ini)"
    r")"
)
_EXPLOIT_SCANNER_UA_RE = re.compile(
    r"(?i)\b(?:"
    r"lkx-[a-z0-9_-]*|apache2449traversalplugin|traversalplugin|leakix(?:\.net)?|"
    r"nuclei|sqlmap|nikto|nmap|masscan|zgrab|gobuster|dirbuster|ffuf|wfuzz|wpscan|"
    r"acunetix|nessus|openvas|metasploit|hydra|go web pentest tool"
    r")\b"
)
_WEB_EXPLOIT_PAYLOAD_RE = re.compile(
    r"(?i)(?:"
    r"\bunion\s+(?:all\s+)?select\b|"
    r"\$\{jndi:(?:ldap|rmi|dns|nis|iiop|corba|nds|http)s?:|"
    r"php://(?:filter|input)|expect://|eval-stdin\.php|"
    r"(?:;|\||`|\$\()\s*(?:wget|curl|chmod|sh|bash|nc|ncat|python|perl|php)\b"
    r")"
)


def _extract_payload_indicators(alert: dict[str, Any]) -> list[dict[str, str]]:
    """Inspect URI, User-Agent, and log payload for high-confidence exploit/scanner patterns."""
    raw = as_dict(alert.get("raw") or alert.get("raw_alert"))
    data = as_dict(alert.get("data") or raw.get("data"))
    parsed = _as_json(alert.get("parsed_details")) if isinstance(alert.get("parsed_details"), str) else as_dict(alert.get("parsed_details"))
    full_log = clean_val(alert.get("full_log") or raw.get("full_log") or "")
    description = clean_val(alert.get("description") or "")

    url = clean_val(
        data.get("url")
        or data.get("uri")
        or parsed.get("path")
        or parsed.get("uri")
        or parsed.get("url_path")
        or ""
    )
    if not url and full_log:
        m = re.search(r'\"(?:GET|POST|HEAD|PUT|DELETE|OPTIONS|PATCH)\s+([^\s\"]+)\s+HTTP/', full_log, re.I)
        if m:
            url = m.group(1)

    ua = clean_val(parsed.get("ua") or parsed.get("user_agent") or data.get("user_agent") or "")
    if not ua and full_log:
        quoted = re.findall(r'\"([^\"]*)\"', full_log)
        if len(quoted) >= 3:
            ua = quoted[-1]

    candidates = " ".join(part for part in (url, ua, full_log, description) if part)
    if not candidates:
        return []
    decoded_once = unquote(candidates)
    decoded_twice = unquote(decoded_once)
    combined = f"{candidates} {decoded_once} {decoded_twice}"

    indicators: list[dict[str, str]] = []
    m_trav = _TRAVERSAL_PAYLOAD_RE.search(candidates) or _TRAVERSAL_PAYLOAD_RE.search(decoded_twice)
    if m_trav:
        sample = clean_val(url or m_trav.group(0))[:120]
        indicators.append({
            "code": "payload_traversal",
            "label": "Eksploitasi Path Traversal / LFI",
            "value": sample,
            "kind": "payload",
            "direction": "supports_tp",
        })
    m_ua = _EXPLOIT_SCANNER_UA_RE.search(ua or combined)
    if m_ua:
        sample_ua = clean_val(ua or m_ua.group(0))[:120]
        indicators.append({
            "code": "scanner_user_agent",
            "label": "Scanner / Exploit Tool User-Agent",
            "value": sample_ua,
            "kind": "payload",
            "direction": "supports_tp",
        })
    m_exp = _WEB_EXPLOIT_PAYLOAD_RE.search(combined)
    if m_exp:
        indicators.append({
            "code": "payload_exploit",
            "label": "Payload Injeksi / RCE",
            "value": clean_val(m_exp.group(0))[:120],
            "kind": "payload",
            "direction": "supports_tp",
        })
    return indicators


def _as_json(value: Any) -> Any:
    if isinstance(value, (dict, list)):
        return value
    if isinstance(value, str):
        try:
            return json.loads(value)
        except (ValueError, TypeError):
            return None
    return None


def extract_active_response(alert: dict[str, Any]) -> dict[str, Any]:
    """Return the origin alert embedded in an Active Response event.

    Supports both shapes shipped by Wazuh:

    * ``data.parameters.alert`` (structured JSON)
    * a JSON object appended to ``full_log`` after ``active-response/<program>:``

    The function is intentionally tolerant: a missing or malformed payload
    returns ``{"is_active_response": False, ...}`` instead of raising.
    """
    raw = as_dict(alert.get("raw") or alert.get("raw_alert"))
    data = as_dict(alert.get("data") or raw.get("data"))
    full_log = clean_val(alert.get("full_log") or raw.get("full_log"))

    payload = None
    for container in (as_dict(data.get("parameters")), data, as_dict(raw.get("parameters"))):
        candidate = _as_json(container.get("alert"))
        if isinstance(candidate, dict):
            payload = candidate
            break
    if payload is None and full_log and "active-response/" in full_log:
        match = _ACTIVE_RESPONSE_RE.search(full_log)
        if match:
            parsed = _as_json(match.group(1))
            if isinstance(parsed, dict):
                payload = as_dict(as_dict(parsed.get("parameters")).get("alert")) or None
                if payload is None and isinstance(parsed.get("rule"), dict):
                    payload = parsed

    groups = alert.get("rule_groups") or as_dict(alert.get("rule")).get("groups") or []
    detected = (
        bool(data.get("command"))
        or "active-response/" in full_log
        or "active_response" in groups
    )
    if not isinstance(payload, dict) or not detected:
        return {
            "is_active_response": detected,
            "command": clean_val(data.get("command")),
            "program": clean_val(raw.get("program") or data.get("program")),
            "origin": None,
        }

    rule = as_dict(payload.get("rule"))
    origin_data = as_dict(payload.get("data"))
    origin_agent = as_dict(payload.get("agent"))
    return {
        "is_active_response": True,
        "command": clean_val(data.get("command")),
        "program": clean_val(raw.get("program") or data.get("program")),
        "origin": {
            "alert_id": clean_val(payload.get("id")),
            "rule_id": clean_val(rule.get("id")),
            "rule_level": int(rule.get("level") or 0) if rule.get("level") is not None else 0,
            "description": clean_val(rule.get("description")),
            "groups": rule.get("groups") if isinstance(rule.get("groups"), list) else [],
            "mitre_ids": as_dict(rule.get("mitre")).get("id") or [],
            "source_ip": valid_ip(origin_data.get("srcip") or origin_data.get("src_ip") or origin_data.get("source_ip")),
            "agent_name": clean_val(origin_agent.get("name")),
            "agent_ip": valid_ip(origin_agent.get("ip")),
            "full_log": clean_val(payload.get("full_log")),
            "data": origin_data,
        },
    }


def _profile_for(rule_id: str, description: str, groups: list[str]) -> tuple[str, str, str, float, str, str]:
    if rule_id in RULE_PROFILES:
        family, role, verdict, confidence, reason = RULE_PROFILES[rule_id]
        return family, role, verdict, confidence, reason, "curated_rule"

    text = f"{description} {' '.join(groups)}".lower()
    if "active_response" in groups:
        return (
            "active_response", "response", "fp", 0.95,
            "Alert berasal dari Active Response; tautkan ke alert asal sebagai bukti containment.",
            "group",
        )
    if "vulnerability-detector" in groups:
        return (
            "vulnerability_lifecycle", "context", "fp", 0.88,
            "Alert berasal dari Vulnerability Detector; ini status kerentanan, bukan aktivitas serangan.",
            "group",
        )
    if any(keyword in text for keyword in _FP_KEYWORDS):
        return (
            "expected_admin", "context", "fp", 0.72,
            "Pola aktivitas rutin/administratif; verifikasi konteks sebelum menutup sebagai noise.",
            "keyword",
        )
    if any(keyword in text for keyword in _TP_KEYWORDS):
        return (
            "suspicious", "indicator", "tp", 0.72,
            "Rule/description menunjukkan aktivitas mencurigakan; verifikasi bukti mentah dan korelasi.",
            "keyword",
        )
    return (
        "unknown", "unknown", "needs_review", 0.35,
        "Belum ada profil rule atau pola yang cukup; tinjau bukti mentah sebelum mengambil keputusan.",
        "default",
    )


def _level_priority(level: int) -> str:
    if level >= 12:
        return "critical"
    if level >= 10:
        return "high"
    if level >= 7:
        return "medium"
    return "low"


def _bump(priority: str, step: int = 1) -> str:
    current = PRIORITY_ORDER.get(priority, 0)
    return next((name for name, rank in PRIORITY_ORDER.items() if rank == min(3, current + step)), priority)


def _intel_context(alert: dict[str, Any], intel: dict[str, Any] | None) -> dict[str, Any]:
    context = dict(intel or {})
    for key in ("abuse_score", "vt_malicious", "is_known_bad_ip", "src_ip_type", "first_occurrence", "is_business_hours"):
        if key in alert and key not in context:
            context[key] = alert.get(key)
    return context


def _known_bad(context: dict[str, Any]) -> bool:
    if context.get("is_known_bad_ip") is True:
        return True
    try:
        if int(context.get("abuse_score") or 0) >= 75:
            return True
        if int(context.get("vt_malicious") or 0) > 0:
            return True
    except (TypeError, ValueError):
        pass
    return False


def classify_alert(alert: dict[str, Any], *, intel: dict[str, Any] | None = None) -> dict[str, Any]:
    """Classify one normalized (or normalized-like) alert.

    Returns an auditable dictionary. ``verdict`` is one of ``tp``, ``fp`` or
    ``needs_review``; ``role`` separates a primary indicator from a containment
    response and from contextual/routine events. A response event is ``fp`` as a
    standalone alert but carries ``origin_verdict`` for the alert it was derived
    from.
    """
    rule = as_dict(alert.get("rule"))
    rule_id = clean_val(alert.get("rule_id") or rule.get("id"))
    description = clean_val(alert.get("description") or rule.get("description"))
    groups = alert.get("rule_groups") or rule.get("groups") or []
    if isinstance(groups, str):
        groups = [part.strip() for part in groups.split(",")]
    if not isinstance(groups, list):
        groups = []
    groups = [clean_val(group) for group in groups if clean_val(group)]
    try:
        level = int(alert.get("rule_level") or rule.get("level") or 0)
    except (TypeError, ValueError):
        level = 0
    origin = extract_active_response(alert)
    family, role, verdict, confidence, reason, source = _profile_for(rule_id, description, groups)
    payload_indicators = [] if origin.get("is_active_response") else _extract_payload_indicators(alert)
    if payload_indicators:
        verdict = "tp"
        role = "indicator"
        family = "web_exploit"
        confidence = max(confidence, 0.96)
        source = "payload_indicator"
        summary_parts = [f"{ind['label']} ({ind['value']})" for ind in payload_indicators]
        reason = (
            f"Terdeteksi serangan eksploitasi/pemindaian pada log: {'; '.join(summary_parts)}. "
            "Diklasifikasikan sebagai True Positive meskipun server mengembalikan HTTP 400/403/404."
        )[:400]

    if origin.get("is_active_response"):
        role = "response"
        if origin.get("origin"):
            origin_rule = as_dict(origin["origin"]).get("rule_id")
            origin_description = as_dict(origin["origin"]).get("description")
            origin_groups = as_dict(origin["origin"]).get("groups") or []
            _f, _r, origin_verdict, _c, _reason, _s = _profile_for(
                clean_val(origin_rule), clean_val(origin_description), origin_groups
            )
        else:
            origin_verdict = "needs_review"

    context = _intel_context(alert, intel)
    known_bad = _known_bad(context)
    priority = _level_priority(level)
    if verdict == "tp" and priority == "low":
        priority = "medium"
    if known_bad:
        priority = _bump(priority)
    try:
        hit_count = int(alert.get("hit_count") or 1)
    except (TypeError, ValueError):
        hit_count = 1
    if hit_count >= 20:
        confidence = min(0.99, confidence + 0.03)

    signals: list[dict[str, str]] = []
    if payload_indicators:
        signals.extend(payload_indicators)
    if rule_id:
        signals.append({"code": "rule_profile", "label": "Profil rule", "value": f"Rule {rule_id}", "kind": "rule"})
    signals.append({"code": "rule_level", "label": "Level Wazuh", "value": str(level), "kind": "severity"})
    if groups:
        signals.append({"code": "rule_groups", "label": "Grup rule", "value": ", ".join(groups[:6]), "kind": "rule"})
    if origin.get("origin"):
        origin_data = as_dict(origin["origin"])
        link_value = clean_val(origin_data.get("alert_id")) or clean_val(origin_data.get("rule_id")) or "tidak tersedia"
        signals.append({
            "code": "origin_link",
            "label": "Alert asal",
            "value": link_value,
            "kind": "correlation",
            "direction": "supports_fp",
        })
    if known_bad:
        signals.append({
            "code": "known_bad_source",
            "label": "Source IP dikenal berisiko",
            "value": str(context.get("abuse_score") or context.get("vt_malicious") or "ya"),
            "kind": "intel",
            "direction": "raises_priority",
        })
    if hit_count >= 20:
        signals.append({
            "code": "repeated",
            "label": "Pengulangan",
            "value": f"{hit_count} hits",
            "kind": "volume",
            "direction": "raises_priority",
        })
    mitre = alert.get("mitre_ids") or as_dict(rule.get("mitre")).get("id") or []
    if isinstance(mitre, list) and mitre:
        signals.append({"code": "mitre", "label": "MITRE ATT&CK", "value": ", ".join(str(item) for item in mitre[:6]), "kind": "mitre"})

    result: dict[str, Any] = {
        "verdict": verdict if verdict in VERDICTS else "needs_review",
        "role": role if role in ROLES else "unknown",
        "family": family,
        "priority": priority if priority in PRIORITIES else "low",
        "confidence": round(max(0.0, min(1.0, confidence)), 2),
        "reason": reason,
        "signals": signals,
        "source": source,
        "origin": origin.get("origin"),
        "origin_verdict": origin_verdict if origin.get("is_active_response") else None,
        "known_bad_source": known_bad,
    }
    if origin.get("is_active_response"):
        result["response_command"] = origin.get("command") or ""
        result["response_program"] = origin.get("program") or ""
    return result


def _intel_for(alert: dict[str, Any]) -> dict[str, Any]:
    if _extract_payload_indicators(alert):
        return classify_alert(alert)
    stored = alert.get("wazuh_intel")
    if not isinstance(stored, dict):
        parsed = alert.get("parsed_details")
        if isinstance(parsed, str):
            parsed = _as_json(parsed)
        stored = as_dict(parsed).get("wazuh_intel")
    if isinstance(stored, dict) and stored.get("verdict") in VERDICTS:
        return stored
    return classify_alert(alert)


def _alert_key(alert: dict[str, Any]) -> str:
    return str(alert.get("id") or alert.get("alert_id") or "")


def _timestamp(alert: dict[str, Any]) -> str:
    return clean_val(alert.get("timestamp") or "")


def _sort_ts(value: str) -> datetime:
    return parse_to_datetime(value) or datetime(9999, 1, 1, tzinfo=timezone.utc)


def _group_identity(alert: dict[str, Any]) -> tuple[str, ...]:
    agent = clean_val(alert.get("agent_name"))
    rule = clean_val(alert.get("rule_id"))
    if agent and agent != "-" and rule and rule != "-":
        return ("host_rule", agent, rule)
    signature = clean_val(alert.get("log_signature"))
    if signature:
        return ("signature", signature)
    source = clean_val(alert.get("source_ip"))
    if source and rule and rule != "-":
        return ("source_rule", source, rule)
    return ("alert", _alert_key(alert))


def _group_title(identity: tuple[str, ...], sample: dict[str, Any]) -> tuple[str, str, str]:
    kind = identity[0] if identity else "alert"
    rule_id = clean_val(sample.get("rule_id")) or "-"
    description = clean_val(sample.get("description")) or "Wazuh Alert"
    if kind == "host_rule":
        agent = identity[1]
        return (
            f"Host {agent} · Rule {rule_id} ({description})",
            "Korelasi host + rule",
            f"Korelasi Host Target: {agent} & Rule {rule_id}",
        )
    if kind == "signature":
        return (
            f"Signature Cluster · Rule {rule_id} ({description})",
            "Signature identik",
            "Pola log signature identik",
        )
    if kind == "source_rule":
        return (
            f"Source {identity[1]} · Rule {rule_id} ({description})",
            "Korelasi source + rule",
            f"Korelasi IP Sumber: {identity[1]} & Rule {rule_id}",
        )
    return (
        f"Alert {rule_id} ({description})",
        "Alert tunggal",
        "Alert tanpa dimensi korelasi lain",
    )


_STAGE_LABELS = {
    "recon": "Pengintaian",
    "web_probe": "Probing web",
    "tls_probe": "Probing TLS",
    "credential_access": "Akses kredensial",
    "persistence": "Persistensi",
    "expected_admin": "Aktivitas administratif",
    "active_response": "Respons aktif",
    "vulnerability_lifecycle": "Siklus kerentanan",
    "maintenance": "Pemeliharaan",
    "baseline_anomaly": "Anomali baseline",
    "suspicious": "Aktivitas mencurigakan",
    "unknown": "Belum terklasifikasi",
}


def _chain_steps(alerts: list[dict[str, Any]]) -> list[dict[str, Any]]:
    ordered = sorted(alerts, key=lambda item: _sort_ts(_timestamp(item)))
    steps: list[dict[str, Any]] = []
    for alert in ordered:
        intel = _intel_for(alert)
        stage = str(intel.get("family") or "unknown")
        label = _STAGE_LABELS.get(stage, stage)
        alert_id = _alert_key(alert)
        if steps and steps[-1]["stage"] == stage:
            steps[-1]["alert_ids"].append(alert_id)
            steps[-1]["count"] += 1
            steps[-1]["last_seen"] = _timestamp(alert) or steps[-1]["last_seen"]
            rule_id = clean_val(alert.get("rule_id"))
            if rule_id and rule_id not in steps[-1]["rule_ids"]:
                steps[-1]["rule_ids"].append(rule_id)
        else:
            steps.append({
                "stage": stage,
                "label": label,
                "first_seen": _timestamp(alert),
                "last_seen": _timestamp(alert),
                "alert_ids": [alert_id],
                "rule_ids": [clean_val(alert.get("rule_id"))] if clean_val(alert.get("rule_id")) else [],
                "count": 1,
            })
    return steps


def correlate_alerts(alerts: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Build canonical incident groups from primary alerts and their responses.

    Active-Response alerts are removed from independent grouping and attached to
    the group that contains their origin alert. If the origin is outside the
    current scope, the response remains a standalone group so evidence is never
    silently lost. Source IP is a facet, not a grouping key: rotating IPs still
    collapse into one host+rule group.
    """
    prepared: list[dict[str, Any]] = []
    by_wazuh_id: dict[str, dict[str, Any]] = {}
    for alert in alerts:
        item = dict(alert)
        item["_intel"] = _intel_for(item)
        prepared.append(item)
        for key in ("alert_id", "wazuh_id", "id"):
            value = clean_val(item.get(key))
            if value:
                by_wazuh_id.setdefault(value, item)

    responses: dict[str, list[dict[str, Any]]] = {}
    primaries: list[dict[str, Any]] = []
    orphan_responses: list[dict[str, Any]] = []
    for item in prepared:
        intel = item["_intel"]
        origin = as_dict(intel.get("origin"))
        origin_id = clean_val(origin.get("alert_id"))
        if intel.get("role") == "response" and origin_id and origin_id in by_wazuh_id and by_wazuh_id[origin_id] is not item:
            responses.setdefault(origin_id, []).append(item)
        elif intel.get("role") == "response" and origin_id:
            orphan_responses.append(item)
        else:
            primaries.append(item)

    buckets: dict[tuple[str, ...], list[dict[str, Any]]] = {}
    for item in primaries:
        buckets.setdefault(_group_identity(item), []).append(item)
    for item in orphan_responses:
        buckets.setdefault(_group_identity(item), []).append(item)

    groups: list[dict[str, Any]] = []
    for identity, members in buckets.items():
        member_ids = {_alert_key(item) for item in members}
        attached: list[dict[str, Any]] = []
        for item in members:
            wazuh_ids = {clean_val(item.get(key)) for key in ("alert_id", "wazuh_id", "id")}
            for wazuh_id in wazuh_ids:
                if wazuh_id in responses:
                    attached.extend(responses[wazuh_id])
        unique_attached = list({
            _alert_key(item): item for item in attached if _alert_key(item) not in member_ids
        }.values())
        all_members = members + unique_attached
        if not all_members:
            continue

        sample = members[0] if members else all_members[0]
        title, category, basis = _group_title(identity, sample)
        source_ips = list(dict.fromkeys(
            str(item.get("source_ip")) for item in all_members
            if item.get("source_ip") and item.get("source_ip") != "-"
        ))
        agents = list(dict.fromkeys(
            str(item.get("agent_name")) for item in all_members
            if item.get("agent_name") and item.get("agent_name") != "-"
        ))
        timestamps = [_timestamp(item) for item in all_members if _timestamp(item)]
        total_hits = sum(int(item.get("hit_count") or 1) for item in all_members)
        primary_intel = [_intel_for(item) for item in members]
        if any(intel.get("verdict") == "tp" for intel in primary_intel):
            verdict = "tp"
        elif any(intel.get("verdict") == "needs_review" for intel in primary_intel):
            verdict = "needs_review"
        else:
            verdict = "fp"
        confidence = max((float(intel.get("confidence") or 0) for intel in primary_intel), default=0.4)
        if unique_attached:
            confidence = min(0.99, confidence + 0.05)
        chain = _chain_steps(all_members)
        response_count = len(unique_attached)
        ip_note = f" dari {len(source_ips)} IP sumber berbeda" if len(source_ips) > 1 else ""
        response_note = f" dan {response_count} event respons aktif tertaut" if response_count else ""
        stages = " → ".join(step["label"] for step in chain) if chain else "tahapan belum tersedia"
        reason = (
            f"Terdeteksi {len(members)} alert primer ({total_hits} hits){ip_note}"
            f"{response_note} pada host target '{agents[0] if agents else 'tidak diketahui'}'. "
            f"Urutan bukti: {stages}."
        )
        groups.append({
            "title": title,
            "category": category,
            "basis": basis,
            "reason": reason,
            "rule_id": clean_val(sample.get("rule_id")) or "-",
            "rule_level": max((int(item.get("rule_level") or 0) for item in all_members), default=0),
            "description": clean_val(sample.get("description")) or "Wazuh Alert",
            "agent_name": agents[0] if agents else "",
            "source_ips": source_ips,
            "alert_count": len(all_members),
            "primary_alert_count": len(members),
            "response_alert_count": response_count,
            "total_hits": total_hits,
            "time_start": min(timestamps) if timestamps else "",
            "time_end": max(timestamps) if timestamps else "",
            "key": list(identity),
            "alert_ids": list(dict.fromkeys(_alert_key(item) for item in all_members)),
            "primary_alert_ids": list(dict.fromkeys(_alert_key(item) for item in members)),
            "response_alert_ids": list(dict.fromkeys(_alert_key(item) for item in unique_attached)),
            "verdict": verdict,
            "confidence": round(confidence, 2),
            "chain": chain,
        })
    return groups


def build_attack_chains(alerts: list[dict[str, Any]], window_minutes: int = 120) -> list[dict[str, Any]]:
    """Group alerts by target host + source IP into ordered multi-rule chains.

    This is intentionally separate from :func:`correlate_alerts`: the canonical
    group stays host+rule, while a chain explains how different rules from the
    same source/target relate over time. The window is a soft guard; alerts
    without parseable timestamps are kept in the same chain.
    """
    prepared = []
    for alert in alerts:
        item = dict(alert)
        item["_intel"] = _intel_for(item)
        prepared.append(item)
    buckets: dict[tuple[str, str], list[dict[str, Any]]] = {}
    for item in prepared:
        agent = clean_val(item.get("agent_name"))
        source = clean_val(item.get("source_ip"))
        if not agent or not source:
            continue
        buckets.setdefault((agent, source), []).append(item)

    chains: list[dict[str, Any]] = []
    for (agent, source), members in buckets.items():
        members.sort(key=lambda item: _sort_ts(_timestamp(item)))
        steps = _chain_steps(members)
        stages = [step["stage"] for step in steps if step["stage"] != "active_response"]
        if len(set(stages)) < 2 and len(members) < 2:
            continue
        if window_minutes > 0:
            parsed = [parse_to_datetime(_timestamp(item)) for item in members]
            parsed = [value for value in parsed if value]
            if len(parsed) >= 2 and (max(parsed) - min(parsed)).total_seconds() > window_minutes * 60:
                continue
        timestamps = [_timestamp(item) for item in members if _timestamp(item)]
        chains.append({
            "title": f"Rantai serangan {source} → {agent}",
            "category": "Rantai lintas-rule",
            "agent_name": agent,
            "source_ip": source,
            "alert_ids": list(dict.fromkeys(_alert_key(item) for item in members)),
            "alert_count": len(members),
            "time_start": min(timestamps) if timestamps else "",
            "time_end": max(timestamps) if timestamps else "",
            "stages": steps,
            "confidence": round(max((float(item["_intel"].get("confidence") or 0) for item in members), default=0.4), 2),
            "reason": "Urutan tahapan: " + " → ".join(step["label"] for step in steps) + ".",
        })
    return chains
