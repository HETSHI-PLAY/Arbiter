# Arbiter Architecture — Wazuh Read, Classify, Correlate

Status: implemented baseline for deterministic read/classify/correlate; UI
surfaces are documented in `docs/ui-ux-redesign/DESIGN.md`.

This document describes how Arbiter turns raw Wazuh alerts into an investigation
queue and a defensible case. It is the missing architecture layer between
`parser.py` (text extraction), `core.py` (normalization/grouping), and
`ai_triage.py` (verdicts). The implementation lives in `app/wazuh_intel.py`.

## 1. Design constraints

- **Airgapped and local-first.** No cloud calls, no CDN, no telemetry. The only
  optional model is a loopback Ollama endpoint; deterministic rules always work.
- **Evidence before verdict.** Every classification carries signals and a
  reason. A high severity or a known-bad IP can raise priority, but it cannot
  invent a true-positive verdict.
- **No "safe" label.** Unknown, cached-empty, redacted, and untested states are
  named explicitly: "Belum ada cache", "Tidak ada deteksi", "Perlu ditinjau".
- **Tenant is workspace context, not authorization.** Correlation and export
  must preserve the active tenant set.
- **Raw telemetry stays local.** `full_log`, `raw`, and `data` never enter a
  prompt, localStorage, analytics, or an external URL.

## 2. Dataset evidence used to shape the architecture

The design was calibrated against four local datasets. No dataset rows are
copied into the repository or the database.

| Dataset | Rows | What it establishes | How Arbiter uses it |
|---|---:|---|---|
| `wazuh_formatted_alerts.json` | 738 | Binary TP/FP labels for real-shaped alerts: 239 TP, 499 FP. 466 rows (63%) are Active Response events. 451 of 466 responses embed an origin alert ID that is also present in the set. | Rule priors, nested Active Response linkage, role separation (`response` vs `indicator` vs `context`). |
| `train-00000-of-00001 (2).parquet` | 606 | Event → case title, case description, and recommended activity. 309/297 balanced quality labels. | Case-editor copy structure: title, narrative, recommended action, evidence references. |
| `train-00000-of-00001 (3).parquet` | 10,000 | Synthetic triage labels: 6,000 IGNORE, 3,000 MONITOR, 1,000 ESCALATE, plus context fields (`is_known_bad_ip`, `src_ip_type`, `is_business_hours`, `first_occurrence`). | Priority calibration only. Labels are severity-threshold driven (ESCALATE = level ≥12 + known-bad; IGNORE = low level + not known-bad); they are **not** semantic ground truth. |
| `train-00000-of-00001.parquet` + `(1)` | 12,210 | Wazuh documentation Q&A. | Future offline rule/knowledge lookup; not required for the deterministic baseline. |

### Key finding: Active Response is evidence, not a separate attack

In the labelled set, rules **651** ("Host Blocked by firewall-drop Active
Response") and **652** ("Host Unblocked…") are always false positives as
standalone alerts. That does **not** mean the underlying event is benign. The
response embeds the true origin rule (for example **5710**, invalid SSH user)
inside:

```
data.parameters.alert
```

or inside a JSON payload appended to `full_log`:

```
active-response/bin/firewall-drop: {"command":"add","parameters":{"alert":{...}}}
```

Treating 651/652 as independent queue rows inflates the queue by ~63% and hides
the attack. Arbiter therefore:

1. extracts the nested origin alert;
2. classifies the response as `role=response`, `verdict=fp` (standalone);
3. exposes `origin_verdict` (usually `tp`);
4. attaches the response to the origin group in `correlate_alerts()`.

### Key finding: severity alone is not a verdict

The synthetic dataset maps severity to priority: level ≤5 → IGNORE, 6–10 →
MONITOR, ≥12 + known-bad → ESCALATE. It does not learn rule semantics. Arbiter
uses those thresholds only for **priority**, never for TP/FP. A level-14
unmapped custom rule remains `needs_review`.

## 3. End-to-end pipeline

```
Wazuh JSON / Indexer
        │
        ▼
┌──────────────────────┐
│ 1. Read & parse      │  parser.py
│  - ES hits / arrays  │  - access, syslog, sshd, PAM, sudo,
│  - JSONL / paste     │    audit, AppArmor, nginx, JSON
│  - active-response   │  - control-byte salvage
└─────────┬────────────┘
          ▼
┌──────────────────────┐
│ 2. Normalize         │  core.normalize_alert()
│  - tenant, agent     │  - rule, decoder, location, MITRE, CVE
│  - source IP         │  - parsed_details + stable signature
│  - nested origin     │  - parsed_details.wazuh_intel
└─────────┬────────────┘
          ▼
┌──────────────────────┐
│ 3. Classify          │  wazuh_intel.classify_alert()
│  - verdict / role    │  - tp / fp / needs_review
│  - priority          │  - indicator / response / context / unknown
│  - confidence        │  - signals + reason (auditable)
└─────────┬────────────┘
          ▼
┌──────────────────────┐
│ 4. Correlate         │  wazuh_intel.correlate_alerts()
│  - origin ↔ response │  - response attached to parent
│  - host + rule       │  - source IPs as facets, not keys
│  - ordered chain     │  - build_attack_chains() for cross-rule
└─────────┬────────────┘
          ▼
┌──────────────────────┐
│ 5. Triage & cases    │  /api/suggestions, /api/ai/triage
│  - queue filters     │  - review status, selection, export scope
│  - incident editor   │  - evidence, analysis, conclusion
└─────────┬────────────┘
          ▼
┌──────────────────────┐
│ 6. Deliverables      │  exports.py
│  - HTML / DOCX       │  - scoped, redaction-aware
│  - XLSX / TSV / MD   │  - never silent partial export
└──────────────────────┘
```

## 4. Data contracts

### 4.1 Raw Wazuh alert (minimum)

| Field | Use |
|---|---|
| `timestamp` / `@timestamp` | Chronology, time filters, chain order. |
| `id` | Wazuh alert identity; used to link Active Response to origin. |
| `rule.id`, `rule.level`, `rule.description`, `rule.groups` | Classification priors and queue severity. |
| `rule.mitre.id/tactic/technique` | Context signal and investigation pivot. |
| `agent.id/name/ip`, `agent.labels.tenant` | Target identity and tenant scope. |
| `data.srcip`, `data.srcport`, `data.srcuser`, `data.dstuser` | Source/actor facets. |
| `decoder.name`, `predecoder.*`, `location` | Parser/source routing and evidence. |
| `full_log` | Raw evidence; never sent to an external model. |
| `data.parameters.alert` | Nested origin alert for Active Response. |
| `data.vulnerability` | CVE, package, severity, status, solved state. |

### 4.2 Normalized alert

`core.normalize_alert()` produces one row with:

- identity: `alert_id`, `wazuh_id`, `tenant`, `timestamp`
- target: `agent_name`, `agent_ip`, `location`
- rule: `rule_id`, `rule_level`, `description`, `rule_groups`, `decoder`
- network/actor: `source_ip`, `parsed_details`, `data`
- context: `mitre_ids`, `cve`
- evidence: `full_log`, `raw`, `previous_output`
- grouping: `log_signature`, `hit_count`, `first_seen`, `last_seen`
- workflow: `is_reviewed`, `reviewer_notes`
- intelligence: `parsed_details.wazuh_intel` (verdict, role, priority,
  confidence, signals, origin, origin_verdict)

`parsed_details.wazuh_intel` is additive JSONB metadata. No schema migration is
required for the baseline; the existing `parsed_details` column stores it.

### 4.3 Classification result

```json
{
  "verdict": "fp",
  "role": "response",
  "family": "active_response",
  "priority": "low",
  "confidence": 0.99,
  "reason": "Active Response 'add' adalah tindakan containment turunan…",
  "signals": [
    {"code": "rule_profile", "label": "Profil rule", "value": "Rule 651", "kind": "rule"},
    {"code": "origin_link", "label": "Alert asal", "value": "origin-alert-5710", "kind": "correlation"}
  ],
  "source": "curated_rule",
  "origin": {"alert_id": "…", "rule_id": "5710", "source_ip": "…"},
  "origin_verdict": "tp",
  "known_bad_source": false
}
```

Rules:

- `verdict` is exactly `tp`, `fp`, or `needs_review`.
- `role` separates a primary `indicator`, a containment `response`, a
  `context` event (vulnerability lifecycle, routine admin), and `unknown`.
- `priority` is urgency (`low`…`critical`), not a verdict.
- `confidence` is evidence strength for the classification, not a probability
  guarantee.
- `signals` are the UI's "why this verdict" list. No signal, no claim.

## 5. Classification policy

### 5.1 Curated rule profiles (explicit, not trained)

| Rule(s) | Family | Role | Verdict | Why |
|---|---|---|---|---|
| 651, 652 | `active_response` | `response` | `fp` | Containment/rollback side effect; link to origin. |
| 5710 | `credential_access` | `indicator` | `tp` | Invalid/non-existent SSH user = credential guessing. |
| 31101 | `web_probe` | `indicator` | `tp` | Repeated 400/404 web errors = probing/malformed requests. |
| 2833 | `persistence` | `indicator` | `tp` | Root crontab change = persistence/execution path. |
| 5762, 5740 | `recon` | `indicator` | `tp` | SSH reset / kex failure before auth = scan signal. |
| 31303 | `tls_probe` | `indicator` | `tp` | Nginx critical TLS handshake failure = probing/misbehaving client. |
| 23502 | `vulnerability_lifecycle` | `context` | `fp` | "CVE solved" is a status change, not an attack. |
| 591 | `maintenance` | `context` | `fp` | Log rotation is routine. |
| 5501, 5502, 5715, 5402 | `expected_admin` | `context` | `fp` | Valid session/sudo; correlate with prior failures. |
| 11 | `baseline_anomaly` | `context` | `needs_review` | Volume anomaly; cause is unknown. |

Unknown rules fall back to group/keyword matching. If nothing matches, the
result is `needs_review` with low confidence. A high `rule.level` never upgrades
an unknown rule to `tp`.

### 5.2 Context signals

- **Known-bad source** (`abuse_score ≥ 75`, `vt_malicious > 0`, or
  `is_known_bad_ip`) raises priority and confidence; it does not flip an
  unknown rule to `tp`.
- **Repetition** (`hit_count ≥ 20`) adds a repetition signal and a small
  confidence increase.
- **MITRE IDs** are shown as context, not proof.
- **Business hours / source-IP type / first occurrence** are displayed as
  context. The synthetic dataset shows they do not change its labels; Arbiter
  must not pretend they are causal.
- **Tenant** scopes query and export; it is not a substitute for authorization.

### 5.3 Wording policy

| State | Allowed copy | Forbidden copy |
|---|---|---|
| No intel cache | "Belum ada cache" | "Clean", "Aman" |
| No detections | "Tidak ada deteksi" | "Safe", "Bersih" |
| Redacted export | "Versi tersamarkan—tinjau sebelum dibagikan" | "Aman untuk dibagikan" |
| Unknown rule | "Perlu ditinjau" | "False positive" without evidence |
| Derived response | "Respons aktif tertaut" | Counting it as a separate attack |

## 6. Correlation policy

### 6.1 Response linkage

`correlate_alerts()` builds a map from each response's embedded
`origin.alert_id` to the primary alert. A response is removed from independent
grouping and attached to the origin group. If the origin is outside the current
scope, the response remains a standalone group so evidence is never silently
lost.

### 6.2 Canonical group identity

1. `(agent_name, rule_id)` when both are usable.
2. `log_signature` when the host/rule identity is unavailable.
3. `(source_ip, rule_id)` as a last resort.
4. The alert itself.

Source IP is a **facet** (`source_ips`), not a grouping key. An attacker rotating
IPs against the same host/rule remains one group. This is covered by a
regression test.

### 6.3 Ordered chain

Each canonical group carries `chain`: consecutive stages derived from the
classification family:

```
Pengintaian → Akses kredensial → Aktivitas administratif → Persistensi → Dampak
```

`build_attack_chains()` additionally groups by `(agent_name, source_ip)` across
rules to explain multi-rule sequences such as:

```
5710 invalid SSH user → 5715 successful login → 5402 sudo root → 2833 crontab change
```

The chain is explanatory evidence, not a verdict. A context event (`5715`,
`5402`) inside a chain does not become an attack by itself.

### 6.4 Correlation confidence

- Base: highest confidence among primary alerts.
- `+0.05` when at least one response event is linked.
- Capped at `0.99`.
- Never reaches `1.0`; analysts always review.

## 7. API surfaces

| Endpoint | Contract |
|---|---|
| `GET /api/suggestions` | Returns canonical correlation groups (`alert_ids`, `primary_alert_ids`, `response_alert_ids`, `source_ips`, `chain`, `verdict`, `confidence`, `reason`). |
| `POST /api/ai/triage` | Deterministic clusters + optional loopback model verdicts; cluster payload never includes raw logs or alert IDs. |
| `POST /api/ai/triage/save` | Persists groups as editable incident cases with `verdict` and source `ai`. |
| `GET /api/alerts` | Queue projection; `parsed_details` is available to the detail view, not to export by default. |
| `GET /api/alerts/{id}` | Inspector detail: raw log, nested origin, classification metadata. |

`safe_alerts()` strips `raw`, `data`, `full_log`, `parsed_details`, and
`duplicate_instances` before any model-facing or client-facing triage payload.

## 8. Storage and migration

Baseline needs **no migration**:

- `wazuh.alerts.parsed_details` JSONB stores `wazuh_intel`.
- `wazuh.analysis_groups.verdict` already supports `tp` / `fp` /
  `needs_review`.
- `wazuh.alert_group_members` stores evidence membership.

Optional future columns (only if query performance requires them):

- `origin_alert_id`, `origin_rule_id` as generated columns for indexing.
- `verdict`, `confidence`, `priority` as top-level columns.
- `response_alert_ids` as a derived view, not a source of truth.

Do not add a new table for every dataset concept. The nested JSON is the
canonical evidence; projections are derived.

## 9. Failure modes and handling

| Failure | Behavior |
|---|---|
| Malformed `full_log` JSON | Keep raw text, no origin; `needs_review` if unmapped. |
| Active Response without embedded origin | Show as standalone response; never invent a parent. |
| Missing `rule.description` | Use "Wazuh Alert"; classification falls back to groups/level. |
| Unknown rule at level 14 | `needs_review`, `priority=critical`; do not auto-escalate to TP. |
| Ollama unavailable | Deterministic classification/correlation; label mode `local_rules_fallback`. |
| Tenant scope mismatch | Reject mutation; never silently widen scope. |
| Export too large | Explicit 413; never partial file. |
| Stale inspector response | Detail version guard discards it. |

## 10. Acceptance tests

- `tests.test_wazuh_intel`: nested Active Response extraction, curated priors,
  unknown-rule behavior, known-bad context, response linkage, rotating IPs,
  chain ordering, normalize integration.
- `tests.test_ai_triage`: clustering, sanitized model payload, fallback mode.
- `tests.test_ui_api`: suggestions respect active scope; alert detail tenant
  guard.
- `tests.test_dedup`: stable signatures and default review state.
- `tests.test_privacy`: no raw telemetry leakage.
- `tests.test_settings`: loopback-only AI endpoint and credential storage.

Run:

```bash
.venv/bin/python -m unittest tests.test_wazuh_intel tests.test_ai_triage \
  tests.test_parser tests.test_exports tests.test_privacy tests.test_dedup \
  tests.test_ui_api tests.test_ui_safety tests.test_settings -q
```

## 11. Non-goals

- No model training on production telemetry.
- No automatic "false positive" dismissal without evidence or analyst action.
- No cross-tenant correlation.
- No replacement of Wazuh's own rules; Arbiter explains and organizes them.
- No claim that redaction, a 0% AbuseIPDB score, or an empty cache means safe.
