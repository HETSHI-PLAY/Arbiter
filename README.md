# Arbiter

<p align="center">
  <strong>Unified Wazuh SIEM Telemetry Normalizer, Attack Chronology Triage &amp; Incident Investigation Platform</strong>
</p>

<p align="center">
  <img src="https://img.shields.io/badge/Python-3.11+-blue?style=flat-square&logo=python" alt="Python">
  <img src="https://img.shields.io/badge/FastAPI-Production-009688?style=flat-square&logo=fastapi" alt="FastAPI">
  <img src="https://img.shields.io/badge/PostgreSQL-16-336791?style=flat-square&logo=postgresql" alt="PostgreSQL">
  <img src="https://img.shields.io/badge/Docker-Ready-2496ED?style=flat-square&logo=docker" alt="Docker">
  <img src="https://img.shields.io/badge/Privacy-Airgapped%20Local-emerald?style=flat-square" alt="Privacy">
</p>

---

## 🎯 Overview

**Arbiter** is an open-source, airgapped SOC investigation desk built to bridge the gap between raw **Wazuh SIEM alerts** and **executive incident reporting**.

When investigating high-volume attacks (credential stuffing, SSH brute-force, web vulnerability probing), raw Wazuh Elasticsearch JSON exports often flood analysts with tens of thousands of repetitive log lines. Arbiter normalizes multi-format logs, **reads nested Wazuh structures**, **classifies each event with auditable local rules**, **links Active Response events back to their origin alert**, deduplicates recurring attacks using stable hashing, enriches source IPs with local Threat Intelligence, and produces **Google Docs**, **Word (.docx)**, and **Excel (.xlsx)** deliverables in one click.

The architecture is documented in [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md): data contracts, classification policy, correlation rules, storage, failure modes, and dataset-derived calibration.

---

## ⚡ Key Capabilities

### 1. Resilient Multi-Format Ingestion
- **Any Ingest Format**: Accepts Elasticsearch `hits.hits[]` exports, raw JSON arrays, JSON Lines (`.jsonl`), or single alert objects.
- **Direct Paste & File Upload**: Ingest via file upload (`.json` / `.txt`) or instant paste with real-time JSON validation.
- **Control Byte Salvage**: Built-in parser (`strict=False`) safely decodes raw logs containing unescaped control characters without mutating or dropping valid events.
- **Duplicate Wazuh ID Safeguard**: Re-ingesting identical alerts is automatically identified and ignored to prevent data corruption.

### 2. High-Precision Log Dissector (No False Fields)
- Specialized regex engines for:
  - **Web Access Logs**: Apache / Nginx combined logs (Method, Path, Query string, Status code, Referer, User-Agent).
  - **Syslog & Auth Logs**: OpenSSH (`sshd`), PAM authentication failures, session lifecycle.
  - **Linux Kernel & Audit**: AppArmor profiles, syscall audit events.
  - **Embedded HTTP & JSON Payloads**: Auto-detects URLs, methods, and status codes inside generic syslog lines.
- **Nested Wazuh readers**: extracts the origin alert from Active Response (`data.parameters.alert` or JSON in `full_log`) and reads Vulnerability Detector metadata (`data.vulnerability`).
- **Role separation**: a containment event (rule 651/652) is `role=response`, not an independent attack; routine admin/vulnerability events are `role=context`.

### 3. Signature-Based Deduplication & Causal Correlation
- Computes a stable SHA-256 signature across `(tenant, agent, rule_id, srcip, normalized_log)`.
- Condenses thousands of repetitive scans into a single triage row with `Hit Count` and `first_seen → last_seen` time range.
- **Response linkage**: Active Response alerts are attached to the alert that triggered them, so 651/652 do not inflate the queue.
- **Host + rule correlation**: rotating source IPs collapse into one target group; source IPs remain facets. Ordered chains expose multi-rule sequences such as invalid SSH user → successful login → sudo → crontab change.

### 4. Enterprise Multi-Tenant Architecture
- Automatic tenant extraction from `agent.labels.tenant`.
- Workspace tenant selector with real-time population from database.
- Isolate investigations per tenant or triage across all tenants simultaneously.

### 5. Modular Destination UI

Arbiter uses a **Quiet Evidence Desk** design with focused destinations instead of a monolithic single-page layout:

| Destination | Route | Purpose |
|-------------|-------|---------|
| **Triage** | `#/triage` | Alert queue with sidebar inspector, scoped `alert_ids` filtering, and inline log viewer. Default home. |
| **AI Triage** | `#/ai-triage` | Local AI (Ollama) & deterministic heuristic TP/FP triage, tenant/severity/grouping controls, persistent state, and daily 17:00 WIB case windowing |
| **Realtime** | `#/realtime` | Live Wazuh Indexer alert counter and on-demand / scheduled pull into active database |
| **Statistik** | `#/stats` | Multi-dimensional pivot charts, Benign/Malicious Spotter, and secondary drill-down |
| **Insiden** | `#/incidents/:id` | Case editor: evidence grouping, analysis, conclusions, recommendations |
| **Impor** | `#/imports` | Paste or upload new Wazuh JSON exports |
| **Laporan** | `#/reports` | Scoped export (CSV, JSON, clipboard HTML, .docx, .xlsx) |
| **Database** | `#/database` | Local / Remote PostgreSQL profile switching and safe preview-gated purge maintenance |
| **Pengaturan** | `#/settings` | Wazuh Indexer connection, local AI (Ollama) model config, realtime monitor, sidebar preference |

### 6. Local AI Triage & Persistent Daily Case Grouping (`#/ai-triage`)
- **Dual-Engine Classification**: Uses a local loopback Ollama model (`http://127.0.0.1:11434`) when enabled, or automatically falls back to deterministic local rules (`local_rules` / `local_rules_fallback`) with explicit mode badges.
- **Granular Severity & Scope Controls**:
  - **Tenant Filter**: Scope AI Triage to a specific tenant or across all tenants (`Semua tenant`).
  - **Exact Severity Bands**: `Low (rule.level 0–6)`, `Medium (rule.level 7–11)`, `High (rule.level 12–14)`, and `Critical (rule.level 15+)`.
  - **Custom Alert Limit**: User-defined maximum alerts (`1`–`5000`).
- **Flexible Grouping with Strict Tenant Isolation**:
  - **Deskripsi Rule (`rule_description`)**: Groups alerts sharing the same rule description within a single tenant (even across multiple agents/hosts in that tenant).
  - **Host / Agent + Rule (`host_rule`)**: Groups alerts by target agent + rule ID within a single tenant.
  - **Single-Tenant Guardrail**: A single triage or incident case group is strictly forbidden from combining 2 or more tenants.
- **Persistent Results & 17:00 WIB (`UTC+7`) Daily Window Cutoff**:
  - Triage results are automatically saved in `wazuh.app_settings` (`GET /api/ai/triage`) and restored when reopening `#/ai-triage`.
  - Newly ingested alerts matching an existing group are automatically merged into that group (and its linked open AI incident case) if they occur before the daily **17:00 WIB** cutoff; alerts after **17:00 WIB** roll over into a new daily window group.
- **Exploit Payload & Scanner True-Positive Lock (`lock_tp`)**:
  - Deep inspection of URL-decoded paths, queries, User-Agents, and raw logs detects Path Traversal / LFI (`.%2e`, `%2e%2e`, `../`, `/cgi-bin/`, `/etc/hosts`, `/etc/passwd`), exploit scanners (`Lkx-Apache2449TraversalPlugin`, `leakix.net`, `nuclei`, `sqlmap`, `nikto`, `nmap`, `zgrab`), and RCE/SQLi/JNDI payloads.
  - Alerts carrying verified exploit indicators are locked as **True Positive (`tp`)** even when the HTTP status is `400`/`403`/`404` or when a local LLM attempts to downgrade the cluster.
- **Focused Triage Drill-Down**: Clicking **Buka di Triage** on any AI Triage group opens `#/triage` filtered exclusively to that group's member `alert_ids` while opening the first alert in the detail inspector.

### 7. Review & Triage Workflow
- Flag alerts as Pending or Reviewed, individually or in batch.
- **Shift + Click** range selection for fast bulk operations.
- Selection survives page re-renders and filter changes (Set-based state, not DOM checkboxes).
- Tenant-scoped selection prevents cross-tenant contamination.
- Quick filter presets: 403 Forbidden, 404 Probes, Repeating, Bot traffic, Curl requests, Non-HTTP, plus `Alert terkait (N)` group filter pills.

### 8. Incident Case Management
- Group selected alerts into named incident cases with category, severity, analysis, conclusion, and recommendation, or save AI Triage groups directly to Incidents in one click (**Simpan ke Insiden**).
- Add or remove evidence (alert group members) from the inspector or case editor.
- Tenant-scoped case policy: a scoped case must have evidence in that tenant.

### 9. Local Threat Intelligence
- Zero external API exposure: joins `source_ip` with local PostgreSQL intelligence tables (`ip_intel_cache`).
- AbuseIPDB confidence score, VirusTotal detection count, ISP, and country code.
- Direct pivot link to local IP intelligence dashboard.

### 10. Privacy-First Redactor
- **Zero-Cloud Log Transmission**: Raw logs, database records, and credentials never leave your local environment.
- **One-Click Sanitizer**: Deterministic regex redactor masks private IPs, public IPs, passwords/tokens, and emails.
- Explicit disclaimer: redaction is not a guarantee of safe external sharing.

### 11. Official Deliverables (5 Export Paths)
- **📋 Clipboard HTML** — formatted table for Google Docs paste.
- **📄 Word (.docx)** — formal landscape document with styled tables.
- **📊 Excel (.xlsx)** — multi-column spreadsheet with Threat Intel metrics.
- **📋 TSV** — tab-separated values for spreadsheet software.
- **📝 Markdown** — executive incident summary.

---

## 🧠 Wazuh Read → Classify → Correlate

Arbiter's deterministic intelligence layer lives in `app/wazuh_intel.py`. It is
local, rule-based, and auditable: every verdict carries the signals that
produced it.

| Stage | What happens | Output |
|---|---|---|
| **Read** | Parse ES hits, JSONL, paste, Active Response JSON, Vulnerability Detector metadata. | Normalized alert + nested origin. |
| **Classify** | Rule profile + groups + payload/UA exploit indicators + severity + context. Unknown rules stay `needs_review`. | `verdict`, `role`, `priority`, `confidence`, `signals`, `reason`. |
| **Correlate & AI Triage** | Link responses to origins; cluster by rule description or host + rule per tenant; enforce 17:00 WIB daily window; optional local Ollama review with `lock_tp` guardrail. | Canonical single-tenant groups + `chain` + persistent AI triage state. |
| **Triage** | Review status, `alert_ids` group drill-down, filters, selection, incident cases. | Scoped evidence and case narrative. |
| **Deliver** | HTML, DOCX, XLSX, TSV, Markdown. | Bounded, scoped, redaction-aware output. |

### Verdict semantics that avoid false certainty

- `tp` — a real suspicious activity **according to explicit rule/context evidence**.
- `fp` — routine, expected, or derived noise (for example a log rotation or an Active Response containment event).
- `needs_review` — insufficient evidence; this is the default for unmapped rules.
- `role=response` means the event is **derived** from another alert. It is `fp`
  as a standalone alert but carries `origin_verdict` and is attached to the
  origin group.
- A known-bad IP or high severity raises **priority**, never invents a verdict.
- No state is ever labelled "Clean", "Aman", or "Safe".

### Dataset calibration and limits

The design was validated against 738 labelled alerts (239 TP / 499 FP), 606
event-to-case examples, and 10,000 synthetic triage rows. Two findings changed
the architecture:

1. **63% of the labelled alerts are Active Response events (rules 651/652).**
   Treating them as independent attacks inflates the queue and hides the origin.
   Arbiter now extracts and links the embedded origin alert.
2. **The synthetic triage labels are severity-threshold driven** (IGNORE ≤5,
   MONITOR 6–10, ESCALATE ≥12 + known-bad). They calibrate priority, not
   semantics. Arbiter therefore keeps semantic rule profiles explicit and sends
   unknown high-severity rules to `needs_review`.

See [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md) for the full data contracts,
classification policy, correlation rules, and failure modes.

---

## 🛠️ Architecture & Tech Stack

```
app/
├── index.html                      # Modular shell
├── main.py                         # FastAPI backend + REST API
├── query.py                        # SQL query builder with filter presets & malicious spotter
├── database.py                     # PostgreSQL layer, profile switching & schema migration
├── parser.py                       # Multi-format log dissector
├── wazuh_intel.py                  # Read nested alerts, payload indicators, classify, correlate
├── ai_triage.py                    # Local Ollama + heuristic triage, tenant/17:00 WIB windowing
├── settings.py                     # Wazuh Indexer, Realtime & AI configuration store
├── secure_store.py                 # Local Fernet encryption for credentials at rest
├── core.py                         # Normalization, deduplication, correlation
├── privacy.py                      # Deterministic redactor
├── exports.py                      # .docx, .xlsx, Markdown, HTML, TSV
├── static/
│   ├── fonts/                      # IBM Plex Sans/Mono (local, OFL)
│   ├── styles/                     # Token-driven CSS (4 sheets)
│   │   ├── tokens.css              # Design token custom properties
│   │   ├── base.css                # Reset, typography
│   │   ├── shell.css               # Sidebar, workspace grid, responsive
│   │   └── components.css          # All component styles
│   └── js/                         # Modular ES features
│       ├── app.js                  # Shell controller + hash router integration
│       ├── router.js               # Hash router (#/triage, #/ai-triage, #/incidents/:id, …)
│       ├── api/client.js           # Same-origin fetch wrapper
│       ├── state/                  # Scope, selection, navigation, triage, workspace
│       ├── ui/primitives.js        # Shared UI utilities
│       └── features/               # triage/, ai-triage/, realtime/, stats/, incidents/, imports/, reports/, database/, settings/
```

- **Backend**: Python 3.11+, FastAPI, Uvicorn, Psycopg 3
- **Frontend**: Vanilla JavaScript ES modules, native CSS with design tokens (IBM Plex Sans/Mono)
- **Reporting**: python-docx, openpyxl
- **Database**: PostgreSQL 16+

---

## 🚀 Setup & Getting Started

### Prerequisites
- Docker & Docker Compose **OR** Python 3.11+ with PostgreSQL.

---

### Method A: Standalone Docker Setup (Fastest for new users)

```bash
git clone https://github.com/Nothrovo/Arbiter.git
cd Arbiter
docker compose --profile standalone up -d --build
```
Open **`http://localhost:8000`**. Database and schemas are pre-configured.

---

### Method B: Host Mode (Connect to existing PostgreSQL / IP Intel)

```bash
cp .env.example .env
# Edit .env: DATABASE_URL=postgresql://user:***@127.0.0.1:5432/abuseip
docker compose up -d --build
```
Open **`http://localhost:8000`**.

---

### Method C: Local Python Setup (Without Docker)

```bash
python -m venv .venv
source .venv/bin/activate  # On Windows: .venv\Scripts\activate
pip install -r requirements.txt
cp .env.example .env
./start.sh
```

---

## 📖 SOC Analyst Quickstart Workflow

1. **Navigate to Impor** (`#/imports`) or **Realtime** (`#/realtime`) — paste/upload your raw Wazuh / Elasticsearch JSON or pull live alerts from Wazuh Indexer. Alerts are parsed, nested Active Response origins are read, classified, deduplicated, and enriched.

2. **Select Tenant** — use the workspace selector in the utility bar (or inside AI Triage) to isolate by tenant (e.g. `wicida`, `sgu`) or view all tenants.

3. **Run AI Triage** (`#/ai-triage`) — choose tenant, severity band (`Low 0–6`, `Medium 7–11`, `High 12–14`, `Critical 15+`), custom alert limit, and grouping basis (`Deskripsi Rule` or `Host / Agent + Rule`). Review True Positive / False Positive groups (saved automatically with a daily **17:00 WIB** window cutoff), click **Buka di Triage** to inspect only the alerts in that group, or click **Simpan ke Insiden** to persist groups as incident cases.

4. **Triage** (`#/triage`) — filter with presets (403, 404 Probes, Bot, Curl, Repeating) or group `alert_ids`, sort by severity/time/hits. Click any alert to open the sidebar inspector with full details, nested origin, classification signals, and IP intel.

5. **Review correlation** — click **Korelasi** to see host+rule groups, linked Active Response evidence, source-IP facets, and ordered stages. Responses stay attached to their origin instead of appearing as separate attacks.

6. **Group into Incident** — Shift+Click to select alerts, click "Buat insiden" on the selection toolbar. Add title, category, severity, analysis, conclusion, and recommendation.

7. **Export** (`#/reports`) — choose scope (current filter, incident case, or selected alerts), pick format (Clipboard HTML, .docx, .xlsx, TSV, Markdown), and export.

---

## 🧪 Testing & Quality Assurance

```bash
# Frontend tests (via npm — see package.json)
npm test
# or directly:
node --test tests/frontend/*.test.mjs

# Backend tests — safe isolated suites
.venv/bin/python -m unittest tests.test_wazuh_intel tests.test_parser \
  tests.test_exports tests.test_privacy tests.test_dedup tests.test_ui_api \
  tests.test_ui_safety tests.test_settings tests.test_stats \
  tests.test_triage_scope tests.test_database_trust tests.test_ai_triage

# Design system lint
npx -y @google/design.md@0.4.0 lint docs/ui-ux-redesign/DESIGN.md
```

---

## 🔒 Security & Privacy Notice

- **No Remote Telemetry**: Arbiter does not phone home, load tracking pixels, or transmit sensitive telemetry to third parties.
- **Airgapped Design**: Local rule-based correlation and local database queries ensure that internal IP addresses, infrastructure paths, and user data remain strictly confidential.
- **Font & Asset Locality**: All fonts and assets served locally. No CDN, no external fetches.
- **Credentials Encrypted at Rest**: Wazuh Indexer passwords and Remote database URIs are encrypted with a local key before being stored in PostgreSQL. The key is read from `ARBITER_SECRET_KEY` / `ARBITER_SECRET_KEY_FILE`, or generated as a `0600` file outside the repository. Never commit it; `.env` is gitignored.

---

## 📄 License

Distributed under the **MIT License**. See `LICENSE` for more information.
