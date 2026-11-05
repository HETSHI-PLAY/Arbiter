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

When investigating high-volume attacks (credential stuffing, SSH brute-force, web vulnerability probing), raw Wazuh Elasticsearch JSON exports often flood analysts with tens of thousands of repetitive log lines. Arbiter normalizes multi-format logs, deduplicates recurring attacks using stable hashing, enriches source IPs with local Threat Intelligence, and produces **Google Docs**, **Word (.docx)**, and **Excel (.xlsx)** deliverables in one click.

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

### 3. Signature-Based Deduplication
- Computes a stable SHA-256 signature across `(tenant, agent, rule_id, srcip, normalized_log)`.
- Condenses thousands of repetitive scans into a single triage row with `Hit Count` and `first_seen → last_seen` time range.

### 4. Enterprise Multi-Tenant Architecture
- Automatic tenant extraction from `agent.labels.tenant`.
- Workspace tenant selector with real-time population from database.
- Isolate investigations per tenant or triage across all tenants simultaneously.

### 5. Modular Destination UI

Arbiter uses a **Quiet Evidence Desk** design with focused destinations instead of a monolithic single-page layout:

| Destination | Route | Purpose |
|-------------|-------|---------|
| **Triage** | `#/triage` | Alert queue with sidebar inspector. Default home. |
| **Insiden** | `#/incidents/:id` | Case editor: evidence grouping, analysis, conclusions, recommendations |
| **Impor** | `#/imports` | Paste or upload new Wazuh JSON exports |
| **Laporan** | `#/reports` | Scoped export (CSV, JSON, clipboard HTML, .docx, .xlsx) |
| **Pengaturan** | `#/settings` | Wazuh Indexer connection, realtime monitor, sidebar preference |

### 6. Review & Triage Workflow
- Flag alerts as Pending or Reviewed, individually or in batch.
- **Shift + Click** range selection for fast bulk operations.
- Selection survives page re-renders and filter changes (Set-based state, not DOM checkboxes).
- Tenant-scoped selection prevents cross-tenant contamination.
- Quick filter presets: 403 Forbidden, 404 Probes, Repeating, Bot traffic, Curl requests, Non-HTTP.

### 7. Incident Case Management
- Group selected alerts into named incident cases with category, severity, analysis, conclusion, and recommendation.
- Add or remove evidence (alert group members) from the inspector or case editor.
- Tenant-scoped case policy: a scoped case must have evidence in that tenant.

### 8. Local Threat Intelligence
- Zero external API exposure: joins `source_ip` with local PostgreSQL intelligence tables (`ip_intel_cache`).
- AbuseIPDB confidence score, VirusTotal detection count, ISP, and country code.
- Direct pivot link to local IP intelligence dashboard.

### 9. Privacy-First Redactor
- **Zero-Cloud Log Transmission**: Raw logs, database records, and credentials never leave your local environment.
- **One-Click Sanitizer**: Deterministic regex redactor masks private IPs, public IPs, passwords/tokens, and emails.
- Explicit disclaimer: redaction is not a guarantee of safe external sharing.

### 10. Official Deliverables (5 Export Paths)
- **📋 Clipboard HTML** — formatted table for Google Docs paste.
- **📄 Word (.docx)** — formal landscape document with styled tables.
- **📊 Excel (.xlsx)** — multi-column spreadsheet with Threat Intel metrics.
- **📋 TSV** — tab-separated values for spreadsheet software.
- **📝 Markdown** — executive incident summary.

---

## 🛠️ Architecture & Tech Stack

```
app/
├── index.html                      # Modular shell (64 lines)
├── main.py                         # FastAPI backend + REST API
├── query.py                        # SQL query builder with filter presets
├── database.py                     # PostgreSQL layer + schema migration
├── parser.py                       # Multi-format log dissector
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
│   └── js/                         # 22 ES modules (feature-based)
│       ├── app.js                  # Shell controller + hash router integration
│       ├── router.js               # Hash router (#/triage, #/incidents/:id, …)
│       ├── api/client.js           # Same-origin fetch wrapper
│       ├── state/                  # Scope, selection, navigation, triage, workspace
│       ├── ui/primitives.js        # Shared UI utilities
│       └── features/               # triage/, incidents/, imports/, reports/
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

1. **Navigate to Impor** (`#/imports`) — paste your raw Wazuh / Elasticsearch JSON or upload `.json`/`.txt` files. Alerts are parsed, deduplicated, and enriched.

2. **Select Tenant** — use the workspace selector in the utility bar to isolate by tenant (e.g. `wicida`, `sgu`) or view all tenants.

3. **Triage** (`#/triage`) — filter with presets (403, 404 Probes, Bot, Curl, Repeating), sort by severity/time/hits. Click any alert to open the sidebar inspector with full details and IP intel.

4. **Group into Incident** — Shift+Click to select alerts, click "Buat insiden" on the selection toolbar. Add title, category, severity, analysis, conclusion, and recommendation.

5. **Export** (`#/reports`) — choose scope (current filter or selected alerts), pick format (Clipboard HTML, .docx, .xlsx, TSV, Markdown), and export.

---

## 🧪 Testing & Quality Assurance

```bash
# Frontend tests (125 tests)
node --test tests/frontend/*.test.mjs

# Backend tests — safe isolated suites (92 tests)
.venv/bin/python -m unittest tests.test_parser tests.test_exports \
  tests.test_privacy tests.test_dedup tests.test_ui_api tests.test_ui_safety tests.test_settings -q

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
