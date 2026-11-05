# AGENTS.md — Arbiter Project Context for AI Agents

This file is the single source of truth for any AI coding agent working on Arbiter.
Read this before writing code, running tests, or making architectural decisions.

## What is Arbiter

Arbiter is an airgapped SOC investigation desk for normalized Wazuh SIEM telemetry.
Analysts triage deduplicated alerts, inspect source intelligence, group evidence into
incident cases, author analysis/conclusions/recommendations, and produce scoped
document deliverables (Google Docs HTML, Word .docx, Excel .xlsx, TSV, Markdown).

## ⚡ Slash Command: /work (Autonomous Deep Engineering Mode)

When user prompt includes `/work`:
- **Full SOP Compliance:** Strictly follow `docs/AUTONOMOUS_ENGINEERING_SOP.md`.
- **3–5 Relevant Skills:** Actively load and enforce at least 3 to 5 relevant skills (`writing-plans`, `subagent-driven-development`, `test-driven-development`, `systematic-debugging`, `requesting-code-review`).
- **Skill Sourcing:** If no matching skill is installed locally, search the catalog/hub or structure a procedural skill via `skill_manage` before executing. Never guess blindly.
- **Auto todo_list:** Initialize structured task tracking at turn 1.
- **Trace Every Seam & Negative Testing:** Enforce 8 layers from UI DOM to DB, eliminate decorative stubs, and assert negative exclusion.
- Without `/work`, effort is proportional to the prompt without multi-agent overhead.

## Stack — do not migrate

| Layer | Technology | Notes |
|-------|-----------|-------|
| Backend | **FastAPI** (Python 3.11+) + **Uvicorn** | Single `app/main.py` entry, modular `app/query.py` |
| Database | **PostgreSQL 16** via `psycopg` | Schema in `init-db.sql` and `app/database.py` |
| Frontend | **Vanilla JavaScript ES modules** + **native CSS** | No React, Vue, Angular, Tailwind. Pure DOM manipulation. |
| Typography | IBM Plex Sans / Mono (local woff2, OFL) | In `app/static/fonts/` |
| Design tokens | CSS custom properties in `app/static/styles/tokens.css` | Exported from `docs/ui-ux-redesign/DESIGN.md` |
| Exports | python-docx, openpyxl | In `app/exports.py` |
| Containerization | Docker + docker-compose | `network_mode: host` connects to host PostgreSQL |

## Architecture (frontend)

```
app/
├── index.html                      # 64-line modular shell, semantic landmarks
├── static/
│   ├── fonts/                      # IBM Plex (local, OFL license)
│   ├── styles/
│   │   ├── tokens.css              # Design token CSS custom properties
│   │   ├── base.css                # Reset, typography, form controls
│   │   ├── shell.css               # Sidebar, workspace grid, responsive
│   │   └── components.css          # All component styles
│   └── js/
│       ├── app.js                  # Shell controller, router, tenant switching, health probe
│       ├── router.js               # Hash router: #/triage, #/incidents/:id, #/imports, #/reports
│       ├── api/client.js           # Same-origin fetch wrapper, timeout, error extraction
│       ├── state/
│       │   ├── scope.js            # Query normalization, export scope, pagination safety
│       │   ├── selection.js        # Tenant-scoped Set-based selection store
│       │   ├── triage.js           # Queue scroll memory, detail version guard
│       │   ├── navigation.js       # Cross-page query memory per destination
│       │   ├── sidebar.js          # Desktop sidebar collapse preference
│       │   └── workspace.js        # Health probe state
│       ├── ui/primitives.js        # esc(), icon(), severity(), formatTime(), emptyState()
│       └── features/
│           ├── triage/             # model.js (intelSummary, renderQueue), view.js
│           ├── incidents/          # model.js, render.js, state.js, view.js, workspace.js
│           ├── imports/            # model.js, render.js, view.js
│           ├── reports/            # model.js, render.js, view.js
│           └── settings/           # model.js, view.js (Wazuh Indexer + realtime)
```

## Four destinations (not a monolithic page)

| Route | Purpose |
|-------|---------|
| `#/triage` | Alert queue with sidebar inspector. Default home. |
| `#/incidents/:id` | Case editor: evidence grouping, analysis, conclusion, recommendation |
| `#/imports` | Paste or upload new Wazuh JSON exports |
| `#/reports` | Scoped export to CSV, JSON, clipboard HTML, .docx, .xlsx |
| `#/settings` | Wazuh Indexer connection, realtime monitor, sidebar preference |

There is **no overview dashboard**. Triage is the entry point.

## Design direction: Quiet Evidence Desk

- Calm functional density; data visible immediately, decoration absent.
- Forensic neutral palette (`#0f1419` → `#f7f9fc`) with signal colors per severity level.
- Full design spec: `docs/ui-ux-redesign/DESIGN.md` (lintable with `@google/design.md`).

## Key policies

1. **Tenant scoping**: Tenant is workspace context, not authorization. Selection store rejects cross-tenant contamination.
2. **Empty case rejection**: A tenant-scoped case must have evidence in that tenant. "Semua tenant" scope allows empty cases.
3. **Detail version guard**: Stale inspector API responses are discarded via monotonic counter.
4. **Export scope consistency**: `scopeParams()` strips pagination and enforces same filters for all export formats.
5. **Intel labels**: Use "Belum ada cache" / "Tidak ada deteksi" / scored value. Never "Clean" or "Aman".
6. **Redaction disclaimer**: "Versi tersamarkan—tinjau sebelum dibagikan", not "Aman".
7. **Credentials at rest**: Wazuh Indexer password and the Remote database URI are encrypted locally (`app/secure_store.py`). The key comes from `ARBITER_SECRET_KEY` / `ARBITER_SECRET_KEY_FILE` or an auto-generated 0600 file outside the repo. Never commit a key or plaintext credential.

## Privacy — STRICT

- **NEVER** read `.env`, production database, real alert records, raw logs, or live UI on port 8000.
- **NEVER** run `tests.test_api` against the active database — it expects live PostgreSQL with real data.
- All development and QA uses synthetic fixtures inside the isolated test suites only.
- Use isolated test suites: `tests.test_ui_api`, `tests.test_ui_safety`, `tests.test_parser`, `tests.test_exports`, `tests.test_privacy`, `tests.test_dedup`, `tests.test_settings`.

## Running tests

```bash
# Frontend (125 tests)
node --test tests/frontend/*.test.mjs

# Backend - SAFE isolated suites only (92 tests)
.venv/bin/python -m unittest tests.test_parser tests.test_exports tests.test_privacy tests.test_dedup tests.test_ui_api tests.test_ui_safety tests.test_settings -q

# Design system lint
npx -y @google/design.md@0.4.0 lint docs/ui-ux-redesign/DESIGN.md
```

## Running production

```bash
# Docker (connects to host PostgreSQL via network_mode: host)
docker compose up -d --build
# → http://localhost:8000

# Or standalone with bundled PostgreSQL
docker compose --profile standalone up -d --build

# Or local Python
source .venv/bin/activate
./start.sh
```

## Graph

This project has a knowledge graph at `graphify-out/`. Run `graphify query "<question>"` before grep/search for codebase questions. After modifying code, run `graphify update .` to keep the graph current.

## What NOT to do

- Do not introduce React, Vue, Angular, Svelte, or Tailwind CSS.
- Do not add CDN-hosted fonts, analytics, or external fetches.
- Do not access production data or the `.env` file.
- Do not run `tests.test_api` — it hits the live database.
- Do not create overview/dashboard pages — the four-destination architecture is intentional.
- Do not label any security state as "Clean", "Aman", or "Safe".
