# Graph Report - Arbiter  (2026-11-03)

## Corpus Check
- 108 files · ~91,668 words
- Verdict: corpus is large enough that graph structure adds value.
- Unclassified: 12 file(s) not represented in the graph (top: .woff2 4, .css 4, (none) 3)

## Summary
- 926 nodes · 2131 edges · 51 communities (43 shown, 8 thin omitted)
- Extraction: 96% EXTRACTED · 4% INFERRED · 0% AMBIGUOUS · INFERRED: 76 edges (avg confidence: 0.9)
- Token cost: 0 input · 0 output

## Graph Freshness
- Built from commit: `bfa3a58b`
- Run `git rev-parse HEAD` and compare to check if the graph is stale.
- Run `graphify update .` after code changes (no API cost).

## Community Hubs (Navigation)
- parser.py
- ref_node_assert
- test_ui_api.py
- stats/model.js
- tenantScope
- imports/render.js
- ApiIntegrationTests
- init-db.sql
- start.sh
- Arbiter — blueprint rombak UI/UX
- Arbiter — audit UI/UX dan keputusan redesign
- ⚡ Key Capabilities
- UIAPIContractTests
- AGENTS.md — Arbiter Project Context for AI Agents
- get_db
- incidents-view.test.mjs
- Control
- incidents/render.js
- SafetyTests
- SyntheticDB
- database.py
- Arbiter
- exports.py
- 5. Halaman web, bagian demi bagian
- intel.py
- IPIntel — CyberSOC & Threat Intelligence Web
- 📋 Protokol Eksekusi Rinci
- stats-trust.test.mjs
- 6. SOC Log Reader — bagian demi bagian
- MANUAL — Menjalankan IP Intel Web
- app.js
- main.py
- 4. Menjalankan aplikasi
- 7. Alur data
- 9. Database
- router.js
- esc
- StatsEndpointContractTests
- triage-request.test.mjs
- generate_gdocs_html_report
- normalize_tenants
- DatabaseTrustTests
- Arbiter UI/UX Redesign — Quiet Evidence Desk
- DESIGN.md
- ui-ux-redesign/README.md
- 8. Roadmap implementasi, tiap tahap bisa diverifikasi
- 4. Wireframe dan first viewport
- Layout
- 5. Information architecture & interaction contracts

## God Nodes (most connected - your core abstractions)
1. `esc()` - 50 edges
2. `json()` - 37 edges
3. `mount()` - 36 edges
4. `UIAPIContractTests` - 32 edges
5. `get_db()` - 30 edges
6. `mount()` - 30 edges
7. `icon()` - 30 edges
8. `StatsEndpointContractTests` - 27 edges
9. `mountWorkspace()` - 26 edges
10. `errorState()` - 26 edges

## Surprising Connections (you probably didn't know these)
- `Arbiter SOC Desk Upgrades Implementation Plan` --references--> `suggest_groups()`  [INFERRED]
  docs/superpowers/plans/2026-10-23-arbiter-enrichment-reports-favicon-correlation.md → app/core.py
- `Arbiter SOC Desk Upgrades Implementation Plan` --references--> `generate_tsv_table()`  [INFERRED]
  docs/superpowers/plans/2026-10-23-arbiter-enrichment-reports-favicon-correlation.md → app/exports.py
- `Task 2: GDocs & TSV Export: Full Log & Clean Borders` --references--> `generate_tsv_table()`  [INFERRED]
  docs/superpowers/plans/2026-10-23-arbiter-enrichment-reports-favicon-correlation.md → app/exports.py
- `Task 1: Establish precise shared multi-tenant scope and safe facet contract` --references--> `normalize_tenants()`  [INFERRED]
  docs/superpowers/plans/2026-10-27-alert-statistics-pivot.md → app/query.py
- `Task 2: Build SQL aggregation endpoints and schema support` --references--> `alert_where()`  [INFERRED]
  docs/superpowers/plans/2026-10-27-alert-statistics-pivot.md → app/query.py

## Import Cycles
- None detected.

## Communities (51 total, 8 thin omitted)

### Community 0 - "parser.py"
Cohesion: 0.06
Nodes (24): local_ai_suggest_groups(), LocalAIUnavailable, normalize_alert(), ollama_request(), suggest_groups(), suggestions_with_fallback(), as_dict(), build_log_signature() (+16 more)

### Community 1 - "ref_node_assert"
Cohesion: 0.13
Nodes (11): renderLineChart(), url, modelURL, url, url, url, url, root (+3 more)

### Community 2 - "test_ui_api.py"
Cohesion: 0.11
Nodes (3): synthetic_boundary(), load_database(), load_isolated_api()

### Community 3 - "stats/model.js"
Cohesion: 0.16
Nodes (19): caseReportRoute(), exportURL(), reportAction(), reportScope(), BENIGN_WHITELIST_PATTERNS, CHART_OPTIONS, INJECTION_PATTERNS, MALICIOUS_PATTERNS (+11 more)

### Community 4 - "tenantScope"
Cohesion: 0.26
Nodes (12): report(), updateQuery(), withParams(), createNavigationMemory(), paramsForScope(), scopeKey(), rawTenantValues(), tenantScope() (+4 more)

### Community 5 - "imports/render.js"
Cohesion: 0.13
Nodes (9): createImportSession(), importPage(), importResult(), mount(), update(), moduleURL, click(), Control (+1 more)

### Community 7 - "init-db.sql"
Cohesion: 0.25
Nodes (14): idx_wazuh_alerts_agent_name, idx_wazuh_alerts_reviewed, idx_wazuh_alerts_rule_id, idx_wazuh_alerts_rule_level, idx_wazuh_alerts_sig, idx_wazuh_alerts_source_ip, idx_wazuh_alerts_status, idx_wazuh_alerts_tenant (+6 more)

### Community 11 - "Arbiter — blueprint rombak UI/UX"
Cohesion: 0.17
Nodes (12): 10. Open decisions sebelum build, 1. Keputusan desain, 2. Sitemap yang diusulkan, 3. Apa yang boleh muncul di depan, 6. Arsitektur module yang disarankan, 7. Kesiapan backend: pakai yang ada vs perlu kerja, 9. Acceptance checklist, Alternatif yang dibandingkan (+4 more)

### Community 12 - "Arbiter — audit UI/UX dan keputusan redesign"
Cohesion: 0.15
Nodes (13): Arbiter — audit UI/UX dan keputusan redesign, Bukti komposisi dan responsive, Detector Impeccable — hasil nyata, bukan daftar bug unik, Hallmark audit — subset yang sesuai operational app, Handoff, Metode dan batas bukti, Nielsen heuristics, Persona dan emotional journey (+5 more)

### Community 13 - "⚡ Key Capabilities"
Cohesion: 0.08
Nodes (23): 10. Official Deliverables (5 Export Paths), 1. Resilient Multi-Format Ingestion, 2. High-Precision Log Dissector (No False Fields), 3. Signature-Based Deduplication, 4. Enterprise Multi-Tenant Architecture, 5. Modular Four-Destination UI, 6. Review & Triage Workflow, 7. Incident Case Management (+15 more)

### Community 15 - "AGENTS.md — Arbiter Project Context for AI Agents"
Cohesion: 0.14
Nodes (13): AGENTS.md — Arbiter Project Context for AI Agents, Architecture (frontend), Design direction: Quiet Evidence Desk, Four destinations (not a monolithic page), Graph, Key policies, Privacy — STRICT, Running production (+5 more)

### Community 16 - "get_db"
Cohesion: 0.15
Nodes (24): get_db(), add_group_members(), api_database_status(), delete_group(), favicon(), get_alert_detail(), get_group_detail(), get_stats() (+16 more)

### Community 17 - "incidents-view.test.mjs"
Cohesion: 0.25
Nodes (3): context(), load(), SyntheticRoot

### Community 18 - "Control"
Cohesion: 0.22
Nodes (3): click(), Control, fixture()

### Community 19 - "incidents/render.js"
Cohesion: 0.10
Nodes (42): caseHref(), cleanIds(), draftFrom(), draftsEqual(), evidenceParams(), filterIncidents(), incidentPayload(), incidentRoute() (+34 more)

### Community 21 - "SyntheticDB"
Cohesion: 0.13
Nodes (3): Task 2: Build SQL aggregation endpoints and schema support, TriageScopeTests, SyntheticDB

### Community 22 - "database.py"
Cohesion: 0.15
Nodes (13): _clean_expired_previews_locked(), create_preview_token(), get_active_profile(), get_database_status(), get_db_connection(), ingest_alert_with_dedup(), mask_connection_url(), purge_alerts() (+5 more)

### Community 23 - "Arbiter"
Cohesion: 0.33
Nodes (5): Arbiter, Audience and usage, Development verification, Implemented case policy without schema changes, Product boundaries

### Community 24 - "exports.py"
Cohesion: 0.09
Nodes (10): generate_docx_landscape_report(), generate_markdown_report(), generate_tsv_table(), generate_xlsx_workbook(), export_csv(), export_docx(), export_markdown(), export_tsv() (+2 more)

### Community 25 - "5. Halaman web, bagian demi bagian"
Cohesion: 0.08
Nodes (24): 5.10 MITRE ATT&CK — `GET /mitre`, 5.11 MISP Events — `GET /misp`, 5.12 Detail Event MISP — `GET /misp/event/<id>`, 5.13 Import MISP — `GET/POST /misp/import`, 5.14 Universal IoCs — `GET /iocs`, 5.15 Korelasi IOC — `GET /correlate?val=...`, 5.16 Threat Feeds — `GET /threat-feeds`, 5.17 Threat Actors / APT — `GET /actors` (+16 more)

### Community 26 - "intel.py"
Cohesion: 0.16
Nodes (7): enrich_ip(), is_private_ip(), is_valid_ip(), query_abuseipdb(), sync_remote_cache(), upsert_ip_cache(), enrich_intel()

### Community 27 - "IPIntel — CyberSOC & Threat Intelligence Web"
Cohesion: 0.17
Nodes (11): 10. Parser SOC dan aturan keamanan tampilan, 11. Konfigurasi dan keamanan, 13. Troubleshooting, 14. Catatan operasional, 1. Ringkasan fungsi, 2. Arsitektur, 3. Struktur folder, 8.1 Halaman (+3 more)

### Community 28 - "📋 Protokol Eksekusi Rinci"
Cohesion: 0.13
Nodes (14): 1. Inisialisasi Task Otomatis (`todo_list`), 1. Mode Maksimal (`/work`) — Autonomous Deep Engineering Mode, 2. Mode Normal (Tanpa `/work`), 2. Proaktif Menggunakan Skills & Subagents, 3. Pelacakan Jahitan Data Ujung-ke-Ujung (*Trace Every Seam*), 4. Pengujian Kasus Negatif (Bukan Cuma Kasus Ideal), 5. Verifikasi Lingkungan & Container, 6. Anti-Pengerdilan Data (Zero Artificial Truncation) (+6 more)

### Community 29 - "stats-trust.test.mjs"
Cohesion: 0.09
Nodes (20): Alert Statistics & Pivot Implementation Plan, File Map and Interfaces, Global Constraints, Review Focus, Self-Review, Task 4: Add the compact Triage filter-summary strip, Task 5: Add approved post-core statistics enhancements, Task 6: Document the completed navigation and verification contract (+12 more)

### Community 30 - "6. SOC Log Reader — bagian demi bagian"
Cohesion: 0.22
Nodes (9): 6.1 Sumber data dan tampilan, 6.2 Filter, 6.3 Impor, 6.4 Signature dan dedup, 6.5 Hit, waktu, dan tampilan log, 6.6 Hapus data, 6.7 Export, 6.8 API SOC (+1 more)

### Community 31 - "MANUAL — Menjalankan IP Intel Web"
Cohesion: 0.25
Nodes (7): 1. Cara cepat (otomatis), 2. Cara manual (langkah per langkah), 3. Fitur web, 4. Utilitas CLI (`ipintel/`), 5. Troubleshooting, 6. File penting, MANUAL — Menjalankan IP Intel Web

### Community 32 - "app.js"
Cohesion: 0.10
Nodes (24): canLeave(), closeNav(), databaseChanged(), health(), help, main, navigationMemory, pageTitles (+16 more)

### Community 33 - "main.py"
Cohesion: 0.17
Nodes (14): init_database(), api_database_config(), api_database_purge_alerts(), api_database_purge_incidents(), api_database_switch(), api_database_test(), api_sanitize_logs(), batch_update_review() (+6 more)

### Community 34 - "4. Menjalankan aplikasi"
Cohesion: 0.50
Nodes (4): 4.1 Lewat Docker (cara yang dipakai sekarang), 4.2 Langsung dengan Python, 4.3 Health check, 4. Menjalankan aplikasi

### Community 35 - "7. Alur data"
Cohesion: 0.50
Nodes (4): 7.1 Enrichment IP, 7.2 Impor SOC, 7.3 MISP / CTI, 7. Alur data

### Community 36 - "9. Database"
Cohesion: 0.50
Nodes (4): 9.1 Tabel inti, 9.2 Tabel CTI, 9.3 Tabel SOC, 9. Database

### Community 37 - "router.js"
Cohesion: 0.31
Nodes (3): createRouter(), change(), parseRoute()

### Community 38 - "esc"
Cohesion: 0.07
Nodes (81): ApiError, apiURL(), copyHTML(), copyText(), download(), json(), request(), notify() (+73 more)

### Community 40 - "triage-request.test.mjs"
Cohesion: 0.31
Nodes (3): createSelection(), Element, requestsFor()

### Community 41 - "generate_gdocs_html_report"
Cohesion: 0.20
Nodes (9): generate_gdocs_html_report(), export_gdocs_html(), export_preview(), Arbiter SOC Desk Upgrades Implementation Plan, Global Constraints, Task 1: Favicon & Logo Arbiter, Task 2: GDocs & TSV Export: Full Log & Clean Borders, Task 3: Rich Forensic Correlation Cards (+1 more)

### Community 42 - "normalize_tenants"
Cohesion: 0.18
Nodes (7): export_scope(), _get_alerts_for_export(), _scope_tenant_value(), _tenant_label(), is_malicious_alert_record(), normalize_tenants(), positive_ids()

### Community 46 - "Arbiter UI/UX Redesign — Quiet Evidence Desk"
Cohesion: 0.18
Nodes (11): Arbiter UI/UX Redesign — Quiet Evidence Desk, Arsitektur yang Terpasang, Audit (sebelum), Batas dan Catatan, Deliverable Desain, Evidence, Implementasi (sesudah), Keputusan Arsitektur Kunci (+3 more)

### Community 47 - "DESIGN.md"
Cohesion: 0.25
Nodes (7): Colors, Components, Do's and Don'ts, Elevation & Depth, Overview, Shapes, Typography

### Community 49 - "ui-ux-redesign/README.md"
Cohesion: 0.29
Nodes (3): Approved implementation contract — Arbiter, Direction contract, Integration boundary

### Community 50 - "8. Roadmap implementasi, tiap tahap bisa diverifikasi"
Cohesion: 0.29
Nodes (7): 8. Roadmap implementasi, tiap tahap bisa diverifikasi, Phase 0 — safety & baseline, Phase 1 — modular foundation + shell, Phase 2 — triage-first experience, Phase 3 — insiden workspace, Phase 4 — impor dan laporan, Phase 5 — hardening & rollout

### Community 51 - "4. Wireframe dan first viewport"
Cohesion: 0.33
Nodes (6): 4. Wireframe dan first viewport, A. Triage desktop, B. Insiden index dan case workspace, C. Impor, D. Laporan, E. Mobile

### Community 52 - "Layout"
Cohesion: 0.33
Nodes (6): Global shell, Impor dan Laporan, Insiden, Layout, Responsive, Triage

### Community 53 - "5. Information architecture & interaction contracts"
Cohesion: 0.40
Nodes (5): 5. Information architecture & interaction contracts, Accessibility, Editing dan destructive actions, Refresh, Scope

## Knowledge Gaps
- **8 thin communities (<3 nodes) omitted from report** — run `graphify query` to explore isolated nodes.

## Suggested Questions
_Questions this graph is uniquely positioned to answer:_

- **Why does `Task 1: Establish precise shared multi-tenant scope and safe facet contract` connect `get_db` to `normalize_tenants`, `stats/model.js`, `stats-trust.test.mjs`, `esc`?**
  _High betweenness centrality (0.223) - this node is a cross-community bridge._
- **Are the 2 inferred relationships involving `json()` (e.g. with `mount()` and `loadSelected()`) actually correct?**
  _`json()` has 2 INFERRED edges - model-reasoned connections that need verification._
- **Should `parser.py` be split into smaller, more focused modules?**
  _Cohesion score 0.06034801925212884 - nodes in this community are weakly interconnected._
- **Why does `Task 2: Build SQL aggregation endpoints and schema support` connect `SyntheticDB` to `test_ui_api.py`, `esc`, `get_db`, `incidents/render.js`, `stats-trust.test.mjs`?**
  _High betweenness centrality (0.186) - this node is a cross-community bridge._
- **Should `ref_node_assert` be split into smaller, more focused modules?**
  _Cohesion score 0.13105413105413105 - nodes in this community are weakly interconnected._
- **Why does `selectedIds()` connect `incidents/render.js` to `Arbiter UI/UX Redesign — Quiet Evidence Desk`?**
  _High betweenness centrality (0.134) - this node is a cross-community bridge._
- **Should `test_ui_api.py` be split into smaller, more focused modules?**
  _Cohesion score 0.1053763440860215 - nodes in this community are weakly interconnected._