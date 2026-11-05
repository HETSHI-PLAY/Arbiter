# Arbiter

Arbiter is a local SOC investigation desk for normalized Wazuh telemetry. Analysts triage deduplicated alerts, inspect occurrences and source intelligence, group evidence into incidents, author conclusions/recommendations, and produce scoped document deliverables.

## Audience and usage

Desktop-first analysts working extended investigation sessions; narrow screens support review through list/detail composition. Calm functional density matters more than dashboard decoration. The approved design direction is **Quiet Evidence Desk**.

## Product boundaries

- FastAPI backend, PostgreSQL storage, native JavaScript ES modules and CSS. No framework migration is required by the UI.
- Four task destinations: Triage, Insiden, Impor, Laporan. Triage is the default entry; there is no decorative overview dashboard.
- Tenant is a visible working context, not an asserted authorization mechanism. Case evidence and exports retain explicit tenant scope.
- Raw alert/log data is sensitive. Development and agent QA use authored synthetic fixtures only; never inspect production records, .env, raw logs or populated production UI.
- Fonts and UI assets are local. No analytics, runtime CDN, external font fetch or silent data upload is introduced. IP intelligence pivot is an explicit user action to the configured local platform.
- Clipboard HTML is a copy/paste deliverable for Google Docs, not Google account integration. Automatic redaction is not a guarantee of safe external sharing.

## Implemented case policy without schema changes

A case with no evidence can be created from **Semua tenant**. A tenant-scoped case must have evidence in that tenant. Removing the last visible tenant evidence requires reviewing the case in all-tenant scope; scoped removal is rejected before mutation. This avoids committing a save that immediately disappears from its verification scope. No case ownership column or permission policy is invented.

## Development verification

Use explicitly named isolated suites for QA. Do not run the original `tests.test_api` against the active SGU database.
