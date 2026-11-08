# Testing — Arbiter

Tests are synthetic-only. Never touch the live database, `.env`, Ollama, or the
Wazuh Indexer.

## Frontend

```bash
npm test
# equivalently:
node --test tests/frontend/*.test.mjs
```

- `.mjs` tests import the ES modules directly under Node.
- Assert on rendered markup and model normalization; never on network.

## Backend (safe isolated suites)

```bash
.venv/bin/python -m unittest \
  tests.test_parser tests.test_exports tests.test_privacy \
  tests.test_dedup tests.test_ui_api tests.test_ui_safety tests.test_settings \
  tests.test_stats tests.test_triage_scope tests.test_database_trust tests.test_ai_triage
```

- `tests/test_ui_api.py` loads `app/main.py` with `app.database`/`app.config`
  stubbed out (`load_isolated_api`), against in-memory SQLite (`SyntheticDB`).
- Mock external HTTP at the boundary (`wazuh_search`, `test_ollama`, `ai_triage`).
  Patch through the bound function's `__globals__`, not the module path — the
  isolated loader orphanes `app.*` modules from `sys.modules`.
- **Never** run `tests.test_api` — it hits live PostgreSQL.

## Design lint

```bash
npx -y @google/design.md@0.4.0 lint docs/ui-ux-redesign/DESIGN.md
```
