# API Conventions — Arbiter

FastAPI under `app/main.py`. Same-origin fetch wrapper in
`app/static/js/api/client.js`.

## Tenant scoping

- Most endpoints take `tenant: list[str] = Query(default=["all"])`.
- `normalize_tenants()` rejects blank tenants and `all` mixed with named tenants.
- `_validate_membership()` refuses any id outside the active tenant before
  mutating or returning data. No silent widening.

## Errors

- 400 — malformed/business-invalid request (out of scope, missing indexer).
- 401/403 — Wazuh Indexer auth denied.
- 404 — index/alert/group not found in scope.
- 422 — validation (non-positive alert ids, blank tenant).
- 502 — upstream failure (Wazuh Indexer down/400, Ollama unreachable).

All user-facing messages are Indonesian, actionable, and never leak raw error
text from upstream (indexer response bodies are discarded).

## Credential redaction

`/api/settings` returns `password_set: true` and never the decrypted secret.
The password is decrypted in-memory only via `wazuh_password()`.
