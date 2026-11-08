# /review — Code review pass

Review staged changes for correctness, security, and consistency with the
stack (FastAPI + vanilla JS + native CSS). Never touch live data or `.env`.

Checklist:

1. **Scope** — every changed file listed; no accidental drift.
2. **Safety** — no credential/secret in diffs; SQL uses bound params; text
   escaped through `esc()`; no raw upstream error bodies surfaced.
3. **Contracts** — new endpoints validate tenant scope and reject out-of-scope
   ids; error codes match `.ai/rules/api-conventions.md`.
4. **Tests** — `npm test` and the safe backend suites pass; new behaviour has a
   synthetic test. Never run `tests.test_api`.
5. **Design** — no `transition: all`, no literal colours outside tokens.css.

Report: findings ordered P0 (blocking) → P3 (polish), each with file:line and a
concrete fix.
