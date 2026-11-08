# Code Style — Arbiter

Backend is Python 3.11+ (FastAPI), frontend is vanilla JS ES modules + native CSS.
No React, Vue, Angular, Svelte, or Tailwind. Do not migrate the stack.

## Python

- Single `app/main.py` entry; domain modules under `app/` (`query.py`, `core.py`,
  `ai_triage.py`, `settings.py`, `secure_store.py`, `parser.py`, `exports.py`).
- Type hints on public functions (`from __future__ import annotations`).
- SQL goes through bound parameters only (`%s`); never f-string raw user input.
- Credentials at rest are Fernet-encrypted (`app/secure_store.py`); the API
  redacts them. Never log or return a password/secret.

## Frontend (JS)

- Native ES modules under `app/static/js/`, one feature per directory under
  `features/` (model.js / view.js / render.js / state.js).
- Escape all user/DB text through `esc()` from `ui/primitives.js` before
  interpolating into innerHTML.
- No `transition: all`. No `overflow-x: hidden`/`100vw` on the body. Prefer
  `overflow-x: clip`.

## CSS

- Design tokens live in `app/static/styles/tokens.css` (source of truth:
  `docs/ui-ux-redesign/DESIGN.md`). No literal colours or font-family outside
  the token block.
- Semantic classes, BEM-lite. Component styles in `components.css`, shell in
  `shell.css`, reset/typography in `base.css`.
