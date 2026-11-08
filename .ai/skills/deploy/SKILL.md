---
name: deploy
description: Deploy Arbiter to a production server via Docker Compose, or run locally.
---

# Deploy Arbiter

Arbiter is a FastAPI + PostgreSQL app shipped as a single container.
See `deploy-config.md` in this directory for the full reference.

## Local dev

```bash
./start.sh          # uvicorn --reload on 127.0.0.1:8000
```

## Production (Docker Compose)

```bash
cp .env.example .env        # edit DATABASE_URL, ARBITER_SECRET_KEY, ABUSEIPDB_API_KEY
docker compose up -d --build
```

Compose uses `network_mode: host` (connects to the host's PostgreSQL).
`docker compose --profile standalone up -d` adds a bundled PostgreSQL 16.

## Pre-deploy checks

1. `npm test` and the safe backend suites are green.
2. `git status` clean; no `.env` or `secret.key` staged.
3. `.dockerignore` excludes `.git`, `.venv`, `.env`, `secret.key`.
