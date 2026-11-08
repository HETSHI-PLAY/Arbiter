# Deploy config reference

## Containers

| Service | Image | Notes |
|---|---|---|
| `arbiter` | built from `Dockerfile` (python:3.11-slim) | `network_mode: host` → talks to host PostgreSQL |
| `db` (profile `standalone`) | postgres:16-alpine | optional bundled DB, mounts `init-db.sql` |

## Environment variables

| Var | Required | Purpose |
|---|---|---|
| `DATABASE_URL` | yes | `postgresql://user:***@host:5432/db` |
| `REMOTE_DATABASE_URL` | no | encrypted-at-rest remote profile |
| `ABUSEIPDB_API_KEY` | no | live threat-intel enrichment |
| `ARBITER_SECRET_KEY` / `ARBITER_SECRET_KEY_FILE` | no | Fernet key for credential encryption; auto-generated 0600 file outside repo if unset |

## Secrets

- Wazuh password and the Remote DB URI are Fernet-encrypted at rest.
- The key is never committed: local `~/.local/share/arbiter/secret.key`, docker
  `/data/secret.key` (volume `arbiter_secrets`).
- `.env` and `secret.key` are git-ignored and docker-ignored.

## Reverse proxy (optional)

`docker/nginx/default.conf` is a ready nginx `proxy_pass` template for putting
Arbiter behind TLS. Not used by the default host-mode compose.
