# Deployment (Docker Compose + Caddy)

Requirements: a host with Docker, two DNS names pointing at it, ports 80/443 open.

```bash
cp .env.example .env
# edit .env: set SOC_SECRET_KEY (python -c "import secrets; print(secrets.token_hex(32))"), INGEST_DOMAIN, SOC_DOMAIN
docker compose up -d --build

docker compose run --rm bi_server python manage.py create-tenant "Client name" "sector"   # prints API key once
docker compose run --rm bi_server python manage.py create-user 1 operator.name            # prompts for password
docker compose run --rm bi_server python manage.py rotate-api-key 1                       # when a key leaks
```

Send events:

```bash
curl -X POST https://$INGEST_DOMAIN/api/v1/events \
  -H "X-API-Key: soc_..." -H "Content-Type: application/json" \
  -d '[{"actor":"jan","action":"login","timestamp":"2026-01-02 10:00:00","ip":"192.168.1.5","status":"failed","records":0}]'
```

Notes: `SOC_TRUSTED_PROXIES=1` is set in compose because Caddy is the single proxy. Back up the `soc_data` volume
(SQLite file `/data/soc.db`). Use one gunicorn worker per web service (pending imports live in process memory).
Folder watcher: `python collector.py <tenant_id> <drop_dir>` (run it as a separate process/container with the folder mounted).
