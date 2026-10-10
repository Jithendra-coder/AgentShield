# Operations

## Health and logs

- `GET /health` is the API liveness check.
- `GET /health/ready` checks PostgreSQL and Redis.
- API access logs are JSON on stdout and include `request_id`. They exclude request bodies, query strings, and API keys.
- Inspect service logs with `docker compose logs -f api worker scheduler`.
- Alert on unhealthy Compose services, repeated worker retries, a growing `job_outbox` table, and sustained 429 or 503 responses. The service does not configure an alert provider.

## Database backups

PostgreSQL is the source of truth for organizations, policies, runs, and evidence. Keep encrypted backups off the host and test restoration on a separate instance.

```powershell
New-Item -ItemType Directory -Force backups | Out-Null
$stamp = Get-Date -Format 'yyyyMMdd-HHmmss'
docker compose exec -T db pg_dump -U agentshield -d agentshield -Fc > "backups/agentshield-$stamp.dump"
```

To restore, stop API, worker, and scheduler services first, then restore into the intended PostgreSQL database. `pg_restore --clean` removes existing objects, so verify the database target before using it.

Redis uses AOF to survive a container restart. PostgreSQL remains authoritative for runs; unsent outbox rows are picked up by the scheduler after restart.

## API key rotation

Create a replacement key before revoking the current one. Verify the new key with `GET /api/v1/auth/me`, move clients to it, then revoke the old key by its ID. A key cannot revoke itself. Updating the bootstrap or platform key in `.env` adds the replacement during startup; it does not revoke prior keys automatically.

## Schema upgrades

PostgreSQL migration versions are stored in `schema_migrations`. Add new migrations in order in `agentshield/db.py`; never edit an already applied migration. Startup takes an advisory lock so multiple API processes do not apply a migration at once. Back up PostgreSQL before deploying a schema change.

Migrations 1 and 2 create a new production schema and add the runner field to an existing AgentShield database. This project does not convert an earlier SQLite or prototype schema into PostgreSQL.

## Reverse proxy

Compose binds the API to `127.0.0.1:8000`. Expose it through a TLS reverse proxy, forward the original host and HTTPS scheme, and set `AGENTSHIELD_ALLOWED_HOSTS` to the names the proxy serves. Keep PostgreSQL and Redis unreachable from the public network. The proxy should enforce its own connection, request, and header limits as well.
