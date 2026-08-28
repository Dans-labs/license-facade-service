# Production Docker Deployment

This profile runs one LFS 0.3.0 production node with PostgreSQL, Alembic-managed schema, persistent signing-key storage, API, federation sync/rotation worker, custom-licence publication worker, and RDF worker.

## Automated startup sequence

```text
PostgreSQL healthy
      |
      v
lfs-migrate runs Alembic upgrade head
      |
      +---- lfs-key-init prepares persistent key directory
      +---- lfs-storage-init prepares resource/log ownership
      +---- lfs-fuseki-init ensures Fuseki dataset
      |
      v
lfs-production-api ready
      |
      +---- lfs-sync-worker
      +---- lfs-custom-licence-worker
      +---- lfs-rdf-worker
```

Schema ownership is Alembic-only. `docker/postgres-init/001-lfs-schema.sql` is not used.

## 1. Prepare configuration

```bash
cp .env.production.example .env.production
chmod 600 .env.production
```

Set unique per-node values for:

- `FEDERATION_NODE_ID`
- `FEDERATION_PUBLIC_BASE_URL`
- `CUSTOM_LICENCE_AUTHORITY_ID`
- `LFS_ADMIN_TOKEN` and `LFS_CURATOR_TOKEN`
- PostgreSQL and Fuseki credentials
- `FEDERATION_ADMIN_CURSOR_SECRET` (32+ chars)

## 2. Validate config

```bash
docker compose --env-file .env.production --profile production config --quiet
```

## 3. Start

```bash
docker compose --env-file .env.production --profile production up -d --build
```

## 4. Verify

```bash
docker compose --env-file .env.production --profile production ps
docker compose --env-file .env.production logs lfs-migrate lfs-key-init lfs-storage-init lfs-fuseki-init
docker compose --env-file .env.production logs lfs-production-api lfs-sync-worker lfs-custom-licence-worker lfs-rdf-worker
curl -fsS http://localhost:12104/api/v1/health
curl -fsS http://localhost:12104/api/v1/ready
curl -fsS http://localhost:12104/.well-known/lfs
curl -fsS http://localhost:12104/.well-known/jwks.json
```

## 5. Upgrade deployment

Run the same `up -d --build` command; `lfs-migrate` applies forward Alembic migrations idempotently.

## 6. Persistence

Back up:

- PostgreSQL volume
- federation signing-key volume
- Fuseki volume

Do not run `docker compose down -v` in production unless full data loss is intended.

## 7. Multi-node safety

Separate nodes must not share:

- PostgreSQL volumes/databases
- federation node IDs
- signing-key directories
- authority IDs

Peer trust remains explicit admin enrollment and key approval; no automatic trust bootstrap is performed in production.
