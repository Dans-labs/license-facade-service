# Production Docker Deployment

This deployment profile starts one production LFS node with PostgreSQL, Fuseki, automatic schema initialization, persistent signing keys, the API, and all federation/RDF workers.

## What is automated

Running the production profile performs this sequence:

```text
PostgreSQL becomes healthy
          |
          v
PostgreSQL runs docker/postgres-init/001-lfs-schema.sql once on an empty data directory
          |
          +---- persistent Ed25519 signing key is initialized once
          +---- persistent resource/log directories are initialized once
          +---- Fuseki `licenses` dataset is created if absent
          |
          v
LFS API starts and becomes ready
          |
          +---- inbound synchronization worker starts
          +---- custom-licence publication worker starts
          +---- RDF outbox worker starts
```

The schema is installed automatically only when PostgreSQL initializes an empty data directory. Later restarts with the same volume do not rerun the SQL, and changing `docker/postgres-init/001-lfs-schema.sql` does not modify an existing database.

## 1. Prepare configuration

```bash
cp .env.production.example .env.production
chmod 600 .env.production
```

Edit `.env.production` and replace every `CHANGE_ME` value. In particular, each deployed LFS node needs its own:

- public HTTPS URL;
- federation node UUID;
- authority ID;
- administrator and curator tokens;
- database and Fuseki passwords.

Generate a node UUID:

```bash
uuidgen | tr '[:upper:]' '[:lower:]'
```

Generate strong tokens/passwords, for example:

```bash
openssl rand -hex 32
```

If a password contains reserved URI characters, URL-encode it in `LFS_DATABASE_URL`.

## 2. Validate configuration

```bash
docker compose \
  --env-file .env.production \
  --profile production \
  config --quiet
```

Inspect the rendered service list if desired:

```bash
docker compose \
  --env-file .env.production \
  --profile production \
  config --services
```

## 3. Start the node

```bash
docker compose \
  --env-file .env.production \
  --profile production \
  up -d --build
```

PostgreSQL applies `docker/postgres-init/001-lfs-schema.sql` automatically on first start with an empty data volume. The `lfs-key-init` container exits after ensuring that the persistent signing key exists, `lfs-storage-init` exits after setting safe ownership on the resource and log volumes, and `lfs-fuseki-init` exits after ensuring that the `licenses` dataset exists.

On the first start with an empty resource volume, LFS downloads its SPDX licence snapshot before reporting ready. The API health check allows extra bootstrap time for this operation. Later restarts reuse the persistent snapshot and are faster.

## 4. Verify startup

```bash
docker compose \
  --env-file .env.production \
  --profile production \
  ps
```

Check the initialization logs:

```bash
docker compose --env-file .env.production logs lfs-postgres lfs-key-init lfs-storage-init lfs-fuseki-init
```

Check the API and workers:

```bash
docker compose --env-file .env.production logs lfs-production-api
docker compose --env-file .env.production logs lfs-sync-worker
docker compose --env-file .env.production logs lfs-custom-licence-worker
docker compose --env-file .env.production logs lfs-rdf-worker
```

Check HTTP health:

```bash
curl -fsS http://localhost:12104/api/v1/health
curl -fsS http://localhost:12104/api/v1/ready
curl -fsS http://localhost:12104/.well-known/lfs
curl -fsS http://localhost:12104/.well-known/jwks.json
```

In production, expose LFS through an HTTPS reverse proxy. The configured `FEDERATION_PUBLIC_BASE_URL` must be the externally reachable HTTPS origin.

## 5. Upgrade LFS later

Update `LFS_IMAGE` or rebuild from the newer source, then run the same command:

```bash
docker compose \
  --env-file .env.production \
  --profile production \
  up -d --build
```

Compose does not rerun schema initialization on an existing volume. Restarting with the same PostgreSQL volume keeps the existing data and does not reapply `docker/postgres-init/001-lfs-schema.sql`.

If you need a schema change after deployment, create a new database or introduce an explicit upgrade mechanism. Do not assume editing `001-lfs-schema.sql` will change a live database.

## 6. Persistent data and backup

The production profile creates named volumes for:

- PostgreSQL data;
- the federation Ed25519 signing key;
- Fuseki data;
- LFS resource/cache data;
- LFS logs.

Back up PostgreSQL and the signing-key volume. Losing the signing key changes the node's cryptographic identity and requires peer trust/key-rotation administration.

Do not use `docker compose down -v` in production: `-v` deletes named volumes and therefore deletes the database, signing key, and Fuseki data.

## 7. Two independent federation nodes

Deploy DANS and RDA as separate Compose projects, on separate hosts or with separate project names and environment files. Never share:

- PostgreSQL volumes/databases;
- federation node UUIDs;
- signing-key volumes;
- authority IDs.

For example:

```bash
docker compose \
  --project-name dans-lfs \
  --env-file .env.dans.production \
  --profile production \
  up -d
```

```bash
docker compose \
  --project-name rda-lfs \
  --env-file .env.rda.production \
  --profile production \
  up -d
```

After both nodes are reachable over HTTPS, enroll each intended source node through the Federation Admin API using its expected node ID and pinned public-key fingerprint. Trust is never created automatically by this production profile.

## 8. External PostgreSQL

The bundled `lfs-postgres` service is the default clean deployment. To use a managed/external PostgreSQL service, set `LFS_DATABASE_URL` to that database. Docker does not execute `/docker-entrypoint-initdb.d` for external databases, so initialize it once with:

```bash
psql "$LFS_DATABASE_URL" \
  -v ON_ERROR_STOP=1 \
  -f docker/postgres-init/001-lfs-schema.sql
```

If you deploy the schema SQL via a host bind mount, ship the Compose file and `docker/postgres-init/001-lfs-schema.sql` together.

Do not point `FEDERATION_DATABASE_URL` and `CUSTOM_LICENCE_REGISTRATION_DATABASE_URL` at different databases. The production profile deliberately derives both from the single `LFS_DATABASE_URL` value.
