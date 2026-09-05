# Production Docker Deployment

This profile runs one LFS **0.3.5** production node with PostgreSQL, Alembic-managed schema, persistent federation key storage, API, federation worker, custom-licence publication worker, and RDF worker.

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

## 1. Required database state

Production migrations must reach:

```text
20260904_03
```

Before starting API or workers, verify:

```bash
uv run alembic -c alembic.ini upgrade head
uv run alembic -c alembic.ini heads
```

## 2. Core configuration

Copy the production environment file and lock it down:

```bash
cp .env.production.example .env.production
chmod 600 .env.production
```

Set deployment-specific placeholders for at least:

- `LFS_ADMIN_TOKEN` or `LFS_ADMIN_TOKEN_FILE`
- `LFS_CURATOR_TOKEN` or `LFS_CURATOR_TOKEN_FILE`
- `CUSTOM_LICENCE_REGISTRATION_DATABASE_URL`
- `CUSTOM_LICENCE_AUTHORITY_ID`
- `CUSTOM_LICENCE_AUTHORITY_BASE_IRI`
- `CUSTOM_LICENCE_CREATOR_ORGANIZATION_NAME`
- `CUSTOM_LICENCE_CREATOR_ORGANIZATION_IRI`
- PostgreSQL connection placeholders such as `<POSTGRESQL_DSN>`
- Fuseki credentials if RDF indexing is enabled

Example placeholders only:

```dotenv
LFS_ADMIN_TOKEN=<OPENREL_ADMIN_TOKEN>
LFS_CURATOR_TOKEN=<LFS_CURATOR_TOKEN>
CUSTOM_LICENCE_REGISTRATION_DATABASE_URL=<POSTGRESQL_DSN>
CUSTOM_LICENCE_AUTHORITY_ID=node-a
CUSTOM_LICENCE_AUTHORITY_BASE_IRI=https://lfs.example.invalid
CUSTOM_LICENCE_CREATOR_ORGANIZATION_NAME=Example Operator
CUSTOM_LICENCE_CREATOR_ORGANIZATION_IRI=https://lfs.example.invalid/spdx/agents/example-operator
```

## 3. OpenREL configuration

OpenREL remains optional and read-only against the upstream provider. Use placeholders only.

Documented OpenREL environment variables from `OpenRelPolicySettings`:

- `OPENREL_ENABLED`
- `OPENREL_POLICY_MODE`
- `OPENREL_POLICY_DATABASE_URL` or `OPENREL_POLICY_DATABASE_URL_FILE`
- `OPENREL_ADMIN_CURSOR_SECRET` or `OPENREL_ADMIN_CURSOR_SECRET_FILE`
- `OPENREL_BASE_URL`
- `OPENREL_APPROVED_PROFILE`
- `OPENREL_APPROVED_VERSION`
- `OPENREL_POLICY_EFFECTIVE_DATE`
- `OPENREL_CACHE_TTL_SECONDS`
- `OPENREL_TIMEOUT_SECONDS`
- `OPENREL_MAX_RESPONSE_BYTES`
- `OPENREL_ALLOW_HTTP_FOR_DEMO`
- `OPENREL_AUTODISCOVERY_ENABLED`
- `OPENREL_MIGRATION_REVIEW_REQUIRED`
- `OPENREL_MAPPING_AUTHORITY`

Safe placeholder example:

```dotenv
OPENREL_ENABLED=true
OPENREL_POLICY_MODE=active
OPENREL_POLICY_DATABASE_URL=<POSTGRESQL_DSN>
OPENREL_ADMIN_CURSOR_SECRET=<OPENREL_CURSOR_SECRET_32_PLUS_CHARS>
OPENREL_BASE_URL=https://openrel.example.invalid/openrel/api/v0.4
OPENREL_APPROVED_PROFILE=https://openrel.org/ns#
OPENREL_APPROVED_VERSION=0.4
OPENREL_POLICY_EFFECTIVE_DATE=2026-09-04
OPENREL_CACHE_TTL_SECONDS=300
OPENREL_TIMEOUT_SECONDS=15
OPENREL_MAX_RESPONSE_BYTES=512000
OPENREL_ALLOW_HTTP_FOR_DEMO=false
OPENREL_AUTODISCOVERY_ENABLED=false
OPENREL_MIGRATION_REVIEW_REQUIRED=true
OPENREL_MAPPING_AUTHORITY=lfs
```

Operational rules:

- OpenREL provider access is read-only.
- Provider availability alone never authorizes trust or mutation.
- If the provider is offline, the public API still runs and evaluation fails closed.
- Apply/rollback always requires admin authentication.
- Federated apply/rollback additionally requires a ready federation publisher and payload configuration.
- RDF processing remains asynchronous; no synchronous Fuseki call is made in admin apply/rollback requests.

## 4. Federation configuration

For federated registration or federated OpenREL apply/rollback, configure the existing federation runtime with placeholders only:

- `FEDERATION_ENABLED=true`
- `FEDERATION_NODE_ID=<UUID>`
- `FEDERATION_PUBLIC_BASE_URL=https://lfs.example.invalid`
- `FEDERATION_NODE_NAME=<NODE_NAME>`
- `FEDERATION_OPERATOR=<OPERATOR_NAME>`
- `FEDERATION_DATABASE_URL=<POSTGRESQL_DSN>`
- `FEDERATION_ACTIVE_KID=<ACTIVE_KEY_ID>`
- one key source:
  - `FEDERATION_SIGNING_KEY_DIR=<PATH>`
  - or `FEDERATION_SIGNING_KEY_PATH=<PATH>`
  - or `FEDERATION_SIGNING_KEY_SECRET_PATH=<PATH>`

Federated OpenREL mutation is unavailable unless the publisher is ready and authoritative publication linkage is valid.

## 5. Validate configuration

```bash
docker compose --env-file .env.production --profile production config --quiet
```

## 6. Start the stack

```bash
docker compose --env-file .env.production --profile production up -d --build
```

## 7. Verify health and readiness

```bash
docker compose --env-file .env.production --profile production ps
docker compose --env-file .env.production logs lfs-migrate lfs-key-init lfs-storage-init lfs-fuseki-init
docker compose --env-file .env.production logs lfs-production-api lfs-sync-worker lfs-custom-licence-worker lfs-rdf-worker
curl -fsS http://localhost:12104/api/v1/health
curl -fsS http://localhost:12104/api/v1/ready
curl -fsS http://localhost:12104/.well-known/lfs
curl -fsS http://localhost:12104/.well-known/jwks.json
```

Use `/openapi.json` or `/docs` to confirm the authenticated admin OpenREL endpoints exist:

- `POST /api/v1/admin/openrel/evaluations`
- `GET /api/v1/admin/openrel/policy-states`
- `GET /api/v1/admin/openrel/policy-states/{state_id}`
- `GET /api/v1/admin/openrel/policy-states/{state_id}/events`
- `POST /api/v1/admin/openrel/policy-states/{state_id}/approve`
- `POST /api/v1/admin/openrel/policy-states/{state_id}/reject`
- `POST /api/v1/admin/openrel/policy-states/{state_id}/apply`
- `POST /api/v1/admin/openrel/policy-states/{state_id}/rollback`

## 8. Logging and secrecy expectations

Do not place real credentials in committed files, shell history, screenshots, or tickets. Current implementation also avoids exposing secrets in normal API responses and OpenREL review/apply/rollback audit output.

Keep these values secret:

- bearer tokens
- PostgreSQL credentials
- federation private-key material
- `OPENREL_ADMIN_CURSOR_SECRET`
- any secret-file contents referenced by `*_FILE` settings

## 9. Upgrade deployment

Run the same `up -d --build` command. `lfs-migrate` applies forward Alembic migrations idempotently.

## 10. Persistence and recovery

Back up:

- PostgreSQL volume
- federation signing-key volume
- Fuseki volume

Do not run `docker compose down -v` in production unless full data loss is intended.

## 11. Safety notes

- Separate nodes must not share PostgreSQL volumes or databases.
- Separate nodes must not share federation node IDs, signing-key directories, or custom authority IDs.
- Peer trust remains explicit; production does not auto-enroll or auto-approve peers.
- If OpenREL is enabled, keep `OPENREL_BASE_URL` on HTTPS in production.
- If Fuseki is offline, PostgreSQL remains the source of truth and RDF retries stay asynchronous.
