# License Facade Service

FastAPI service for SPDX-compatible license metadata and negotiated public representations.

## Build and run

```bash
uv sync
uv run python -m src.license_facade_service.main
```

Docker:

```bash
docker compose up --build
```

## Public API contract (v1)

Canonical endpoint:

- `GET /api/v1/licenses/{id}` with `Accept` negotiation:
  - `text/html` (default when missing or `*/*`)
  - `application/json`
  - `application/ld+json`
  - `text/turtle`
  - `application/rdf+xml`
- Unsupported `Accept` returns `406` with `application/problem+json`.
- Compatibility alias: `/api/v1/licences/{id}` and the same sibling routes.

Convenience endpoints map to the same service-layer implementation:

- `/api/v1/licenses/{id}/html`
- `/api/v1/licenses/{id}/json`
- `/api/v1/licenses/{id}/json-ld`
- `/api/v1/licenses/{id}/turtle`
- `/api/v1/licenses/{id}/rdfxml`
- `/api/v1/licenses/{id}/encoding`

Identifier resolution supports:

- SPDX license ID (exact, case-sensitive)
- LFS UUID
- Full LFS URI (URL-encoded)
- Explicit aliases if present in source data

Static routes take precedence over `{id}`:

- `/api/v1/licenses/taxonomy`
- `/api/v1/licenses/cache/status`
- `/api/v1/licenses/spdx3/minimal`

## Optional representations

- `/api/v1/licenses/{id}/original`: redirects to authoritative curated source if known; otherwise `404` problem details.
- `/api/v1/licenses/{id}/legal`: returns separately curated legal representation if available; otherwise `404`.
- `/api/v1/licenses/{id}/machine`: returns rights-expression representation only when explicitly available and profile/vocabulary indicates an allowed REL (ODRL, ccREL, DALICC, OpenREL); otherwise `404`.
- `/api/v1/licenses/{id}/encoding`: redirects to a curated encoding reference if available; otherwise `404`.

Canonical JSON metadata includes the Table 4 fields and aliases:

- `uri`, `referenceNumber`, `licenseId`/`licenseID`/`licenceID`
- `name`, `detailsURL`/`detailsUrl`, `reference`
- `isDeprecatedLicenseId`/`isDeprecatedLicenseID`
- `seeAlso`, `isOsiApproved`, `licenseText`, `standardLicenseTemplate`, `licenseTextHtml`
- `crossRef`, `representations`, and `_links`

## Authentication for mutation endpoints

Protected endpoints:

- `POST /api/v1/licenses/cache/update`
- `POST /api/v1/licenses/cache/refresh`
- `POST /api/v1/licenses/spdx3/minimal`
- `POST /api/v1/licenses/spdx3/complete/{license_id}`

Configuration (no hard-coded defaults):

- `LFS_ADMIN_TOKEN` or `LFS_ADMIN_TOKEN_FILE`
- `LFS_CURATOR_TOKEN` or `LFS_CURATOR_TOKEN_FILE`

Behavior:

- missing/invalid token: `401`
- authenticated but role not `admin|curator`: `403`

## Runtime and ops defaults

- reload disabled by default (`RELOAD_ENABLE=false`)
- CORS origins configured explicitly through `CORS_ORIGINS` (comma-separated)
- no wildcard CORS defaults with credentials
- Fuseki image pinned in compose
- service runs as non-root in Dockerfile
- readiness split:
  - `GET /api/v1/health` (liveness)
  - `GET /api/v1/ready` (license snapshot readiness + Fuseki status when enabled)

## Migration note

See `docs/migration-note.md` for behavior changes from previous route/auth/representation behavior.
