# License Facade Service

FastAPI service for SPDX-compatible license metadata and negotiated public representations.

## Run

```bash
uv sync
uv run python -m src.license_facade_service.main
```

## API contract

- Canonical lookup: `GET /api/v1/licenses/{id}`
- Specification alias: `GET /api/v1/licences/{id}`
- Default response: `application/json`
- Explicit HTML: `Accept: text/html` or `/html`

Supported negotiated media types:

- `application/json`
- `text/html`
- `application/ld+json`
- `text/turtle`
- `application/rdf+xml`

Convenience routes:

- `/api/v1/licenses/{id}/html`
- `/api/v1/licenses/{id}/json`
- `/api/v1/licenses/{id}/json-ld`
- `/api/v1/licenses/{id}/turtle`
- `/api/v1/licenses/{id}/rdfxml`
- `/api/v1/licenses/{id}/original`
- `/api/v1/licenses/{id}/legal`
- `/api/v1/licenses/{id}/machine`
- `/api/v1/licenses/{id}/encoding`

## Representation rules

- `/original` uses curated original-source metadata only; SPDX `reference` is not treated as original.
- `/machine` requires a curated rights-expression representation; SPDX JSON alone is not enough.
- Missing mandatory representations return `404` problem details and non-conformance metadata.

## Metadata

Detailed JSON responses include the Table 4 fields plus:

- `spdxDetailsURL`
- `representations`
- `representationStatus`
- `conformance`
- `_links`

## Authentication

Mutation endpoints require bearer auth via env/secret file:

- `LFS_ADMIN_TOKEN` or `LFS_ADMIN_TOKEN_FILE`
- `LFS_CURATOR_TOKEN` or `LFS_CURATOR_TOKEN_FILE`

`401` means missing/invalid credentials; `403` means insufficient role.

## Deployment defaults

- reload disabled by default
- explicit CORS origins only
- pinned Fuseki image
- non-root container user
- Fuseki not host-published by default

See `docs/specification.md` and `docs/migration-note.md` for details.

## Federation Phase 1 (foundation only)

Federation is **feature-gated** and disabled by default.

- `FEDERATION_ENABLED=false` keeps current licence API behaviour and does not require PostgreSQL or signing keys.
- `FEDERATION_ENABLED=true` requires validated node identity, PostgreSQL DSN, and signing-key configuration.

Required federation settings when enabled:

- `FEDERATION_NODE_ID` (UUID)
- `FEDERATION_PUBLIC_BASE_URL` (absolute `https://...`)
- `FEDERATION_NODE_NAME`
- `FEDERATION_OPERATOR`
- `FEDERATION_DATABASE_URL` (PostgreSQL)
- `FEDERATION_ACTIVE_KID`
- `FEDERATION_SIGNING_KEY_PATH` or `FEDERATION_SIGNING_KEY_SECRET_PATH`

Signing-key policy:

- Ed25519/EdDSA key loaded from configured file/secret path.
- Private keys are never stored in PostgreSQL or API responses.
- Database stores only public key metadata and supports multiple keys with one active key.

Optional JWKS endpoint (feature-gated):

- `GET /.well-known/jwks.json`
- enable with `FEDERATION_ENABLED=true` and `FEDERATION_JWKS_ENABLED=true`.
