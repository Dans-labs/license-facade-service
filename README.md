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
- JSON/LD/RDF: `application/json`, `application/ld+json`, `text/turtle`, `application/rdf+xml`
- Arbitrary identifiers: `GET /api/v1/licenses/resolution?identifier=...`

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
- `/api/v1/licenses/provenance?identifier=...`

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

## OpenAPI and Swagger

- Swagger UI: `/docs`
- ReDoc: `/redoc`
- Raw OpenAPI schema: `/openapi.json`

Public endpoint groups are documented under **Service status**, **Licences**, **Licence representations**, **Federation discovery**, **Federation outbound**, and **Federation resolution**.

Protected endpoint groups are documented under **Federation administration** and **Federation conflicts**. In Swagger UI, use **Authorize** and paste a bearer token value such as `Bearer example-token` for admin/curator operations. Missing or invalid credentials return `401`; authenticated callers without the required role return `403`.

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

## Federation Phase 2 (authoritative outbound only)

Implemented outbound endpoints (all read-only):

- `GET /.well-known/lfs`
- `GET /.well-known/jwks.json`
- `GET /api/v1/federation/catalog`
- `GET /api/v1/federation/changes`
- `GET /api/v1/federation/records/{encoded_id}`

Key rules:

- only authoritative local records are exposed (`is_authoritative=true`, local authority node, published, non-imported);
- federation endpoints return `404` when `FEDERATION_ENABLED=false`;
- change events are append-only and inserted transactionally at publication/deprecate/tombstone operations (not by GET);
- cursor tokens are opaque, versioned, Ed25519-signed claims;
- catalog pagination uses keyset ordering plus a stable event-sequence watermark;
- event and record payload digests/signatures use RFC 8785/JCS canonical JSON (UTF-8) + SHA-256 + Ed25519.

## Federation Phase 3 (trusted peers + inbound synchronization)

Implemented:

- admin-only peer APIs:
  - `GET/POST /api/v1/admin/federation/peers`
  - `GET/PATCH/DELETE /api/v1/admin/federation/peers/{peer-id}`
  - `POST /api/v1/admin/federation/peers/{peer-id}/sync`
  - `GET /api/v1/admin/federation/peers/{peer-id}/imports`
  - `GET /api/v1/admin/federation/status`
- explicit trusted-peer enrollment with pinned expected node ID + key fingerprint/kid;
- separate inbound event store (`federation_inbound_events`), separate from outbound authoritative feed;
- per-page transactional import with persisted `resumeCursor` and idempotent replay handling;
- worker entrypoint: `python -m src.license_facade_service.worker`;
- imported records are persisted as `is_authoritative=false` and are not re-exported via outbound authoritative catalog/changes.

Security behavior:

- no automatic peer enrollment;
- no blind TOFU in production (`FEDERATION_DEMO_TOFU_UNSAFE` is explicit and disabled by default);
- unknown/revoked peer keys are rejected;
- duplicate JSON keys are rejected before Pydantic validation;
- outbound sync HTTP enforces bounded timeouts, size limits, strict content types, and DNS/IP policy checks.

DNS rebinding note:

- requests re-resolve and validate addresses before each call, but the default HTTP client may still perform its own DNS lookup at connect time; production deployment must additionally enforce egress network policy to trusted destinations.

## Federation Phase 4 (local resolution + RDF outbox)

Implemented:

- `GET /api/v1/licenses/resolution`
- `GET /api/v1/licenses/provenance`
- canonical content negotiation for HTML, SPDX JSON, JSON-LD, Turtle, and RDF/XML;
- local authoritative records always win over imported candidates;
- imported snapshots are immutable and resolved through separate provenance/history state;
- RDF graph URIs are deterministic per record/decision:
  - `urn:lfs:graph:record:{recordId}`
  - `urn:lfs:graph:provenance:{recordId}`
  - `urn:lfs:graph:decision:{conflictId}`
- outbox statuses: `pending`, `running`, `succeeded`, `retryable_failed`, `dead_lettered`, `superseded`;
- worker mode: `python -m src.license_facade_service.rdf_worker` for continuous or one-shot processing;
- maintenance commands: `process`, `retry`, `requeue`, `rebuild`, `reconcile`;
- Fuseki outages do not block PostgreSQL resolution; failed RDF jobs retry with leases/backoff and can be dead-lettered;
- rebuild/reconcile operate only on graphs owned by this service.
