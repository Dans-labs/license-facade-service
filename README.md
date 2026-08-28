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
- one of:
  - `FEDERATION_SIGNING_KEY_DIR` (directory provider, Increment 5 default)
  - `FEDERATION_SIGNING_KEY_PATH`
  - `FEDERATION_SIGNING_KEY_SECRET_PATH`

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

## Federation Phase 5 Increment 3-5 (lease-fenced sync + peer-key trust workflow + scheduled local-key rotation)

Implemented:

- synchronization uses persisted per-peer leases with globally monotonic fencing tokens;
- lease claim/load/network/page-commit/release flow keeps all remote HTTP (discovery/JWKS/changes/records) outside DB transactions;
- per-page commit verifies lease ownership (peer + owner instance + fencing token + DB-time expiry) before import/cursor update;
- lease heartbeat/expiry are renewed at page commit; stale fencing aborts page commit and cursor advancement;
- circuit breaker states: `closed`, `open`, `half_open` with transient/permanent failure handling;
- admin-only controls:
  - `POST /api/v1/admin/federation/peers/{peer-id}/suspend`
  - `POST /api/v1/admin/federation/peers/{peer-id}/resume`
  - `POST /api/v1/admin/federation/peers/{peer-id}/circuit/reset`
  - `POST /api/v1/admin/federation/peers/{peer-id}/probe`
- health snapshots are appended after actual sync attempts and explicit probes;
- operational audit events are written for sync circuit transitions, probe, suspension/resume, circuit reset, and peer-key operations;
- admin-only peer-key trust workflow:
  - `GET /api/v1/admin/federation/peers/{peer-id}/keys`
  - `POST /api/v1/admin/federation/peers/{peer-id}/keys/inspect`
  - `POST /api/v1/admin/federation/peers/{peer-id}/keys/approve`
  - `POST /api/v1/admin/federation/peers/{peer-id}/keys/{kid}/retire`
  - `POST /api/v1/admin/federation/peers/{peer-id}/keys/{kid}/revoke`
- no blind TOFU or automatic key trust/replacement for existing peers; operators inspect, verify fingerprint out-of-band, then approve;
- inspect diff categories are deterministic and mutually exclusive with precedence `invalid -> changed -> expired -> known/new/removed`;
- same-kid/different-material approval is rejected and opens a permanent circuit requiring admin reset;
- inbound authorization for new events requires `active` peer keys and DB-time validity windows (`valid_from <= now < valid_until`, where bounds may be null);
- Key eligibility is checked again using PostgreSQL time in the fenced page-commit transaction.
- new inbound validity failures use bounded codes (`signing-key-not-yet-valid`, `signing-key-expired`) and map to permanent identity-trust circuit handling;
- historical verification is cryptographic evidence-only (including retired/expired/revoked material) and never authorizes imports or state mutation;
- enrollment `expectedKeyKid`/`expectedKeyFingerprint` remain enrollment evidence and are not silently overwritten by key approval.

Increment 5 scheduled activation worker:

- integrated into the existing `python -m src.license_facade_service.worker` loop (no separate scheduler process);
- worker can run in sync-only, rotation-only, or combined mode; outbound-only publisher nodes can run scheduled rotation with `FEDERATION_INBOUND_ENABLED=false` and `FEDERATION_ROTATION_WORKER_ENABLED=true`;
- each worker cycle runs enabled subsystems only and at most one scheduled rotation pass (`FEDERATION_ROTATION_MAX_OPERATIONS_PER_PASS=1`);
- rotation uses PostgreSQL time for due checks and lifecycle state transitions;
- private-key file loading happens before the locked activation transaction, and no filesystem I/O occurs while `FOR UPDATE` activation locks are held;
- races are idempotent (`no due`, `not due`, `already activated elsewhere`, `no longer due`, schedule canceled, or candidate retired/revoked during preparation) and do not switch keys incorrectly;
- benign race outcomes are treated as no-op (not failures): no activation-failed/material-mismatch audit, no error heartbeat, and no backoff penalty;
- retriable worker failures use bounded exponential backoff with optional jitter `[0.75, 1.25]`, permanent/operator-action failures use max backoff; rotation backoff does not delay peer synchronization scheduling;
- successful activation is followed by runtime signing verification (degraded status if post-commit verification fails);
- worker heartbeat updates stay on existing `sync` worker type with bounded status/error codes; idle/deferred no-op rotation states are not recorded as heartbeat errors.

Rotation worker settings:

- `FEDERATION_WORKER_INSTANCE_ID` (optional UUID for stable per-process worker identity; defaults to a generated UUID per startup and is distinct from federation node identity)
- `FEDERATION_ROTATION_WORKER_ENABLED` (default `true`)
- `FEDERATION_ROTATION_POLL_INTERVAL_SECONDS` (default `60`)
- `FEDERATION_ROTATION_FAILURE_BACKOFF_MIN_SECONDS` (default `30`)
- `FEDERATION_ROTATION_FAILURE_BACKOFF_MAX_SECONDS` (default `900`)
- `FEDERATION_ROTATION_BACKOFF_JITTER_ENABLED` (default `true`)
- `FEDERATION_ROTATION_MAX_OPERATIONS_PER_PASS` (must be `1`)

Two-node rotation demo (Compose profile `federation-demo`):

- Node A API + Node A rotation worker share only Node A read-only key directory (`FEDERATION_SIGNING_KEY_DIR`) and database.
- Node B API + Node B inbound worker share only Node B read-only key directory (`FEDERATION_SIGNING_KEY_DIR`) and database.
- No private-key directory is shared across nodes.
- The demo script (`./scripts/demo-federation.sh`) exercises staged A2 activation by Node A worker, unknown-key rejection on B with unchanged cursor, explicit key approval/reset, successful resync, historical A1 evidence checks, restart persistence, and output leak scanning.

Deferred beyond Increment 5:

- cursor replay/checkpoint tooling;
- RDF recovery enhancements beyond existing Phase 4 behavior;
- rate limiting / metrics / logging expansions;
- protocol-compatibility enforcement expansion;
- production compose hardening changes.
