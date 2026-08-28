# API Specification Note

This note aligns the implementation with `LICENCE FACADE SERVICE - Rights & Ethics.docx.pdf`.

## Normative ambiguity

The introductory prose suggests HTML as the default landing page, but **normative Table 2** defines the base `/licences/{id}` endpoint as the mandatory machine-readable metadata resource.  
This implementation follows the normative table:

- no `Accept` header → `application/json`
- no `Accept` header → `application/json`
- `Accept: */*` → `application/json`
- `Accept: text/html` → HTML
- unsupported media types → `406 application/problem+json`

`/api/v1/licences/{id}` is the specification alias; `/api/v1/licenses/{id}` is the documented implementation path.

## Conformance matrix

| PDF endpoint | Status | Implemented media type | When unavailable | Upstream limitation |
|---|---|---|---|---|
| `/licences/{id}` | Mandatory | negotiated; default JSON | `406` on unsupported `Accept` | none |
| `/licences/{id}/html` | Optional | `text/html` | 404/problem if unavailable | none |
| `/licences/{id}/json-ld` | Optional | `application/ld+json` | 404/problem if unavailable | none |
| `/licences/{id}/original` | Mandatory | redirect to curated `https://...` | 404/problem and conformance failure if missing | SPDX `reference` is **not** treated as original |
| `/licences/{id}/machine` | Mandatory | `application/ld+json`, `text/turtle`, or `application/rdf+xml` depending on curated rep | 404/problem and conformance failure if missing | SPDX metadata alone does **not** satisfy machine |
| `/licences/{id}/legal` | Optional | curated source-defined representation | 404/problem if unavailable | no invented legal code |
| `/licences/{id}/encoding` | Optional | redirect to curated encoding URL | 404/problem if unavailable | no invented encoding URL |

## Table 4 response fields

Detailed JSON metadata includes:

- `uri`
- `referenceNumber`
- `licenseId` / `licenseID` / `licenceID`
- `name`
- `detailsURL` (local `/licenses/{id}/json`)
- `spdxDetailsURL` (upstream SPDX details URL)
- `reference`
- `isDeprecatedLicenseId` / `isDeprecatedLicenseID`
- `seeAlso`
- `isOsiApproved`
- `licenseText`
- `standardLicenseTemplate`
- `licenseTextHtml`
- `crossRef`
- `representations`
- `representationStatus`
- `conformance`
- `_links`

Missing mandatory fields are not fabricated; the record is marked non-conformant instead.

## Table 6 mappings

- `detailsURL` → `/api/v1/licenses/{id}/json`
- `crossRef[type=original]` → `/api/v1/licenses/{id}/original`
- `crossRef[type=machine]` → `/api/v1/licenses/{id}/machine`
- `crossRef[type=legal]` → `/api/v1/licenses/{id}/legal`

Upstream SPDX cross-references are preserved with provenance/source fields.

## REL validation

The implementation validates RELs syntactically and by registered vocabulary/profile IRIs:

- ODRL
- ccREL
- DALICC
- OpenREL
- Dublin Core where allowed
- schema.org for agents/concepts/things

This is **syntax/vocabulary validation only**, not legal or semantic validation.

## Federation Phase 1 foundation

Implemented in this phase:

- PostgreSQL schema + Alembic migrations for federation state tables.
- Feature flag: `FEDERATION_ENABLED`.
- Validated node identity from configuration (no request-header derivation).
- Persisted node identity fingerprint/state for configuration drift detection.
- Ed25519 signing-key loading from configured file/secret path.
- Public-key metadata persistence (`kid`, `alg`, status, validity).
- Typed JWKS service and optional `/.well-known/jwks.json` endpoint.
- Canonical licence identity utility using UUIDv5 with fixed namespace.
- Canonical JSON (RFC 8785/JCS) + SHA-256 digest helpers.
- Typed federation peer/provenance/record/change-event models.

Compatibility decision:

- With `FEDERATION_ENABLED=false`, the current public licence API remains operational without federation configuration, PostgreSQL, or signing keys.

## Federation Phase 2 outbound protocol

Implemented:

- `GET /.well-known/lfs`
- `GET /.well-known/jwks.json`
- `GET /api/v1/federation/catalog`
- `GET /api/v1/federation/changes`
- `GET /api/v1/federation/records/{encoded_id}`

### Signed immutable payloads

- Canonicalization: RFC 8785 / JCS
- Encoding: UTF-8 bytes
- Digest: SHA-256 hex over canonical bytes
- Signature: Ed25519 (EdDSA), base64url signature, with `kid` and `alg`

Signed record payload fields:

- `nodeId`
- `canonicalId`
- `authorityNodeId`
- `localId`
- `version`
- `publicationState`
- `publishedAt`
- `payload`
- `payloadDigestSha256`

Signed change-event payload fields:

- `nodeId`
- `eventId`
- `eventPosition` (database-generated monotonic sequence)
- `operation` (`upsert|deprecate|tombstone`)
- `generatedAt`
- `record` (signed record payload structure)
- `provenance` (`publication|backfill`)
- `backfillCreatedAt` (optional)

### Cursor format and watermark

- Opaque cursor token format: `v{n}.{kid}.{payload_b64url}.{sig_b64url}`
- Cursor payload contains pagination state only (kind, node, watermark, after/last keys).
- `changes` uses position cursor (`since` means strictly after position).
- `catalog` uses keyset cursor plus snapshot watermark (max event sequence seen at initial page).
- Later pages are constrained to the cursor watermark to prevent mid-traversal inserts from causing skips/duplicates.

### ETag and conditional requests

- Strong ETags are derived from deterministic canonical response bytes.
- `If-None-Match` is supported (lists and `*`).
- `304` responses are body-empty and include `ETag` and `Cache-Control`.

### Backfill

- Backfill is explicit and separate from GET/startup.
- Command path: `src/license_facade_service/federation/backfill.py`
- Defaults to dry-run; write mode requires explicit confirmation; idempotent.

## Federation Phase 3 inbound synchronization

Implemented Phase 3 boundaries:

- trusted peers are explicitly admin-enrolled; automatic enrollment is not implemented;
- peer trust material is pinned (node ID + verification key `kid` + fingerprint);
- inbound synchronization uses `/changes` paging with `nextCursor` traversal and persisted `resumeCursor`;
- per-page transactional import: if one page fails, that page and cursor update roll back, prior committed pages remain;
- remote event positions are required to be strictly increasing for newly accepted events, but sequence gaps are allowed;
- duplicate JSON keys are rejected before schema validation;
- imported records are stored with `is_authoritative=false`, provenance metadata, and verification status;
- imported events are stored in dedicated inbound tables and are never inserted into outbound `federation_change_events`.

Security notes:

- unknown/revoked peer keys are rejected;
- HTTPS-only by default (demo profile may allow HTTP with explicit config);
- SSRF protections validate resolved addresses and reject loopback/private/link-local/metadata ranges by default;
- DNS is revalidated per request; deployment should still enforce outbound network policy to close resolver-to-connect rebinding gaps.

## Federation Phase 4 resolution and RDF outbox

Implemented Phase 4 boundaries:

- `GET /api/v1/licenses/resolution?identifier=...` and `GET /api/v1/licenses/provenance?identifier=...` are the canonical arbitrary-identifier lookups.
- Path lookup remains available for simple IDs, but query lookup is preferred for identifiers containing `/`, `:`, `#`, `?`, or encoded characters.
- Local authoritative records always win; imported candidates are resolvable only when no local authoritative record is selected.
- Imported records are immutable snapshots; signed inbound source/event history is preserved separately from current resolution state.
- Canonical success outcomes are `200`, `404`, `409`, `410`, and `503` with RFC 9457 problem details for errors.
- RDF graph ownership is per-record and per-conflict:
  - `urn:lfs:graph:record:{recordId}`
  - `urn:lfs:graph:provenance:{recordId}`
  - `urn:lfs:graph:decision:{conflictId}`
- Outbox statuses are `pending`, `running`, `succeeded`, `retryable_failed`, `dead_lettered`, and `superseded`.
- Lease ownership is tracked in PostgreSQL and skipped by competing claimers; a stale or superseded job never overwrites newer graph state.
- PostgreSQL remains the source of truth; Fuseki outages do not block resolution, publication, or imported-history lookup.
- Worker/maintenance operations are bounded and explicit:
  - `python -m src.license_facade_service.rdf_worker`
  - `python -m src.license_facade_service.federation.maintenance process`
  - `retry`
  - `requeue`
  - `rebuild`
  - `reconcile`

## Federation Phase 5 Increment 3-4 synchronization and peer-key trust hardening

Implemented boundaries:

- synchronization coordination uses persisted per-peer leases with fencing tokens (no long-held advisory lock during HTTP traversal);
- lease claim and release are short transactions, and page commit re-verifies owner/token/expiry against PostgreSQL time;
- remote discovery/JWKS/changes/record HTTP is executed outside DB transactions;
- cursor advancement is atomic with per-page import commit and lease renewal;
- transient/permanent peer circuit states (`closed`, `open`, `half_open`) govern synchronization/probe eligibility;
- admin controls exist for suspend/resume, circuit reset, and read-only probe;
- health snapshots and operational audit events are persisted for explicit probe and actual synchronization attempts;
- peer-key trust is operator-controlled with explicit endpoints for inventory, remote inspection, approval, retirement, and revocation;
- remote key inspection is read-only and deterministic with mutually exclusive category precedence `invalid -> changed -> expired -> known/new/removed`; inspection does not mutate trusted keys, cursor, or import state;
- explicit approval requires exact `sha256:<hex>` fingerprint confirmation and rejects same-kid/different-material collisions;
- collision rejection opens a permanent circuit (`key_collision`) requiring admin reset;
- inbound event authorization for new imports requires `active` peer keys and DB-time validity windows (`valid_from` is null or `<= now`; `valid_until` is null or `now < valid_until`), using a single PostgreSQL timestamp per page verification path;
- Key eligibility is checked again using PostgreSQL time in the fenced page-commit transaction.
- `signing-key-not-yet-valid` and `signing-key-expired` are treated as permanent trust/integrity failures and map to permanent identity-mismatch circuit classification;
- historical-evidence verification remains cryptographic-only and never authorizes imports, cursor movement, or state mutation;
- enrollment `expected_key_kid` / `expected_key_fingerprint` remain enrollment evidence and are not silently overwritten by approval.

Deferred from Increment 4:

- local signing-key rotation operations (Increment 5);
- cursor replay/checkpoint/recovery tooling;
- RDF recovery additions beyond existing outbox behavior;
- rate limiting, metrics, and expanded production logging;
- additional protocol compatibility enforcement.
