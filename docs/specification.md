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

## OpenREL integration (read-only facade)

Architecture:

- LFS implements a read-only, LFS-controlled proxy facade for external OpenREL provider resources.
- Public canonical prefix: `/openrel/api/v0.4`.
- Provider URL is deployment configuration (`OpenRelSettings`), not derived from caller input.

### Exact public operation contract

| Method | Path | Operation ID | `prefix` |
|---|---|---|---|
| GET | `/openrel/api/v0.4/actions` | `openrel_list_actions` | optional |
| GET | `/openrel/api/v0.4/actions/{id}` | `openrel_get_action` | optional |
| GET | `/openrel/api/v0.4/constraints` | `openrel_list_constraints` | none |
| GET | `/openrel/api/v0.4/constraints/{id}` | `openrel_get_constraint` | none |
| GET | `/openrel/api/v0.4/leftoperands` | `openrel_list_left_operands` | none |
| GET | `/openrel/api/v0.4/leftoperands/{id}` | `openrel_get_left_operand` | none |
| GET | `/openrel/api/v0.4/mappings` | `openrel_list_mappings` | optional |
| GET | `/openrel/api/v0.4/actionclasses` | `openrel_list_action_classes` | optional |
| GET | `/openrel/api/v0.4/actionclasses/{id}` | `openrel_get_action_class` | optional |
| GET | `/openrel/api/v0.4/assetclasses` | `openrel_list_asset_classes` | optional |
| GET | `/openrel/api/v0.4/assetclasses/{id}` | `openrel_get_asset_class` | optional |
| GET | `/openrel/api/v0.4/constraintclasses` | `openrel_list_constraint_classes` | optional |
| GET | `/openrel/api/v0.4/constraintclasses/{id}` | `openrel_get_constraint_class` | optional |
| GET | `/openrel/api/v0.4/leftoperandclasses` | `openrel_list_left_operand_classes` | optional |
| GET | `/openrel/api/v0.4/leftoperandclasses/{id}` | `openrel_get_left_operand_class` | optional |
| GET | `/openrel/api/v0.4/ruleclasses` | `openrel_list_rule_classes` | optional |
| GET | `/openrel/api/v0.4/ruleclasses/{id}` | `openrel_get_rule_class` | optional |

Exactly 13 operations support optional `prefix` (all except both `constraints` and both `leftoperands` routes).

### Response contracts

- List/detail resources use `OpenRELResource`; mappings list uses `OpenRELMapping`.
- `iri` is required and non-empty/non-whitespace.
- `label` and `definition` are optional, may be omitted, and are not nullable.
- Unknown provider fields are accepted as input and omitted from LFS output.
- Successful responses are unwrapped and preserve provider ordering.

### Upstream handling and error mapping

- Success requires upstream `200` with accepted JSON media type.
- Accepted content types are `application/json` and `application/*+json` (application subtype ending in `+json`).
- Redirects are forbidden.
- Timeouts/retries: bounded per-attempt timeouts plus bounded total timeout budget; retries for retryable transport/timeouts and 502/503/504 only.
- RFC 9457 `application/problem+json` mapping is centralized and stable, including: disabled/configuration, invalid ID/prefix, destination/DNS/connection/timeout, provider status classes, redirect/content/JSON/schema/shape/size failures.
- Rate-limited responses use an LFS-controlled bounded `Retry-After`; upstream header strings are never forwarded directly.

### SSRF and DNS policy

- Destination host is normalized and resolved per attempt.
- Loopback/private/link-local/multicast/reserved/unspecified and metadata destinations are blocked by default.
- Non-public demo destinations require allow-listed hostname + CIDR + port (+ HTTP demo flag where relevant).
- Redirect following is disabled.
- Residual DNS rebinding race remains possible between validation and connect; production egress controls are still required.

### Security boundaries and side effects

- Caller authorization/cookies are not forwarded upstream.
- OpenREL requests do not write PostgreSQL, federation state, or RDF/Fuseki graphs.
- OpenREL responses are not persisted and response caching is not implemented.
- OpenREL data is not imported into federation catalog/changes.

### Readiness semantics

- `/api/v1/ready` reports OpenREL as optional configuration readiness only:
  - disabled: `enabled=false`, `ready=null`, `errors=[]`;
  - enabled + config valid: `enabled=true`, `ready=true`, `errors=[]`;
  - enabled + config invalid: `enabled=true`, `ready=false`, sanitized errors.
- Readiness never probes OpenREL DNS/HTTP and does not affect overall service readiness when only OpenREL is invalid.
