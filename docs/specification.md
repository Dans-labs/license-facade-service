# API Specification Note

This note aligns the implementation with `LICENCE FACADE SERVICE - Rights & Ethics.docx.pdf`.

## Normative ambiguity

The introductory prose suggests HTML as the default landing page, but **normative Table 2** defines the base `/licences/{id}` endpoint as the mandatory machine-readable metadata resource.  
This implementation follows the normative table:

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
