# Migration note

## Behavior changes

1. `GET /api/v1/licenses/{id}` now defaults to JSON for no `Accept` or `*/*`.
2. `text/html` is explicit only.
3. `/original` no longer falls back to SPDX `reference`; missing curated originals are reported as non-conformant.
4. `/machine` requires curated REL metadata; SPDX JSON alone does not satisfy it.
5. Detailed JSON now exposes `spdxDetailsURL`, `representationStatus`, `conformance`, and Table 6 cross-reference mappings.
6. British `/api/v1/licences/*` aliases remain available but are hidden from OpenAPI.
7. Cached SPDX snapshots remain the source of inventory/details; curated representations live in a separate local store.
8. Federation Phase 1 adds PostgreSQL/Alembic schema and feature-gated runtime wiring without changing public licence endpoint semantics.
9. Federation identity (`NODE_ID`, public base URL, node name, operator) is configuration-driven and fingerprinted; drift is detected and reported as not ready.
10. Federation signing keys are loaded from file/secret path (Ed25519) and only public metadata is persisted.
11. Canonical federation digests now use RFC 8785/JCS canonical JSON before SHA-256.
12. Federation Phase 2 adds authoritative outbound federation endpoints (`/.well-known/lfs`, `/.well-known/jwks.json`, catalog, changes, record).
13. Federation GET endpoints are read-only and do not create change events.
14. Change events are append-only and sequence-ordered by a database-generated monotonic position.
15. Cursor pagination is opaque, versioned, signature-verified, and watermark-bounded for deterministic traversal.
