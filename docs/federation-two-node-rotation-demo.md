# Two-node federation rotation demo (manual curl/Postman guide)

This guide mirrors the automated `scripts/demo-federation.sh` Step 6 flow with explicit operator calls.

Use placeholders only:

- `<ADMIN_TOKEN_A>`
- `<ADMIN_TOKEN_B>`
- `<PEER_ID_ON_B>`
- `<A2_FINGERPRINT_SHA256>` (format `sha256:<lowercase-hex>`)
- `<ISO8601_ACTIVATE_AT_UTC>`

## 1. Inspect initial inventory

1. Node A discovery:
   - `GET http://localhost:12114/.well-known/lfs`
2. Node A JWKS:
   - `GET http://localhost:12114/.well-known/jwks.json`
3. Node A local signing keys:
   - `GET /api/v1/admin/federation/signing-keys` (Node A admin token)
4. Node B trusted peer key inventory:
   - `GET /api/v1/admin/federation/peers/<PEER_ID_ON_B>/keys` (Node B admin token)

## 2. Stage A2 on Node A

1. Stage:
   - `POST /api/v1/admin/federation/signing-keys/stage`
   - body: `{"kid":"node-a-k2","expectedState":"staged","reason":"stage A2"}`
2. Verify staged/not active:
   - `GET /api/v1/admin/federation/signing-keys`
3. Verify discovery still reports A1:
   - `GET /.well-known/lfs`
4. Verify JWKS now includes A1 and A2, and ETag changed:
   - `GET /.well-known/jwks.json` (capture `ETag`)

## 3. Inspect A2 from Node B (no approval yet)

1. Inspect diff:
   - `POST /api/v1/admin/federation/peers/<PEER_ID_ON_B>/keys/inspect`
   - body: `{"reason":"inspect staged key"}`
2. Confirm A2 appears exactly once in `new[]`.
3. Do not approve yet.

## 4. Schedule activation (worker-driven)

1. Schedule A2:
   - `POST /api/v1/admin/federation/signing-keys/node-a-k2/schedule-activation`
   - body: `{"activateAt":"<ISO8601_ACTIVATE_AT_UTC>","expectedState":"staged","reason":"scheduled activation"}`
2. Poll Node A key inventory until:
   - A2 is `active`
   - A1 is `retired`
   - exactly one active key exists
   - schedule is cleared
   - A1 `rotatedToKid` is `node-a-k2`
3. Re-check:
   - discovery now reports A2
   - JWKS ETag changed again

## 5. Demonstrate unknown-key rejection on B

1. Publish new event on A (signed with A2).
2. On B, record cursor:
   - `GET /api/v1/admin/federation/peers/<PEER_ID_ON_B>/cursor`
3. Trigger sync on B:
   - `POST /api/v1/admin/federation/peers/<PEER_ID_ON_B>/sync`
4. Verify:
   - rejection/failed outcome with bounded error class
   - new A2-signed record not imported
   - cursor unchanged
   - previously imported records still resolve

## 6. Explicit approval on B and recovery sync

1. Approve A2 with exact fingerprint:
   - `POST /api/v1/admin/federation/peers/<PEER_ID_ON_B>/keys/approve`
   - body: `{"kid":"node-a-k2","expectedFingerprint":"<A2_FINGERPRINT_SHA256>","reason":"approve verified key"}`
2. If circuit is open/admin-reset-required:
   - `POST /api/v1/admin/federation/peers/<PEER_ID_ON_B>/circuit/reset`
   - body: `{"reason":"post-approval reset"}`
3. Trigger sync again:
   - `POST /api/v1/admin/federation/peers/<PEER_ID_ON_B>/sync`
4. Verify:
   - import succeeds
   - provenance points to Node A
   - imported records remain non-authoritative
   - cursor advances
   - repeated sync imports zero duplicates

## 7. Historical evidence and restart persistence

1. Confirm prior A1-signed record digest/signature evidence unchanged.
2. Confirm A1 remains in JWKS as retired.
3. Restart Node A API + Node A worker containers.
4. Verify after restart:
   - active key remains A2 from DB state
   - discovery reports A2
   - newly published record signs with A2
   - no duplicate activation audit is created

## 8. Safety checks to include in manual runs

- Wrong fingerprint approval must be rejected.
- `warningAck` missing/false must reject activate/emergency admin operations.
- Unauthenticated warningAck-false request must return `401`.
- Curator token on admin-only endpoint must return `403` (if curator token exists in your environment).
- Stage request must reject private-key/path fields (`422`).

Never place private PEM content, private-key bytes, or real bearer tokens in saved logs/screenshots.
