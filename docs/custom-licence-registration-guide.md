# Registering a Custom Licence in LFS

This guide describes the implemented LFS **0.3.5** workflow for local and federated custom licences, OpenREL evaluation, admin review, apply, rollback, federation revision observation, and asynchronous RDF indexing.

## 1. Prerequisites

You need:

- a running LFS instance
- PostgreSQL migrated to Alembic head `20260904_03`
- a curator or admin bearer token for `POST /api/v1/licenses`
- an admin bearer token for OpenREL review/apply/rollback
- optional OpenREL placeholder configuration
- optional federation and Fuseki services for federated/RDF demonstrations

Example placeholders:

```bash
export LFS_URL='https://lfs.labs.dansdemo.nl'
export LFS_ADMIN_TOKEN='<OPENREL_ADMIN_TOKEN>'
export LFS_CURATOR_TOKEN='<LFS_CURATOR_TOKEN>'
```

## 2. Register a local custom licence

```bash
curl -sS -X POST "$LFS_URL/api/v1/licenses" \
  -H "Authorization: Bearer $LFS_CURATOR_TOKEN" \
  -H 'Content-Type: application/json' \
  -d '{
    "requestedLicenseId": "DANS-Custom-Local-1.0",
    "version": "1.0",
    "name": "DANS Custom Local License 1.0",
    "summary": "Local custom licence example.",
    "description": "Stored only on this node.",
    "licenseText": "Example local licence text.",
    "scope": "local",
    "aliases": ["DANS Custom Local"]
  }'
```

Expected result:

- `201 Created`
- `scope=local`
- `federationStatus=not_published`
- `lifecycleStatus=registered`

## 3. Register a federated custom licence

```bash
curl -sS -X POST "$LFS_URL/api/v1/licenses" \
  -H "Authorization: Bearer $LFS_CURATOR_TOKEN" \
  -H 'Content-Type: application/json' \
  -d '{
    "requestedLicenseId": "DANS-Custom-Federated-1.0",
    "version": "1.0",
    "name": "DANS Custom Federated License 1.0",
    "summary": "Federated custom licence example.",
    "description": "Published asynchronously by worker.",
    "licenseText": "Example federated licence text.",
    "scope": "federated",
    "aliases": ["DANS Custom Federated"]
  }'
```

Expected result:

- `201 Created`
- `scope=federated`
- initial `federationStatus=pending`
- no synchronous peer synchronization

## 4. Evaluate an existing custom licence against OpenREL

Evaluation compares an externally supplied OpenREL candidate with local policy rules. It does **not** mutate the licence.

```bash
curl -sS -X POST "$LFS_URL/api/v1/admin/openrel/evaluations" \
  -H "Authorization: Bearer $LFS_ADMIN_TOKEN" \
  -H 'Content-Type: application/json' \
  -d '{
    "canonicalLicenseId": "lic-eval-1",
    "sourceKind": "custom",
    "sourceRecordRef": "<CUSTOM_LICENCE_UUID>",
    "registrationTimestamp": "2026-09-05T12:00:00Z",
    "candidatePayload": {"candidate": 1},
    "candidate": {
      "providerUrl": "https://openrel.example.invalid/openrel/api/v0.4",
      "profile": "https://openrel.org/ns#",
      "vocabulary": "https://openrel.org/ns#",
      "version": "0.4",
      "content": "<openrel>candidate</openrel>",
      "href": "https://openrel.example.invalid/openrel/api/v0.4/licence/123",
      "provenance": "candidate provenance",
      "mappingProfile": "https://openrel.org/ns#",
      "mappingProvenance": "mapping provenance"
    },
    "originalRepresentation": {"profile": "https://example.invalid/original-profile"},
    "originalContentDigest": null
  }'
```

Expected result:

- `200 OK`
- a policy classification and plan
- `policyStateId` when persisted
- no licence mutation yet

## 5. Review the persisted policy state and events

```bash
curl -sS -H "Authorization: Bearer $LFS_ADMIN_TOKEN" \
  "$LFS_URL/api/v1/admin/openrel/policy-states"

curl -sS -H "Authorization: Bearer $LFS_ADMIN_TOKEN" \
  "$LFS_URL/api/v1/admin/openrel/policy-states/<STATE_ID>"

curl -sS -H "Authorization: Bearer $LFS_ADMIN_TOKEN" \
  "$LFS_URL/api/v1/admin/openrel/policy-states/<STATE_ID>/events"
```

Expected result:

- `200 OK`
- sanitized state metadata only
- append-only sanitized event history

## 6. Approve or reject the policy state

Approve:

```bash
curl -sS -X POST "$LFS_URL/api/v1/admin/openrel/policy-states/<STATE_ID>/approve" \
  -H "Authorization: Bearer $LFS_ADMIN_TOKEN" \
  -H 'Content-Type: application/json' \
  -d '{"reason":"Approve after review"}'
```

Reject:

```bash
curl -sS -X POST "$LFS_URL/api/v1/admin/openrel/policy-states/<STATE_ID>/reject" \
  -H "Authorization: Bearer $LFS_ADMIN_TOKEN" \
  -H 'Content-Type: application/json' \
  -d '{"reason":"Reject after review"}'
```

Expected result:

- `200 OK`
- state status changes to `approved` or `rejected`
- no licence mutation yet

## 7. Apply an approved state

The request accepts only an optional `reason`. Candidate content, digests, mapping data, actor identity, or target overrides are rejected.

```bash
curl -sS -X POST "$LFS_URL/api/v1/admin/openrel/policy-states/<STATE_ID>/apply" \
  -H "Authorization: Bearer $LFS_ADMIN_TOKEN" \
  -H 'Content-Type: application/json' \
  -d '{"reason":"Apply approved OpenREL policy state"}'
```

Expected result:

- `200 OK`
- local target updated for local scope
- or local target updated plus federated revision enqueued for published federated scope
- exact retry returns `200` without duplicate transition events

## 8. Roll back an applied state

```bash
curl -sS -X POST "$LFS_URL/api/v1/admin/openrel/policy-states/<STATE_ID>/rollback" \
  -H "Authorization: Bearer $LFS_ADMIN_TOKEN" \
  -H 'Content-Type: application/json' \
  -d '{"reason":"Rollback applied OpenREL policy state"}'
```

Expected result:

- `200 OK`
- target restored from the stored pre-apply snapshot
- for published federated scope, a restoring federation revision is appended and RDF work is enqueued asynchronously
- exact retry returns `200` without duplicate rollback transition events

## 9. Observe the changed licence

Use the normal public licence endpoint after apply or rollback:

```bash
curl -sS "$LFS_URL/api/v1/licenses/<LICENCE_ID>/json"
```

Expected result:

- applied state: updated current payload
- rolled-back state: restored pre-apply payload

## 10. Observe federation synchronization on another node

Node A publishes authoritative revisions. Node B later pulls them asynchronously.

Example placeholder hosts:

- Node A: `https://lfs.labs.dansdemo.nl`
- Node B: `https://lfs.rda.dansdemo.nl`

After Node A publishes a federated licence or federated OpenREL apply/rollback revision:

1. confirm Node A exposes a new federation change event
2. run Node B synchronization with the existing federation admin workflow
3. verify Node B stores the result as imported and non-authoritative
4. verify Node B does not re-export the imported record as its own authority

This is pull-based synchronization; the Node A API request does not synchronously update Node B.

## 11. Observe asynchronous RDF indexing

RDF work is queued by registration/publication/apply/rollback transactions but processed later by the RDF worker.

Operational boundary:

- admin apply/rollback never calls Fuseki synchronously
- PostgreSQL remains the source of truth while RDF jobs are pending or while Fuseki is offline

## 12. Postman-friendly request summary

### Create evaluation

- Method: `POST`
- URL: `{{lfs_base_url}}/api/v1/admin/openrel/evaluations`
- Headers:
  - `Authorization: Bearer {{lfs_admin_token}}`
  - `Content-Type: application/json`
- Body: same JSON as the evaluation example above
- Expected status: `200`

### Approve

- Method: `POST`
- URL: `{{lfs_base_url}}/api/v1/admin/openrel/policy-states/{{state_id}}/approve`
- Headers:
  - `Authorization: Bearer {{lfs_admin_token}}`
  - `Content-Type: application/json`
- Body:

```json
{"reason":"Approve after review"}
```

- Expected status: `200`

### Apply

- Method: `POST`
- URL: `{{lfs_base_url}}/api/v1/admin/openrel/policy-states/{{state_id}}/apply`
- Headers:
  - `Authorization: Bearer {{lfs_admin_token}}`
  - `Content-Type: application/json`
- Body:

```json
{"reason":"Apply approved OpenREL policy state"}
```

- Expected status: `200`

### Rollback

- Method: `POST`
- URL: `{{lfs_base_url}}/api/v1/admin/openrel/policy-states/{{state_id}}/rollback`
- Headers:
  - `Authorization: Bearer {{lfs_admin_token}}`
  - `Content-Type: application/json`
- Body:

```json
{"reason":"Rollback applied OpenREL policy state"}
```

- Expected status: `200`

## 13. Safety boundaries

The examples above do **not** imply any of the following:

- direct licence mutation from the evaluation request
- automatic trust because the provider is reachable
- synchronous federation peer synchronization
- synchronous Fuseki updates
- mutation of SPDX or imported licences

## 14. Common failures

- `401`: missing or invalid bearer token
- `403`: authenticated caller lacks required role
- `404`: missing policy state or persisted target
- `409`: invalid transition, stale target, digest mismatch, linkage conflict, unsupported lifecycle
- `422`: malformed request, extra fields, oversized reason
- `503`: otherwise-valid federated apply/rollback cannot proceed because required federation publisher or payload configuration is unavailable
