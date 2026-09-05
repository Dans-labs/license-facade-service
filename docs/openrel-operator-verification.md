# OpenREL operator verification checklist

This checklist is for manual verification of the currently implemented LFS **0.3.5** OpenREL workflow. Use placeholders only; do not paste real secrets into screenshots, tickets, or committed files.

Example hosts:

- Node A / DANS: `https://lfs.labs.dansdemo.nl`
- Node B / RDA: `https://lfs.rda.dansdemo.nl`

## A. Prerequisites

### A1. PostgreSQL and migrations

- [ ] PostgreSQL is reachable
- [ ] Alembic migrations are at head `20260904_03`
- [ ] OpenREL policy tables, federation tables, and custom-licence tables exist

Verify:

```bash
uv run alembic -c alembic.ini heads
```

Expected result:

- head includes `20260904_03`

### A2. Admin token

- [ ] you have an admin bearer token
- [ ] you can authenticate to `/docs` protected operations or admin endpoints

Placeholder header:

```text
Authorization: Bearer <OPENREL_ADMIN_TOKEN>
```

### A3. Optional OpenREL configuration

- [ ] if OpenREL is enabled, the provider URL is configured with placeholders only in documentation and deployment manifests
- [ ] provider base URL is HTTPS in production
- [ ] provider unavailability does not block public licence retrieval

### A4. Optional federation and Fuseki services

- [ ] federation publisher is configured if federated apply/rollback will be tested
- [ ] RDF worker/Fuseki are configured if RDF indexing will be observed
- [ ] operators understand both are asynchronous dependencies

## B. Local workflow

### B1. Health and readiness

```bash
curl -sS https://lfs.labs.dansdemo.nl/api/v1/health
curl -sS https://lfs.labs.dansdemo.nl/api/v1/ready
```

Expected status:

- `200`

Expected result:

- service is healthy
- readiness reflects configured subsystems without requiring a live OpenREL provider mutation path

### B2. Register a local licence

```bash
curl -sS -X POST 'https://lfs.labs.dansdemo.nl/api/v1/licenses' \
  -H 'Authorization: Bearer <LFS_CURATOR_TOKEN>' \
  -H 'Content-Type: application/json' \
  -d '{
    "requestedLicenseId": "DANS-LOCAL-VERIFY-1.0",
    "version": "1.0",
    "name": "DANS Local Verify 1.0",
    "summary": "Local verification licence.",
    "description": "Manual operator verification example.",
    "licenseText": "Example local licence text.",
    "scope": "local"
  }'
```

Postman summary:

- Method: `POST`
- URL: `https://lfs.labs.dansdemo.nl/api/v1/licenses`
- Headers:
  - `Authorization: Bearer <LFS_CURATOR_TOKEN>`
  - `Content-Type: application/json`
- Expected status: `201`

Expected observable result:

- local custom licence is created
- `federationStatus=not_published`

### B3. Create evaluation

```bash
curl -sS -X POST 'https://lfs.labs.dansdemo.nl/api/v1/admin/openrel/evaluations' \
  -H 'Authorization: Bearer <OPENREL_ADMIN_TOKEN>' \
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

Postman summary:

- Method: `POST`
- URL: `https://lfs.labs.dansdemo.nl/api/v1/admin/openrel/evaluations`
- Headers:
  - `Authorization: Bearer <OPENREL_ADMIN_TOKEN>`
  - `Content-Type: application/json`
- Expected status: `200`

Expected observable result:

- response includes policy classification and `policyStateId`
- licence content is unchanged after evaluation

### B4. Inspect policy state and events

```bash
curl -sS -H 'Authorization: Bearer <OPENREL_ADMIN_TOKEN>' \
  'https://lfs.labs.dansdemo.nl/api/v1/admin/openrel/policy-states'

curl -sS -H 'Authorization: Bearer <OPENREL_ADMIN_TOKEN>' \
  'https://lfs.labs.dansdemo.nl/api/v1/admin/openrel/policy-states/<STATE_ID>'

curl -sS -H 'Authorization: Bearer <OPENREL_ADMIN_TOKEN>' \
  'https://lfs.labs.dansdemo.nl/api/v1/admin/openrel/policy-states/<STATE_ID>/events'
```

Expected status:

- `200`

Expected observable result:

- sanitized persisted state metadata
- append-only event history

### B5. Approve

```bash
curl -sS -X POST 'https://lfs.labs.dansdemo.nl/api/v1/admin/openrel/policy-states/<STATE_ID>/approve' \
  -H 'Authorization: Bearer <OPENREL_ADMIN_TOKEN>' \
  -H 'Content-Type: application/json' \
  -d '{"reason":"Approve after manual review"}'
```

Expected status:

- `200`

Expected observable result:

- status changes to `approved`
- no licence mutation yet

### B6. Apply

```bash
curl -sS -X POST 'https://lfs.labs.dansdemo.nl/api/v1/admin/openrel/policy-states/<STATE_ID>/apply' \
  -H 'Authorization: Bearer <OPENREL_ADMIN_TOKEN>' \
  -H 'Content-Type: application/json' \
  -d '{"reason":"Apply approved state"}'
```

Expected status:

- `200`

Expected observable result:

- local licence changes
- one `applied` policy event is added
- response contains safe metadata only

### B7. Inspect changed licence

```bash
curl -sS 'https://lfs.labs.dansdemo.nl/api/v1/licenses/<LICENCE_ID>/json'
```

Expected status:

- `200`

Expected observable result:

- public representation matches applied content

### B8. Roll back

```bash
curl -sS -X POST 'https://lfs.labs.dansdemo.nl/api/v1/admin/openrel/policy-states/<STATE_ID>/rollback' \
  -H 'Authorization: Bearer <OPENREL_ADMIN_TOKEN>' \
  -H 'Content-Type: application/json' \
  -d '{"reason":"Rollback applied state"}'
```

Expected status:

- `200`

Expected observable result:

- one `rolled-back` policy event is added
- response contains safe metadata only

### B9. Verify restored licence

```bash
curl -sS 'https://lfs.labs.dansdemo.nl/api/v1/licenses/<LICENCE_ID>/json'
```

Expected status:

- `200`

Expected observable result:

- current public licence payload matches the pre-apply state

## C. Federated workflow

### C1. Register and publish federated licence on Node A

```bash
curl -sS -X POST 'https://lfs.labs.dansdemo.nl/api/v1/licenses' \
  -H 'Authorization: Bearer <LFS_CURATOR_TOKEN>' \
  -H 'Content-Type: application/json' \
  -d '{
    "requestedLicenseId": "DANS-FED-VERIFY-1.0",
    "version": "1.0",
    "name": "DANS Federated Verify 1.0",
    "summary": "Federated verification example.",
    "description": "Authoritative on Node A.",
    "licenseText": "Example federated licence text.",
    "scope": "federated"
  }'
```

Expected status:

- `201`

Expected observable result:

- initial `federationStatus=pending`
- later `published` after worker processing

### C2. Evaluate, approve, and apply on Node A

Repeat the local OpenREL evaluation/review/apply steps against `https://lfs.labs.dansdemo.nl`.

Expected observable result:

- local authoritative licence mutates on Node A
- one new federation change event is created for the apply revision

### C3. Verify new federation change event

```bash
curl -sS 'https://lfs.labs.dansdemo.nl/api/v1/federation/changes'
```

Expected status:

- `200`

Expected observable result:

- a new authoritative upsert event exists for the record

### C4. Trigger synchronization on Node B

Use the existing federation admin workflow on Node B.

Postman summary:

- Method: `POST`
- URL: `https://lfs.rda.dansdemo.nl/api/v1/admin/federation/peers/<PEER_ID>/sync`
- Headers:
  - `Authorization: Bearer <OPENREL_ADMIN_TOKEN>`
- Expected status: implementation-specific success/problem response according to peer state

Expected observable result:

- Node B imports the latest authoritative revision after trust prerequisites are satisfied

### C5. Verify imported copy is non-authoritative

Expected observable result on Node B:

- imported record exists
- imported record remains non-authoritative
- Node B does not present the import as its own authoritative publication

### C6. Verify provenance

Expected observable result:

- provenance identifies imported history and authoritative source node
- no review/apply reason is present in federation payload or provenance

### C7. Roll back on Node A and synchronize Node B again

Repeat rollback on Node A, then rerun synchronization on Node B.

Expected observable result:

- Node A appends a restoring authoritative revision
- Node B imports that restoring revision on the next synchronization cycle

## D. RDF workflow

### D1. Observe queued job

Expected observable result:

- after federated publication/apply/rollback, RDF outbox work exists in PostgreSQL before Fuseki is updated

### D2. Run RDF worker

```bash
uv run python -m src.license_facade_service.rdf_worker
```

Expected observable result:

- pending RDF jobs are processed asynchronously

### D3. Verify named graph update

Expected observable result:

- record/provenance graphs reflect the latest authoritative state after worker success

### D4. Demonstrate service continuity while Fuseki is offline

Expected observable result:

- public and admin PostgreSQL-backed behavior remains available
- RDF jobs fail/retry asynchronously rather than blocking API requests

### D5. Restore Fuseki and retry

Expected observable result:

- queued or retried jobs succeed after connectivity is restored

## E. Failure demonstrations

### E1. Unauthorized request

```bash
curl -i -X POST 'https://lfs.labs.dansdemo.nl/api/v1/admin/openrel/policy-states/<STATE_ID>/apply' \
  -H 'Content-Type: application/json' \
  -d '{}'
```

Expected status:

- `401`

### E2. Extra request field

```bash
curl -i -X POST 'https://lfs.labs.dansdemo.nl/api/v1/admin/openrel/policy-states/<STATE_ID>/apply' \
  -H 'Authorization: Bearer <OPENREL_ADMIN_TOKEN>' \
  -H 'Content-Type: application/json' \
  -d '{"candidatePayload":{"x":1}}'
```

Expected status:

- `422`

### E3. Malformed or oversized reason

```bash
curl -i -X POST 'https://lfs.labs.dansdemo.nl/api/v1/admin/openrel/policy-states/<STATE_ID>/apply' \
  -H 'Authorization: Bearer <OPENREL_ADMIN_TOKEN>' \
  -H 'Content-Type: application/json' \
  -d '{"reason":"{\"token\""}'
```

Expected status:

- `409`

Oversized reason body:

- expected status: `422`

### E4. Missing policy state

```bash
curl -i -X POST 'https://lfs.labs.dansdemo.nl/api/v1/admin/openrel/policy-states/00000000-0000-0000-0000-000000000000/apply' \
  -H 'Authorization: Bearer <OPENREL_ADMIN_TOKEN>' \
  -H 'Content-Type: application/json' \
  -d '{}'
```

Expected status:

- `404`

### E5. Invalid lifecycle transition

Expected demonstration:

- try `apply` before approval, or `rollback` before apply

Expected status:

- `409`

### E6. Unavailable federation publisher

Expected demonstration:

- call federated apply/rollback when federation publication dependencies are not ready

Expected status:

- `503`

### E7. Offline OpenREL provider

Expected demonstration:

- disable or isolate provider reachability, then submit evaluation

Expected result:

- evaluation fails closed or returns review-required/no-op planning behavior
- no automatic mutation occurs

### E8. Idempotent retry

Expected demonstration:

- repeat exact apply or rollback after the first success

Expected status:

- `200`

Expected observable result:

- existing state is returned
- no duplicate transition event is added

## OpenAPI checklist

Verify `/openapi.json` or Swagger contains exactly these OpenREL admin paths:

- `POST /api/v1/admin/openrel/evaluations`
- `GET /api/v1/admin/openrel/policy-states`
- `GET /api/v1/admin/openrel/policy-states/{state_id}`
- `GET /api/v1/admin/openrel/policy-states/{state_id}/events`
- `POST /api/v1/admin/openrel/policy-states/{state_id}/approve`
- `POST /api/v1/admin/openrel/policy-states/{state_id}/reject`
- `POST /api/v1/admin/openrel/policy-states/{state_id}/apply`
- `POST /api/v1/admin/openrel/policy-states/{state_id}/rollback`
