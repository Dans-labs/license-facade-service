# Registering a Custom Licence in LFS

This guide shows how to register a new custom licence in License Facade Service (LFS) 0.3.0 using `curl`, Swagger UI, or Postman. It includes complete examples for all three registration scopes:

| Scope | Stored locally | Published for federation | Prepared for SPDX review |
|---|---:|---:|---:|
| `local` | Yes | No | No |
| `federated` | Yes | Yes, asynchronously | No |
| `spdx-submission` | Yes | No | Marked `ready_for_review` |

Registration does not send a licence to the official SPDX project and does not open a GitHub pull request.

## 1. Prerequisites

You need:

- a running LFS instance;
- PostgreSQL configured for custom-licence registration;
- an Alembic-migrated PostgreSQL schema (`uv run alembic -c alembic.ini upgrade head`);
- an LFS curator or administrator bearer token;
- `curl` and optionally `jq` for the command-line examples.

For local development, define at least:

```dotenv
LFS_ADMIN_TOKEN=change-this-admin-token
LFS_CURATOR_TOKEN=change-this-curator-token

CUSTOM_LICENCE_REGISTRATION_DATABASE_URL=postgresql+psycopg://lfs:lfs-password@localhost:5432/lfs
CUSTOM_LICENCE_AUTHORITY_ID=lfs-local-authority
CUSTOM_LICENCE_AUTHORITY_BASE_IRI=https://lfs.example
CUSTOM_LICENCE_CREATOR_ORGANIZATION_NAME=LFS Operator
CUSTOM_LICENCE_CREATOR_ORGANIZATION_IRI=https://lfs.example/spdx/agents/lfs-operator
```

Use deployment-specific values. Do not use the example passwords or tokens in production.

The normal Docker Compose `app` profile does not create a PostgreSQL service. Point `CUSTOM_LICENCE_REGISTRATION_DATABASE_URL` at an existing PostgreSQL database, or use the federation-demo profile described later in this guide.

## 2. Install or upgrade the database schema

```bash
uv run alembic -c alembic.ini upgrade head
```

In production Compose, the `lfs-migrate` service owns this step before API/workers start. For external PostgreSQL service deployments, run the command above before starting API/workers.

## 3. Start LFS and check readiness

Set reusable shell variables:

```bash
export LFS_URL='http://localhost:12104'
export LFS_TOKEN='change-this-curator-token'
```

Check health and readiness:

```bash
curl -sS "$LFS_URL/api/v1/health" | jq .
curl -sS "$LFS_URL/api/v1/ready" | jq .
```

Open Swagger UI at:

```text
http://localhost:12104/docs
```

The registration operation is `POST /api/v1/licenses` under the **Licences** tag.

## 4. Understand the request fields

The endpoint accepts this JSON structure:

```json
{
  "requestedLicenseId": "DANS-Custom-1.0",
  "version": "1.0",
  "name": "DANS Custom License 1.0",
  "summary": "A custom licence maintained by DANS.",
  "description": "Terms for using selected DANS datasets and services.",
  "licenseText": "Copyright 2026 DANS.\n\nPermission is granted...",
  "scope": "local",
  "aliases": ["DANS Custom License", "DANS-Custom"]
}
```

Field rules:

- `requestedLicenseId` is required and identifies the licence requested by the user.
- `version` is required. Different versions may use the same `requestedLicenseId`.
- `name` is required and must be nonblank.
- `licenseText` is required and must be nonblank. LFS preserves its exact contents in the generated SPDX data.
- `scope` is required and must be `local`, `federated`, or `spdx-submission`.
- `summary` and `description` are optional.
- `aliases` is optional and may contain up to 64 nonblank values.
- Unknown JSON fields are rejected.

Choose the identifier and version carefully. Registering the same authority, requested ID, and version again returns `409 Conflict`; registration is not an overwrite operation.

## 5. Example A — register and keep the licence locally

Create a request file:

```bash
cat > /tmp/dans-custom-local.json <<'JSON'
{
  "requestedLicenseId": "DANS-Custom-1.0",
  "version": "1.0",
  "name": "DANS Custom License 1.0",
  "summary": "A custom licence maintained locally by DANS.",
  "description": "Terms for using selected DANS datasets and services.",
  "licenseText": "DANS CUSTOM LICENSE 1.0\n\nCopyright 2026 DANS.\n\nPermission is granted to use and redistribute the licensed material provided that attribution is given to DANS. The material is provided without warranty.",
  "scope": "local",
  "aliases": [
    "DANS Custom License",
    "DANS-Custom"
  ]
}
JSON
```

Register it:

```bash
curl -sS -i \
  -X POST "$LFS_URL/api/v1/licenses" \
  -H "Authorization: Bearer $LFS_TOKEN" \
  -H 'Content-Type: application/json' \
  --data-binary @/tmp/dans-custom-local.json
```

Expected result:

- HTTP status: `201 Created`
- `scope`: `local`
- `federationStatus`: `not_published`
- `spdxSubmissionStatus`: `not_requested`
- `lifecycleStatus`: `registered`

Example response excerpt:

```json
{
  "id": "e9d6f8cb-4a2a-45ef-ae31-5596dbf31f3f",
  "requestedLicenseId": "DANS-Custom-1.0",
  "version": "1.0",
  "canonicalId": "lfs-custom:lfs-local-authority:DANS-Custom-1.0:1.0",
  "resolvingUuid": "f7c402f8-c406-5153-b6af-1b652f7930df",
  "resolvingUri": "https://lfs.example/custom-licences/lfs-local-authority/DANS-Custom-1.0/1.0",
  "name": "DANS Custom License 1.0",
  "scope": "local",
  "federationStatus": "not_published",
  "spdxSubmissionStatus": "not_requested",
  "lifecycleStatus": "registered",
  "normalizedTextDigest": "...",
  "spdxJsonld": {
    "@context": "https://spdx.org/rdf/3.0.1/spdx-context.jsonld",
    "@graph": []
  },
  "createdAt": "2026-08-13T10:00:00Z",
  "updatedAt": "2026-08-13T10:00:00Z"
}
```

IDs, digests, timestamps, and the complete `spdxJsonld.@graph` are generated by the server and will differ from this abbreviated example.

## 6. Example B — register for federation

Use a different identifier, or a new version, to avoid colliding with Example A:

```bash
cat > /tmp/dans-custom-federated.json <<'JSON'
{
  "requestedLicenseId": "DANS-Federated-1.0",
  "version": "1.0",
  "name": "DANS Federated License 1.0",
  "summary": "A DANS licence made available to trusted LFS peers.",
  "description": "The authoritative copy remains on this DANS LFS node.",
  "licenseText": "DANS FEDERATED LICENSE 1.0\n\nCopyright 2026 DANS.\n\nPermission is granted under the conditions stated in this licence.",
  "scope": "federated",
  "aliases": ["DANS Federated License"]
}
JSON

curl -sS \
  -X POST "$LFS_URL/api/v1/licenses" \
  -H "Authorization: Bearer $LFS_TOKEN" \
  -H 'Content-Type: application/json' \
  --data-binary @/tmp/dans-custom-federated.json \
  | tee /tmp/dans-federated-response.json \
  | jq .
```

Expected initial state:

```json
{
  "scope": "federated",
  "federationStatus": "pending",
  "spdxSubmissionStatus": "not_requested",
  "lifecycleStatus": "registered"
}
```

`pending` means the registration transaction created a durable publication job. The HTTP request does not contact peer nodes and does not publish inline.

Federated registration requires:

- `FEDERATION_ENABLED=true` with valid node identity and signing configuration;
- `FEDERATION_DATABASE_URL` and `CUSTOM_LICENCE_REGISTRATION_DATABASE_URL` referring to the same PostgreSQL database;
- the custom-licence federation worker running.

Start the publication worker:

```bash
uv run python -m src.license_facade_service.custom_licence_federation_worker
```

Save the returned record ID and inspect publication status as an administrator:

```bash
export RECORD_ID="$(jq -r '.id' /tmp/dans-federated-response.json)"

curl -sS \
  -H "Authorization: Bearer $LFS_TOKEN" \
  "$LFS_URL/api/v1/admin/licenses/$RECORD_ID/federation" \
  | jq .
```

After successful worker processing, `federationStatus` becomes `published`. Trusted peer nodes do not receive a pushed copy. Their synchronization worker pulls the signed change feed and stores a non-authoritative imported copy.

## 7. Example C — register for later SPDX submission

```bash
cat > /tmp/dans-custom-spdx.json <<'JSON'
{
  "requestedLicenseId": "DANS-Proposed-1.0",
  "version": "1.0",
  "name": "DANS Proposed License 1.0",
  "summary": "A DANS licence proposed for later SPDX review.",
  "description": "This registration is retained locally while an operator reviews it.",
  "licenseText": "DANS PROPOSED LICENSE 1.0\n\nCopyright 2026 DANS.\n\nPermission is granted under the following terms...",
  "scope": "spdx-submission",
  "aliases": ["DANS Proposed License"]
}
JSON

curl -sS \
  -X POST "$LFS_URL/api/v1/licenses" \
  -H "Authorization: Bearer $LFS_TOKEN" \
  -H 'Content-Type: application/json' \
  --data-binary @/tmp/dans-custom-spdx.json \
  | jq .
```

Expected state:

```json
{
  "scope": "spdx-submission",
  "federationStatus": "not_published",
  "spdxSubmissionStatus": "ready_for_review",
  "lifecycleStatus": "registered"
}
```

`ready_for_review` does not mean that the licence was submitted to or accepted by SPDX. No SPDX or GitHub network request occurs during registration. See [SPDX Fork Submission Workflow](spdx-fork-submission-workflow.md) for the proposed controlled-fork workflow.

## 8. Use Postman

### 8.1 Create an environment

Create these Postman environment variables:

| Variable | Local example |
|---|---|
| `lfs_base_url` | `http://localhost:12104` |
| `lfs_token` | your curator or admin token |

### 8.2 Create the request

1. Create a new HTTP request.
2. Select method **POST**.
3. Enter `{{lfs_base_url}}/api/v1/licenses`.
4. Open **Authorization**.
5. Select **Bearer Token**.
6. Enter `{{lfs_token}}`.
7. Open **Body** and select **raw**.
8. Select **JSON** as the body type.
9. Paste one of the complete JSON examples above.
10. Select **Send**.

Postman should add `Content-Type: application/json`. A successful registration returns `201 Created`.

### 8.3 Save useful response values

Add this Postman post-response script if you want to reuse the identifiers:

```javascript
const body = pm.response.json();
pm.environment.set("custom_licence_record_id", body.id);
pm.environment.set("custom_licence_canonical_id", body.canonicalId);
pm.environment.set("custom_licence_resolving_uuid", body.resolvingUuid);
```

For a federated registration, create another GET request:

```text
{{lfs_base_url}}/api/v1/admin/licenses/{{custom_licence_record_id}}/federation
```

Use the administrator bearer token for federation administration endpoints.

## 9. Use Swagger UI

1. Open `http://localhost:12104/docs`.
2. Select **Authorize**.
3. Enter the curator or administrator bearer token.
4. Expand the **Licences** tag.
5. Expand `POST /api/v1/licenses`.
6. Select **Try it out**.
7. Replace the example body with one of the examples in this guide.
8. Select **Execute**.
9. Confirm the response code is `201` and review the generated identifiers and statuses.

## 10. Run the complete two-node federation demo manually

For a local two-node test, the Compose federation-demo profile exposes:

- Node A at `http://localhost:12114`;
- Node B at `http://localhost:12124`.

Set the demo token and start the topology:

```bash
export FEDERATION_DEMO_ADMIN_TOKEN='demo-admin-token'
docker compose --profile federation-demo up -d --build
```

Wait for both nodes:

```bash
curl -fsS http://localhost:12114/api/v1/ready | jq .
curl -fsS http://localhost:12124/api/v1/ready | jq .
```

Register the `federated` example on Node A:

```bash
curl -sS \
  -X POST 'http://localhost:12114/api/v1/licenses' \
  -H "Authorization: Bearer $FEDERATION_DEMO_ADMIN_TOKEN" \
  -H 'Content-Type: application/json' \
  --data-binary @/tmp/dans-custom-federated.json \
  | tee /tmp/node-a-registration.json \
  | jq .
```

The Node A publication worker processes the pending job. Node B can import it only after Node A has been enrolled as a trusted peer on Node B and Node B synchronization runs. Peer enrollment requires the expected Node A identity and pinned public-key information; use the **Federation Admin** endpoints in Swagger for the exact running-node values.

After synchronization, verify these properties:

- Node A reports the custom licence publication as `published`.
- Node A exposes the signed authoritative record in its federation feed.
- Node B lists the imported record in its peer-import status.
- Node B stores the record as non-authoritative.
- Node B does not re-export that imported record as its own authoritative licence.
- Repeating synchronization imports zero duplicate records.

For the complete, deployment-specific trust-enrollment procedure, see the federation demo documentation and `scripts/demo-federation.sh`. That script is useful as a reference for request shapes, even when you execute every request manually.

## 11. SPDX validation behavior

During `POST /api/v1/licenses`, LFS builds a server-controlled SPDX 3.0.1 JSON-LD custom-licence representation and validates it offline against:

```text
vendor/spdx/3.0.1/spdx-json-schema.json
```

Important boundaries:

- validation is structural JSON Schema validation;
- LFS does not use the `spdx-tools` library for this validation;
- LFS does not claim OWL or SHACL semantic validation;
- no schema or JSON-LD context is downloaded at request time;
- passing validation does not mean SPDX has reviewed or accepted the licence.

The helper endpoints:

```text
POST /api/v1/licenses/spdx3/minimal
POST /api/v1/licenses/spdx3/complete/{license_id}
```

use the same vendored structural validator. Currently, the `complete` endpoint resolves licences from the official SPDX snapshot only. It does not yet resolve newly registered PostgreSQL custom licences.

## 12. Common errors

All documented API errors use `application/problem+json`.

### `401 Unauthorized`

The bearer token is missing or invalid. Confirm the header format:

```text
Authorization: Bearer your-token
```

### `403 Forbidden`

The token is valid but does not have curator or administrator permission.

### `409 Conflict`

The same authority, `requestedLicenseId`, and `version` already exists, or an alias conflicts with another record. Use a new version or a distinct alias. Do not retry the same request expecting an overwrite.

### `422 Unprocessable Entity`

The request is invalid. Typical causes include:

- missing `requestedLicenseId`, `version`, `name`, `licenseText`, or `scope`;
- blank licence text;
- unsupported scope spelling;
- invalid identifier characters;
- blank or duplicate/conflicting aliases;
- unknown JSON fields.

Example invalid request:

```bash
curl -sS \
  -X POST "$LFS_URL/api/v1/licenses" \
  -H "Authorization: Bearer $LFS_TOKEN" \
  -H 'Content-Type: application/json' \
  -d '{"requestedLicenseId":"Broken","version":"1.0","name":"Broken","licenseText":"","scope":"local"}' \
  | jq .
```

### `503 Service Unavailable`

Registration configuration is missing or invalid, PostgreSQL is unavailable, or federated registration was requested without valid federation configuration. Check the custom-licence environment variables, database connectivity, migrations, and federation settings.

## 13. What happens to each scope

### `local`

The licence belongs to the registering LFS authority. It is stored locally and is not added to the outbound federation feed.

### `federated`

The registering LFS remains the authority. The local worker publishes a signed authoritative event. Trusted peers may pull and store an imported, non-authoritative copy. The licence is not duplicated as a new peer-owned licence.

### `spdx-submission`

The licence remains local and is marked for human review. A later, separate workflow may prepare files and commit them to an organization-controlled fork of `spdx/license-list-XML`. An operator must manually open the upstream pull request.

These events are distinct:

```text
Registered in LFS
        !=
Published to trusted LFS peers
        !=
Prepared for an SPDX contribution
        !=
Committed to an SPDX fork
        !=
Submitted to SPDX by pull request
        !=
Accepted into the SPDX License List
```
