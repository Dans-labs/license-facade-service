# API Specification Note

Integrated application version: **0.3.5**.

This note documents the behavior currently implemented in the repository. It aligns the service with the current Rights & Ethics interpretation, OpenREL policy workflow, federated revision model, and asynchronous RDF processing.

## Normative ambiguity

The Rights & Ethics prose suggests HTML prominence, but the normative endpoint table still makes the base licence resource the machine-readable metadata entry point. The implementation follows the normative table:

- no `Accept` header → `application/json`
- `Accept: */*` → `application/json`
- `Accept: text/html` → HTML
- unsupported media types → `406 application/problem+json`

`/api/v1/licences/{id}` remains the specification alias; `/api/v1/licenses/{id}` is the implementation path.

## Public licence architecture

Main responsibilities are split across these components:

- `src/license_facade_service/api/v1/licenses.py`: public HTTP routes, protected mutation routes, OpenAPI documentation
- `src/license_facade_service/services/licenses.py`: licence retrieval, content negotiation, representation selection, response shaping
- `src/license_facade_service/utils/rdf_transformer.py`: RDF serialization and vocabulary-aware transformation boundaries
- `src/license_facade_service/services/problem.py`: RFC 9457 problem responses

The service distinguishes route existence from actual representation availability. Optional or mandatory representation routes may still return `404 application/problem+json` when curated data does not exist.

## Custom licence registration boundary

`POST /api/v1/licenses` supports three scopes:

- `local`
- `federated`
- `spdx-submission`

Registration persists local data atomically in PostgreSQL. Federated scope also creates durable publication intent for the separate worker. SPDX-submission scope remains local and does not contact SPDX or GitHub.

## OpenREL architecture

OpenREL responsibilities are split across these components:

- `src/license_facade_service/services/openrel_client.py`: strict read-only provider client
- `src/license_facade_service/services/openrel_policy.py`: configuration, policy classification, candidate validation, fail-closed rules
- `src/license_facade_service/services/openrel_evaluation.py`: evaluation coordinator and provider-availability handling
- `src/license_facade_service/services/openrel_policy_store.py`: persisted plan storage, transition events, reason sanitization, idempotent plan recording
- `src/license_facade_service/services/openrel_application.py`: local/federated apply and rollback execution
- `src/license_facade_service/api/admin/openrel.py`: authenticated admin HTTP surface and RFC 9457 mapping
- `src/license_facade_service/runtime/openrel_policy.py`: runtime/session wiring

The provider facade under `/openrel/api/v0.4/*` is read-only `GET` only. Provider availability does not create trust, does not mutate licences, and does not perform automatic application.

## OpenREL configuration

Current OpenREL settings are read from these environment variables:

- `OPENREL_ENABLED`
- `OPENREL_POLICY_MODE`
- `OPENREL_POLICY_DATABASE_URL`
- `OPENREL_POLICY_DATABASE_URL_FILE`
- `OPENREL_ADMIN_CURSOR_SECRET`
- `OPENREL_ADMIN_CURSOR_SECRET_FILE`
- `OPENREL_BASE_URL`
- `OPENREL_APPROVED_PROFILE`
- `OPENREL_APPROVED_VERSION`
- `OPENREL_POLICY_EFFECTIVE_DATE`
- `OPENREL_CACHE_TTL_SECONDS`
- `OPENREL_TIMEOUT_SECONDS`
- `OPENREL_MAX_RESPONSE_BYTES`
- `OPENREL_ALLOW_HTTP_FOR_DEMO`
- `OPENREL_AUTODISCOVERY_ENABLED`
- `OPENREL_MIGRATION_REVIEW_REQUIRED`
- `OPENREL_MAPPING_AUTHORITY`

Mode behavior:

- `disabled`: inert, no persisted policy-store activity required
- `dry-run`: evaluation only, no mutation allowed
- `active`: evaluation and later admin-controlled apply/rollback are enabled

`active` mode requires enabled runtime, configured provider base URL, approved profile/version, and effective date. Autodiscovery is not allowed in `active` mode.

## OpenREL policy lifecycle

The implemented lifecycle is:

```text
evaluation -> persisted plan -> review -> apply -> rollback
```

### Evaluation

Evaluation accepts external candidate input for comparison against configured OpenREL policy rules. It does not mutate the target licence. When the provider is unavailable or the timestamp is missing/untrusted, evaluation fails closed and may persist a no-op or review-required plan instead of applying anything.

### Review

Persisted policy states are reviewed through admin endpoints:

- `POST /api/v1/admin/openrel/policy-states/{state_id}/approve`
- `POST /api/v1/admin/openrel/policy-states/{state_id}/reject`

Reasons are sanitized and persisted only in safe audit-event details.

### Apply and rollback

Persisted approved states are mutated only through admin endpoints:

- `POST /api/v1/admin/openrel/policy-states/{state_id}/apply`
- `POST /api/v1/admin/openrel/policy-states/{state_id}/rollback`

Requests accept only an optional `reason`. They do not accept candidate payload, digest, target identity, actor identity, mapping content, federation IDs, or status overrides.

## Allowed state transitions

`OpenRelPolicyStore.transition_status()` currently allows:

- `pending-review -> approved`
- `pending-review -> rejected`
- `planned -> applied`
- `approved -> applied`
- `planned -> failed`
- `pending-review -> failed`
- `approved -> failed`
- `applied -> rolled-back`

Exact retries are idempotent only for terminal or already-completed states with matching retry metadata.

## OpenREL idempotency and append-only events

Two idempotency boundaries are implemented.

### Plan recording

`OpenRelPolicyStore.record_plan()` performs an initial lookup, inserts state/event inside `session.begin_nested()`, and recovers only for the PostgreSQL uniqueness race on `uq_openrel_policy_states_license_policy_candidate_action`. Exact replays reuse the winner without rolling back the caller’s outer transaction.

### Apply/rollback

`OpenRelApplicationService.apply()` and `.rollback()` are idempotent on exact replay of already-applied or already-rolled-back states when the live target still matches the stored snapshot digest boundary. Retries do not create duplicate transition events or overwrite the first persisted sanitized reason.

`OpenRelPolicyEvent` rows remain append-only audit history.

## Transaction ownership

Both policy storage and application logic are caller-owned transaction services.

- `OpenRelPolicyStore` never commits the caller session.
- `OpenRelApplicationService` never commits the caller session.
- Federated savepoint handling uses `session.begin_nested()` and never calls outer `rollback()` for handled races or nested publication failures.
- Admin HTTP handlers own one request transaction, commit once on success, roll back once on failure, and always close the session.

## PostgreSQL constraints and persistence

Current persistence includes:

- `openrel_policy_states`
- `openrel_policy_events`
- `custom_licence_representations`
- `federation_change_events.idempotency_key`

Current Alembic head is:

- `20260904_03`

OpenREL apply/rollback relies on persisted target snapshots and digests, historical mapping representation state, and append-only transition events rather than overwriting history.

## Local mutation boundary

OpenREL apply/rollback supports only local authoritative `CustomLicence` mutation targets.

Rejected targets include:

- SPDX sources
- imported federation records
- unsupported lifecycle/publication states

For local targets, mutation stays within PostgreSQL and local audit history.

## Federated apply/rollback revision behavior

Published federated custom licences are supported through `OpenRelApplicationService` only when federation publication linkage is valid and the publisher/payload dependencies are ready.

Federated apply/rollback behavior:

- mutate local `CustomLicence` state
- compute exact before/after snapshots and digests
- append one authoritative federation revision event with deterministic idempotency key
- update outbox linkage to the latest authoritative event
- enqueue RDF jobs asynchronously
- append OpenREL transition event and custom audit event
- perform all of the above atomically inside a nested savepoint relative to the outer request transaction

If required federation dependencies are unavailable for an otherwise-valid federated action, the admin API returns `503` rather than `409`.

## Latest-event projection

Current authoritative federated record state is projected from the latest authoritative `FederationChangeEvent`, not by mutating historical record payload in place. This preserves append-only revision history while still allowing current catalog/record responses to reflect the newest authoritative content.

## RDF outbox behavior

RDF processing remains asynchronous.

- queueing occurs in PostgreSQL during publication/apply/rollback work
- worker execution happens separately through `python -m src.license_facade_service.rdf_worker`
- Fuseki outages do not block registration, evaluation persistence, apply/rollback, or resolution from PostgreSQL
- retries, requeue, rebuild, and reconcile are explicit maintenance actions

## Failure and retry behavior

- unavailable OpenREL provider during evaluation: fail closed, no automatic mutation
- malformed JSON-like review/apply reason: rejected before mutation
- oversized reason: `422`
- extra request fields on review/apply/rollback: `422`
- missing state or missing persisted target: `404`
- invalid transition, digest mismatch, stale target, linkage mismatch, unsupported lifecycle: `409`
- missing federation publisher/payload dependency for otherwise-valid federated apply/rollback: `503`

## Admin authentication and problem responses

Admin OpenREL endpoints require existing bearer authentication and administrator authorization.

Documented admin endpoints:

- `POST /api/v1/admin/openrel/evaluations`
- `GET /api/v1/admin/openrel/policy-states`
- `GET /api/v1/admin/openrel/policy-states/{state_id}`
- `GET /api/v1/admin/openrel/policy-states/{state_id}/events`
- `POST /api/v1/admin/openrel/policy-states/{state_id}/approve`
- `POST /api/v1/admin/openrel/policy-states/{state_id}/reject`
- `POST /api/v1/admin/openrel/policy-states/{state_id}/apply`
- `POST /api/v1/admin/openrel/policy-states/{state_id}/rollback`

All documented errors use RFC 9457 `application/problem+json`.

## Security and data-redaction rules

OpenREL review/apply/rollback reasons are sanitized through `sanitize_review_reason()`:

- malformed structured JSON-looking input is rejected
- duplicate keys are rejected
- sensitive fields are redacted recursively
- assignment-style secrets are redacted
- persisted output is bounded to 512 characters

Sanitized reasons are stored only in safe policy-event details. They are not included in:

- admin response models
- licence snapshots
- federation event payloads
- federation provenance
- RDF payloads

## Migration ownership and startup sequencing

Alembic is authoritative for schema creation and evolution.

- startup migration command: `uv run alembic -c alembic.ini upgrade head`
- no `Base.metadata.create_all` startup path is used
- the removed SQL dump `docker/postgres-init/001-lfs-schema.sql` is not used

Each deployment path keeps one migration owner per database path before API or worker startup.
