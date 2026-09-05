# Rights & Ethics compliance matrix

Integrated application version: **0.3.5**.

This matrix re-audits the implementation against `LICENCE FACADE SERVICE - Rights & Ethics-2.docx`, the current source tree, Alembic head `20260904_03`, and validated tests. Status values mean:

- **implemented**: verified in current code and backed by explicit tests
- **partial**: implemented only in a narrower form than the source row suggests
- **missing**: no verified implementation found
- **ambiguous**: the source row or surrounding prose is internally unclear or conflicts with other normative text

## 12 requirement totals

| Status | Count |
|---|---:|
| implemented | 10 |
| partial | 1 |
| missing | 0 |
| ambiguous | 1 |
| total | 12 |

## Requirement matrix

| # | Requirement | Status | Implementation evidence | Test evidence | Notes |
|---|---|---|---|---|---|
| 1 | Base licence metadata and negotiated public representations | implemented | `src/license_facade_service/api/v1/licenses.py`; `src/license_facade_service/services/licenses.py` | `tests/test_api_contract.py`, `tests/test_rights_ethics_conformance.py` | Route existence is distinguished from representation availability. |
| 2 | Original/machine/legal/encoding cross-reference and representation contract | implemented | `src/license_facade_service/services/licenses.py`; `src/license_facade_service/services/contract.py` | `tests/test_cross_reference_contract.py`, `tests/test_rights_ethics_conformance.py` | Curated representation data is required for actual availability. |
| 3 | RFC 9457 error handling and role-protected mutation APIs | implemented | `src/license_facade_service/services/problem.py`; `src/license_facade_service/api/v1/licenses.py`; `src/license_facade_service/api/admin/openrel.py` | `tests/test_api_contract.py`, `tests/test_openrel_admin_api.py` | `401` and `403` remain distinct. |
| 4 | Custom licence registration and scope separation | implemented | `src/license_facade_service/api/v1/licenses.py`; `src/license_facade_service/services/custom_licence_federation_publication.py` | `tests/test_custom_licence_phase3.py`, `tests/test_api_contract.py` | `local`, `federated`, and `spdx-submission` are separate workflows. |
| 5 | Federated authoritative publication, append-only revisions, and imported non-authoritative resolution | implemented | `src/license_facade_service/federation/outbound.py`; `src/license_facade_service/federation/rdf_outbox.py`; `src/license_facade_service/federation/models.py` | `tests/federation/test_outbound_phase2.py`, `tests/federation/test_phase4_resolution.py`, `tests/test_fuseki_optional.py` | Latest state is projected from the latest authoritative event. |
| 6 | Optional read-only OpenREL provider facade | implemented | `src/license_facade_service/services/openrel_client.py`; `src/license_facade_service/services/openrel_policy.py` | `tests/test_openrel_client.py`, `tests/test_openrel_policy.py` | Read-only provider access only. |
| 7 | OpenREL evaluation and persisted plans | implemented | `src/license_facade_service/services/openrel_evaluation.py`; `src/license_facade_service/services/openrel_policy_store.py` | `tests/test_openrel_evaluation.py`, `tests/test_openrel_policy_store.py` | Unavailable provider behavior is fail-closed. |
| 8 | OpenREL admin review, apply, rollback, and audit events | implemented | `src/license_facade_service/api/admin/openrel.py`; `src/license_facade_service/services/openrel_application.py`; `src/license_facade_service/services/openrel_policy_store.py` | `tests/test_openrel_admin_api.py`, `tests/test_openrel_application.py`, `tests/test_openrel_policy_postgres.py` | Apply/rollback uses persisted state only. |
| 9 | Local versus federated OpenREL mutation boundaries | implemented | `src/license_facade_service/services/openrel_application.py` | `tests/test_openrel_application.py`, `tests/test_openrel_policy_postgres.py` | SPDX/imported records remain rejected. |
| 10 | Asynchronous RDF indexing and provider/fuseki outage safety | implemented | `src/license_facade_service/federation/rdf_outbox.py`; `src/license_facade_service/services/openrel_evaluation.py` | `tests/test_fuseki_optional.py`, `tests/test_openrel_evaluation.py` | PostgreSQL remains source of truth while Fuseki is unavailable. |
| 11 | Automated legal or semantic trust of OpenREL content | partial | bounded syntax/profile/version/vocabulary checks in `src/license_facade_service/services/openrel_policy.py` | `tests/test_openrel_policy.py`, `tests/test_rights_ethics_conformance.py` | Legal or semantic approval is intentionally not automated. |
| 12 | Default landing-page semantics in prose versus normative table | ambiguous | `src/license_facade_service/api/v1/licenses.py` | `tests/test_api_contract.py` | Source prose conflicts with normative table; implementation follows the normative table. |

## Tables 1–6 totals

| Table | implemented | partial | missing | ambiguous | total |
|---|---:|---:|---:|---:|---:|
| Table 1 | 2 | 0 | 0 | 0 | 2 |
| Table 2 | 6 | 0 | 0 | 1 | 7 |
| Table 3 | 6 | 0 | 0 | 0 | 6 |
| Table 4 | 13 | 0 | 0 | 0 | 13 |
| Table 5 | 7 | 0 | 0 | 0 | 7 |
| Table 6 | 5 | 0 | 0 | 0 | 5 |
| Combined | 39 | 0 | 0 | 1 | 40 |

## Table details

### Table 1

| Source row | Status | Implementation evidence | Test evidence | Notes |
|---|---|---|---|---|
| Base licence metadata resource | implemented | `src/license_facade_service/api/v1/licenses.py`; `src/license_facade_service/services/licenses.py` | `tests/test_api_contract.py::test_static_routes_take_precedence` | `/api/v1/licenses/{id}` is the implementation path. |
| Protected mutation/auth separation | implemented | `src/license_facade_service/api/v1/licenses.py`; `src/license_facade_service/api/admin/openrel.py` | `tests/test_api_contract.py::test_openapi_security_scheme_marks_only_protected_operations` | Public GET and protected POST boundaries are distinct. |

### Table 2

| Source row | Status | Implementation evidence | Test evidence | Notes |
|---|---|---|---|---|
| `/licences/{id}` base negotiated metadata | implemented | `src/license_facade_service/api/v1/licenses.py`; `src/license_facade_service/services/licenses.py` | `tests/test_api_contract.py::test_openapi_problem_media_types_and_public_response_types` | Default response is JSON. |
| `/licences/{id}/html` | implemented | `src/license_facade_service/api/v1/licenses.py` | `tests/test_api_contract.py::test_static_routes_take_precedence` | Returns HTML when available. |
| `/licences/{id}/json-ld` | implemented | `src/license_facade_service/api/v1/licenses.py`; `src/license_facade_service/utils/rdf_transformer.py` | `tests/test_rights_ethics_conformance.py::test_rdf_preserves_canonical_lfs_field_names` | Negotiated RDF path is implemented. |
| `/licences/{id}/original` | implemented | `src/license_facade_service/services/licenses.py` | `tests/test_cross_reference_contract.py::test_cross_reference_accepts_upstream_https_url` | Availability depends on curated original representation data. |
| `/licences/{id}/machine` | implemented | `src/license_facade_service/services/licenses.py` | `tests/test_cross_reference_contract.py::test_cross_reference_rejects_traversal_and_backslash_local_path` | Route existence is not treated as machine-representation compliance by itself. |
| `/licences/{id}/legal` | implemented | `src/license_facade_service/services/licenses.py` | `tests/test_rights_ethics_conformance.py::test_legal_endpoint_redirects_to_curated_reference` | Curated legal target only; not invented. |
| default human vs machine landing expectation | ambiguous | `src/license_facade_service/api/v1/licenses.py` | `tests/test_api_contract.py::test_openapi_problem_media_types_and_public_response_types` | Source prose conflicts with the normative table. |

### Table 3

| Source row | Status | Implementation evidence | Test evidence | Notes |
|---|---|---|---|---|
| `application/json` metadata response | implemented | `src/license_facade_service/services/licenses.py` | `tests/test_api_contract.py::test_openapi_problem_media_types_and_public_response_types` | Default representation. |
| `text/html` response | implemented | `src/license_facade_service/services/licenses.py` | `tests/test_api_contract.py::test_static_routes_take_precedence` | Explicit HTML route exists. |
| `application/ld+json` response | implemented | `src/license_facade_service/utils/rdf_transformer.py` | `tests/test_rights_ethics_conformance.py::test_rdf_preserves_upstream_spdx_field_names[json-ld]` | RDF serialization is supported. |
| `text/turtle` response | implemented | `src/license_facade_service/utils/rdf_transformer.py` | `tests/test_rights_ethics_conformance.py::test_rdf_preserves_upstream_spdx_field_names[turtle]` | RDF serialization is supported. |
| `application/rdf+xml` response | implemented | `src/license_facade_service/utils/rdf_transformer.py` | `tests/test_rights_ethics_conformance.py::test_rdf_preserves_upstream_spdx_field_names[xml]` | RDF serialization is supported. |
| unsupported media-type problem response | implemented | `src/license_facade_service/services/problem.py` | `tests/test_api_contract.py::test_openapi_problem_media_types_and_public_response_types` | Uses `application/problem+json`. |

### Table 4

| Source row | Status | Implementation evidence | Test evidence | Notes |
|---|---|---|---|---|
| `uri` | implemented | `src/license_facade_service/services/licenses.py` | `tests/test_rights_ethics_conformance.py::test_pid_resolution_by_spdx_id_uuid_and_full_uri_is_stable` | Included in metadata. |
| `referenceNumber` | implemented | `src/license_facade_service/services/licenses.py` | `tests/test_api_contract.py::test_optional_original_legal_machine_representations` | Emitted in metadata when available. |
| `licenseId` / aliases | implemented | `src/license_facade_service/services/licenses.py` | `tests/test_api_contract.py::test_table6_mappings_and_response_schema` | Canonical and compatibility fields are both supported. |
| `name` | implemented | `src/license_facade_service/services/licenses.py` | `tests/test_api_contract.py::test_table6_mappings_and_response_schema` | Included in metadata. |
| `detailsURL` | implemented | `src/license_facade_service/services/licenses.py` | `tests/test_rights_ethics_conformance.py::test_table6_maps_available_representations_to_local_endpoints` | Local details endpoint mapping. |
| `spdxDetailsURL` | implemented | `src/license_facade_service/services/licenses.py` | `tests/test_api_contract.py::test_table6_mappings_and_response_schema` | Upstream details URL retained. |
| `reference` | implemented | `src/license_facade_service/services/licenses.py` | `tests/test_rights_ethics_conformance.py::test_table5_complete_upstream_crossref_passes_conformance` | Preserved as upstream metadata. |
| `isDeprecatedLicenseId` / `isDeprecatedLicenseID` | implemented | `src/license_facade_service/services/licenses.py` | `tests/test_api_contract.py::test_table6_mappings_and_response_schema` | Compatibility field aliases retained. |
| `seeAlso` | implemented | `src/license_facade_service/services/licenses.py` | `tests/test_api_contract.py::test_optional_original_legal_machine_representations` | Passed through when available. |
| `isOsiApproved` | implemented | `src/license_facade_service/services/licenses.py` | `tests/test_api_contract.py::test_table6_mappings_and_response_schema` | Included in metadata. |
| `licenseText` | implemented | `src/license_facade_service/services/licenses.py` | `tests/test_rights_ethics_conformance.py::test_table4_failure_is_independent_of_representation_success` | Conformance tracked independently. |
| `standardLicenseTemplate` | implemented | `src/license_facade_service/services/licenses.py` | `tests/test_rights_ethics_conformance.py::test_table4_failure_is_independent_of_representation_success` | Conformance tracked independently. |
| `licenseTextHtml` | implemented | `src/license_facade_service/services/licenses.py` | `tests/test_rights_ethics_conformance.py::test_table4_failure_is_independent_of_representation_success` | Missing field is surfaced as conformance failure, not silently fabricated. |

### Table 5

| Source row | Status | Implementation evidence | Test evidence | Notes |
|---|---|---|---|---|
| `crossRef[].URL` | implemented | `src/license_facade_service/services/licenses.py`; `src/license_facade_service/services/contract.py` | `tests/test_rights_ethics_conformance.py::test_table5_crossref_without_url_is_reported_not_silently_discarded` | Missing/invalid URL is surfaced. |
| `crossRef[].match` | implemented | `src/license_facade_service/services/licenses.py` | `tests/test_rights_ethics_conformance.py::test_table5_missing_required_crossref_fields_are_reported` | Missing/invalid field is surfaced. |
| `crossRef[].isValid` | implemented | `src/license_facade_service/services/licenses.py` | `tests/test_rights_ethics_conformance.py::test_table5_missing_required_crossref_fields_are_reported` | Missing/invalid field is surfaced. |
| `crossRef[].isLive` | implemented | `src/license_facade_service/services/licenses.py` | `tests/test_rights_ethics_conformance.py::test_table5_conformance_paths_use_stable_crossref_indexes` | Stable index reporting is verified. |
| `crossRef[].timeStamp` | implemented | `src/license_facade_service/services/licenses.py` | `tests/test_rights_ethics_conformance.py::test_table5_invalid_crossref_field_is_reported` | Timestamp path compatibility is retained. |
| `crossRef[].isWayBackLink` | implemented | `src/license_facade_service/services/licenses.py` | `tests/test_rights_ethics_conformance.py::test_table5_missing_required_crossref_fields_are_reported` | Missing/invalid field is surfaced. |
| `crossRef[].order` | implemented | `src/license_facade_service/services/licenses.py` | `tests/test_rights_ethics_conformance.py::test_table5_invalid_crossref_field_is_reported` | Missing/invalid field is surfaced. |

### Table 6

| Source row | Status | Implementation evidence | Test evidence | Notes |
|---|---|---|---|---|
| `detailsURL` mapping | implemented | `src/license_facade_service/services/licenses.py` | `tests/test_rights_ethics_conformance.py::test_table6_maps_available_representations_to_local_endpoints` | Local details URL emitted. |
| `crossRef[type=original]` mapping | implemented | `src/license_facade_service/services/licenses.py` | `tests/test_rights_ethics_conformance.py::test_table6_maps_available_representations_to_local_endpoints` | Generated local endpoint mapping. |
| `crossRef[type=machine]` mapping | implemented | `src/license_facade_service/services/licenses.py` | `tests/test_rights_ethics_conformance.py::test_table6_maps_available_representations_to_local_endpoints` | Generated local endpoint mapping. |
| `crossRef[type=encoding]` mapping | implemented | `src/license_facade_service/services/licenses.py` | `tests/test_rights_ethics_conformance.py::test_table6_maps_available_representations_to_local_endpoints` | Generated local endpoint mapping. |
| upstream cross-reference preservation | implemented | `src/license_facade_service/services/licenses.py` | `tests/test_rights_ethics_conformance.py::test_table6_maps_available_representations_to_local_endpoints` | Upstream refs remain alongside generated local refs. |

## OpenREL behavior

### Configuration and policy modes

OpenREL uses placeholder operator configuration only. Current settings are defined in `src/license_facade_service/services/openrel_policy.py`:

- `OPENREL_ENABLED`
- `OPENREL_POLICY_MODE` (`disabled`, `dry-run`, `active`)
- `OPENREL_POLICY_DATABASE_URL` / `OPENREL_POLICY_DATABASE_URL_FILE`
- `OPENREL_ADMIN_CURSOR_SECRET` / `OPENREL_ADMIN_CURSOR_SECRET_FILE`
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

`disabled` is inert, `dry-run` evaluates without allowing mutation, and `active` enables persisted evaluation and later admin-controlled review/apply paths.

### Recent versus historical classification

Classification in `src/license_facade_service/services/openrel_policy.py` uses the timezone-aware registration timestamp and the configured effective date to distinguish recent versus historical inputs.

### Timezone-aware timestamp requirement

Active-policy behavior depends on timezone-aware registration timestamps. Missing or untrusted timestamps fail closed to `action=none`, review-required handling, and no automatic mapping application.

### Fail-closed behavior

Unavailable provider behavior fails closed. Provider availability alone never authorizes mutation.

### Read-only OpenREL client

`src/license_facade_service/services/openrel_client.py` is read-only, bounded by timeout, response-size, content-type, and URL safety checks.

### Candidate validation

`src/license_facade_service/services/openrel_policy.py` enforces profile, version, vocabulary, source-kind, and mapping boundaries before a plan can be persisted or later applied.

### Persisted policy states and audit events

`src/license_facade_service/services/openrel_policy_store.py` persists `OpenRelPolicyState` rows and append-only `OpenRelPolicyEvent` audit rows with PostgreSQL-safe idempotency and savepoints.

### Admin review

`src/license_facade_service/api/admin/openrel.py` exposes authenticated admin review endpoints for list/detail/events plus approve/reject.

### Apply and rollback

`src/license_facade_service/services/openrel_application.py` applies only persisted approved states and rolls back only persisted applied states. Apply/rollback reasons are sanitized at the API boundary, persisted only in the first successful transition event, and not exposed in responses.

### Local versus federated targets

Local authoritative `CustomLicence` targets are supported. SPDX and imported federation records are rejected. Published federated local targets additionally require valid publication linkage and ready federation dependencies.

### Federation revision publication

Federated apply/rollback appends one authoritative revision through `src/license_facade_service/federation/outbound.py::append_authoritative_upsert_in_session` and updates latest outbox linkage atomically.

### Asynchronous RDF enqueue

Federated apply/rollback enqueues RDF work through `src/license_facade_service/federation/rdf_outbox.py` without synchronous Fuseki calls.

### Unavailable-provider behavior

Unavailable OpenREL provider evaluation produces fail-closed planning rather than licence mutation. Otherwise-valid federated apply/rollback without required publisher or payload dependencies returns `503`.

### Security and data-redaction rules

`sanitize_review_reason()` in `src/license_facade_service/services/openrel_policy_store.py` redacts secrets, rejects malformed structured input, bounds persisted content, and keeps sanitized reasons out of response models, federation payloads/provenance, RDF payloads, and licence snapshots.

## Remaining partial, missing, or ambiguous items

- **partial**: no automated legal or semantic trust of OpenREL output beyond bounded syntax/profile/version/vocabulary checks
- **ambiguous**: source prose around the default landing behavior conflicts with the normative endpoint table
- **missing**: none verified in this audit
