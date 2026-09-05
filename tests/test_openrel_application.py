from __future__ import annotations

import json
import uuid
from datetime import datetime, timezone
from types import SimpleNamespace

import pytest

from src.license_facade_service.db.models.custom_licence import (
    CustomLicence,
    CustomLicenceAuditEvent,
    CustomLicenceFederationOutbox,
    CustomLicenceRepresentation,
)
from src.license_facade_service.db.models.federation import FederationRecord
from src.license_facade_service.db.models.federation import FederationChangeEvent
from src.license_facade_service.db.models.openrel_policy import OpenRelPolicyEvent, OpenRelPolicyState
from src.license_facade_service.config.custom_licence import CustomLicenceRegistrationSettings
from src.license_facade_service.federation.license_identity import build_canonical_license_identity
from src.license_facade_service.services.openrel_application import (
    FullReplacementCandidate,
    HistoricalMappingCandidate,
    OPENREL_FEDERATION_IDEMPOTENCY_NAMESPACE,
    OpenRelApplicationConflictError,
    OpenRelApplicationService,
    OpenRelApplicationUnavailableError,
    OpenRelApplicationValidationError,
    build_custom_licence_snapshot,
    compute_custom_licence_snapshot_digest,
)
from src.license_facade_service.services.custom_licence_registration import compute_normalized_text_digest
from src.license_facade_service.services.openrel_policy_store import compute_candidate_digest
from tests.test_openrel_policy_store import FakeSession


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


def _custom_licence(*, public_scope: str = "local") -> CustomLicence:
    now = _utcnow()
    text = "Before text"
    return CustomLicence(
        id=uuid.uuid4(),
        authority_id="node-a",
        requested_license_id="lic-a",
        version="1.0",
        canonical_id="lfs:node-a:lic-a:1.0",
        resolving_uuid=uuid.uuid4(),
        public_scope=public_scope,
        federation_status="not_published",
        spdx_submission_status="not_requested",
        lifecycle_status="registered",
        name="Before",
        summary="Before summary",
        description="Before description",
        license_text=text,
        normalized_text_digest=compute_normalized_text_digest(text),
        spdx_jsonld={"before": True},
        creator_role="admin",
        created_at=now,
        updated_at=now,
        deprecated_at=None,
        withdrawn_at=None,
        tombstoned_at=None,
    )


def _replacement_payload(**overrides) -> dict:
    payload = {
        "name": "After",
        "summary": "After summary",
        "description": "After description",
        "licenseText": "After text",
        "spdxJsonld": {"after": True},
    }
    payload.update(overrides)
    return payload


def _mapping_payload(**overrides) -> dict:
    payload = {
        "mediaType": "application/json",
        "profile": "https://example.invalid/profile",
        "vocabulary": "https://example.invalid/vocab",
        "content": {"mapping": True},
        "mappingProfile": "https://example.invalid/mapping",
        "mappingProvenance": {"source": "openrel"},
    }
    payload.update(overrides)
    return payload


def _state(
    custom: CustomLicence,
    *,
    status: str = "approved",
    action: str = "full-replacement",
    apply_allowed: bool = True,
    source_kind: str = "custom",
    candidate_payload: dict | None = None,
    mapping_profile: str | None = None,
    mapping_provenance: dict | None = None,
) -> OpenRelPolicyState:
    now = _utcnow()
    payload = candidate_payload or _replacement_payload()
    return OpenRelPolicyState(
        id=uuid.uuid4(),
        canonical_license_id="lic-openrel",
        source_kind=source_kind,
        source_record_ref=str(custom.id),
        classification="historical" if action == "historical-mapping" else "new",
        policy_mode="active",
        policy_version="2026.09",
        effective_date=now,
        action=action,
        status=status,
        provider_url="https://openrel.example.invalid/provider",
        active_profile="https://openrel.example.invalid/profile",
        active_vocabulary="https://openrel.example.invalid/vocab",
        original_profile="https://openrel.example.invalid/original-profile",
        mapping_profile=mapping_profile,
        mapping_provenance=mapping_provenance,
        candidate_digest_sha256=compute_candidate_digest(payload),
        original_content_digest_sha256=custom.normalized_text_digest,
        candidate_payload=payload,
        original_representation={"orig": True},
        target_custom_licence_id=None,
        target_snapshot_before=None,
        target_digest_before=None,
        target_snapshot_after=None,
        target_digest_after=None,
        apply_allowed=apply_allowed,
        review_required=(action == "historical-mapping"),
        reason="apply me",
        created_at=now,
        updated_at=now,
        reviewed_at=now if status == "approved" else None,
        reviewed_by="reviewer@example.org" if status == "approved" else None,
        applied_at=None,
        applied_by=None,
        rolled_back_at=None,
        rolled_back_by=None,
        error_code=None,
        error_detail=None,
    )


def _audit_rows(session: FakeSession) -> list[CustomLicenceAuditEvent]:
    return [obj for obj in session._objects if isinstance(obj, CustomLicenceAuditEvent)]


def _policy_events(session: FakeSession, event_type: str) -> list[OpenRelPolicyEvent]:
    return [obj for obj in session._objects if isinstance(obj, OpenRelPolicyEvent) and obj.event_type == event_type]


def _representations(session: FakeSession) -> list[CustomLicenceRepresentation]:
    return [obj for obj in session._objects if isinstance(obj, CustomLicenceRepresentation)]


def _outbox_rows(session: FakeSession) -> list[CustomLicenceFederationOutbox]:
    return [obj for obj in session._objects if isinstance(obj, CustomLicenceFederationOutbox)]


class _FakePublisher:
    def __init__(self, *, node_id: str = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa", current_state: str = "published", fail_with: Exception | None = None):
        self.settings = SimpleNamespace(node_id=node_id)
        self.current_state = current_state
        self.fail_with = fail_with
        self.calls: list[dict] = []

    def get_record(self, canonical_id: str | None = None, *, encoded_canonical_id: str | None = None):
        return SimpleNamespace(canonicalId=canonical_id or encoded_canonical_id, currentState=self.current_state)

    def append_authoritative_upsert_in_session(self, **kwargs):
        if self.fail_with is not None:
            raise self.fail_with
        self.calls.append(kwargs)
        return SimpleNamespace(id=uuid.uuid4())


def _federated_settings() -> CustomLicenceRegistrationSettings:
    return CustomLicenceRegistrationSettings(
        database_url="postgresql+psycopg://example/db",
        authority_id="node-a",
        authority_base_iri="https://lfs.example",
        creator_organization_name="LFS",
        creator_organization_iri="https://lfs.example/org",
        validation_errors=(),
    )


def _published_outbox(custom: CustomLicence, record_id: uuid.UUID, event_id: uuid.UUID | None = None) -> CustomLicenceFederationOutbox:
    now = _utcnow()
    return CustomLicenceFederationOutbox(
        id=uuid.uuid4(),
        custom_licence_id=custom.id,
        operation="upsert",
        status="published",
        attempt_count=1,
        available_at=now,
        lease_owner=None,
        lease_expires_at=None,
        last_error_class=None,
        last_error_at=None,
        federation_record_id=record_id,
        federation_event_id=event_id or uuid.uuid4(),
        created_at=now,
        updated_at=now,
        published_at=now,
    )


def _record_for(custom: CustomLicence, *, node_id: str = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa") -> FederationRecord:
    identity = build_canonical_license_identity(
        authority_node_id=node_id,
        local_id=f"custom-{custom.id}",
        version=custom.version,
    )
    return FederationRecord(
        id=uuid.uuid4(),
        authority_node_id=node_id,
        local_id=f"custom-{custom.id}",
        version=custom.version,
        canonical_id=identity.canonicalId,
        resolving_uuid=uuid.UUID(identity.resolvingUuid),
        is_authoritative=True,
        payload={"baseline": True},
        payload_digest_sha256="a" * 64,
        published_at=_utcnow(),
        created_at=_utcnow(),
        updated_at=_utcnow(),
        materialized_generation=1,
        imported_from_peer_id=None,
    )


def _event_for(record: FederationRecord) -> FederationChangeEvent:
    now = _utcnow()
    return FederationChangeEvent(
        id=uuid.uuid4(),
        event_sequence=1,
        event_type="record.changed",
        authority_node_id=record.authority_node_id,
        record_id=record.id,
        operation="upsert",
        generated_at=now,
        payload_schema_version="1",
        signed_payload={"record": {"payload": {"baseline": True}}},
        signed_payload_digest_sha256="a" * 64,
        signature_base64url="sig",
        signature_kid="k1",
        signature_alg="EdDSA",
        provenance_type="publication",
        backfill_created_at=None,
        event_payload={"record": {"payload": {"baseline": True}}},
        event_digest_sha256="a" * 64,
        occurred_at=now,
        created_at=now,
        idempotency_key=None,
    )


def test_candidate_models_forbid_extra_fields():
    FullReplacementCandidate.model_validate(_replacement_payload())
    HistoricalMappingCandidate.model_validate(_mapping_payload())
    with pytest.raises(Exception):
        FullReplacementCandidate.model_validate(_replacement_payload(extra=1))
    with pytest.raises(Exception):
        HistoricalMappingCandidate.model_validate(_mapping_payload(extra=1))


def test_build_snapshot_and_digest_are_deterministic_and_exclude_operational_fields():
    custom = _custom_licence()
    row = CustomLicenceRepresentation(
        id=uuid.uuid4(),
        custom_licence_id=custom.id,
        representation_type="openrel-mapping",
        status="active",
        media_type="application/json",
        profile_uri="https://example.invalid/profile",
        vocabulary_uri="https://example.invalid/vocab",
        content={"b": 2, "a": 1},
        href=None,
        content_digest_sha256="b" * 64,
        mapping_profile="https://example.invalid/mapping",
        mapping_provenance={"z": 1, "a": 2},
        source_policy_state_id=uuid.uuid4(),
        created_at=_utcnow(),
        updated_at=_utcnow(),
        rolled_back_at=None,
    )
    snapshot = build_custom_licence_snapshot(custom, [row])
    assert "created_at" not in snapshot
    assert "updated_at" not in snapshot
    assert snapshot["representations"][0]["source_policy_state_id"] == str(row.source_policy_state_id)
    assert compute_custom_licence_snapshot_digest(snapshot) == compute_custom_licence_snapshot_digest(snapshot)


def test_apply_full_replacement_changes_only_mutable_fields():
    session = FakeSession()
    custom = _custom_licence()
    state = _state(custom)
    session._objects.extend([custom, state])
    service = OpenRelApplicationService(session)

    result = service.apply(state.id, actor_id="admin@example.org")

    assert result.status == "applied"
    assert custom.name == "After"
    assert custom.summary == "After summary"
    assert custom.description == "After description"
    assert custom.license_text == "After text"
    assert custom.normalized_text_digest == compute_normalized_text_digest("After text")
    assert custom.spdx_jsonld == {"after": True}
    assert custom.canonical_id == "lfs:node-a:lic-a:1.0"
    assert custom.public_scope == "local"
    assert custom.lifecycle_status == "registered"
    assert state.target_custom_licence_id == custom.id
    assert state.target_snapshot_before is not None
    assert state.target_snapshot_after is not None
    assert len(_policy_events(session, "applied")) == 1
    assert len(_audit_rows(session)) == 1


def test_apply_historical_mapping_adds_representation_without_overwriting_original_content():
    session = FakeSession()
    custom = _custom_licence()
    payload = _mapping_payload()
    state = _state(
        custom,
        action="historical-mapping",
        candidate_payload=payload,
        mapping_profile=payload["mappingProfile"],
        mapping_provenance=payload["mappingProvenance"],
    )
    session._objects.extend([custom, state])
    service = OpenRelApplicationService(session)

    service.apply(state.id, actor_id="admin@example.org")

    reps = _representations(session)
    assert len(reps) == 1
    assert reps[0].status == "active"
    assert reps[0].content == {"mapping": True}
    assert custom.license_text == "Before text"
    assert custom.spdx_jsonld == {"before": True}
    assert len(_policy_events(session, "applied")) == 1
    assert len(_audit_rows(session)) == 1


def test_apply_rejects_malformed_candidate_extra_fields_and_digest_mismatch():
    session = FakeSession()
    custom = _custom_licence()
    extra_state = _state(custom, candidate_payload=_replacement_payload(extra=1))
    bad_digest_state = _state(custom)
    bad_digest_state.candidate_digest_sha256 = "f" * 64
    session._objects.extend([custom, extra_state, bad_digest_state])
    service = OpenRelApplicationService(session)

    with pytest.raises(OpenRelApplicationValidationError):
        service.apply(extra_state.id, actor_id="admin@example.org")
    with pytest.raises(OpenRelApplicationConflictError):
        service.apply(bad_digest_state.id, actor_id="admin@example.org")


def test_apply_rejects_imported_spdx_and_missing_federated_collaborators():
    session = FakeSession()
    local = _custom_licence()
    federated = _custom_licence(public_scope="federated")
    federated.federation_status = "published"
    imported = _state(local, source_kind="federation-imported")
    spdx = _state(local, source_kind="spdx")
    fed_state = _state(federated)
    session._objects.extend([local, federated, imported, spdx, fed_state, _published_outbox(federated, uuid.uuid4())])
    service = OpenRelApplicationService(session)

    with pytest.raises(OpenRelApplicationConflictError):
        service.apply(imported.id, actor_id="admin@example.org")
    with pytest.raises(OpenRelApplicationConflictError):
        service.apply(spdx.id, actor_id="admin@example.org")
    with pytest.raises(OpenRelApplicationUnavailableError):
        service.apply(fed_state.id, actor_id="admin@example.org")


def test_apply_idempotency_and_rolled_back_state_is_terminal():
    session = FakeSession()
    custom = _custom_licence()
    payload = _mapping_payload()
    state = _state(
        custom,
        action="historical-mapping",
        candidate_payload=payload,
        mapping_profile=payload["mappingProfile"],
        mapping_provenance=payload["mappingProvenance"],
    )
    session._objects.extend([custom, state])
    service = OpenRelApplicationService(session)

    service.apply(state.id, actor_id="admin@example.org")
    apply_events = len(_policy_events(session, "applied"))
    apply_audits = len(_audit_rows(session))
    service.apply(state.id, actor_id="admin@example.org")
    assert len(_policy_events(session, "applied")) == apply_events
    assert len(_audit_rows(session)) == apply_audits

    service.rollback(state.id, actor_id="admin@example.org")
    rolled_back_rep = _representations(session)[0]
    assert rolled_back_rep.status == "rolled-back"
    with pytest.raises(OpenRelApplicationConflictError):
        service.apply(state.id, actor_id="admin@example.org")
    assert len(_representations(session)) == 1
    assert len(_policy_events(session, "applied")) == 1
    assert len(_policy_events(session, "rolled-back")) == 1


def test_rollback_restores_exact_snapshot_and_is_idempotent():
    session = FakeSession()
    custom = _custom_licence()
    state = _state(custom)
    session._objects.extend([custom, state])
    before = build_custom_licence_snapshot(custom, [])
    service = OpenRelApplicationService(session)

    service.apply(state.id, actor_id="admin@example.org")
    service.rollback(state.id, actor_id="admin@example.org")

    restored = build_custom_licence_snapshot(custom, [])
    assert restored == before
    rollback_events = len(_policy_events(session, "rolled-back"))
    audit_count = len(_audit_rows(session))
    service.rollback(state.id, actor_id="admin@example.org")
    assert len(_policy_events(session, "rolled-back")) == rollback_events
    assert len(_audit_rows(session)) == audit_count


def test_stale_target_rejects_apply_and_rollback_without_outer_commit_or_rollback():
    session = FakeSession()
    custom = _custom_licence()
    state = _state(custom)
    session._objects.extend([custom, state])
    service = OpenRelApplicationService(session)

    state.original_content_digest_sha256 = "b" * 64
    with pytest.raises(OpenRelApplicationConflictError):
        service.apply(state.id, actor_id="admin@example.org")
    assert session.commit_count == 0
    assert session.rollback_count == 0

    state.original_content_digest_sha256 = custom.normalized_text_digest
    service.apply(state.id, actor_id="admin@example.org")
    custom.name = "Changed externally"
    with pytest.raises(OpenRelApplicationConflictError):
        service.rollback(state.id, actor_id="admin@example.org")
    assert session.commit_count == 0
    assert session.rollback_count == 0


def test_new_policy_state_can_create_new_mapping_while_old_mapping_remains():
    session = FakeSession()
    custom = _custom_licence()
    payload1 = _mapping_payload(content={"mapping": 1}, mappingProvenance={"source": "one"})
    payload2 = _mapping_payload(content={"mapping": 2}, mappingProvenance={"source": "two"})
    state1 = _state(custom, action="historical-mapping", candidate_payload=payload1, mapping_profile=payload1["mappingProfile"], mapping_provenance=payload1["mappingProvenance"])
    state2 = _state(custom, action="historical-mapping", candidate_payload=payload2, mapping_profile=payload2["mappingProfile"], mapping_provenance=payload2["mappingProvenance"])
    session._objects.extend([custom, state1, state2])
    service = OpenRelApplicationService(session)

    service.apply(state1.id, actor_id="admin@example.org")
    service.rollback(state1.id, actor_id="admin@example.org")
    service.apply(state2.id, actor_id="admin@example.org")

    reps = sorted(_representations(session), key=lambda row: row.source_policy_state_id.hex)
    assert len(reps) == 2
    assert sorted(row.status for row in reps) == ["active", "rolled-back"]


def test_safe_audit_details_do_not_expose_secrets_or_raw_candidate_content():
    session = FakeSession()
    custom = _custom_licence()
    state = _state(
        custom,
        candidate_payload=_replacement_payload(summary="token=secret", spdxJsonld={"private_key": "super-secret"}),
    )
    session._objects.extend([custom, state])
    service = OpenRelApplicationService(session)

    service.apply(state.id, actor_id="admin@example.org")

    audit = _audit_rows(session)[0]
    text = json.dumps({"before": audit.before_state, "after": audit.after_state}).lower()
    assert "super-secret" not in text
    assert "token=secret" not in text


def test_invalid_actor_and_wrong_state_are_rejected_without_mutation():
    session = FakeSession()
    custom = _custom_licence()
    state = _state(custom, status="planned")
    session._objects.extend([custom, state])
    service = OpenRelApplicationService(session)
    with pytest.raises(OpenRelApplicationValidationError):
        service.apply(state.id, actor_id=" ")
    with pytest.raises(OpenRelApplicationConflictError):
        service.apply(state.id, actor_id="admin@example.org")
    with pytest.raises(OpenRelApplicationConflictError):
        service.rollback(state.id, actor_id="admin@example.org")
    assert len(_policy_events(session, "applied")) == 0
    assert len(_policy_events(session, "rolled-back")) == 0
    assert len(_audit_rows(session)) == 0


def test_deterministic_federation_idempotency_helpers():
    session = FakeSession()
    service = OpenRelApplicationService(session)
    state_id = uuid.uuid4()
    other_state_id = uuid.uuid4()
    apply1 = service._federation_idempotency_key(state_id=state_id, action="apply")
    apply2 = service._federation_idempotency_key(state_id=state_id, action="apply")
    rollback1 = service._federation_idempotency_key(state_id=state_id, action="rollback")
    other_apply = service._federation_idempotency_key(state_id=other_state_id, action="apply")
    assert apply1 == apply2 == uuid.uuid5(OPENREL_FEDERATION_IDEMPOTENCY_NAMESPACE, f"openrel-policy-state:{state_id}:apply")
    assert rollback1 == uuid.uuid5(OPENREL_FEDERATION_IDEMPOTENCY_NAMESPACE, f"openrel-policy-state:{state_id}:rollback")
    assert apply1 != rollback1
    assert apply1 != other_apply


def test_federated_full_replacement_emits_one_revision_and_updates_outbox():
    session = FakeSession()
    custom = _custom_licence(public_scope="federated")
    custom.federation_status = "published"
    state = _state(custom)
    record = _record_for(custom)
    event = _event_for(record)
    outbox = _published_outbox(custom, record.id, event.id)
    publisher = _FakePublisher()
    service = OpenRelApplicationService(
        session,
        federation_publisher=publisher,
        federation_custom_settings=_federated_settings(),
    )
    session._objects.extend([custom, state, outbox, record, event])

    service.apply(state.id, actor_id="admin@example.org")

    assert len(publisher.calls) == 1
    call = publisher.calls[0]
    assert call["idempotency_key"] == service._federation_idempotency_key(state_id=state.id, action="apply")
    assert call["payload"]["name"] == "After"
    assert "representations" not in call["payload"]
    assert call["provenance"] == {
        "source": "openrel-policy",
        "policyStateId": str(state.id),
        "action": "apply",
        "policyVersion": state.policy_version,
        "candidateDigest": state.candidate_digest_sha256,
    }
    assert outbox.federation_event_id == call["session"]._objects[-2].id or outbox.federation_event_id is not None
    assert session.begin_nested_count == 1
    assert session.commit_count == 0
    assert session.rollback_count == 0


def test_federated_historical_mapping_payload_is_deterministic_and_rollback_excludes_mapping():
    session = FakeSession()
    custom = _custom_licence(public_scope="federated")
    custom.federation_status = "published"
    payload = _mapping_payload(content={"mapping": 2, "a": 1}, mappingProvenance={"z": 1, "a": 2})
    state = _state(
        custom,
        action="historical-mapping",
        candidate_payload=payload,
        mapping_profile=payload["mappingProfile"],
        mapping_provenance=payload["mappingProvenance"],
    )
    record = _record_for(custom)
    event = _event_for(record)
    outbox = _published_outbox(custom, record.id, event.id)
    publisher = _FakePublisher()
    service = OpenRelApplicationService(
        session,
        federation_publisher=publisher,
        federation_custom_settings=_federated_settings(),
    )
    session._objects.extend([custom, state, outbox, record, event])

    service.apply(state.id, actor_id="admin@example.org")
    apply_payload = publisher.calls[-1]["payload"]
    assert apply_payload["representations"] == [
        {
            "representationType": "openrel-mapping",
            "mediaType": "application/json",
            "profile": "https://example.invalid/profile",
            "vocabulary": "https://example.invalid/vocab",
            "content": {"mapping": 2, "a": 1},
            "contentDigestSha256": apply_payload["representations"][0]["contentDigestSha256"],
            "mappingProfile": "https://example.invalid/mapping",
            "mappingProvenance": {"z": 1, "a": 2},
            "sourcePolicyStateId": str(state.id),
        }
    ]
    payload_text = json.dumps(apply_payload)
    assert "review" not in payload_text.lower()
    assert "secret" not in payload_text.lower()
    assert "target_snapshot_before" not in payload_text
    assert "target_snapshot_after" not in payload_text
    publisher.calls.clear()

    service.rollback(state.id, actor_id="admin@example.org")
    rollback_payload = publisher.calls[-1]["payload"]
    assert "representations" not in rollback_payload


def test_apply_reason_is_persisted_only_in_transition_event_and_retry_keeps_original():
    session = FakeSession()
    custom = _custom_licence()
    state = _state(custom)
    service = OpenRelApplicationService(session)
    session._objects.extend([custom, state])

    service.apply(state.id, actor_id="admin@example.org", reason='{"token":"secret","note":"keep"}')
    retry = service.apply(state.id, actor_id="admin@example.org", reason="different")

    assert retry is state
    events = _policy_events(session, "applied")
    assert len(events) == 1
    assert events[0].details["review_reason"] == '{"note":"keep","token":"[REDACTED]"}'
    assert "secret" not in json.dumps(events[0].details)


def test_transition_status_accepts_pre_sanitized_review_reason_string_without_change():
    session = FakeSession()
    custom = _custom_licence()
    state = _state(custom, status="approved")
    session._objects.extend([custom, state])

    OpenRelApplicationService(session).store.transition_status(
        state.id,
        new_status="applied",
        actor_type="admin",
        actor_id="admin@example.org",
        review_reason='{"note":"keep","token":"[REDACTED]"}',
    )

    events = _policy_events(session, "applied")
    assert len(events) == 1
    assert events[0].details["review_reason"] == '{"note":"keep","token":"[REDACTED]"}'


def test_federated_dependency_unavailability_uses_distinct_exception():
    session = FakeSession()
    custom = _custom_licence(public_scope="federated")
    custom.federation_status = "published"
    state = _state(custom)
    record = _record_for(custom)
    session._objects.extend([custom, state, _published_outbox(custom, record.id), record, _event_for(record)])
    service = OpenRelApplicationService(session)

    with pytest.raises(OpenRelApplicationUnavailableError):
        service.apply(state.id, actor_id="admin@example.org")


@pytest.mark.parametrize("status", ["pending", "publication_failed", "not_published", "deprecated", "tombstoned"])
def test_federated_unsupported_statuses_reject_before_mutation(status: str):
    session = FakeSession()
    custom = _custom_licence(public_scope="federated")
    custom.federation_status = status
    state = _state(custom)
    service = OpenRelApplicationService(
        session,
        federation_publisher=_FakePublisher(),
        federation_custom_settings=_federated_settings(),
    )
    session._objects.extend([custom, state])
    with pytest.raises(OpenRelApplicationConflictError):
        service.apply(state.id, actor_id="admin@example.org")
    assert custom.name == "Before"
    assert state.status == "approved"


def test_federated_publisher_failure_rolls_back_nested_changes_without_outer_rollback():
    session = FakeSession()
    custom = _custom_licence(public_scope="federated")
    custom.federation_status = "published"
    state = _state(custom)
    record = _record_for(custom)
    event = _event_for(record)
    outbox = _published_outbox(custom, record.id, event.id)
    service = OpenRelApplicationService(
        session,
        federation_publisher=_FakePublisher(fail_with=RuntimeError("signing unavailable")),
        federation_custom_settings=_federated_settings(),
    )
    session._objects.extend([custom, state, outbox, record, event])
    before_name = custom.name
    with pytest.raises(OpenRelApplicationConflictError):
        service.apply(state.id, actor_id="admin@example.org")
    assert state.status == "approved"
    assert len(_policy_events(session, "applied")) == 0
    assert len(_audit_rows(session)) == 0
    assert session.rollback_count == 0
    assert session.commit_count == 0


def test_federated_exact_retry_emits_nothing_new():
    session = FakeSession()
    custom = _custom_licence(public_scope="federated")
    custom.federation_status = "published"
    state = _state(custom, status="applied")
    state.target_custom_licence_id = custom.id
    snapshot = build_custom_licence_snapshot(custom, [])
    state.target_snapshot_after = snapshot
    state.target_digest_after = compute_custom_licence_snapshot_digest(snapshot)
    record = _record_for(custom)
    event = _event_for(record)
    outbox = _published_outbox(custom, record.id, event.id)
    publisher = _FakePublisher()
    service = OpenRelApplicationService(
        session,
        federation_publisher=publisher,
        federation_custom_settings=_federated_settings(),
    )
    session._objects.extend([custom, state, outbox, record, event])
    service.apply(state.id, actor_id="admin@example.org")
    assert publisher.calls == []
