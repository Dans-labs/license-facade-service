from __future__ import annotations

import json
import os
from dataclasses import replace
from datetime import date, datetime, timezone
from uuid import uuid4, uuid5, NAMESPACE_URL

from fastapi.testclient import TestClient

from src.license_facade_service.federation.license_identity import build_canonical_license_identity
from src.license_facade_service.api.v1 import licenses as licenses_api
from src.license_facade_service.main import create_app
from src.license_facade_service.runtime.openrel_policy import OpenRelPolicyRuntime, OpenRelPolicyRuntimeState
from src.license_facade_service.db.models.custom_licence import CustomLicence, CustomLicenceFederationOutbox
from src.license_facade_service.db.models.federation import FederationRecord, FederationChangeEvent
from src.license_facade_service.services.openrel_policy import OpenRelPolicyMode, OpenRelPolicySettings
from src.license_facade_service.services.openrel_application import build_custom_licence_snapshot, compute_custom_licence_snapshot_digest
from src.license_facade_service.services.openrel_policy_store import OpenRelPolicyStore
from src.license_facade_service.services.custom_licence_registration import compute_normalized_text_digest
from tests.test_openrel_policy_store import FakeSession, FakePlanBuilder


class TrackingSession(FakeSession):
    def __init__(self):
        super().__init__()
        self.close_count = 0

    def close(self):
        self.close_count += 1


class FakeClient:
    def __init__(self, *, available: bool = True):
        self.available = available
        self.calls = 0
        self.closed = 0

    def check_availability(self) -> bool:
        self.calls += 1
        return self.available

    def close(self) -> None:
        self.closed += 1


class FakeDatabase:
    def __init__(self, session: TrackingSession):
        self.session = session
        self.close_count = 0
        self.transaction_entries = 0

    class _Txn:
        def __init__(self, outer):
            self.outer = outer

        def __enter__(self):
            self.outer.transaction_entries += 1
            return self.outer.session

        def __exit__(self, exc_type, exc, tb):
            if exc_type is None:
                self.outer.session.commit()
            else:
                self.outer.session.rollback()
            self.outer.session.close()
            return False

    def transaction(self):
        return self._Txn(self)

    def session_factory(self):
        return self.session

    def close(self) -> None:
        self.close_count += 1


class _AdminFakePublisher:
    def __init__(self):
        self.settings = type("S", (), {"node_id": "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"})()
        self.calls: list[dict] = []

    def append_authoritative_upsert_in_session(self, **kwargs):
        self.calls.append(kwargs)
        return type("Event", (), {"id": uuid4()})()


def _settings(**overrides) -> OpenRelPolicySettings:
    values = dict(
        enabled=True,
        mode=OpenRelPolicyMode.active,
        database_url="postgresql+psycopg://postgres:postgres@127.0.0.1:5432/lfs_schema",
        admin_cursor_secret="x" * 32,
        base_url="https://openrel.example.invalid/openrel/api/v0.4",
        approved_profile="https://openrel.org/ns#",
        approved_version="0.4",
        effective_date=date(2026, 9, 4),
        cache_ttl_seconds=5,
        timeout_seconds=1.0,
        max_response_bytes=256,
        migration_review_required=False,
    )
    values.update(overrides)
    return OpenRelPolicySettings(**values)


def _payload(**overrides):
    values = {
        "canonicalLicenseId": "lic-eval-1",
        "sourceKind": "custom",
        "sourceRecordRef": "ref-1",
        "registrationTimestamp": "2026-09-05T12:00:00Z",
        "candidatePayload": {"candidate": 1, "token": "secret-token"},
        "candidate": {
            "providerUrl": "https://openrel.example.invalid/openrel/api/v0.4",
            "profile": "https://openrel.org/ns#",
            "vocabulary": "https://openrel.org/ns#",
            "version": "0.4",
            "content": "<openrel>candidate</openrel>",
            "href": "https://openrel.example.invalid/openrel/api/v0.4/licence/123",
            "provenance": "candidate provenance",
            "mappingProfile": "https://openrel.org/ns#",
            "mappingProvenance": "mapping provenance",
        },
        "originalRepresentation": {"profile": "https://example.com/original-profile", "token": "secret-token"},
        "originalContentDigest": None,
    }
    values.update(overrides)
    return values


def _app_with_runtime(runtime: OpenRelPolicyRuntime, state: OpenRelPolicyRuntimeState) -> TestClient:
    os.environ["LFS_ADMIN_TOKEN"] = "admin-token"
    os.environ["LFS_CURATOR_TOKEN"] = "curator-token"
    app = create_app()
    app.state.openrel_policy_runtime = runtime
    app.state.openrel_policy_state = state
    return TestClient(app)


def _admin_headers() -> dict[str, str]:
    return {"Authorization": "Bearer admin-token"}


def _ready_runtime(*, settings: OpenRelPolicySettings | None = None, session: TrackingSession | None = None, client: FakeClient | None = None):
    fake_session = session or TrackingSession()
    runtime = OpenRelPolicyRuntime(settings or _settings())
    runtime.db = FakeDatabase(fake_session)  # type: ignore[assignment]
    runtime.client = client or FakeClient()  # type: ignore[assignment]
    return runtime, fake_session


def _custom(public_scope: str = "local", federation_status: str = "not_published") -> CustomLicence:
    now = datetime.now(timezone.utc)
    requested_license_id = f"lic-{uuid4().hex[:8]}"
    return CustomLicence(
        id=uuid4(),
        authority_id="node-a",
        requested_license_id=requested_license_id,
        version="1.0",
        canonical_id=f"lfs:node-a:{requested_license_id}:1.0",
        resolving_uuid=uuid4(),
        public_scope=public_scope,
        federation_status=federation_status,
        spdx_submission_status="not_requested",
        lifecycle_status="registered",
        name="Before",
        summary="Before summary",
        description="Before description",
        license_text="Before text",
        normalized_text_digest=compute_normalized_text_digest("Before text"),
        spdx_jsonld={"before": True},
        creator_role="admin",
        created_at=now,
        updated_at=now,
        deprecated_at=None,
        withdrawn_at=None,
        tombstoned_at=None,
    )


def _published_federation_objects(custom: CustomLicence):
    record_id = uuid4()
    event_id = uuid4()
    identity = build_canonical_license_identity(
        authority_node_id="aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa",
        local_id=f"custom-{custom.id}",
        version=custom.version,
    )
    record = FederationRecord(
        id=record_id,
        canonical_id=identity.canonicalId,
        local_id=f"custom-{custom.id}",
        version=custom.version,
        authority_node_id="aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa",
        resolving_uuid=identity.resolvingUuid,
        payload={"name": custom.name},
        payload_digest_sha256="0" * 64,
        is_authoritative=True,
        imported_from_peer_id=None,
        created_at=datetime.now(timezone.utc),
        updated_at=datetime.now(timezone.utc),
    )
    event = FederationChangeEvent(
        id=event_id,
        event_sequence=1,
        event_type="record.changed",
        authority_node_id="aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa",
        idempotency_key=uuid4(),
        record_id=record_id,
        operation="upsert",
        generated_at=datetime.now(timezone.utc),
        payload_schema_version="1",
        signed_payload={"record": {"payload": {"name": custom.name}}},
        signed_payload_digest_sha256="0" * 64,
        signature_base64url="sig",
        signature_kid="k1",
        signature_alg="EdDSA",
        provenance_type="publication",
        backfill_created_at=None,
        event_payload={"record": {"payload": {"name": custom.name}}},
        event_digest_sha256="0" * 64,
        occurred_at=datetime.now(timezone.utc),
        created_at=datetime.now(timezone.utc),
    )
    outbox = CustomLicenceFederationOutbox(
        id=uuid4(),
        custom_licence_id=custom.id,
        operation="upsert",
        status="published",
        attempt_count=1,
        available_at=datetime.now(timezone.utc),
        lease_owner=None,
        lease_expires_at=None,
        last_error_class=None,
        last_error_at=None,
        federation_record_id=record_id,
        federation_event_id=event_id,
        created_at=datetime.now(timezone.utc),
        updated_at=datetime.now(timezone.utc),
        published_at=datetime.now(timezone.utc),
    )
    return record, event, outbox


def test_core_validation_unaffected_by_absent_db_and_cursor():
    settings = OpenRelPolicySettings(
        enabled=True,
        mode=OpenRelPolicyMode.active,
        base_url="https://openrel.example.invalid/openrel/api/v0.4",
        approved_profile="https://openrel.org/ns#",
        approved_version="0.4",
        effective_date=date(2026, 9, 4),
    )
    assert settings.validation_errors == ()
    assert len(settings.admin_runtime_validation_errors) == 2


def test_runtime_validation_requires_db_and_cursor_only_when_enabled():
    disabled = OpenRelPolicySettings(enabled=False, mode=OpenRelPolicyMode.disabled)
    active = OpenRelPolicySettings(enabled=True, mode=OpenRelPolicyMode.active)
    assert disabled.admin_runtime_validation_errors == ()
    assert active.admin_runtime_validation_errors


def test_env_and_file_precedence_and_secret_not_in_repr(tmp_path):
    db_file = tmp_path / "db.txt"
    secret_file = tmp_path / "secret.txt"
    db_file.write_text("postgresql+psycopg://file-user:file-pass@127.0.0.1:5432/filedb\n", encoding="utf-8")
    secret_file.write_text("f" * 32 + "\n", encoding="utf-8")
    settings = OpenRelPolicySettings.from_env(
        {
            "OPENREL_ENABLED": "true",
            "OPENREL_POLICY_MODE": "active",
            "OPENREL_POLICY_DATABASE_URL": "postgresql+psycopg://inline-user:inline-pass@127.0.0.1:5432/inlinedb",
            "OPENREL_POLICY_DATABASE_URL_FILE": str(db_file),
            "OPENREL_ADMIN_CURSOR_SECRET": "i" * 32,
            "OPENREL_ADMIN_CURSOR_SECRET_FILE": str(secret_file),
            "OPENREL_BASE_URL": "https://openrel.example.invalid/openrel/api/v0.4",
            "OPENREL_APPROVED_PROFILE": "https://openrel.org/ns#",
            "OPENREL_APPROVED_VERSION": "0.4",
            "OPENREL_POLICY_EFFECTIVE_DATE": "2026-09-04",
        }
    )
    assert settings.database_url.endswith("/inlinedb")
    assert settings.admin_cursor_secret == "i" * 32
    assert "inline-user" not in repr(settings)
    assert "i" * 32 not in repr(settings)


def test_missing_secret_file_safe_failure():
    settings = OpenRelPolicySettings.from_env(
        {
            "OPENREL_ENABLED": "true",
            "OPENREL_POLICY_MODE": "active",
            "OPENREL_POLICY_DATABASE_URL": "postgresql+psycopg://user:pass@127.0.0.1:5432/db",
            "OPENREL_ADMIN_CURSOR_SECRET_FILE": "/no/such/file",
            "OPENREL_BASE_URL": "https://openrel.example.invalid/openrel/api/v0.4",
            "OPENREL_APPROVED_PROFILE": "https://openrel.org/ns#",
            "OPENREL_APPROVED_VERSION": "0.4",
            "OPENREL_POLICY_EFFECTIVE_DATE": "2026-09-04",
        }
    )
    assert "cursor secret" in " ".join(settings.admin_runtime_validation_errors).lower()


def test_disabled_runtime_inert_without_database():
    runtime = OpenRelPolicyRuntime(OpenRelPolicySettings())
    state = runtime.initialize()
    client = _app_with_runtime(runtime, state)
    response = client.post("/api/v1/admin/openrel/evaluations", headers={"Authorization": "Bearer admin-token"}, json=_payload(candidate=None))
    assert response.status_code == 200
    body = response.json()
    assert body["policyStateId"] is None
    assert body["persistedStatus"] is None
    assert body["candidateDigest"] is None
    assert body["policyPlan"]["action"] == "none"


def test_partial_initialization_cleanup_and_idempotent_close():
    settings = _settings(database_url="sqlite:///tmp/not-postgres.db")
    runtime = OpenRelPolicyRuntime(settings)
    state = runtime.initialize()
    assert state.ready is False
    runtime.close()
    runtime.close()


def test_startup_makes_no_provider_request_and_public_survives_unavailable_runtime():
    os.environ.pop("CUSTOM_LICENCE_REGISTRATION_DATABASE_URL", None)
    licenses_api._license_service = None
    runtime = OpenRelPolicyRuntime(_settings(database_url=None, admin_cursor_secret=None))
    state = runtime.initialize()
    client = _app_with_runtime(runtime, state)
    assert client.get("/api/v1/licenses/MIT").status_code == 200
    assert client.get("/api/v1/admin/openrel/policy-states", headers={"Authorization": "Bearer admin-token"}).status_code == 503


def test_all_six_endpoints_authentication_rules():
    runtime, _session = _ready_runtime()
    client = _app_with_runtime(runtime, OpenRelPolicyRuntimeState(enabled=True, ready=True, errors=()))
    targets = [
        ("post", "/api/v1/admin/openrel/evaluations", _payload()),
        ("get", "/api/v1/admin/openrel/policy-states", None),
        ("get", f"/api/v1/admin/openrel/policy-states/{uuid4()}", None),
        ("get", f"/api/v1/admin/openrel/policy-states/{uuid4()}/events", None),
        ("post", f"/api/v1/admin/openrel/policy-states/{uuid4()}/approve", {}),
        ("post", f"/api/v1/admin/openrel/policy-states/{uuid4()}/reject", {}),
        ("post", f"/api/v1/admin/openrel/policy-states/{uuid4()}/apply", {}),
        ("post", f"/api/v1/admin/openrel/policy-states/{uuid4()}/rollback", {}),
    ]
    for method, path, body in targets:
        if method == "get":
            assert client.get(path).status_code == 401
            assert client.get(path, headers={"Authorization": "Bearer nope"}).status_code == 401
            assert client.get(path, headers={"Authorization": "Bearer curator-token"}).status_code == 403
        else:
            assert client.post(path, json=body).status_code == 401
            assert client.post(path, headers={"Authorization": "Bearer nope"}, json=body).status_code == 401
            assert client.post(path, headers={"Authorization": "Bearer curator-token"}, json=body).status_code == 403


def test_get_routes_never_commit_and_close_sessions():
    runtime, session = _ready_runtime(settings=_settings(migration_review_required=True))
    store = OpenRelPolicyStore(session)
    state = store.record_plan(
        canonical_license_id="lic-read",
        source_kind="custom",
        source_record_ref="ref-read",
        settings=replace(runtime.settings, database_url=None, admin_cursor_secret=None),
        plan=FakePlanBuilder.default_plan(review_required=True),
        candidate_payload={"candidate": 1},
        original_representation={"profile": "https://example.com/original-profile"},
        original_content_digest=None,
        actor_type="admin",
        actor_id="admin",
    )
    client = _app_with_runtime(runtime, OpenRelPolicyRuntimeState(enabled=True, ready=True, errors=()))
    assert client.get("/api/v1/admin/openrel/policy-states", headers={"Authorization": "Bearer admin-token"}).status_code == 200
    assert client.get(f"/api/v1/admin/openrel/policy-states/{state.id}", headers={"Authorization": "Bearer admin-token"}).status_code == 200
    assert client.get(f"/api/v1/admin/openrel/policy-states/{state.id}/events", headers={"Authorization": "Bearer admin-token"}).status_code == 200
    assert session.commit_count == 0
    assert session.close_count == 3


def test_successful_post_commits_once_failed_post_rolls_back_and_sessions_close():
    runtime, session = _ready_runtime(settings=_settings(migration_review_required=True))
    client = _app_with_runtime(runtime, OpenRelPolicyRuntimeState(enabled=True, ready=True, errors=()))
    ok = client.post("/api/v1/admin/openrel/evaluations", headers={"Authorization": "Bearer admin-token"}, json=_payload())
    assert ok.status_code == 200
    assert session.commit_count == 1
    fail = client.post("/api/v1/admin/openrel/evaluations", headers={"Authorization": "Bearer admin-token"}, json={**_payload(), "canonicalLicenseId": "   "})
    assert fail.status_code == 422
    assert session.rollback_count == 1
    assert session.close_count == 2


def test_apply_and_rollback_routes_openapi_and_validation_contract():
    runtime, session = _ready_runtime(settings=_settings(migration_review_required=True))
    store = OpenRelPolicyStore(session)
    state = store.record_plan(
        canonical_license_id="lic-apply-api",
        source_kind="custom",
        source_record_ref="ref-apply-api",
        settings=replace(runtime.settings, database_url=None, admin_cursor_secret=None),
        plan=FakePlanBuilder.default_plan(review_required=True),
        candidate_payload={"name": "After", "summary": "After summary", "description": "After description", "licenseText": "After text", "spdxJsonld": {"after": True}},
        original_representation={"profile": "https://example.com/original-profile"},
        original_content_digest=None,
        actor_type="admin",
        actor_id="admin",
    )
    store.transition_status(
        state.id,
        new_status="approved",
        actor_type="admin",
        actor_id="admin",
        reviewer_identity="admin",
    )
    client = _app_with_runtime(runtime, OpenRelPolicyRuntimeState(enabled=True, ready=True, errors=()))
    openapi = client.get("/openapi.json").json()
    apply_op = openapi["paths"]["/api/v1/admin/openrel/policy-states/{state_id}/apply"]["post"]
    rollback_op = openapi["paths"]["/api/v1/admin/openrel/policy-states/{state_id}/rollback"]["post"]
    assert apply_op["tags"] == ["OpenREL Admin"]
    assert rollback_op["tags"] == ["OpenREL Admin"]
    assert "stored candidate" in apply_op["description"]
    assert "stored verified pre-apply snapshot" in rollback_op["description"]
    assert {"200", "401", "403", "404", "409", "422", "503"}.issubset(apply_op["responses"].keys())
    bad = client.post(
        f"/api/v1/admin/openrel/policy-states/{state.id}/apply",
        headers={"Authorization": "Bearer admin-token"},
        json={"candidatePayload": {"x": 1}},
    )
    assert bad.status_code == 422
    too_long = client.post(
        f"/api/v1/admin/openrel/policy-states/{state.id}/apply",
        headers={"Authorization": "Bearer admin-token"},
        json={"reason": "x" * 1025},
    )
    assert too_long.status_code == 422


def test_apply_and_rollback_admin_success_and_idempotent_retry():
    runtime, session = _ready_runtime(settings=_settings(migration_review_required=True))
    custom = _custom()
    session._objects.append(custom)
    store = OpenRelPolicyStore(session)
    state = store.record_plan(
        canonical_license_id="lic-apply-ok",
        source_kind="custom",
        source_record_ref=str(custom.id),
        settings=replace(runtime.settings, database_url=None, admin_cursor_secret=None),
        plan=FakePlanBuilder.default_plan(review_required=True),
        candidate_payload={"name": "After", "summary": "After summary", "description": "After description", "licenseText": "After text", "spdxJsonld": {"after": True}},
        original_representation={"profile": "https://example.com/original-profile"},
        original_content_digest=custom.normalized_text_digest,
        actor_type="admin",
        actor_id="admin",
    )
    store.transition_status(
        state.id,
        new_status="approved",
        actor_type="admin",
        actor_id="admin",
        reviewer_identity="admin",
    )
    client = _app_with_runtime(runtime, OpenRelPolicyRuntimeState(enabled=True, ready=True, errors=()))
    apply = client.post(
        f"/api/v1/admin/openrel/policy-states/{state.id}/apply",
        headers={"Authorization": "Bearer admin-token"},
        json={"reason": "{\"token\":\"secret\",\"note\":\"apply\"}"},
    )
    assert apply.status_code == 200
    body = apply.json()
    assert body["status"] == "applied"
    assert "candidatePayload" not in body
    assert "targetSnapshotBefore" not in body
    retry = client.post(f"/api/v1/admin/openrel/policy-states/{state.id}/apply", headers={"Authorization": "Bearer admin-token"}, json={"reason": "different"})
    assert retry.status_code == 200
    assert len([obj for obj in session._objects if getattr(obj, "event_type", "") == "applied"]) == 1
    rollback = client.post(
        f"/api/v1/admin/openrel/policy-states/{state.id}/rollback",
        headers={"Authorization": "Bearer admin-token"},
        json={},
    )
    assert rollback.status_code == 200
    rollback_retry = client.post(
        f"/api/v1/admin/openrel/policy-states/{state.id}/rollback",
        headers={"Authorization": "Bearer admin-token"},
        json={"reason": "different"},
    )
    assert rollback_retry.status_code == 200
    assert len([obj for obj in session._objects if getattr(obj, "event_type", "") == "rolled-back"]) == 1


def test_apply_reason_is_sanitized_persisted_and_hidden_from_response_and_retry():
    runtime, session = _ready_runtime(settings=_settings(migration_review_required=True))
    custom = _custom()
    session._objects.append(custom)
    store = OpenRelPolicyStore(session)
    state = store.record_plan(
        canonical_license_id="lic-apply-reason",
        source_kind="custom",
        source_record_ref=str(custom.id),
        settings=replace(runtime.settings, database_url=None, admin_cursor_secret=None),
        plan=FakePlanBuilder.default_plan(review_required=True),
        candidate_payload={"name": "After", "summary": "After summary", "description": "After description", "licenseText": "After text", "spdxJsonld": {"after": True}},
        original_representation={"profile": "https://example.com/original-profile"},
        original_content_digest=custom.normalized_text_digest,
        actor_type="admin",
        actor_id="admin",
    )
    store.transition_status(state.id, new_status="approved", actor_type="admin", actor_id="admin", reviewer_identity="admin")
    client = _app_with_runtime(runtime, OpenRelPolicyRuntimeState(enabled=True, ready=True, errors=()))

    first = client.post(
        f"/api/v1/admin/openrel/policy-states/{state.id}/apply",
        headers=_admin_headers(),
        json={"reason": ' {"token":"secret","note":"apply"} '},
    )
    assert first.status_code == 200
    assert '"review_reason"' not in first.text
    assert '"reason":"' not in first.text
    retry = client.post(
        f"/api/v1/admin/openrel/policy-states/{state.id}/apply",
        headers=_admin_headers(),
        json={"reason": '{"token":"different","note":"retry"}'},
    )
    assert retry.status_code == 200
    events = [obj for obj in session._objects if getattr(obj, "event_type", "") == "applied"]
    assert len(events) == 1
    assert events[0].details["review_reason"] == '{"note":"apply","token":"[REDACTED]"}'
    assert "secret" not in json.dumps(events[0].details)
    assert "[REDACTED]" in json.dumps(events[0].details)


def test_federated_apply_reason_excluded_from_federation_payload_and_503_without_publisher():
    runtime, session = _ready_runtime(settings=_settings(migration_review_required=True))
    custom = _custom(public_scope="federated", federation_status="published")
    record, event, outbox = _published_federation_objects(custom)
    session._objects.extend([custom, record, event, outbox])
    store = OpenRelPolicyStore(session)
    state = store.record_plan(
        canonical_license_id="lic-fed-reason",
        source_kind="custom",
        source_record_ref=str(custom.id),
        settings=replace(runtime.settings, database_url=None, admin_cursor_secret=None),
        plan=FakePlanBuilder.default_plan(review_required=True),
        candidate_payload={"name": "After", "summary": "After summary", "description": "After description", "licenseText": "After text", "spdxJsonld": {"after": True}},
        original_representation={"profile": "https://example.com/original-profile"},
        original_content_digest=custom.normalized_text_digest,
        actor_type="admin",
        actor_id="admin",
    )
    store.transition_status(state.id, new_status="approved", actor_type="admin", actor_id="admin", reviewer_identity="admin")
    runtime.publisher = _AdminFakePublisher()  # type: ignore[attr-defined]
    client = _app_with_runtime(runtime, OpenRelPolicyRuntimeState(enabled=True, ready=True, errors=()))
    client.app.state.federation_runtime = type("FR", (), {"publisher": runtime.publisher})()
    client.app.state.federation_state = type("FS", (), {"ready": True})()
    client.app.state.custom_licence_registration_settings = type("CS", (), {
        "database_url": "postgresql+psycopg://example/db",
        "authority_id": "node-a",
        "authority_base_iri": "https://lfs.example",
        "creator_organization_name": "LFS",
        "creator_organization_iri": "https://lfs.example/org",
        "validation_errors": (),
    })()

    response = client.post(
        f"/api/v1/admin/openrel/policy-states/{state.id}/apply",
        headers=_admin_headers(),
        json={"reason": '{"token":"secret","note":"federated"}'},
    )
    assert response.status_code == 200
    payload_text = json.dumps(runtime.publisher.calls[0]["payload"])
    provenance_text = json.dumps(runtime.publisher.calls[0]["provenance"])
    assert "secret" not in payload_text
    assert "reason" not in payload_text.lower()
    assert "secret" not in provenance_text
    assert "reason" not in provenance_text.lower()


def test_local_apply_succeeds_without_federation_runtime_and_missing_federated_dependencies_return_503():
    runtime, session = _ready_runtime(settings=_settings(migration_review_required=True))
    local_custom = _custom()
    fed_custom = _custom(public_scope="federated", federation_status="published")
    record, event, outbox = _published_federation_objects(fed_custom)
    session._objects.extend([local_custom, fed_custom, record, event, outbox])
    store = OpenRelPolicyStore(session)
    local_state = store.record_plan(
        canonical_license_id="lic-local-only",
        source_kind="custom",
        source_record_ref=str(local_custom.id),
        settings=replace(runtime.settings, database_url=None, admin_cursor_secret=None),
        plan=FakePlanBuilder.default_plan(review_required=True),
        candidate_payload={"name": "After", "summary": "After summary", "description": "After description", "licenseText": "After text", "spdxJsonld": {"after": True}},
        original_representation={"profile": "https://example.com/original-profile"},
        original_content_digest=local_custom.normalized_text_digest,
        actor_type="admin",
        actor_id="admin",
    )
    fed_apply_state = store.record_plan(
        canonical_license_id="lic-fed-503-apply",
        source_kind="custom",
        source_record_ref=str(fed_custom.id),
        settings=replace(runtime.settings, database_url=None, admin_cursor_secret=None),
        plan=FakePlanBuilder.default_plan(review_required=True),
        candidate_payload={"name": "After", "summary": "After summary", "description": "After description", "licenseText": "After text", "spdxJsonld": {"after": True}},
        original_representation={"profile": "https://example.com/original-profile"},
        original_content_digest=fed_custom.normalized_text_digest,
        actor_type="admin",
        actor_id="admin",
    )
    fed_rollback_state = store.record_plan(
        canonical_license_id="lic-fed-503-rollback",
        source_kind="custom",
        source_record_ref=str(fed_custom.id),
        settings=replace(runtime.settings, database_url=None, admin_cursor_secret=None),
        plan=FakePlanBuilder.default_plan(review_required=True),
        candidate_payload={"name": "After2", "summary": "After summary", "description": "After description", "licenseText": "After text", "spdxJsonld": {"after": True}},
        original_representation={"profile": "https://example.com/original-profile"},
        original_content_digest=fed_custom.normalized_text_digest,
        actor_type="admin",
        actor_id="admin",
    )
    store.transition_status(local_state.id, new_status="approved", actor_type="admin", actor_id="admin", reviewer_identity="admin")
    store.transition_status(fed_apply_state.id, new_status="approved", actor_type="admin", actor_id="admin", reviewer_identity="admin")
    store.transition_status(fed_rollback_state.id, new_status="approved", actor_type="admin", actor_id="admin", reviewer_identity="admin")
    snapshot = build_custom_licence_snapshot(fed_custom, [])
    digest = compute_custom_licence_snapshot_digest(snapshot)
    fed_rollback_state.status = "applied"
    fed_rollback_state.target_custom_licence_id = fed_custom.id
    fed_rollback_state.target_digest_before = digest
    fed_rollback_state.target_digest_after = digest
    fed_rollback_state.target_snapshot_before = snapshot
    client = _app_with_runtime(runtime, OpenRelPolicyRuntimeState(enabled=True, ready=True, errors=()))

    local = client.post(f"/api/v1/admin/openrel/policy-states/{local_state.id}/apply", headers=_admin_headers(), json={})
    assert local.status_code == 200
    apply_503 = client.post(f"/api/v1/admin/openrel/policy-states/{fed_apply_state.id}/apply", headers=_admin_headers(), json={})
    assert apply_503.status_code == 503
    assert "application/problem+json" in apply_503.headers["content-type"]
    rollback_503 = client.post(f"/api/v1/admin/openrel/policy-states/{fed_rollback_state.id}/rollback", headers=_admin_headers(), json={})
    assert rollback_503.status_code == 503
    assert "application/problem+json" in rollback_503.headers["content-type"]
    assert session.rollback_count >= 2
    assert session.close_count >= 3


def test_apply_endpoint_missing_state_404_invalid_transition_409_and_malformed_reason_no_mutation():
    runtime, session = _ready_runtime(settings=_settings(migration_review_required=True))
    custom = _custom()
    session._objects.append(custom)
    store = OpenRelPolicyStore(session)
    state = store.record_plan(
        canonical_license_id="lic-apply-errors",
        source_kind="custom",
        source_record_ref=str(custom.id),
        settings=replace(runtime.settings, database_url=None, admin_cursor_secret=None),
        plan=FakePlanBuilder.default_plan(review_required=True),
        candidate_payload={"name": "After", "summary": "After summary", "description": "After description", "licenseText": "After text", "spdxJsonld": {"after": True}},
        original_representation={"profile": "https://example.com/original-profile"},
        original_content_digest=custom.normalized_text_digest,
        actor_type="admin",
        actor_id="admin",
    )
    client = _app_with_runtime(runtime, OpenRelPolicyRuntimeState(enabled=True, ready=True, errors=()))
    missing = client.post(f"/api/v1/admin/openrel/policy-states/{uuid4()}/apply", headers=_admin_headers(), json={})
    assert missing.status_code == 404
    assert "application/problem+json" in missing.headers["content-type"]
    conflict = client.post(f"/api/v1/admin/openrel/policy-states/{state.id}/apply", headers=_admin_headers(), json={})
    assert conflict.status_code == 409
    before_events = len([obj for obj in session._objects if getattr(obj, "policy_state_id", None) == state.id])
    malformed = client.post(
        f"/api/v1/admin/openrel/policy-states/{state.id}/apply",
        headers=_admin_headers(),
        json={"reason": '{"token"'},
    )
    assert malformed.status_code == 409
    assert len([obj for obj in session._objects if getattr(obj, "policy_state_id", None) == state.id]) == before_events


def test_request_override_fields_rejected_and_sensitive_fields_excluded():
    runtime, session = _ready_runtime()
    client = _app_with_runtime(runtime, OpenRelPolicyRuntimeState(enabled=True, ready=True, errors=()))
    bad = client.post("/api/v1/admin/openrel/evaluations", headers={"Authorization": "Bearer admin-token"}, json={**_payload(), "actorType": "system"})
    assert bad.status_code == 422
    ok = client.post("/api/v1/admin/openrel/evaluations", headers={"Authorization": "Bearer admin-token"}, json=_payload())
    body = ok.json()
    assert "candidatePayload" not in body
    assert "originalRepresentation" not in body
    assert "errorDetail" not in body
    assert "secret-token" not in str(body)


def test_review_reason_sanitized_stored_and_retry_is_idempotent():
    runtime, session = _ready_runtime(settings=_settings(migration_review_required=True))
    client = _app_with_runtime(runtime, OpenRelPolicyRuntimeState(enabled=True, ready=True, errors=()))
    created = client.post("/api/v1/admin/openrel/evaluations", headers={"Authorization": "Bearer admin-token"}, json=_payload())
    state_id = created.json()["policyStateId"]
    approve = client.post(
        f"/api/v1/admin/openrel/policy-states/{state_id}/approve",
        headers={"Authorization": "Bearer admin-token"},
        json={"reason": "{\"token\":\"secret\",\"note\":\"approve\"}"},
    )
    assert approve.status_code == 200
    retry = client.post(
        f"/api/v1/admin/openrel/policy-states/{state_id}/approve",
        headers={"Authorization": "Bearer admin-token"},
        json={"reason": "{\"token\":\"secret\",\"note\":\"approve\"}"},
    )
    assert retry.status_code == 200
    reject = client.post(f"/api/v1/admin/openrel/policy-states/{state_id}/reject", headers={"Authorization": "Bearer admin-token"}, json={"reason": "no"})
    assert reject.status_code == 409
    events = [obj for obj in session._objects if getattr(obj, "event_type", "") == "review-approved"]
    assert "secret" not in events[-1].details["review_reason"]
    assert "[REDACTED]" in events[-1].details["review_reason"]
    assert "approve" in events[-1].details["review_reason"]
    http_events = client.get(f"/api/v1/admin/openrel/policy-states/{state_id}/events", headers={"Authorization": "Bearer admin-token"}).json()
    assert "secret" not in str(http_events)
    assert "[REDACTED]" in str(http_events)


def test_oversized_structured_review_reason_stays_bounded_and_redacted_in_event_response():
    runtime, session = _ready_runtime(settings=_settings(migration_review_required=True))
    client = _app_with_runtime(runtime, OpenRelPolicyRuntimeState(enabled=True, ready=True, errors=()))
    created = client.post("/api/v1/admin/openrel/evaluations", headers={"Authorization": "Bearer admin-token"}, json=_payload())
    state_id = created.json()["policyStateId"]
    reason = '{"token":"secret","items":[{"note":"approve","blob":"' + ("x" * 480) + '"},{"password":"pw"}],"tail":"' + ("y" * 200) + '"}'
    response = client.post(
        f"/api/v1/admin/openrel/policy-states/{state_id}/approve",
        headers={"Authorization": "Bearer admin-token"},
        json={"reason": reason},
    )
    assert response.status_code == 200
    event = next(obj for obj in session._objects if getattr(obj, "event_type", "") == "review-approved")
    assert len(event.details["review_reason"]) <= 512
    json.loads(event.details["review_reason"])
    assert "secret" not in event.details["review_reason"]
    assert "[REDACTED]" in event.details["review_reason"]
    assert "[TRUNCATED]" in event.details["review_reason"]
    http_events = client.get(f"/api/v1/admin/openrel/policy-states/{state_id}/events", headers={"Authorization": "Bearer admin-token"}).json()
    assert "secret" not in str(http_events)


def test_malformed_structured_review_reason_returns_problem_without_transition():
    runtime, session = _ready_runtime(settings=_settings(migration_review_required=True))
    client = _app_with_runtime(runtime, OpenRelPolicyRuntimeState(enabled=True, ready=True, errors=()))
    created = client.post("/api/v1/admin/openrel/evaluations", headers={"Authorization": "Bearer admin-token"}, json=_payload())
    state_id = created.json()["policyStateId"]
    before = len([obj for obj in session._objects if getattr(obj, "policy_state_id", None) == state_id])
    response = client.post(
        f"/api/v1/admin/openrel/policy-states/{state_id}/approve",
        headers={"Authorization": "Bearer admin-token"},
        json={"reason": "{\"token\""},
    )
    assert response.status_code == 409
    assert "application/problem+json" in response.headers["content-type"]
    state = next(obj for obj in session._objects if str(getattr(obj, "id", None)) == state_id)
    assert state.status == "pending-review"
    after = len([obj for obj in session._objects if getattr(obj, "policy_state_id", None) == state_id])
    assert before == after


def test_oversized_review_reason_is_rejected_by_validation():
    runtime, _session = _ready_runtime(settings=_settings(migration_review_required=True))
    client = _app_with_runtime(runtime, OpenRelPolicyRuntimeState(enabled=True, ready=True, errors=()))
    created = client.post("/api/v1/admin/openrel/evaluations", headers={"Authorization": "Bearer admin-token"}, json=_payload())
    state_id = created.json()["policyStateId"]
    response = client.post(
        f"/api/v1/admin/openrel/policy-states/{state_id}/approve",
        headers={"Authorization": "Bearer admin-token"},
        json={"reason": "x" * 1025},
    )
    assert response.status_code == 422


def test_plain_review_reason_approval_and_rejection_succeed():
    runtime, _session = _ready_runtime(settings=_settings(migration_review_required=True))
    client = _app_with_runtime(runtime, OpenRelPolicyRuntimeState(enabled=True, ready=True, errors=()))
    created = client.post("/api/v1/admin/openrel/evaluations", headers={"Authorization": "Bearer admin-token"}, json=_payload())
    state_id = created.json()["policyStateId"]
    approve = client.post(
        f"/api/v1/admin/openrel/policy-states/{state_id}/approve",
        headers={"Authorization": "Bearer admin-token"},
        json={"reason": "  approve this  "},
    )
    assert approve.status_code == 200
    created2 = client.post("/api/v1/admin/openrel/evaluations", headers={"Authorization": "Bearer admin-token"}, json={**_payload(), "canonicalLicenseId": "lic-eval-2"})
    state_id2 = created2.json()["policyStateId"]
    reject = client.post(
        f"/api/v1/admin/openrel/policy-states/{state_id2}/reject",
        headers={"Authorization": "Bearer admin-token"},
        json={"reason": "reject this"},
    )
    assert reject.status_code == 200


def test_unknown_state_404_and_event_details_allow_list():
    runtime, session = _ready_runtime()
    client = _app_with_runtime(runtime, OpenRelPolicyRuntimeState(enabled=True, ready=True, errors=()))
    assert client.get(f"/api/v1/admin/openrel/policy-states/{uuid4()}", headers={"Authorization": "Bearer admin-token"}).status_code == 404
    store = OpenRelPolicyStore(session)
    state = store.record_plan(
        canonical_license_id="lic-event",
        source_kind="custom",
        source_record_ref="ref-event",
        settings=replace(runtime.settings, database_url=None, admin_cursor_secret=None),
        plan=FakePlanBuilder.default_plan(),
        candidate_payload={"candidate": 1},
        original_representation={"profile": "https://example.com/original-profile"},
        original_content_digest=None,
        actor_type="admin",
        actor_id="admin",
    )
    event = next(obj for obj in session._objects if getattr(obj, "policy_state_id", None) == state.id)
    event.details["token"] = "secret"
    body = client.get(f"/api/v1/admin/openrel/policy-states/{state.id}/events", headers={"Authorization": "Bearer admin-token"}).json()
    assert "token" not in str(body)


def test_pagination_filters_and_signed_cursor_require_secret():
    runtime, session = _ready_runtime()
    store = OpenRelPolicyStore(session)
    semantic_settings = replace(runtime.settings, database_url=None, admin_cursor_secret=None)
    for idx, source_kind in enumerate(["custom", "spdx", "federation-authoritative"]):
        store.record_plan(
            canonical_license_id=f"lic-{idx}",
            source_kind=source_kind,
            source_record_ref=f"ref-{idx}",
            settings=semantic_settings,
            plan=FakePlanBuilder.default_plan(),
            candidate_payload={"candidate": idx},
            original_representation={"profile": "https://example.com/original-profile"},
            original_content_digest=None,
            actor_type="admin",
            actor_id="admin",
        )
    client = _app_with_runtime(runtime, OpenRelPolicyRuntimeState(enabled=True, ready=True, errors=()))
    first = client.get("/api/v1/admin/openrel/policy-states?limit=2&sourceKind=custom", headers={"Authorization": "Bearer admin-token"})
    assert first.status_code == 200
    next_cursor = first.json()["nextCursor"]
    if next_cursor:
        assert client.get(f"/api/v1/admin/openrel/policy-states?limit=2&sourceKind=spdx&cursor={next_cursor}", headers={"Authorization": "Bearer admin-token"}).status_code == 400
        assert client.get(f"/api/v1/admin/openrel/policy-states?limit=2&sourceKind=custom&cursor={next_cursor}x", headers={"Authorization": "Bearer admin-token"}).status_code == 400
    assert client.get("/api/v1/admin/openrel/policy-states?limit=0", headers={"Authorization": "Bearer admin-token"}).status_code == 422
    assert client.get("/api/v1/admin/openrel/policy-states?limit=101", headers={"Authorization": "Bearer admin-token"}).status_code == 422


def test_openapi_admin_contract_and_public_openrel_unchanged():
    runtime, _session = _ready_runtime()
    client = _app_with_runtime(runtime, OpenRelPolicyRuntimeState(enabled=True, ready=True, errors=()))
    openapi = client.get("/openapi.json").json()
    admin_ops = [(path, method) for path, methods in openapi["paths"].items() for method in methods if path.startswith("/api/v1/admin/openrel")]
    assert len(admin_ops) == 8
    assert "/api/v1/admin/openrel/policy-states/{state_id}/apply" in openapi["paths"]
    assert "/api/v1/admin/openrel/policy-states/{state_id}/rollback" in openapi["paths"]
    public_ops = [(path, method) for path, methods in openapi["paths"].items() for method in methods if path.startswith("/openrel/api/v0.4")]
    assert len(public_ops) == 17
