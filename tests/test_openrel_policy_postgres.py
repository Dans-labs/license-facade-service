from __future__ import annotations

import json
import threading
import uuid
from collections.abc import Callable
from datetime import date, datetime, timezone
from pathlib import Path

import psycopg
import pytest
from sqlalchemy import create_engine, select, text
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session, sessionmaker
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from src.license_facade_service.db.models.custom_licence import CustomLicenceAuditEvent, CustomLicenceRepresentation
from src.license_facade_service.db.models.custom_licence import CustomLicence, CustomLicenceFederationOutbox
from src.license_facade_service.db.models.federation import FederationChangeEvent, FederationRecord
from src.license_facade_service.db.models.openrel_policy import OpenRelPolicyEvent, OpenRelPolicyState
from src.license_facade_service.db.session import Database
from src.license_facade_service.config.custom_licence import CustomLicenceRegistrationSettings
from src.license_facade_service.config.federation import FederationSettings
from src.license_facade_service.federation.canonical_json import canonicalize_to_bytes
from src.license_facade_service.federation.digests import sha256_hex
from src.license_facade_service.federation.license_identity import build_canonical_license_identity
from src.license_facade_service.federation.runtime import FederationRuntime
from src.license_facade_service.federation.outbound import FederationError, FederationPublicationService
from src.license_facade_service.services.openrel_application import (
    OpenRelApplicationConflictError,
    OpenRelApplicationService,
    build_custom_licence_snapshot,
    compute_custom_licence_snapshot_digest,
)
from src.license_facade_service.services.custom_licence_registration import compute_normalized_text_digest
from src.license_facade_service.services.openrel_policy import (
    OpenRelLicenceClassification,
    OpenRelPolicyAction,
    OpenRelPolicyMode,
    OpenRelPolicyPlan,
    OpenRelPolicySettings,
)
from src.license_facade_service.services.openrel_policy_store import (
    OpenRelPolicyStore,
    OpenRelPolicyStoreCollisionError,
    OpenRelPolicyTransitionError,
    compute_candidate_digest,
)
from tests.schema_init import (
    ALEMBIC_HEAD_REVISION,
    docker_available,
    free_port,
    list_public_tables,
    read_current_revision,
    run_alembic,
    start_postgres_container,
    stop_postgres_container,
)

OPENREL_REVISION = "20260904_03"
PREV_REVISION = "20260904_01"


class _ExpectPgError:
    def __init__(self, cur: psycopg.Cursor, name: str):
        self._cur = cur
        self._name = name

    def __enter__(self) -> None:
        self._cur.execute(f"SAVEPOINT {self._name}")
        return None

    def __exit__(self, exc_type, exc, tb) -> bool:
        if exc_type is None:
            self._cur.execute(f"RELEASE SAVEPOINT {self._name}")
            raise AssertionError("expected psycopg.Error was not raised")
        if not issubclass(exc_type, psycopg.Error):
            self._cur.execute(f"ROLLBACK TO SAVEPOINT {self._name}")
            self._cur.execute(f"RELEASE SAVEPOINT {self._name}")
            return False
        self._cur.execute(f"ROLLBACK TO SAVEPOINT {self._name}")
        self._cur.execute(f"RELEASE SAVEPOINT {self._name}")
        return True


@pytest.fixture()
def postgres_db() -> str:
    if not docker_available():
        pytest.skip("docker not available for OpenREL PostgreSQL tests")
    container_name = f"lfs-openrel-{uuid.uuid4().hex[:8]}"
    port = free_port()
    dsn = start_postgres_container(container_name, port)
    try:
        yield dsn
    finally:
        stop_postgres_container(container_name)


@pytest.fixture()
def upgraded_db(postgres_db: str) -> str:
    run_alembic(postgres_db, "upgrade", OPENREL_REVISION)
    return postgres_db


def _raw_dsn(dsn: str) -> str:
    return dsn.replace("+psycopg", "")


def _settings() -> OpenRelPolicySettings:
    return OpenRelPolicySettings(
        enabled=True,
        mode=OpenRelPolicyMode.active,
        base_url="https://openrel.example.invalid/provider",
        approved_profile="https://openrel.example.invalid/profile",
        approved_version="2026.09",
        effective_date=date(2026, 9, 4),
    )


def _plan(*, review_required: bool = False) -> OpenRelPolicyPlan:
    return OpenRelPolicyPlan(
        action=OpenRelPolicyAction.full_replacement,
        classification=OpenRelLicenceClassification.new,
        policy_version="2026.09",
        active_profile="https://openrel.example.invalid/profile",
        active_vocabulary="https://openrel.org/ns#",
        original_profile="https://openrel.example.invalid/original-profile",
        mapping_profile=None,
        mapping_provenance=None,
        source_provider_url="https://openrel.example.invalid/provider",
        apply_allowed=True,
        review_required=review_required,
        reason="postgres test plan",
    )


def _insert_valid_state(
    raw_dsn: str,
    *,
    status: str = "planned",
    canonical_license_id: str = "lic-a",
    source_record_ref: str = "ref-a",
    candidate_digest_sha256: str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
) -> str:
    state_id = str(uuid.uuid4())
    applied_at = "NOW()" if status == "applied" else "NULL"
    rolled_back_at = "NOW()" if status == "rolled-back" else "NULL"
    reviewed_at = "NOW()" if status in {"approved", "rejected"} else "NULL"
    reviewed_by = "'reviewer@example.com'" if status in {"approved", "rejected"} else "NULL"
    with psycopg.connect(raw_dsn) as conn:
        with conn.cursor() as cur:
            cur.execute(
                f"""
                INSERT INTO openrel_policy_states (
                    id, canonical_license_id, source_kind, source_record_ref, classification, policy_mode, policy_version,
                    effective_date, action, status, provider_url, active_profile, active_vocabulary, original_profile,
                    mapping_profile, mapping_provenance, candidate_digest_sha256, original_content_digest_sha256,
                    candidate_payload, original_representation, apply_allowed, review_required, reason,
                    created_at, updated_at, reviewed_at, reviewed_by, applied_at, rolled_back_at, error_code, error_detail
                ) VALUES (
                    %s, %s, 'custom', %s, 'new', 'active', '2026.09',
                    NOW(), 'full-replacement', %s, 'https://openrel.example.invalid/provider',
                    'https://openrel.example.invalid/profile', 'https://openrel.org/ns#',
                    'https://openrel.example.invalid/original-profile',
                    NULL, NULL, %s, NULL,
                    %s::jsonb, %s::jsonb, true, false, 'valid state',
                    NOW(), NOW(), {reviewed_at}, {reviewed_by}, {applied_at}, {rolled_back_at}, NULL, NULL
                )
                """,
                (
                    state_id,
                    canonical_license_id,
                    source_record_ref,
                    status,
                    candidate_digest_sha256,
                    json.dumps({"k": "v"}),
                    json.dumps({"orig": True}),
                ),
            )
        conn.commit()
    return state_id


def _insert_custom_licence(raw_dsn: str) -> str:
    custom_id = str(uuid.uuid4())
    with psycopg.connect(raw_dsn) as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                INSERT INTO custom_licences (
                    id, authority_id, requested_license_id, version, canonical_id, resolving_uuid,
                    public_scope, federation_status, spdx_submission_status, lifecycle_status,
                    name, license_text, normalized_text_digest, spdx_jsonld, creator_role, created_at, updated_at
                ) VALUES (
                    %s, 'node-a', 'lic-a', '1.0', 'lfs:node-a:lic-a:1.0', %s,
                    'local', 'not_published', 'not_requested', 'registered',
                    'Licence A', 'Text A',
                    'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa',
                    '{}'::jsonb, 'admin', NOW(), NOW()
                )
                """,
                (custom_id, str(uuid.uuid4())),
            )
        conn.commit()
    return custom_id


def _insert_custom_licence_with_requested_id(raw_dsn: str, *, requested_license_id: str) -> str:
    custom_id = str(uuid.uuid4())
    with psycopg.connect(raw_dsn) as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                INSERT INTO custom_licences (
                    id, authority_id, requested_license_id, version, canonical_id, resolving_uuid,
                    public_scope, federation_status, spdx_submission_status, lifecycle_status,
                    name, license_text, normalized_text_digest, spdx_jsonld, creator_role, created_at, updated_at
                ) VALUES (
                    %s, 'node-a', %s, '1.0', %s, %s,
                    'local', 'not_published', 'not_requested', 'registered',
                    'Licence A', 'Text A',
                    'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa',
                    '{}'::jsonb, 'admin', NOW(), NOW()
                )
                """,
                (custom_id, requested_license_id, f"lfs:node-a:{requested_license_id}:1.0", str(uuid.uuid4())),
            )
        conn.commit()
    return custom_id


def _insert_custom_licence_with_scope(raw_dsn: str, *, requested_license_id: str, public_scope: str = "local") -> str:
    custom_id = str(uuid.uuid4())
    with psycopg.connect(raw_dsn) as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                INSERT INTO custom_licences (
                    id, authority_id, requested_license_id, version, canonical_id, resolving_uuid,
                    public_scope, federation_status, spdx_submission_status, lifecycle_status,
                    name, license_text, normalized_text_digest, spdx_jsonld, creator_role, created_at, updated_at
                ) VALUES (
                    %s, 'node-a', %s, '1.0', %s, %s,
                    %s, 'not_published', 'not_requested', 'registered',
                    'Before', 'Before text', %s,
                    '{"before":true}'::jsonb, 'admin', NOW(), NOW()
                )
                """,
                (
                    custom_id,
                    requested_license_id,
                    f"lfs:node-a:{requested_license_id}:1.0",
                    str(uuid.uuid4()),
                    public_scope,
                    compute_normalized_text_digest("Before text"),
                ),
            )
        conn.commit()
    return custom_id


def _write_signing_key(tmp_path: Path) -> Path:
    key = Ed25519PrivateKey.generate()
    pem = key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    key_path = tmp_path / "federation-signing-key.pem"
    key_path.write_bytes(pem)
    key_path.chmod(0o600)
    return key_path


def _federation_settings(postgres_url: str, key_path: Path) -> FederationSettings:
    return FederationSettings(
        enabled=True,
        node_id="aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa",
        public_base_url="https://node.example.org",
        node_name="EDEN Node",
        operator_name="EDEN Operator",
        database_url=postgres_url,
        signing_key_dir=None,
        signing_key_path=str(key_path),
        signing_key_secret_path=None,
        signing_key_enforce_permissions=True,
        active_kid="k1",
        jwks_enabled=True,
        inbound_enabled=False,
        admin_sync_timeout_seconds=30,
        worker_interval_seconds=5,
        worker_max_sync_seconds=30,
        worker_instance_id=None,
        rotation_worker_enabled=False,
        rotation_poll_interval_seconds=60,
        rotation_failure_backoff_min_seconds=5,
        rotation_failure_backoff_max_seconds=60,
        rotation_backoff_jitter_enabled=False,
        rotation_max_operations_per_pass=1,
        sync_connect_timeout_seconds=5,
        sync_read_timeout_seconds=5,
        sync_write_timeout_seconds=5,
        sync_pool_timeout_seconds=5,
        sync_retry_attempts=1,
        sync_retry_base_seconds=0.1,
        sync_retry_max_seconds=0.2,
        sync_max_discovery_bytes=1024 * 1024,
        sync_max_jwks_bytes=1024 * 1024,
        sync_max_changes_bytes=1024 * 1024,
        sync_max_record_bytes=1024 * 1024,
        sync_max_embedded_payload_bytes=1024 * 1024,
        sync_max_jwks_keys=8,
        sync_max_events_per_page=100,
        sync_max_future_seconds=60,
        sync_max_duration_seconds=60,
        sync_lease_duration_seconds=30,
        sync_lease_renewal_seconds=10,
        sync_probe_timeout_seconds=5,
        circuit_open_threshold=3,
        circuit_base_open_seconds=5,
        circuit_max_open_seconds=30,
        circuit_half_open_probe_limit=1,
        sync_allowed_ports=(443,),
        sync_allowed_hostnames=(),
        sync_allowed_cidrs=(),
        allow_private_network=False,
        allow_http_for_demo=False,
        demo_tofu_unsafe_enabled=False,
        admin_cursor_secret="c" * 64,
        admin_cursor_secret_allow_ephemeral=False,
        admin_cursor_secret_generated=False,
        admin_cursor_secret_source="inline",
        validation_errors=(),
        rdf_fuseki_timeout_seconds=5,
        rdf_outbox_lease_seconds=30,
        rdf_outbox_retry_attempts=1,
        rdf_outbox_retry_base_seconds=0.1,
        rdf_outbox_retry_max_seconds=0.2,
        rdf_outbox_batch_size=10,
    )


def _custom_settings(postgres_url: str) -> CustomLicenceRegistrationSettings:
    return CustomLicenceRegistrationSettings(
        database_url=postgres_url,
        authority_id="node-a",
        authority_base_iri="https://lfs.example",
        creator_organization_name="LFS",
        creator_organization_iri="https://lfs.example/org",
        validation_errors=(),
    )


def _setup_federated_custom_record(postgres_url: str, raw_dsn: str, tmp_path: Path, *, requested_license_id: str) -> tuple[FederationPublicationService, CustomLicenceRegistrationSettings, uuid.UUID, uuid.UUID]:
    custom_id = uuid.UUID(_insert_custom_licence_with_scope(raw_dsn, requested_license_id=requested_license_id, public_scope="federated"))
    with psycopg.connect(raw_dsn) as conn:
        with conn.cursor() as cur:
            cur.execute("UPDATE custom_licences SET federation_status = 'published' WHERE id = %s", (str(custom_id),))
        conn.commit()
    key_path = _write_signing_key(tmp_path)
    settings = _federation_settings(postgres_url, key_path)
    state = FederationRuntime(settings).initialize()
    assert state.ready, state.errors
    publisher = FederationPublicationService(Database.from_url(postgres_url), settings)
    custom_settings = _custom_settings(postgres_url)
    with Session(create_engine(postgres_url), expire_on_commit=False) as session:
        custom = session.get(CustomLicence, custom_id)
        assert custom is not None
        identity = build_canonical_license_identity(
            authority_node_id=settings.node_id or "",
            local_id=f"custom-{custom.id}",
            version=custom.version,
        )
        record_id, event_id = publisher.publish_new_version_in_session(
            session=session,
            canonical_id=identity.canonicalId,
            authority_node_id=settings.node_id or "",
            local_id=f"custom-{custom.id}",
            version=custom.version,
            payload={
                "schema": "lfs.custom-licence.federation.v1",
                "customLicenceId": str(custom.id),
                "customCanonicalId": custom.canonical_id,
                "customResolvingUuid": str(custom.resolving_uuid),
                "customResolvingUri": f"https://lfs.example/custom-licences/{custom.authority_id}/{custom.requested_license_id}/{custom.version}",
                "requestedLicenseId": custom.requested_license_id,
                "version": custom.version,
                "name": custom.name,
                "summary": custom.summary,
                "description": custom.description,
                "licenseText": custom.license_text,
                "normalizedTextDigest": custom.normalized_text_digest,
                "spdxJsonld": custom.spdx_jsonld,
                "customAuthorityId": custom.authority_id,
                "publishingFederationNodeId": settings.node_id,
                "sourceRecordUuid": str(custom.id),
                "scope": custom.public_scope,
                "lifecycleStatus": custom.lifecycle_status,
                "createdAt": custom.created_at.astimezone(timezone.utc).isoformat(),
                "updatedAt": custom.updated_at.astimezone(timezone.utc).isoformat(),
                "aliases": [],
            },
        )
        outbox = CustomLicenceFederationOutbox(
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
        session.add(outbox)
        session.commit()
    return publisher, custom_settings, custom_id, record_id


def _federated_baseline(session: Session, *, custom_id: uuid.UUID, record_id: uuid.UUID) -> dict[str, object]:
    outbox = session.execute(
        select(CustomLicenceFederationOutbox).where(CustomLicenceFederationOutbox.custom_licence_id == custom_id)
    ).scalars().one()
    event_count = session.execute(
        select(text("count(*)")).select_from(FederationChangeEvent).where(FederationChangeEvent.record_id == record_id)
    ).scalar_one()
    rdf_count = session.execute(
        text("SELECT count(*) FROM federation_rdf_outbox_jobs WHERE record_id = :record_id"),
        {"record_id": record_id},
    ).scalar_one()
    record = session.get(FederationRecord, record_id)
    assert record is not None
    latest = session.execute(
        select(FederationChangeEvent).where(FederationChangeEvent.record_id == record_id).order_by(FederationChangeEvent.event_sequence.desc())
    ).scalars().first()
    return {
        "generation": int(record.materialized_generation or 0),
        "event_count": int(event_count),
        "rdf_count": int(rdf_count),
        "outbox_event_id": outbox.federation_event_id,
        "outbox_published_at": outbox.published_at,
        "latest_event_id": latest.id if latest is not None else None,
    }


class _FailingFederatedPublisher:
    def __init__(self, real: FederationPublicationService) -> None:
        self._real = real
        self.settings = real.settings

    def append_authoritative_upsert_in_session(self, **kwargs):
        raise FederationError("invalid-state-transition", "injected publication failure")


def _insert_policy_state_for_application(
    raw_dsn: str,
    *,
    custom_id: str,
    action: str,
    status: str = "approved",
    apply_allowed: bool = True,
    source_kind: str = "custom",
    policy_mode: str = "active",
    candidate_payload: dict,
    mapping_profile: str | None = None,
    mapping_provenance: dict | None = None,
    original_content_digest: str | None = None,
    canonical_license_id: str = "lic-openrel",
) -> str:
    state_id = str(uuid.uuid4())
    reviewed_at = "NOW()" if status == "approved" else "NULL"
    reviewed_by = "'reviewer@example.org'" if status == "approved" else "NULL"
    normalized_mapping_provenance = (
        json.dumps(mapping_provenance, sort_keys=True, separators=(",", ":"))
        if mapping_provenance is not None
        else None
    )
    with psycopg.connect(raw_dsn) as conn:
        with conn.cursor() as cur:
            cur.execute(
                f"""
                INSERT INTO openrel_policy_states (
                    id, canonical_license_id, source_kind, source_record_ref, classification, policy_mode, policy_version,
                    effective_date, action, status, provider_url, active_profile, active_vocabulary, original_profile,
                    mapping_profile, mapping_provenance, candidate_digest_sha256, original_content_digest_sha256,
                    candidate_payload, original_representation, apply_allowed, review_required, reason,
                    created_at, updated_at, reviewed_at, reviewed_by, applied_at, applied_by, rolled_back_at, rolled_back_by,
                    target_custom_licence_id, target_snapshot_before, target_digest_before, target_snapshot_after, target_digest_after,
                    error_code, error_detail
                ) VALUES (
                    %s, %s, %s, %s, %s, %s, '2026.09',
                    NOW(), %s, %s, 'https://openrel.example.invalid/provider',
                    'https://openrel.example.invalid/profile', 'https://openrel.org/ns#', 'https://openrel.example.invalid/original-profile',
                    %s, %s::jsonb, %s, %s,
                    %s::jsonb, '{{"orig":true}}'::jsonb, %s, %s, 'application test',
                    NOW(), NOW(), {reviewed_at}, {reviewed_by}, NULL, NULL, NULL, NULL,
                    NULL, NULL, NULL, NULL, NULL,
                    NULL, NULL
                )
                """,
                (
                    state_id,
                    canonical_license_id,
                    source_kind,
                    custom_id,
                    "historical" if action == "historical-mapping" else "new",
                    policy_mode,
                    action,
                    status,
                    mapping_profile,
                    normalized_mapping_provenance,
                    compute_candidate_digest(candidate_payload),
                    original_content_digest,
                    json.dumps(candidate_payload),
                    apply_allowed,
                    action == "historical-mapping",
                ),
            )
        conn.commit()
    return state_id


def test_migration_upgrade_downgrade_upgrade_repeatable(postgres_db: str):
    run_alembic(postgres_db, "upgrade", PREV_REVISION)
    assert read_current_revision(postgres_db) == PREV_REVISION
    run_alembic(postgres_db, "upgrade", OPENREL_REVISION)
    assert read_current_revision(postgres_db) == OPENREL_REVISION
    assert {"openrel_policy_states", "openrel_policy_events", "custom_licence_representations"} <= list_public_tables(postgres_db)
    run_alembic(postgres_db, "downgrade", PREV_REVISION)
    assert {"custom_licence_representations"}.isdisjoint(list_public_tables(postgres_db))
    run_alembic(postgres_db, "upgrade", OPENREL_REVISION)
    assert {"openrel_policy_states", "openrel_policy_events", "custom_licence_representations"} <= list_public_tables(postgres_db)
    heads = run_alembic(postgres_db, "heads")
    assert heads.stdout.count("(head)") == 1
    assert OPENREL_REVISION in heads.stdout


def test_constraints_reject_invalid_states(upgraded_db: str):
    raw = _raw_dsn(upgraded_db)
    with psycopg.connect(raw) as conn:
        with conn.cursor() as cur:
            cases = [
                (
                    "bad_candidate_digest",
                    """
                    INSERT INTO openrel_policy_states (
                        id, canonical_license_id, source_kind, classification, policy_mode, policy_version, effective_date,
                        action, status, provider_url, candidate_digest_sha256, candidate_payload, apply_allowed, review_required, reason
                    ) VALUES (%s,'c1','custom','new','active','v1',NOW(),'full-replacement','planned','https://p','xyz','{}'::jsonb,true,false,'r')
                    """,
                ),
                (
                    "bad_original_digest",
                    """
                    INSERT INTO openrel_policy_states (
                        id, canonical_license_id, source_kind, classification, policy_mode, policy_version, effective_date,
                        action, status, provider_url, candidate_digest_sha256, original_content_digest_sha256, candidate_payload, apply_allowed, review_required, reason
                    ) VALUES (%s,'c2','custom','new','active','v1',NOW(),'full-replacement','planned','https://p',
                    'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa','NOPE','{}'::jsonb,true,false,'r')
                    """,
                ),
                (
                    "imported_actionable",
                    """
                    INSERT INTO openrel_policy_states (
                        id, canonical_license_id, source_kind, classification, policy_mode, policy_version, effective_date,
                        action, status, provider_url, candidate_digest_sha256, candidate_payload, apply_allowed, review_required, reason
                    ) VALUES (%s,'c3','federation-imported','historical','active','v1',NOW(),'full-replacement','planned','https://p',
                    'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa','{}'::jsonb,false,true,'r')
                    """,
                ),
                (
                    "imported_apply_allowed",
                    """
                    INSERT INTO openrel_policy_states (
                        id, canonical_license_id, source_kind, classification, policy_mode, policy_version, effective_date,
                        action, status, provider_url, candidate_digest_sha256, candidate_payload, apply_allowed, review_required, reason
                    ) VALUES (%s,'c4','federation-imported','historical','active','v1',NOW(),'none','planned','https://p',
                    'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa','{}'::jsonb,true,true,'r')
                    """,
                ),
                (
                    "applied_without_timestamp",
                    """
                    INSERT INTO openrel_policy_states (
                        id, canonical_license_id, source_kind, classification, policy_mode, policy_version, effective_date,
                        action, status, provider_url, candidate_digest_sha256, candidate_payload, apply_allowed, review_required, reason, applied_at
                    ) VALUES (%s,'c5','custom','new','active','v1',NOW(),'full-replacement','applied','https://p',
                    'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa','{}'::jsonb,true,false,'r',NULL)
                    """,
                ),
                (
                    "applied_disallowed",
                    """
                    INSERT INTO openrel_policy_states (
                        id, canonical_license_id, source_kind, classification, policy_mode, policy_version, effective_date,
                        action, status, provider_url, candidate_digest_sha256, candidate_payload, apply_allowed, review_required, reason, applied_at
                    ) VALUES (%s,'c6','custom','new','active','v1',NOW(),'full-replacement','applied','https://p',
                    'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa','{}'::jsonb,false,false,'r',NOW())
                    """,
                ),
            ]
            for _, stmt in cases:
                with pytest.raises(psycopg.Error):
                    cur.execute("SAVEPOINT sp")
                    try:
                        cur.execute(stmt, (str(uuid.uuid4()),))
                    finally:
                        cur.execute("ROLLBACK TO SAVEPOINT sp")


def test_immutable_state_trigger_blocks_protected_field_updates(upgraded_db: str):
    raw = _raw_dsn(upgraded_db)
    state_id = _insert_valid_state(raw)
    protected_updates = [
        "canonical_license_id = 'lic-new'",
        "source_kind = 'spdx'",
        "source_record_ref = 'changed'",
        "policy_version = 'v2'",
        "effective_date = NOW() + interval '1 day'",
        "candidate_digest_sha256 = 'bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb'",
        "original_content_digest_sha256 = 'cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc'",
        "original_profile = 'https://changed'",
        "original_representation = '{\"x\":1}'::jsonb",
        "created_at = NOW()",
    ]
    with psycopg.connect(raw) as conn:
        with conn.cursor() as cur:
            for clause in protected_updates:
                with pytest.raises(psycopg.Error):
                    cur.execute("SAVEPOINT sp")
                    try:
                        cur.execute(f"UPDATE openrel_policy_states SET {clause} WHERE id = %s", (state_id,))
                    finally:
                        cur.execute("ROLLBACK TO SAVEPOINT sp")
            cur.execute("UPDATE openrel_policy_states SET status = 'failed', error_code = 'E1', updated_at = NOW() WHERE id = %s", (state_id,))
        conn.commit()


def test_events_are_append_only_and_fk_restricts(upgraded_db: str):
    raw = _raw_dsn(upgraded_db)
    state_id = _insert_valid_state(raw)
    event_id = str(uuid.uuid4())
    with psycopg.connect(raw) as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                INSERT INTO openrel_policy_events (
                    id, policy_state_id, event_type, actor_type, actor_id, before_status, after_status, details, occurred_at, created_at
                ) VALUES (%s,%s,'planned','system','worker-1',NULL,'planned','{}'::jsonb,NOW(),NOW())
                """,
                (event_id, state_id),
            )
        conn.commit()
        with conn.cursor() as cur:
            with pytest.raises(psycopg.Error):
                cur.execute("UPDATE openrel_policy_events SET actor_id = 'x' WHERE id = %s", (event_id,))
            conn.rollback()
            with pytest.raises(psycopg.Error):
                cur.execute("DELETE FROM openrel_policy_events WHERE id = %s", (event_id,))
            conn.rollback()
            with pytest.raises(psycopg.Error):
                cur.execute(
                    """
                    INSERT INTO openrel_policy_events (
                        id, policy_state_id, event_type, actor_type, actor_id, before_status, after_status, details, occurred_at, created_at
                    ) VALUES (%s,%s,'planned','system','worker-1',NULL,'planned','{}'::jsonb,NOW(),NOW())
                    """,
                    (str(uuid.uuid4()), str(uuid.uuid4())),
                )
            conn.rollback()
            with pytest.raises(psycopg.Error):
                cur.execute("DELETE FROM openrel_policy_states WHERE id = %s", (state_id,))
            conn.rollback()
            cur.execute(
                """
                INSERT INTO openrel_policy_events (
                    id, policy_state_id, event_type, actor_type, actor_id, before_status, after_status, details, occurred_at, created_at
                ) VALUES (%s,%s,'failed','system','worker-2','planned','failed','{}'::jsonb,NOW(),NOW())
                """,
                (str(uuid.uuid4()), state_id),
            )
        conn.commit()


def test_store_transaction_ownership_visibility_and_rollback(upgraded_db: str):
    run_alembic(upgraded_db, "upgrade", OPENREL_REVISION)
    engine = create_engine(upgraded_db)
    SessionLocal = sessionmaker(bind=engine, autoflush=False, autocommit=False, expire_on_commit=False)
    s1 = SessionLocal()
    s2 = SessionLocal()
    try:
        store = OpenRelPolicyStore(s1)
        state = store.record_plan(
            canonical_license_id="lic-tx-1",
            source_kind="custom",
            source_record_ref="ref-tx-1",
            settings=_settings(),
            plan=_plan(review_required=True),
            candidate_payload={"v": 1},
            original_representation={"orig": 1},
            original_content_digest=None,
            actor_type="system",
            actor_id="worker-1",
        )
        assert s1.query(OpenRelPolicyState).filter_by(id=state.id).first() is not None
        assert s2.query(OpenRelPolicyState).filter_by(id=state.id).first() is None
        s1.rollback()
        assert s2.query(OpenRelPolicyState).filter_by(id=state.id).first() is None

        persisted = store.record_plan(
            canonical_license_id="lic-tx-2",
            source_kind="custom",
            source_record_ref="ref-tx-2",
            settings=_settings(),
            plan=_plan(review_required=True),
            candidate_payload={"v": 2},
            original_representation={"orig": 2},
            original_content_digest=None,
            actor_type="system",
            actor_id="worker-2",
        )
        s1.commit()
        assert s2.query(OpenRelPolicyState).filter_by(id=persisted.id).first() is not None
        prev_event_count = s2.query(OpenRelPolicyEvent).filter_by(policy_state_id=persisted.id).count()
        store.transition_status(persisted.id, new_status="approved", reviewer_identity="rev@example.org")
        assert s2.query(OpenRelPolicyState).filter_by(id=persisted.id).first().status == "pending-review"
        s1.rollback()
        reloaded = s2.query(OpenRelPolicyState).filter_by(id=persisted.id).first()
        assert reloaded.status == "pending-review"
        assert s2.query(OpenRelPolicyEvent).filter_by(policy_state_id=persisted.id).count() == prev_event_count
    finally:
        s1.close()
        s2.close()
        engine.dispose()


def test_sequential_idempotency_and_collision(upgraded_db: str):
    engine = create_engine(upgraded_db)
    SessionLocal = sessionmaker(bind=engine, autoflush=False, autocommit=False, expire_on_commit=False)
    s = SessionLocal()
    try:
        store = OpenRelPolicyStore(s)
        settings = _settings()
        plan = _plan()
        first = store.record_plan(
            canonical_license_id="lic-idem-1",
            source_kind="custom",
            source_record_ref="ref-1",
            settings=settings,
            plan=plan,
            candidate_payload={"payload": 1},
            original_representation={"orig": 1},
            original_content_digest=None,
            actor_type="system",
            actor_id="worker",
        )
        second = store.record_plan(
            canonical_license_id="lic-idem-1",
            source_kind="custom",
            source_record_ref="ref-1",
            settings=settings,
            plan=plan,
            candidate_payload={"payload": 1},
            original_representation={"orig": 1},
            original_content_digest=None,
            actor_type="system",
            actor_id="worker",
        )
        assert first.id == second.id
        s.commit()
        third = store.record_plan(
            canonical_license_id="lic-idem-1",
            source_kind="custom",
            source_record_ref="ref-1",
            settings=settings,
            plan=plan,
            candidate_payload={"payload": 1},
            original_representation={"orig": 1},
            original_content_digest=None,
            actor_type="system",
            actor_id="worker",
        )
        assert first.id == third.id
        with pytest.raises(OpenRelPolicyStoreCollisionError):
            store.record_plan(
                canonical_license_id="lic-idem-1",
                source_kind="custom",
                source_record_ref="ref-CHANGED",
                settings=settings,
                plan=plan,
                candidate_payload={"payload": 1},
                original_representation={"orig": 1},
                original_content_digest=None,
                actor_type="system",
                actor_id="worker",
            )
        s.rollback()
    finally:
        s.close()
        engine.dispose()


def test_concurrent_idempotency_single_row_single_event(upgraded_db: str):
    engine = create_engine(upgraded_db)
    SessionLocal = sessionmaker(bind=engine, autoflush=False, autocommit=False, expire_on_commit=False)
    barrier = threading.Barrier(2)
    results: list[dict[str, object]] = []

    def worker(actor: str):
        session = SessionLocal()
        store = OpenRelPolicyStore(session)
        rollback_count = 0
        try:
            unrelated_license_id = f"lic-race-unrelated-{actor}"
            unrelated_state = store.record_plan(
                canonical_license_id=unrelated_license_id,
                source_kind="custom",
                source_record_ref=f"ref-{actor}-unrelated",
                settings=_settings(),
                plan=_plan(),
                candidate_payload={"actor": actor, "kind": "unrelated"},
                original_representation={"actor": actor, "kind": "unrelated"},
                original_content_digest=None,
                actor_type="system",
                actor_id=actor,
            )
            barrier.wait(timeout=10)
            state = store.record_plan(
                canonical_license_id="lic-race-1",
                source_kind="custom",
                source_record_ref="ref-race-1",
                settings=_settings(),
                plan=_plan(),
                candidate_payload={"race": 1},
                original_representation={"orig": "race"},
                original_content_digest=None,
                actor_type="system",
                actor_id=actor,
            )
            session.commit()
            results.append(
                {
                    "actor": actor,
                    "status": "ok",
                    "state_id": str(state.id),
                    "unrelated_state_id": str(unrelated_state.id),
                    "rollback_count": 0,
                    "unrelated_license_id": unrelated_license_id,
                }
            )
        except Exception as exc:  # pragma: no cover - assertions below report exact failure
            session.rollback()
            rollback_count += 1
            results.append(
                {
                    "actor": actor,
                    "status": "error",
                    "error_type": type(exc).__name__,
                    "error_message": str(exc),
                    "rollback_count": rollback_count,
                }
            )
        finally:
            session.close()

    t1 = threading.Thread(target=worker, args=("w1",))
    t2 = threading.Thread(target=worker, args=("w2",))
    t1.start()
    t2.start()
    t1.join()
    t2.join()

    verify = SessionLocal()
    try:
        race_states = verify.query(OpenRelPolicyState).filter_by(canonical_license_id="lic-race-1").all()
        state_count = len(race_states)
        states = race_states
        assert state_count == 1
        assert len(states) == 1
        planned_events = verify.query(OpenRelPolicyEvent).filter_by(policy_state_id=states[0].id, event_type="planned").all()
        event_count = len(planned_events)
        assert event_count == 1
        assert len(results) == 2
        assert all(result["status"] == "ok" for result in results), results
        returned_state_ids = {result["state_id"] for result in results}
        assert returned_state_ids == {str(states[0].id)}
        assert all(result["rollback_count"] == 0 for result in results)
        unrelated_ids = {result["unrelated_license_id"] for result in results}
        persisted_unrelated = verify.query(OpenRelPolicyState).all()
        persisted_unrelated_ids = {state.canonical_license_id for state in persisted_unrelated}
        assert unrelated_ids <= persisted_unrelated_ids
    finally:
        verify.close()
        engine.dispose()


def test_postgres_type_compatibility_and_sanitized_failure(upgraded_db: str):
    engine = create_engine(upgraded_db)
    SessionLocal = sessionmaker(bind=engine, autoflush=False, autocommit=False, expire_on_commit=False)
    s = SessionLocal()
    try:
        store = OpenRelPolicyStore(s)
        pending = store.record_plan(
            canonical_license_id="lic-type-1",
            source_kind="custom",
            source_record_ref="ref-type-1",
            settings=_settings(),
            plan=_plan(review_required=True),
            candidate_payload={"nested": [1, {"x": True}]},
            original_representation={"orig": {"k": "v"}},
            original_content_digest="aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            actor_type="admin",
            actor_id=" admin@example.org ",
        )
        assert isinstance(pending.id, uuid.UUID)
        assert isinstance(pending.created_at, datetime)
        assert pending.created_at.tzinfo is not None
        assert isinstance(pending.effective_date, date)
        approved = store.transition_status(pending.id, new_status="approved", reviewer_identity="reviewer@example.org")
        failed = store.transition_status(
            approved.id,
            new_status="failed",
            error_code="E-SAFE",
            error_detail={"Authorization": "Bearer abc", "private_key": "sekrit", "nested": {"password": "p", "ok": "x" * 2000}},
        )
        s.commit()
        reloaded = s.get(OpenRelPolicyState, failed.id)
        assert reloaded is not None
        assert "bearer abc" not in (reloaded.error_detail or "").lower()
        assert "sekrit" not in (reloaded.error_detail or "").lower()
        event = s.query(OpenRelPolicyEvent).filter_by(policy_state_id=failed.id, event_type="failed").first()
        assert event is not None
        assert isinstance(event.details, dict)
        details_text = json.dumps(event.details).lower()
        assert "authorization" in details_text
        assert "redacted" in details_text
        assert "private_key" in details_text
        assert "bearer abc" not in details_text
    finally:
        s.close()
        engine.dispose()


def test_new_apply_rollback_constraints_and_mapping_table(upgraded_db: str):
    raw = _raw_dsn(upgraded_db)
    state_id = _insert_valid_state(raw, status="approved")
    custom_id = _insert_custom_licence(raw)
    cascade_state_id = _insert_valid_state(
        raw,
        canonical_license_id="lic-cascade",
        source_record_ref="ref-cascade",
        candidate_digest_sha256="ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
    )
    cascade_custom_id = _insert_custom_licence_with_requested_id(raw, requested_license_id="lic-cascade")
    with psycopg.connect(raw) as conn:
        with conn.cursor() as cur:
            with _ExpectPgError(cur, "sp_apply_missing_fields"):
                cur.execute(
                    """
                    UPDATE openrel_policy_states
                    SET status = 'applied', applied_at = NOW()
                    WHERE id = %s
                    """,
                    (state_id,),
                )
            with _ExpectPgError(cur, "sp_rollback_missing_apply_identity"):
                cur.execute(
                    """
                    UPDATE openrel_policy_states
                    SET status = 'rolled-back', rolled_back_at = NOW(), rolled_back_by = 'admin'
                    WHERE id = %s
                    """,
                    (state_id,),
                )
            cur.execute(
                """
                UPDATE openrel_policy_states
                SET status = 'applied',
                    target_custom_licence_id = %s,
                    target_snapshot_before = '{"before":1}'::jsonb,
                    target_digest_before = 'bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb',
                    target_snapshot_after = '{"after":1}'::jsonb,
                    target_digest_after = 'cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc',
                    applied_at = NOW(),
                    applied_by = 'admin'
                WHERE id = %s
                """,
                (custom_id, state_id),
            )
            cur.execute(
                """
                UPDATE openrel_policy_states
                SET status = 'rolled-back',
                    rolled_back_at = NOW(),
                    rolled_back_by = 'admin'
                WHERE id = %s
                """,
                (state_id,),
            )
            with _ExpectPgError(cur, "sp_representation_missing_content_href"):
                cur.execute(
                    """
                    INSERT INTO custom_licence_representations (
                        id, custom_licence_id, representation_type, status, media_type, profile_uri, vocabulary_uri,
                        content, href, content_digest_sha256, mapping_profile, mapping_provenance, source_policy_state_id,
                        created_at, updated_at, rolled_back_at
                    ) VALUES (
                        %s, %s, 'openrel-mapping', 'active', 'application/ld+json', 'https://profile',
                        'https://vocab', NULL, NULL,
                        'dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd',
                        'https://mapping', '{}'::jsonb, %s, NOW(), NOW(), NULL
                    )
                    """,
                    (str(uuid.uuid4()), custom_id, state_id),
                )
            rep_id = str(uuid.uuid4())
            cur.execute(
                """
                INSERT INTO custom_licence_representations (
                    id, custom_licence_id, representation_type, status, media_type, profile_uri, vocabulary_uri,
                    content, href, content_digest_sha256, mapping_profile, mapping_provenance, source_policy_state_id,
                    created_at, updated_at, rolled_back_at
                ) VALUES (
                    %s, %s, 'openrel-mapping', 'active', 'application/ld+json', 'https://profile',
                    'https://vocab', '{"x":1}'::jsonb, NULL,
                    'dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd',
                    'https://mapping', '{"p":"v"}'::jsonb, %s, NOW(), NOW(), NULL
                )
                """,
                (rep_id, custom_id, state_id),
            )
            cur.execute(
                "SELECT count(*) FROM custom_licence_representations WHERE source_policy_state_id = %s",
                (state_id,),
            )
            assert cur.fetchone() == (1,)
            cur.execute(
                "SELECT count(*) FROM custom_licence_representations WHERE id = %s",
                (rep_id,),
            )
            assert cur.fetchone() == (1,)
            with _ExpectPgError(cur, "sp_duplicate_policy_mapping"):
                cur.execute(
                    """
                    INSERT INTO custom_licence_representations (
                        id, custom_licence_id, representation_type, status, media_type, profile_uri, vocabulary_uri,
                        content, href, content_digest_sha256, mapping_profile, mapping_provenance, source_policy_state_id,
                        created_at, updated_at, rolled_back_at
                    ) VALUES (
                        %s, %s, 'openrel-mapping', 'active', 'application/ld+json', 'https://profile',
                        'https://vocab', '{"x":2}'::jsonb, NULL,
                        'eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee',
                        'https://mapping', '{"p":"v"}'::jsonb, %s, NOW(), NOW(), NULL
                    )
                    """,
                    (str(uuid.uuid4()), custom_id, state_id),
                )
            cur.execute(
                "SELECT count(*) FROM custom_licence_representations WHERE id = %s",
                (rep_id,),
            )
            assert cur.fetchone() == (1,)
            with _ExpectPgError(cur, "sp_delete_policy_state_restricted"):
                cur.execute("DELETE FROM openrel_policy_states WHERE id = %s", (state_id,))
            cur.execute(
                "SELECT count(*) FROM custom_licence_representations WHERE id = %s",
                (rep_id,),
            )
            assert cur.fetchone() == (1,)
            with _ExpectPgError(cur, "sp_delete_target_custom_licence_restricted"):
                cur.execute("DELETE FROM custom_licences WHERE id = %s", (custom_id,))
            cur.execute("SELECT count(*) FROM custom_licences WHERE id = %s", (custom_id,))
            assert cur.fetchone() == (1,)
            cur.execute("SELECT count(*) FROM openrel_policy_states WHERE id = %s", (state_id,))
            assert cur.fetchone() == (1,)
            cur.execute("SELECT count(*) FROM custom_licence_representations WHERE id = %s", (rep_id,))
            assert cur.fetchone() == (1,)
            cascade_rep_id = str(uuid.uuid4())
            cur.execute(
                """
                INSERT INTO custom_licence_representations (
                    id, custom_licence_id, representation_type, status, media_type, profile_uri, vocabulary_uri,
                    content, href, content_digest_sha256, mapping_profile, mapping_provenance, source_policy_state_id,
                    created_at, updated_at, rolled_back_at
                ) VALUES (
                    %s, %s, 'openrel-mapping', 'active', 'application/ld+json', 'https://profile',
                    'https://vocab', '{"cascade":1}'::jsonb, NULL,
                    'ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff',
                    'https://mapping', '{"source":"cascade"}'::jsonb, %s, NOW(), NOW(), NULL
                )
                """,
                (cascade_rep_id, cascade_custom_id, cascade_state_id),
            )
            cur.execute("SELECT count(*) FROM custom_licences WHERE id = %s", (cascade_custom_id,))
            assert cur.fetchone() == (1,)
            cur.execute("SELECT count(*) FROM custom_licence_representations WHERE id = %s", (cascade_rep_id,))
            assert cur.fetchone() == (1,)
            cur.execute("SELECT count(*) FROM openrel_policy_states WHERE id = %s", (cascade_state_id,))
            assert cur.fetchone() == (1,)
            cur.execute("DELETE FROM custom_licences WHERE id = %s", (cascade_custom_id,))
            cur.execute("SELECT count(*) FROM custom_licences WHERE id = %s", (cascade_custom_id,))
            assert cur.fetchone() == (0,)
            cur.execute("SELECT count(*) FROM custom_licence_representations WHERE id = %s", (cascade_rep_id,))
            assert cur.fetchone() == (0,)
            cur.execute("SELECT count(*) FROM openrel_policy_states WHERE id = %s", (cascade_state_id,))
            assert cur.fetchone() == (1,)
        conn.commit()


def test_application_service_apply_commit_rollback_and_conflicts(upgraded_db: str):
    engine = create_engine(upgraded_db)
    SessionLocal = sessionmaker(bind=engine, autoflush=False, autocommit=False, expire_on_commit=False)
    try:
        raw = _raw_dsn(upgraded_db)

        rollback_custom_id = _insert_custom_licence_with_scope(raw, requested_license_id="lic-apply-rollback")
        rollback_state_id = _insert_policy_state_for_application(
            raw,
            custom_id=rollback_custom_id,
            action="full-replacement",
            candidate_payload={
                "name": "After rollback",
                "summary": "After summary",
                "description": "After description",
                "licenseText": "After text rollback",
                "spdxJsonld": {"after": True},
            },
            original_content_digest=compute_normalized_text_digest("Before text"),
            canonical_license_id="lic-apply-rollback",
        )
        rollback_session = SessionLocal()
        try:
            service = OpenRelApplicationService(rollback_session)
            applied = service.apply(uuid.UUID(rollback_state_id), actor_id="admin@example.org")
            assert applied.status == "applied"
            rollback_session.rollback()
        finally:
            rollback_session.close()
        verify = SessionLocal()
        try:
            target = verify.get(type(next(iter(verify.query(OpenRelPolicyState).all()), None)), uuid.UUID(rollback_state_id))
        finally:
            verify.close()

        commit_custom_id = _insert_custom_licence_with_scope(raw, requested_license_id="lic-apply-commit")
        commit_state_id = _insert_policy_state_for_application(
            raw,
            custom_id=commit_custom_id,
            action="full-replacement",
            candidate_payload={
                "name": "After commit",
                "summary": "Committed summary",
                "description": "Committed description",
                "licenseText": "Committed text",
                "spdxJsonld": {"committed": True},
            },
            original_content_digest=compute_normalized_text_digest("Before text"),
            canonical_license_id="lic-apply-commit",
        )
        session = SessionLocal()
        try:
            service = OpenRelApplicationService(session)
            state = service.apply(uuid.UUID(commit_state_id), actor_id="admin@example.org")
            session.commit()
            target = session.execute(select(OpenRelPolicyState).where(OpenRelPolicyState.id == uuid.UUID(commit_state_id))).scalars().one()
            assert target.status == "applied"
            custom = session.execute(select(OpenRelPolicyState).where(OpenRelPolicyState.id == uuid.UUID(commit_state_id))).scalars().one()
            assert custom.target_digest_before is not None
        finally:
            session.close()

        map_custom_id = _insert_custom_licence_with_scope(raw, requested_license_id="lic-map")
        map_state_id = _insert_policy_state_for_application(
            raw,
            custom_id=map_custom_id,
            action="historical-mapping",
            candidate_payload={
                "mediaType": "application/json",
                "profile": "https://example.invalid/profile",
                "vocabulary": "https://example.invalid/vocab",
                "content": {"mapping": True},
                "mappingProfile": "https://example.invalid/mapping",
                "mappingProvenance": {"source": "openrel"},
            },
            mapping_profile="https://example.invalid/mapping",
            mapping_provenance={"source": "openrel"},
            original_content_digest=compute_normalized_text_digest("Before text"),
            canonical_license_id="lic-map",
        )
        map_session = SessionLocal()
        try:
            persisted_state = map_session.execute(
                select(OpenRelPolicyState).where(OpenRelPolicyState.id == uuid.UUID(map_state_id))
            ).scalars().one()
            assert json.loads(persisted_state.mapping_provenance) == {"source": "openrel"}
            service = OpenRelApplicationService(map_session)
            service.apply(uuid.UUID(map_state_id), actor_id="admin@example.org")
            service.rollback(uuid.UUID(map_state_id), actor_id="admin@example.org")
            map_session.commit()
            assert json.loads(persisted_state.mapping_provenance) == {"source": "openrel"}
            reps = map_session.execute(
                select(CustomLicenceRepresentation).where(CustomLicenceRepresentation.source_policy_state_id == uuid.UUID(map_state_id))
            ).scalars().all()
            assert len(reps) == 1
            assert reps[0].status == "rolled-back"
        finally:
            map_session.close()

        conflict_custom_id = _insert_custom_licence_with_scope(raw, requested_license_id="lic-conflict")
        conflict_state_id = _insert_policy_state_for_application(
            raw,
            custom_id=conflict_custom_id,
            action="full-replacement",
            candidate_payload={
                "name": "After conflict",
                "summary": "Conflict summary",
                "description": "Conflict description",
                "licenseText": "Conflict text",
                "spdxJsonld": {"conflict": True},
            },
            original_content_digest="f" * 64,
            canonical_license_id="lic-conflict",
        )
        conflict_session = SessionLocal()
        try:
            service = OpenRelApplicationService(conflict_session)
            unrelated = _insert_valid_state(raw, canonical_license_id="lic-unrelated-conflict", source_record_ref="ref-unrelated-conflict", candidate_digest_sha256="e" * 64)
            with pytest.raises(OpenRelApplicationConflictError):
                service.apply(uuid.UUID(conflict_state_id), actor_id="admin@example.org")
            conflict_session.commit()
            assert unrelated is not None
        finally:
            conflict_session.close()
    finally:
        engine.dispose()


def _run_application_worker(
    SessionLocal,
    barrier: threading.Barrier,
    results: list[dict[str, object]],
    results_lock: threading.Lock,
    *,
    worker_name: str,
    operation: Callable[[OpenRelApplicationService, uuid.UUID], OpenRelPolicyState],
    state_id: uuid.UUID,
) -> None:
    session = SessionLocal()
    try:
        barrier.wait(timeout=10)
        service = OpenRelApplicationService(session)
        state = operation(service, state_id)
        session.commit()
        outcome = {
            "worker": worker_name,
            "status": "ok",
            "state_id": str(state.id),
            "state_status": state.status,
        }
    except Exception as exc:  # pragma: no cover - assertions below report exact failure
        session.rollback()
        outcome = {
            "worker": worker_name,
            "status": "error",
            "error_type": type(exc).__name__,
            "error_message": str(exc),
        }
    finally:
        session.close()
    with results_lock:
        results.append(outcome)


def _join_or_fail(*threads: threading.Thread) -> None:
    for thread in threads:
        thread.join(timeout=15)
    assert all(not thread.is_alive() for thread in threads), "concurrency test thread hung"


def _load_custom_licence(session: Session, custom_id: uuid.UUID) -> CustomLicence:
    custom = session.get(CustomLicence, custom_id)
    assert custom is not None
    return custom


def test_application_service_concurrent_apply_is_serialized_and_idempotent(upgraded_db: str):
    engine = create_engine(upgraded_db)
    SessionLocal = sessionmaker(bind=engine, autoflush=False, autocommit=False, expire_on_commit=False)
    barrier = threading.Barrier(2)
    results: list[dict[str, object]] = []
    results_lock = threading.Lock()
    raw = _raw_dsn(upgraded_db)
    custom_id = _insert_custom_licence_with_scope(raw, requested_license_id="lic-concurrent-apply")
    state_id = uuid.UUID(
        _insert_policy_state_for_application(
            raw,
            custom_id=custom_id,
            action="full-replacement",
            candidate_payload={
                "name": "Concurrent Apply",
                "summary": "Concurrent summary",
                "description": "Concurrent description",
                "licenseText": "Concurrent text",
                "spdxJsonld": {"concurrent": True},
            },
            original_content_digest=compute_normalized_text_digest("Before text"),
            canonical_license_id="lic-concurrent-apply",
        )
    )
    try:
        t1 = threading.Thread(
            target=_run_application_worker,
            args=(SessionLocal, barrier, results, results_lock),
            kwargs={
                "worker_name": "apply-1",
                "operation": lambda service, sid: service.apply(sid, actor_id="apply-1@example.org"),
                "state_id": state_id,
            },
        )
        t2 = threading.Thread(
            target=_run_application_worker,
            args=(SessionLocal, barrier, results, results_lock),
            kwargs={
                "worker_name": "apply-2",
                "operation": lambda service, sid: service.apply(sid, actor_id="apply-2@example.org"),
                "state_id": state_id,
            },
        )
        t1.start()
        t2.start()
        _join_or_fail(t1, t2)

        assert len(results) == 2
        assert not any(result.get("error_type") == "IntegrityError" for result in results), results
        assert not any("deadlock" in str(result.get("error_message", "")).lower() for result in results), results
        assert all(result["status"] == "ok" for result in results), results

        verify = SessionLocal()
        try:
            state = verify.execute(select(OpenRelPolicyState).where(OpenRelPolicyState.id == state_id)).scalars().one()
            assert state.status == "applied"
            custom_id = verify.execute(
                select(OpenRelPolicyState.target_custom_licence_id).where(OpenRelPolicyState.id == state_id)
            ).scalar_one()
            custom = _load_custom_licence(verify, custom_id)
            assert custom.name == "Concurrent Apply"
            assert custom.summary == "Concurrent summary"
            assert custom.description == "Concurrent description"
            assert custom.license_text == "Concurrent text"
            assert custom.normalized_text_digest == compute_normalized_text_digest("Concurrent text")
            assert custom.spdx_jsonld == {"concurrent": True}
            applied_events = verify.query(OpenRelPolicyEvent).filter_by(policy_state_id=state_id, event_type="applied").all()
            assert len(applied_events) == 1
            audits = verify.query(CustomLicenceAuditEvent).filter_by(custom_licence_id=custom_id, event_type="openrel_policy_applied").all()
            assert len(audits) == 1
            representations = verify.query(CustomLicenceRepresentation).filter_by(source_policy_state_id=state_id).all()
            assert len(representations) == 0
            live_digest = compute_custom_licence_snapshot_digest(
                build_custom_licence_snapshot(custom, [])
            )
            assert live_digest == state.target_digest_after
            assert state.target_digest_before != state.target_digest_after
        finally:
            verify.close()
    finally:
        engine.dispose()


def test_application_service_concurrent_apply_and_rollback_are_serialized(upgraded_db: str):
    engine = create_engine(upgraded_db)
    SessionLocal = sessionmaker(bind=engine, autoflush=False, autocommit=False, expire_on_commit=False)
    barrier = threading.Barrier(2)
    results: list[dict[str, object]] = []
    results_lock = threading.Lock()
    raw = _raw_dsn(upgraded_db)
    custom_id = _insert_custom_licence_with_scope(raw, requested_license_id="lic-concurrent-apply-rollback")
    state_id = uuid.UUID(
        _insert_policy_state_for_application(
            raw,
            custom_id=custom_id,
            action="full-replacement",
            candidate_payload={
                "name": "Concurrent Final",
                "summary": "Concurrent rollback summary",
                "description": "Concurrent rollback description",
                "licenseText": "Concurrent rollback text",
                "spdxJsonld": {"rollback": True},
            },
            original_content_digest=compute_normalized_text_digest("Before text"),
            canonical_license_id="lic-concurrent-apply-rollback",
        )
    )
    try:
        t_apply = threading.Thread(
            target=_run_application_worker,
            args=(SessionLocal, barrier, results, results_lock),
            kwargs={
                "worker_name": "apply",
                "operation": lambda service, sid: service.apply(sid, actor_id="apply@example.org"),
                "state_id": state_id,
            },
        )
        t_rollback = threading.Thread(
            target=_run_application_worker,
            args=(SessionLocal, barrier, results, results_lock),
            kwargs={
                "worker_name": "rollback",
                "operation": lambda service, sid: service.rollback(sid, actor_id="rollback@example.org"),
                "state_id": state_id,
            },
        )
        t_apply.start()
        t_rollback.start()
        _join_or_fail(t_apply, t_rollback)

        assert len(results) == 2
        assert not any(result.get("error_type") == "IntegrityError" for result in results), results
        assert not any("deadlock" in str(result.get("error_message", "")).lower() for result in results), results
        assert {result["worker"] for result in results} == {"apply", "rollback"}

        apply_result = next(result for result in results if result["worker"] == "apply")
        rollback_result = next(result for result in results if result["worker"] == "rollback")
        assert apply_result["status"] == "ok", results
        if rollback_result["status"] == "error":
            assert rollback_result["error_type"] == "OpenRelApplicationConflictError", results
            assert rollback_result["error_message"] == "only applied states can be rolled back", results
        else:
            assert rollback_result["state_status"] == "rolled-back", results

        verify = SessionLocal()
        try:
            state = verify.execute(select(OpenRelPolicyState).where(OpenRelPolicyState.id == state_id)).scalars().one()
            custom = _load_custom_licence(verify, uuid.UUID(custom_id))
            events = (
                verify.query(OpenRelPolicyEvent)
                .filter_by(policy_state_id=state_id)
                .order_by(OpenRelPolicyEvent.occurred_at.asc(), OpenRelPolicyEvent.created_at.asc())
                .all()
            )
            event_types = [event.event_type for event in events if event.event_type in {"applied", "rolled-back"}]
            audits = (
                verify.query(CustomLicenceAuditEvent)
                .filter_by(custom_licence_id=uuid.UUID(custom_id))
                .order_by(CustomLicenceAuditEvent.created_at.asc())
                .all()
            )
            if rollback_result["status"] == "ok":
                assert state.status == "rolled-back"
                assert event_types == ["applied", "rolled-back"]
                assert len(audits) == 2
                assert custom.name == "Before"
                assert custom.summary is None
                assert custom.description is None
                assert custom.license_text == "Before text"
                assert custom.normalized_text_digest == compute_normalized_text_digest("Before text")
                live_digest = compute_custom_licence_snapshot_digest(build_custom_licence_snapshot(custom, []))
                assert live_digest == state.target_digest_before
                assert state.target_digest_after != state.target_digest_before
            else:
                assert state.status == "applied"
                assert event_types == ["applied"]
                assert len(audits) == 1
                assert custom.name == "Concurrent Final"
                assert custom.summary == "Concurrent rollback summary"
                assert custom.description == "Concurrent rollback description"
                assert custom.license_text == "Concurrent rollback text"
                assert custom.normalized_text_digest == compute_normalized_text_digest("Concurrent rollback text")
                live_digest = compute_custom_licence_snapshot_digest(build_custom_licence_snapshot(custom, []))
                assert live_digest == state.target_digest_after
            assert event_types[:1] != ["rolled-back"]
        finally:
            verify.close()
    finally:
        engine.dispose()


def test_application_service_caller_rollback_removes_all_apply_effects(upgraded_db: str):
    engine = create_engine(upgraded_db)
    SessionLocal = sessionmaker(bind=engine, autoflush=False, autocommit=False, expire_on_commit=False)
    raw = _raw_dsn(upgraded_db)
    custom_id = uuid.UUID(_insert_custom_licence_with_scope(raw, requested_license_id="lic-caller-rollback"))
    state_id = uuid.UUID(
        _insert_policy_state_for_application(
            raw,
            custom_id=str(custom_id),
            action="full-replacement",
            candidate_payload={
                "name": "Rollback Candidate",
                "summary": "Rollback summary",
                "description": "Rollback description",
                "licenseText": "Rollback text",
                "spdxJsonld": {"rollback": "candidate"},
            },
            original_content_digest=compute_normalized_text_digest("Before text"),
            canonical_license_id="lic-caller-rollback",
        )
    )
    session = SessionLocal()
    try:
        service = OpenRelApplicationService(session)
        state = service.apply(state_id, actor_id="rollback@example.org")
        assert state.status == "applied"
        session.rollback()
    finally:
        session.close()

    verify = SessionLocal()
    try:
        state = verify.execute(select(OpenRelPolicyState).where(OpenRelPolicyState.id == state_id)).scalars().one()
        custom = _load_custom_licence(verify, custom_id)
        assert state.status == "approved"
        assert state.target_custom_licence_id is None
        assert state.target_snapshot_before is None
        assert state.target_digest_before is None
        assert state.target_snapshot_after is None
        assert state.target_digest_after is None
        assert state.applied_at is None
        assert state.applied_by is None
        assert custom.name == "Before"
        assert custom.summary is None
        assert custom.description is None
        assert custom.license_text == "Before text"
        assert custom.normalized_text_digest == compute_normalized_text_digest("Before text")
        assert custom.spdx_jsonld == {"before": True}
        assert verify.query(OpenRelPolicyEvent).filter_by(policy_state_id=state_id, event_type="applied").count() == 0
        assert verify.query(CustomLicenceAuditEvent).filter_by(custom_licence_id=custom_id, event_type="openrel_policy_applied").count() == 0
        assert verify.query(CustomLicenceRepresentation).filter_by(source_policy_state_id=state_id).count() == 0
    finally:
        verify.close()
        engine.dispose()


def test_application_service_conflict_does_not_destroy_unrelated_outer_work(upgraded_db: str):
    engine = create_engine(upgraded_db)
    SessionLocal = sessionmaker(bind=engine, autoflush=False, autocommit=False, expire_on_commit=False)
    raw = _raw_dsn(upgraded_db)
    custom_id = uuid.UUID(_insert_custom_licence_with_scope(raw, requested_license_id="lic-conflict-survival"))
    state_id = uuid.UUID(
        _insert_policy_state_for_application(
            raw,
            custom_id=str(custom_id),
            action="full-replacement",
            candidate_payload={
                "name": "Conflict Candidate",
                "summary": "Conflict summary",
                "description": "Conflict description",
                "licenseText": "Conflict text",
                "spdxJsonld": {"conflict": "candidate"},
            },
            original_content_digest="f" * 64,
            canonical_license_id="lic-conflict-survival",
        )
    )
    session = SessionLocal()
    try:
        unrelated = OpenRelPolicyState(
            id=uuid.uuid4(),
            canonical_license_id="lic-unrelated-outer-work",
            source_kind="custom",
            source_record_ref="ref-unrelated-outer-work",
            classification="new",
            policy_mode="active",
            policy_version="2026.09",
            effective_date=datetime.now(timezone.utc),
            action="none",
            status="planned",
            provider_url="https://openrel.example.invalid/provider",
            active_profile="https://openrel.example.invalid/profile",
            active_vocabulary="https://openrel.org/ns#",
            original_profile="https://openrel.example.invalid/original-profile",
            mapping_profile=None,
            mapping_provenance=None,
            candidate_digest_sha256="a" * 64,
            original_content_digest_sha256=None,
            candidate_payload={},
            original_representation={"orig": True},
            target_custom_licence_id=None,
            target_snapshot_before=None,
            target_digest_before=None,
            target_snapshot_after=None,
            target_digest_after=None,
            apply_allowed=False,
            review_required=False,
            reason="unrelated outer work",
            created_at=datetime.now(timezone.utc),
            updated_at=datetime.now(timezone.utc),
            reviewed_at=None,
            reviewed_by=None,
            applied_at=None,
            applied_by=None,
            rolled_back_at=None,
            rolled_back_by=None,
            error_code=None,
            error_detail=None,
        )
        session.add(unrelated)
        session.flush()
        service = OpenRelApplicationService(session)
        with pytest.raises(OpenRelApplicationConflictError):
            service.apply(state_id, actor_id="conflict@example.org")
        session.commit()
    finally:
        session.close()

    verify = SessionLocal()
    try:
        custom = _load_custom_licence(verify, custom_id)
        state = verify.execute(select(OpenRelPolicyState).where(OpenRelPolicyState.id == state_id)).scalars().one()
        unrelated = verify.execute(
            select(OpenRelPolicyState).where(OpenRelPolicyState.canonical_license_id == "lic-unrelated-outer-work")
        ).scalars().one_or_none()
        assert unrelated is not None
        assert state.status == "approved"
        assert state.target_custom_licence_id is None
        assert state.target_digest_before is None
        assert state.target_digest_after is None
        assert custom.name == "Before"
        assert custom.license_text == "Before text"
        assert verify.query(OpenRelPolicyEvent).filter_by(policy_state_id=state_id, event_type="applied").count() == 0
        assert verify.query(CustomLicenceAuditEvent).filter_by(custom_licence_id=custom_id, event_type="openrel_policy_applied").count() == 0
        assert verify.query(CustomLicenceRepresentation).filter_by(source_policy_state_id=state_id).count() == 0
    finally:
        verify.close()
        engine.dispose()


def test_federated_application_service_apply_and_rollback_publish_revisions_and_rdf(upgraded_db: str, tmp_path: Path):
    engine = create_engine(upgraded_db)
    SessionLocal = sessionmaker(bind=engine, autoflush=False, autocommit=False, expire_on_commit=False)
    raw = _raw_dsn(upgraded_db)
    publisher, custom_settings, custom_id, record_id = _setup_federated_custom_record(
        upgraded_db, raw, tmp_path, requested_license_id=f"lic-fed-{uuid.uuid4().hex[:8]}"
    )
    full_state_id = uuid.UUID(
        _insert_policy_state_for_application(
            raw,
            custom_id=str(custom_id),
            action="full-replacement",
            candidate_payload={
                "name": "Federated After",
                "summary": "Federated summary",
                "description": "Federated description",
                "licenseText": "Federated text",
                "spdxJsonld": {"federated": True},
            },
            original_content_digest=compute_normalized_text_digest("Before text"),
            canonical_license_id="lic-fed-apply",
        )
    )
    map_state_id = uuid.UUID(
        _insert_policy_state_for_application(
            raw,
            custom_id=str(custom_id),
            action="historical-mapping",
            candidate_payload={
                "mediaType": "application/json",
                "profile": "https://example.invalid/profile",
                "vocabulary": "https://example.invalid/vocab",
                "content": {"mapping": True},
                "mappingProfile": "https://example.invalid/mapping",
                "mappingProvenance": {"source": "openrel"},
            },
            mapping_profile="https://example.invalid/mapping",
            mapping_provenance={"source": "openrel"},
            original_content_digest=compute_normalized_text_digest("Federated text"),
            canonical_license_id="lic-fed-map",
        )
    )
    session = SessionLocal()
    try:
        service = OpenRelApplicationService(
            session,
            federation_publisher=publisher,
            federation_custom_settings=custom_settings,
        )
        service.apply(full_state_id, actor_id="admin@example.org")
        session.commit()
    finally:
        session.close()
    verify = SessionLocal()
    try:
        full_state = verify.get(OpenRelPolicyState, full_state_id)
        assert full_state is not None and full_state.status == "applied"
        custom = _load_custom_licence(verify, custom_id)
        assert custom.name == "Federated After"
        outbox = verify.execute(select(CustomLicenceFederationOutbox).where(CustomLicenceFederationOutbox.custom_licence_id == custom_id)).scalars().one()
        record = verify.get(FederationRecord, record_id)
        assert record is not None and int(record.materialized_generation or 0) == 2
        events = verify.execute(select(FederationChangeEvent).where(FederationChangeEvent.record_id == record_id).order_by(FederationChangeEvent.event_sequence.asc())).scalars().all()
        assert len(events) == 2
        assert events[-1].signed_payload["record"]["payload"]["name"] == "Federated After"
        rdf_jobs = verify.execute(text("SELECT count(*) FROM federation_rdf_outbox_jobs WHERE record_id = :record_id"), {"record_id": record_id}).scalar_one()
        assert int(rdf_jobs) == 4
        assert outbox.federation_event_id == events[-1].id
        assert verify.query(CustomLicenceAuditEvent).filter_by(custom_licence_id=custom_id, event_type="openrel_policy_applied").count() == 1
    finally:
        verify.close()

    session = SessionLocal()
    try:
        service = OpenRelApplicationService(
            session,
            federation_publisher=publisher,
            federation_custom_settings=custom_settings,
        )
        service.apply(map_state_id, actor_id="admin@example.org")
        session.commit()
    finally:
        session.close()
    verify = SessionLocal()
    try:
        record = verify.get(FederationRecord, record_id)
        assert record is not None and int(record.materialized_generation or 0) == 3
        latest = verify.execute(select(FederationChangeEvent).where(FederationChangeEvent.record_id == record_id).order_by(FederationChangeEvent.event_sequence.desc())).scalars().first()
        assert latest is not None
        assert latest.signed_payload["record"]["payload"]["name"] == "Federated After"
        assert latest.signed_payload["record"]["payload"]["representations"][0]["sourcePolicyStateId"] == str(map_state_id)
        rep = verify.execute(select(CustomLicenceRepresentation).where(CustomLicenceRepresentation.source_policy_state_id == map_state_id)).scalars().one()
        assert rep.status == "active"
    finally:
        verify.close()

    session = SessionLocal()
    try:
        service = OpenRelApplicationService(
            session,
            federation_publisher=publisher,
            federation_custom_settings=custom_settings,
        )
        service.rollback(map_state_id, actor_id="admin@example.org")
        session.commit()
    finally:
        session.close()
    verify = SessionLocal()
    try:
        map_state = verify.get(OpenRelPolicyState, map_state_id)
        assert map_state is not None and map_state.status == "rolled-back"
        record = verify.get(FederationRecord, record_id)
        assert record is not None and int(record.materialized_generation or 0) == 4
        latest = verify.execute(select(FederationChangeEvent).where(FederationChangeEvent.record_id == record_id).order_by(FederationChangeEvent.event_sequence.desc())).scalars().first()
        assert latest is not None
        assert "representations" not in latest.signed_payload["record"]["payload"]
        rep = verify.execute(select(CustomLicenceRepresentation).where(CustomLicenceRepresentation.source_policy_state_id == map_state_id)).scalars().one()
        assert rep.status == "rolled-back"
        rdf_jobs = verify.execute(text("SELECT count(*) FROM federation_rdf_outbox_jobs WHERE record_id = :record_id"), {"record_id": record_id}).scalar_one()
        assert int(rdf_jobs) == 8
    finally:
        verify.close()
        publisher.db.close()
        engine.dispose()


def test_federated_application_caller_rollback_removes_all_effects(upgraded_db: str, tmp_path: Path):
    engine = create_engine(upgraded_db)
    SessionLocal = sessionmaker(bind=engine, autoflush=False, autocommit=False, expire_on_commit=False)
    raw = _raw_dsn(upgraded_db)
    publisher, custom_settings, custom_id, record_id = _setup_federated_custom_record(
        upgraded_db, raw, tmp_path, requested_license_id=f"lic-fed-rollback-{uuid.uuid4().hex[:8]}"
    )
    state_id = uuid.UUID(
        _insert_policy_state_for_application(
            raw,
            custom_id=str(custom_id),
            action="full-replacement",
            candidate_payload={
                "name": "Rollback Candidate",
                "summary": "Rollback summary",
                "description": "Rollback description",
                "licenseText": "Rollback text",
                "spdxJsonld": {"rollback": True},
            },
            original_content_digest=compute_normalized_text_digest("Before text"),
            canonical_license_id="lic-fed-rollback",
        )
    )
    verify = SessionLocal()
    try:
        baseline = _federated_baseline(verify, custom_id=custom_id, record_id=record_id)
    finally:
        verify.close()
    session = SessionLocal()
    try:
        service = OpenRelApplicationService(session, federation_publisher=publisher, federation_custom_settings=custom_settings)
        service.apply(state_id, actor_id="admin@example.org")
        session.rollback()
    finally:
        session.close()
    verify = SessionLocal()
    try:
        custom = _load_custom_licence(verify, custom_id)
        state = verify.get(OpenRelPolicyState, state_id)
        assert state is not None
        assert custom.name == "Before"
        assert custom.summary is None
        assert custom.description is None
        assert custom.license_text == "Before text"
        assert custom.spdx_jsonld == {"before": True}
        assert state.status == "approved"
        assert state.target_custom_licence_id is None
        assert state.target_snapshot_before is None
        assert state.target_digest_before is None
        assert state.target_snapshot_after is None
        assert state.target_digest_after is None
        assert state.applied_at is None
        assert state.applied_by is None
        assert verify.query(OpenRelPolicyEvent).filter_by(policy_state_id=state_id, event_type="applied").count() == 0
        assert verify.query(CustomLicenceAuditEvent).filter_by(custom_licence_id=custom_id, event_type="openrel_policy_applied").count() == 0
        assert verify.query(CustomLicenceRepresentation).filter_by(source_policy_state_id=state_id).count() == 0
        after = _federated_baseline(verify, custom_id=custom_id, record_id=record_id)
        assert after == baseline
    finally:
        verify.close()
        publisher.db.close()
        engine.dispose()


def test_federated_application_failure_rolls_back_savepoint_and_preserves_outer_work(upgraded_db: str, tmp_path: Path):
    engine = create_engine(upgraded_db)
    SessionLocal = sessionmaker(bind=engine, autoflush=False, autocommit=False, expire_on_commit=False)
    raw = _raw_dsn(upgraded_db)
    real_publisher, custom_settings, custom_id, record_id = _setup_federated_custom_record(
        upgraded_db, raw, tmp_path, requested_license_id=f"lic-fed-failure-{uuid.uuid4().hex[:8]}"
    )
    state_id = uuid.UUID(
        _insert_policy_state_for_application(
            raw,
            custom_id=str(custom_id),
            action="full-replacement",
            candidate_payload={
                "name": "Failure Candidate",
                "summary": "Failure summary",
                "description": "Failure description",
                "licenseText": "Failure text",
                "spdxJsonld": {"failure": True},
            },
            original_content_digest=compute_normalized_text_digest("Before text"),
            canonical_license_id="lic-fed-failure",
        )
    )
    verify = SessionLocal()
    try:
        baseline = _federated_baseline(verify, custom_id=custom_id, record_id=record_id)
    finally:
        verify.close()
    session = SessionLocal()
    unrelated_id = uuid.uuid4()
    try:
        session.add(
            OpenRelPolicyState(
                id=unrelated_id,
                canonical_license_id="lic-fed-unrelated-work",
                source_kind="custom",
                source_record_ref="ref-fed-unrelated-work",
                classification="new",
                policy_mode="active",
                policy_version="2026.09",
                effective_date=datetime.now(timezone.utc),
                action="none",
                status="planned",
                provider_url="https://openrel.example.invalid/provider",
                active_profile="https://openrel.example.invalid/profile",
                active_vocabulary="https://openrel.org/ns#",
                original_profile="https://openrel.example.invalid/original-profile",
                mapping_profile=None,
                mapping_provenance=None,
                candidate_digest_sha256="a" * 64,
                original_content_digest_sha256=None,
                candidate_payload={},
                original_representation={"orig": True},
                target_custom_licence_id=None,
                target_snapshot_before=None,
                target_digest_before=None,
                target_snapshot_after=None,
                target_digest_after=None,
                apply_allowed=False,
                review_required=False,
                reason="fed unrelated outer work",
                created_at=datetime.now(timezone.utc),
                updated_at=datetime.now(timezone.utc),
                reviewed_at=None,
                reviewed_by=None,
                applied_at=None,
                applied_by=None,
                rolled_back_at=None,
                rolled_back_by=None,
                error_code=None,
                error_detail=None,
            )
        )
        session.flush()
        service = OpenRelApplicationService(
            session,
            federation_publisher=_FailingFederatedPublisher(real_publisher),
            federation_custom_settings=custom_settings,
        )
        with pytest.raises(OpenRelApplicationConflictError) as excinfo:
            service.apply(state_id, actor_id="admin@example.org")
        assert str(excinfo.value) == "injected publication failure"
        session.commit()
    finally:
        session.close()
    verify = SessionLocal()
    try:
        assert verify.get(OpenRelPolicyState, unrelated_id) is not None
        custom = _load_custom_licence(verify, custom_id)
        state = verify.get(OpenRelPolicyState, state_id)
        assert state is not None
        assert custom.name == "Before"
        assert state.status == "approved"
        assert state.target_custom_licence_id is None
        assert state.target_snapshot_before is None
        assert state.target_digest_before is None
        assert state.target_snapshot_after is None
        assert state.target_digest_after is None
        assert verify.query(OpenRelPolicyEvent).filter_by(policy_state_id=state_id, event_type="applied").count() == 0
        assert verify.query(CustomLicenceAuditEvent).filter_by(custom_licence_id=custom_id, event_type="openrel_policy_applied").count() == 0
        assert verify.query(CustomLicenceRepresentation).filter_by(source_policy_state_id=state_id).count() == 0
        after = _federated_baseline(verify, custom_id=custom_id, record_id=record_id)
        assert after == baseline
    finally:
        verify.close()
        real_publisher.db.close()
        engine.dispose()


def test_federated_application_concurrent_apply_is_single_revision(upgraded_db: str, tmp_path: Path):
    engine = create_engine(upgraded_db)
    SessionLocal = sessionmaker(bind=engine, autoflush=False, autocommit=False, expire_on_commit=False)
    raw = _raw_dsn(upgraded_db)
    publisher, custom_settings, custom_id, record_id = _setup_federated_custom_record(
        upgraded_db, raw, tmp_path, requested_license_id=f"lic-fed-concurrent-apply-{uuid.uuid4().hex[:8]}"
    )
    state_id = uuid.UUID(
        _insert_policy_state_for_application(
            raw,
            custom_id=str(custom_id),
            action="full-replacement",
            candidate_payload={
                "name": "Concurrent Federated Apply",
                "summary": "Concurrent federated summary",
                "description": "Concurrent federated description",
                "licenseText": "Concurrent federated text",
                "spdxJsonld": {"concurrent": "federated"},
            },
            original_content_digest=compute_normalized_text_digest("Before text"),
            canonical_license_id="lic-fed-concurrent-apply",
        )
    )
    verify = SessionLocal()
    try:
        baseline = _federated_baseline(verify, custom_id=custom_id, record_id=record_id)
    finally:
        verify.close()
    barrier = threading.Barrier(2)
    results: list[dict[str, object]] = []
    results_lock = threading.Lock()

    def _worker(worker_name: str) -> None:
        session = SessionLocal()
        try:
            barrier.wait(timeout=10)
            service = OpenRelApplicationService(session, federation_publisher=publisher, federation_custom_settings=custom_settings)
            state = service.apply(state_id, actor_id=f"{worker_name}@example.org")
            session.commit()
            outcome = {"worker": worker_name, "status": "ok", "state_status": state.status}
        except Exception as exc:
            session.rollback()
            outcome = {"worker": worker_name, "status": "error", "error_type": type(exc).__name__, "error_message": str(exc)}
        finally:
            session.close()
        with results_lock:
            results.append(outcome)

    t1 = threading.Thread(target=_worker, args=("fed-apply-1",))
    t2 = threading.Thread(target=_worker, args=("fed-apply-2",))
    t1.start()
    t2.start()
    _join_or_fail(t1, t2)
    assert len(results) == 2
    assert all(item["status"] == "ok" for item in results), results
    assert not any(item.get("error_type") in {"IntegrityError", "OperationalError"} for item in results), results
    assert not any("deadlock" in str(item.get("error_message", "")).lower() for item in results), results
    verify = SessionLocal()
    try:
        after = _federated_baseline(verify, custom_id=custom_id, record_id=record_id)
        state = verify.get(OpenRelPolicyState, state_id)
        custom = _load_custom_licence(verify, custom_id)
        assert state is not None and state.status == "applied"
        assert custom.name == "Concurrent Federated Apply"
        assert after["generation"] == baseline["generation"] + 1
        assert after["event_count"] == baseline["event_count"] + 1
        assert after["rdf_count"] == baseline["rdf_count"] + 2
        assert verify.query(OpenRelPolicyEvent).filter_by(policy_state_id=state_id, event_type="applied").count() == 1
        assert verify.query(CustomLicenceAuditEvent).filter_by(custom_licence_id=custom_id, event_type="openrel_policy_applied").count() == 1
        latest = verify.execute(
            select(FederationChangeEvent).where(FederationChangeEvent.record_id == record_id).order_by(FederationChangeEvent.event_sequence.desc())
        ).scalars().first()
        assert latest is not None
        assert latest.idempotency_key == OpenRelApplicationService(verify)._federation_idempotency_key(state_id=state_id, action="apply")
        assert latest.signed_payload["record"]["payload"]["name"] == "Concurrent Federated Apply"
        outbox = verify.execute(select(CustomLicenceFederationOutbox).where(CustomLicenceFederationOutbox.custom_licence_id == custom_id)).scalars().one()
        assert outbox.federation_event_id == latest.id
    finally:
        verify.close()
        publisher.db.close()
        engine.dispose()


def test_federated_application_concurrent_apply_and_rollback_is_serialized(upgraded_db: str, tmp_path: Path):
    engine = create_engine(upgraded_db)
    SessionLocal = sessionmaker(bind=engine, autoflush=False, autocommit=False, expire_on_commit=False)
    raw = _raw_dsn(upgraded_db)
    publisher, custom_settings, custom_id, record_id = _setup_federated_custom_record(
        upgraded_db, raw, tmp_path, requested_license_id=f"lic-fed-concurrent-ar-{uuid.uuid4().hex[:8]}"
    )
    state_id = uuid.UUID(
        _insert_policy_state_for_application(
            raw,
            custom_id=str(custom_id),
            action="full-replacement",
            candidate_payload={
                "name": "Concurrent Apply Rollback",
                "summary": "Concurrent AR summary",
                "description": "Concurrent AR description",
                "licenseText": "Concurrent AR text",
                "spdxJsonld": {"concurrent": "apply-rollback"},
            },
            original_content_digest=compute_normalized_text_digest("Before text"),
            canonical_license_id="lic-fed-concurrent-ar",
        )
    )
    verify = SessionLocal()
    try:
        baseline = _federated_baseline(verify, custom_id=custom_id, record_id=record_id)
    finally:
        verify.close()
    barrier = threading.Barrier(2)
    results: list[dict[str, object]] = []
    results_lock = threading.Lock()

    def _worker(worker_name: str, operation: Callable[[OpenRelApplicationService], OpenRelPolicyState]) -> None:
        session = SessionLocal()
        try:
            barrier.wait(timeout=10)
            service = OpenRelApplicationService(session, federation_publisher=publisher, federation_custom_settings=custom_settings)
            state = operation(service)
            session.commit()
            outcome = {"worker": worker_name, "status": "ok", "state_status": state.status}
        except Exception as exc:
            session.rollback()
            outcome = {"worker": worker_name, "status": "error", "error_type": type(exc).__name__, "error_message": str(exc)}
        finally:
            session.close()
        with results_lock:
            results.append(outcome)

    t_apply = threading.Thread(target=_worker, args=("apply", lambda service: service.apply(state_id, actor_id="apply@example.org")))
    t_rollback = threading.Thread(target=_worker, args=("rollback", lambda service: service.rollback(state_id, actor_id="rollback@example.org")))
    t_apply.start()
    t_rollback.start()
    _join_or_fail(t_apply, t_rollback)
    assert len(results) == 2
    assert not any(item.get("error_type") in {"IntegrityError", "OperationalError"} for item in results), results
    assert not any("deadlock" in str(item.get("error_message", "")).lower() for item in results), results
    apply_result = next(item for item in results if item["worker"] == "apply")
    rollback_result = next(item for item in results if item["worker"] == "rollback")
    assert apply_result["status"] == "ok", results
    verify = SessionLocal()
    try:
        after = _federated_baseline(verify, custom_id=custom_id, record_id=record_id)
        state = verify.get(OpenRelPolicyState, state_id)
        assert state is not None
        applied_count = verify.query(OpenRelPolicyEvent).filter_by(policy_state_id=state_id, event_type="applied").count()
        rolled_back_count = verify.query(OpenRelPolicyEvent).filter_by(policy_state_id=state_id, event_type="rolled-back").count()
        applied_audits = verify.query(CustomLicenceAuditEvent).filter_by(custom_licence_id=custom_id, event_type="openrel_policy_applied").count()
        rollback_audits = verify.query(CustomLicenceAuditEvent).filter_by(custom_licence_id=custom_id, event_type="openrel_policy_rolled_back").count()
        events = verify.execute(
            select(FederationChangeEvent).where(FederationChangeEvent.record_id == record_id).order_by(FederationChangeEvent.event_sequence.asc())
        ).scalars().all()
        assert events[0].operation == "upsert"
        if rollback_result["status"] == "ok":
            assert state.status == "rolled-back"
            assert rolled_back_count == 1
            assert applied_count == 1
            assert applied_audits == 1
            assert rollback_audits == 1
            assert after["generation"] == baseline["generation"] + 2
            assert after["event_count"] == baseline["event_count"] + 2
            assert after["rdf_count"] == baseline["rdf_count"] + 4
            assert [event.operation for event in events[-2:]] == ["upsert", "upsert"]
        else:
            assert rollback_result["error_type"] == "OpenRelApplicationConflictError", results
            assert rollback_result["error_message"] == "only applied states can be rolled back", results
            assert state.status == "applied"
            assert rolled_back_count == 0
            assert applied_count == 1
            assert applied_audits == 1
            assert rollback_audits == 0
            assert after["generation"] == baseline["generation"] + 1
            assert after["event_count"] == baseline["event_count"] + 1
            assert after["rdf_count"] == baseline["rdf_count"] + 2
        outbox = verify.execute(select(CustomLicenceFederationOutbox).where(CustomLicenceFederationOutbox.custom_licence_id == custom_id)).scalars().one()
        assert outbox.federation_event_id == events[-1].id
    finally:
        verify.close()
        publisher.db.close()
        engine.dispose()
