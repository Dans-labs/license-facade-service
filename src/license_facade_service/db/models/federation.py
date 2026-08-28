from __future__ import annotations

import uuid
from datetime import datetime

from sqlalchemy import BigInteger, Boolean, CheckConstraint, DateTime, ForeignKey, Index, Integer, String, Text, UniqueConstraint, text
from sqlalchemy.dialects.postgresql import JSONB, UUID
from sqlalchemy.orm import Mapped, mapped_column
from sqlalchemy.schema import FetchedValue

from src.license_facade_service.db.base import Base


class FederationNodeIdentityState(Base):
    __tablename__ = "federation_node_identity_state"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, default=1)
    node_id: Mapped[str] = mapped_column(String(128), unique=True, nullable=False)
    public_base_url: Mapped[str] = mapped_column(String(1024), nullable=False)
    node_name: Mapped[str] = mapped_column(String(256), nullable=False)
    operator_name: Mapped[str] = mapped_column(String(256), nullable=False)
    config_fingerprint: Mapped[str] = mapped_column(String(128), nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)

    __table_args__ = (CheckConstraint("id = 1", name="ck_federation_node_identity_singleton"),)


class FederationSigningKey(Base):
    __tablename__ = "federation_signing_keys"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    kid: Mapped[str] = mapped_column(String(128), unique=True, nullable=False)
    alg: Mapped[str] = mapped_column(String(32), nullable=False)
    kty: Mapped[str] = mapped_column(String(16), nullable=False)
    crv: Mapped[str] = mapped_column(String(32), nullable=False)
    x: Mapped[str] = mapped_column(String(1024), nullable=False)
    is_active: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    status: Mapped[str] = mapped_column(String(32), nullable=False, default="staged")
    valid_from: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    valid_until: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    # Phase 5 rotation tracking
    rotation_scheduled_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    rotated_to_kid: Mapped[str | None] = mapped_column(
        String(128),
        ForeignKey("federation_signing_keys.kid", ondelete="RESTRICT"),
    )
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)

    __table_args__ = (
        CheckConstraint("alg = 'EdDSA'", name="ck_federation_signing_keys_alg"),
        CheckConstraint("kty = 'OKP'", name="ck_federation_signing_keys_kty"),
        CheckConstraint("crv = 'Ed25519'", name="ck_federation_signing_keys_crv"),
        CheckConstraint("status IN ('staged','active','retired','revoked')", name="ck_fsk_status_v5"),
        CheckConstraint("is_active = (status = 'active')", name="ck_fsk_active_status_equivalence_v5"),
        CheckConstraint("rotation_scheduled_at IS NULL OR status = 'staged'", name="ck_fsk_schedule_only_staged_v5"),
        CheckConstraint("rotated_to_kid IS NULL OR status IN ('retired','revoked')", name="ck_fsk_rotated_to_status_v5"),
        CheckConstraint("rotated_to_kid IS NULL OR rotated_to_kid <> kid", name="ck_fsk_rotated_to_self_v5"),
        CheckConstraint("valid_from IS NULL OR valid_until IS NULL OR valid_from < valid_until", name="ck_fsk_validity_bounds_v5"),
        Index(
            "uq_fsk_single_scheduled_v5",
            text("(1)"),
            unique=True,
            postgresql_where=text("rotation_scheduled_at IS NOT NULL"),
        ),
    )


class FederationTrustedPeer(Base):
    __tablename__ = "federation_trusted_peers"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    peer_node_id: Mapped[str] = mapped_column(String(128), unique=True, nullable=False)
    base_url: Mapped[str] = mapped_column(String(1024), nullable=False)
    jwks_url: Mapped[str] = mapped_column(String(1024), nullable=False)
    peer_name: Mapped[str] = mapped_column(String(256), nullable=False)
    operator_name: Mapped[str | None] = mapped_column(String(256))
    trust_status: Mapped[str] = mapped_column(String(32), nullable=False, default="trusted")
    sync_enabled: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)
    allow_private_network: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    allowed_hostnames: Mapped[str | None] = mapped_column(Text)
    allowed_cidrs: Mapped[str | None] = mapped_column(Text)
    enrollment_mode: Mapped[str] = mapped_column(String(32), nullable=False, default="strict")
    expected_key_fingerprint: Mapped[str | None] = mapped_column(String(128))
    expected_key_kid: Mapped[str | None] = mapped_column(String(128))
    last_sync_attempt_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    last_sync_success_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    last_sync_status: Mapped[str | None] = mapped_column(String(32))
    last_sync_error_code: Mapped[str | None] = mapped_column(String(128))
    last_sync_error_detail: Mapped[str | None] = mapped_column(Text)
    archived_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    # Phase 5 — circuit breaker columns
    circuit_state: Mapped[str] = mapped_column(String(16), nullable=False, server_default="closed")
    circuit_requires_admin_reset: Mapped[bool] = mapped_column(Boolean, nullable=False, server_default="false")
    circuit_failure_count: Mapped[int] = mapped_column(Integer, nullable=False, server_default="0")
    circuit_opened_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    circuit_next_attempt_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    circuit_half_open_probe_count: Mapped[int] = mapped_column(Integer, nullable=False, server_default="0")
    circuit_last_failure_reason: Mapped[str | None] = mapped_column(String(64))
    # Phase 5 — administrative suspension columns (distinct from circuit breaker)
    suspended_until: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    suspension_reason: Mapped[str | None] = mapped_column(String(1024))
    # Phase 5 — peer key management
    last_key_refresh_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))


class FederationRecord(Base):
    __tablename__ = "federation_records"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    authority_node_id: Mapped[str] = mapped_column(String(128), nullable=False)
    local_id: Mapped[str] = mapped_column(String(256), nullable=False)
    version: Mapped[str] = mapped_column(String(128), nullable=False)
    canonical_id: Mapped[str] = mapped_column(String(512), nullable=False)
    resolving_uuid: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), nullable=False, unique=True)
    is_authoritative: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    payload: Mapped[dict] = mapped_column(JSONB, nullable=False, default=dict)
    payload_digest_sha256: Mapped[str] = mapped_column(String(128), nullable=False)
    published_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    materialized_generation: Mapped[int] = mapped_column(BigInteger, nullable=False, default=0)
    imported_from_peer_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True), ForeignKey("federation_trusted_peers.id", ondelete="SET NULL")
    )
    lifecycle_state: Mapped[str] = mapped_column(String(32), nullable=False, default="published")
    source_record_url: Mapped[str | None] = mapped_column(String(2048))
    source_event_id: Mapped[uuid.UUID | None] = mapped_column(UUID(as_uuid=True))
    source_event_position: Mapped[int | None] = mapped_column(BigInteger)
    source_signature_kid: Mapped[str | None] = mapped_column(String(128))
    source_signed_payload_digest_sha256: Mapped[str | None] = mapped_column(String(128))
    verification_status: Mapped[str | None] = mapped_column(String(32))
    last_verified_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)

    __table_args__ = (
        UniqueConstraint("authority_node_id", "local_id", "version", name="uq_federation_record_authority_local_version"),
        UniqueConstraint("canonical_id", name="uq_federation_record_canonical_id"),
    )


class FederationRecordAlias(Base):
    __tablename__ = "federation_record_aliases"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    record_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("federation_records.id", ondelete="CASCADE"), nullable=False
    )
    alias: Mapped[str] = mapped_column(String(512), nullable=False)
    alias_type: Mapped[str] = mapped_column(String(64), nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)

    __table_args__ = (UniqueConstraint("alias", name="uq_federation_record_alias"),)


class FederationRecordRepresentation(Base):
    __tablename__ = "federation_record_representations"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    record_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("federation_records.id", ondelete="CASCADE"), nullable=False
    )
    representation_type: Mapped[str] = mapped_column(String(64), nullable=False)
    media_type: Mapped[str] = mapped_column(String(128), nullable=False)
    profile_uri: Mapped[str | None] = mapped_column(String(1024))
    vocabulary_uri: Mapped[str | None] = mapped_column(String(1024))
    href: Mapped[str | None] = mapped_column(String(2048))
    content: Mapped[str | None] = mapped_column(Text)
    content_digest_sha256: Mapped[str | None] = mapped_column(String(128))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)

    __table_args__ = (
        UniqueConstraint("record_id", "representation_type", "media_type", name="uq_federation_representation_kind"),
    )


class FederationRecordProvenance(Base):
    __tablename__ = "federation_record_provenance"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    record_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("federation_records.id", ondelete="CASCADE"), nullable=False
    )
    source_node_id: Mapped[str | None] = mapped_column(String(128))
    source_uri: Mapped[str | None] = mapped_column(String(2048))
    source_digest_sha256: Mapped[str | None] = mapped_column(String(128))
    provenance_type: Mapped[str] = mapped_column(String(64), nullable=False)
    imported_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    asserted_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    metadata_json: Mapped[dict] = mapped_column("metadata", JSONB, nullable=False, default=dict)


class FederationChangeEvent(Base):
    __tablename__ = "federation_change_events"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    event_sequence: Mapped[int] = mapped_column(BigInteger, nullable=False, unique=True)
    event_type: Mapped[str] = mapped_column(String(64), nullable=False, default="record.changed")
    authority_node_id: Mapped[str] = mapped_column(String(128), nullable=False)
    record_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True), ForeignKey("federation_records.id", ondelete="SET NULL")
    )
    operation: Mapped[str] = mapped_column(String(32), nullable=False, default="upsert")
    generated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    payload_schema_version: Mapped[str] = mapped_column(String(16), nullable=False, default="1")
    signed_payload: Mapped[dict] = mapped_column(JSONB, nullable=False, default=dict)
    signed_payload_digest_sha256: Mapped[str] = mapped_column(String(128), nullable=False)
    signature_base64url: Mapped[str] = mapped_column(String(512), nullable=False)
    signature_kid: Mapped[str] = mapped_column(String(128), nullable=False)
    signature_alg: Mapped[str] = mapped_column(String(32), nullable=False, default="EdDSA")
    provenance_type: Mapped[str] = mapped_column(String(32), nullable=False, default="publication")
    backfill_created_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    event_payload: Mapped[dict] = mapped_column(JSONB, nullable=False, default=dict)
    event_digest_sha256: Mapped[str] = mapped_column(String(128), nullable=False)
    occurred_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)

    __table_args__ = (
        UniqueConstraint("authority_node_id", "event_sequence", name="uq_federation_change_events_authority_sequence"),
        CheckConstraint("operation IN ('upsert','deprecate','tombstone')", name="ck_federation_change_events_operation"),
        CheckConstraint("signature_alg = 'EdDSA'", name="ck_federation_change_events_signature_alg"),
    )


class FederationPeerCursor(Base):
    __tablename__ = "federation_peer_cursors"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    peer_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("federation_trusted_peers.id", ondelete="CASCADE"), nullable=False, unique=True
    )
    cursor: Mapped[str | None] = mapped_column(String(512))
    last_remote_position: Mapped[int | None] = mapped_column(BigInteger)
    synced_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)


class FederationSyncAttempt(Base):
    __tablename__ = "federation_sync_attempts"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    peer_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("federation_trusted_peers.id", ondelete="CASCADE"), nullable=False
    )
    started_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    completed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    status: Mapped[str] = mapped_column(String(32), nullable=False)
    trigger_type: Mapped[str] = mapped_column(String(32), nullable=False, default="manual")
    pages_processed: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    events_processed: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    cursor_before: Mapped[str | None] = mapped_column(String(1024))
    cursor_after: Mapped[str | None] = mapped_column(String(1024))
    error_code: Mapped[str | None] = mapped_column(String(128))
    error_detail: Mapped[str | None] = mapped_column(Text)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)


class FederationConflictRecord(Base):
    __tablename__ = "federation_conflicts"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    record_key: Mapped[str] = mapped_column(String(512), nullable=False)
    local_record_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True), ForeignKey("federation_records.id", ondelete="SET NULL")
    )
    remote_peer_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True), ForeignKey("federation_trusted_peers.id", ondelete="SET NULL")
    )
    remote_record_ref: Mapped[str | None] = mapped_column(String(512))
    reason: Mapped[str] = mapped_column(Text, nullable=False)
    status: Mapped[str] = mapped_column(String(32), nullable=False, default="open")
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    resolved_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))

    __table_args__ = (Index("ix_federation_conflicts_record_key", "record_key"),)


class FederationPeerSigningKey(Base):
    __tablename__ = "federation_peer_signing_keys"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    peer_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("federation_trusted_peers.id", ondelete="CASCADE"), nullable=False
    )
    kid: Mapped[str] = mapped_column(String(128), nullable=False)
    alg: Mapped[str] = mapped_column(String(32), nullable=False)
    kty: Mapped[str] = mapped_column(String(16), nullable=False)
    crv: Mapped[str] = mapped_column(String(32), nullable=False)
    x: Mapped[str] = mapped_column(String(1024), nullable=False)
    key_fingerprint: Mapped[str] = mapped_column(String(128), nullable=False)
    key_status: Mapped[str] = mapped_column(String(32), nullable=False, default="active")
    first_seen_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    last_seen_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    valid_from: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    valid_until: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    approved_by: Mapped[str | None] = mapped_column(String(128))
    approved_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)

    __table_args__ = (
        UniqueConstraint("peer_id", "kid", name="uq_federation_peer_signing_keys_peer_kid"),
        CheckConstraint("alg = 'EdDSA'", name="ck_federation_peer_signing_keys_alg"),
        CheckConstraint("kty = 'OKP'", name="ck_federation_peer_signing_keys_kty"),
        CheckConstraint("crv = 'Ed25519'", name="ck_federation_peer_signing_keys_crv"),
        CheckConstraint("key_status IN ('active','retired','revoked')", name="ck_federation_peer_signing_keys_status"),
    )


class FederationInboundEvent(Base):
    __tablename__ = "federation_inbound_events"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    source_peer_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("federation_trusted_peers.id", ondelete="CASCADE"), nullable=False
    )
    authority_node_id: Mapped[str] = mapped_column(String(128), nullable=False)
    remote_event_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), nullable=False)
    remote_event_position: Mapped[int] = mapped_column(BigInteger, nullable=False)
    remote_operation: Mapped[str] = mapped_column(String(32), nullable=False)
    signed_payload: Mapped[dict] = mapped_column(JSONB, nullable=False, default=dict)
    signed_payload_digest_sha256: Mapped[str] = mapped_column(String(128), nullable=False)
    signature_kid: Mapped[str] = mapped_column(String(128), nullable=False)
    signature_alg: Mapped[str] = mapped_column(String(32), nullable=False)
    signature_base64url: Mapped[str] = mapped_column(String(512), nullable=False)
    generated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    received_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    processing_status: Mapped[str] = mapped_column(String(32), nullable=False)
    record_canonical_id: Mapped[str] = mapped_column(String(512), nullable=False)
    record_payload_digest_sha256: Mapped[str] = mapped_column(String(128), nullable=False)
    error_code: Mapped[str | None] = mapped_column(String(128))
    error_detail: Mapped[str | None] = mapped_column(Text)

    __table_args__ = (
        UniqueConstraint("authority_node_id", "remote_event_id", name="uq_federation_inbound_events_authority_event_id"),
        UniqueConstraint(
            "authority_node_id",
            "remote_event_position",
            name="uq_federation_inbound_events_authority_event_position",
        ),
        UniqueConstraint(
            "source_peer_id",
            "signed_payload_digest_sha256",
            name="uq_federation_inbound_events_peer_digest",
        ),
    )


class FederationPeerAuditLog(Base):
    __tablename__ = "federation_peer_audit_log"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    peer_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("federation_trusted_peers.id", ondelete="CASCADE"), nullable=False
    )
    action: Mapped[str] = mapped_column(String(64), nullable=False)
    actor: Mapped[str] = mapped_column(String(128), nullable=False)
    details: Mapped[dict] = mapped_column(JSONB, nullable=False, default=dict)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)


class FederationResolutionAlias(Base):
    __tablename__ = "federation_resolution_aliases"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    normalized_identifier: Mapped[str] = mapped_column(String(1024), nullable=False)
    alias_value: Mapped[str] = mapped_column(String(2048), nullable=False)
    alias_kind: Mapped[str] = mapped_column(String(64), nullable=False)
    record_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("federation_records.id", ondelete="CASCADE"), nullable=False
    )
    authority_node_id: Mapped[str | None] = mapped_column(String(128))
    source_peer_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True), ForeignKey("federation_trusted_peers.id", ondelete="SET NULL")
    )
    is_authoritative: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)

    __table_args__ = (
        UniqueConstraint("normalized_identifier", "record_id", "alias_kind", name="uq_federation_resolution_alias"),
        Index("ix_federation_resolution_aliases_normalized_identifier", "normalized_identifier"),
    )


class FederationResolutionConflict(Base):
    __tablename__ = "federation_resolution_conflicts"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    normalized_identifier: Mapped[str] = mapped_column(String(1024), nullable=False, unique=True)
    conflict_type: Mapped[str] = mapped_column(String(64), nullable=False)
    status: Mapped[str] = mapped_column(String(32), nullable=False, default="open")
    version: Mapped[int] = mapped_column(Integer, nullable=False, default=1)
    decision_effectiveness: Mapped[str | None] = mapped_column(String(32))
    candidate_summary: Mapped[dict] = mapped_column(JSONB, nullable=False, default=dict)
    resolved_record_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True), ForeignKey("federation_records.id", ondelete="SET NULL")
    )
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    resolved_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    reopened_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))

    __table_args__ = (Index("ix_federation_resolution_conflicts_normalized_identifier", "normalized_identifier"),)


class FederationConflictDecisionEvent(Base):
    __tablename__ = "federation_conflict_decision_events"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    conflict_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("federation_resolution_conflicts.id", ondelete="CASCADE"), nullable=False
    )
    expected_version: Mapped[int] = mapped_column(Integer, nullable=False)
    version: Mapped[int] = mapped_column(Integer, nullable=False)
    decision_type: Mapped[str] = mapped_column(String(32), nullable=False)
    decision_effectiveness: Mapped[str] = mapped_column(String(32), nullable=False)
    actor_role: Mapped[str] = mapped_column(String(32), nullable=False)
    actor_identifier: Mapped[str | None] = mapped_column(String(256))
    rationale: Mapped[str | None] = mapped_column(Text)
    before_state: Mapped[dict] = mapped_column(JSONB, nullable=False, default=dict)
    after_state: Mapped[dict] = mapped_column(JSONB, nullable=False, default=dict)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)

    __table_args__ = (
        Index("ix_federation_conflict_decisions_conflict_version", "conflict_id", "version"),
        UniqueConstraint("conflict_id", "version", name="uq_federation_conflict_decisions_conflict_version"),
    )


class FederationResolutionAuditLog(Base):
    __tablename__ = "federation_resolution_audit_log"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    subject_type: Mapped[str] = mapped_column(String(64), nullable=False)
    subject_id: Mapped[str] = mapped_column(String(256), nullable=False)
    action: Mapped[str] = mapped_column(String(64), nullable=False)
    actor_role: Mapped[str] = mapped_column(String(32), nullable=False)
    actor_identifier: Mapped[str | None] = mapped_column(String(256))
    rationale: Mapped[str | None] = mapped_column(Text)
    before_state: Mapped[dict] = mapped_column(JSONB, nullable=False, default=dict)
    after_state: Mapped[dict] = mapped_column(JSONB, nullable=False, default=dict)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)


class FederationRdfOutboxJob(Base):
    __tablename__ = "federation_rdf_outbox_jobs"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    dedupe_key: Mapped[str] = mapped_column(String(512), nullable=False, unique=True)
    job_type: Mapped[str] = mapped_column(String(64), nullable=False)
    status: Mapped[str] = mapped_column(String(32), nullable=False, default="pending")
    record_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True), ForeignKey("federation_records.id", ondelete="CASCADE")
    )
    authority_node_id: Mapped[str | None] = mapped_column(String(128))
    source_peer_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True), ForeignKey("federation_trusted_peers.id", ondelete="SET NULL")
    )
    graph_uri: Mapped[str] = mapped_column(String(2048), nullable=False)
    expected_generation: Mapped[int] = mapped_column(BigInteger, nullable=False)
    expected_digest_sha256: Mapped[str] = mapped_column(String(128), nullable=False)
    payload_json: Mapped[dict] = mapped_column(JSONB, nullable=False, default=dict)
    attempt_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    leased_until: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    leased_by: Mapped[str | None] = mapped_column(String(128))
    next_attempt_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    last_error_code: Mapped[str | None] = mapped_column(String(128))
    last_error_detail: Mapped[str | None] = mapped_column(Text)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    dead_lettered_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))

    __table_args__ = (
        Index("ix_federation_rdf_outbox_status_next_attempt", "status", "next_attempt_at"),
        Index("ix_federation_rdf_outbox_record_generation", "record_id", "expected_generation"),
        Index("ix_federation_rdf_outbox_graph_uri", "graph_uri"),
        CheckConstraint("status IN ('pending','running','succeeded','retryable_failed','dead_lettered','superseded')", name="ck_federation_rdf_outbox_status"),
    )


class FederationRdfGraphState(Base):
    __tablename__ = "federation_rdf_graph_state"

    graph_uri: Mapped[str] = mapped_column(String(2048), primary_key=True)
    graph_kind: Mapped[str] = mapped_column(String(64), nullable=False)
    record_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True), ForeignKey("federation_records.id", ondelete="CASCADE")
    )
    authority_node_id: Mapped[str | None] = mapped_column(String(128))
    source_peer_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True), ForeignKey("federation_trusted_peers.id", ondelete="SET NULL")
    )
    expected_generation: Mapped[int] = mapped_column(BigInteger, nullable=False, default=0)
    expected_digest_sha256: Mapped[str | None] = mapped_column(String(128))
    current_generation: Mapped[int] = mapped_column(BigInteger, nullable=False, default=0)
    current_digest_sha256: Mapped[str | None] = mapped_column(String(128))
    status: Mapped[str] = mapped_column(String(32), nullable=False, default="pending")
    active_lease_job_id: Mapped[uuid.UUID | None] = mapped_column(UUID(as_uuid=True))
    active_lease_by: Mapped[str | None] = mapped_column(String(128))
    active_lease_until: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    last_success_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    last_attempt_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    last_error_code: Mapped[str | None] = mapped_column(String(128))
    last_error_detail: Mapped[str | None] = mapped_column(Text)
    owned_by_service: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)


Index("ix_federation_records_authority", FederationRecord.authority_node_id)
Index("ix_federation_records_canonical_id", FederationRecord.canonical_id)
Index("ix_federation_records_imported_peer", FederationRecord.imported_from_peer_id)
Index("ix_federation_record_aliases_record_id", FederationRecordAlias.record_id)
Index("ix_federation_representations_record_id", FederationRecordRepresentation.record_id)
Index("ix_federation_provenance_record_id", FederationRecordProvenance.record_id)
Index("ix_federation_change_events_occurred_at", FederationChangeEvent.occurred_at)
Index("ix_federation_sync_attempts_peer_started", FederationSyncAttempt.peer_id, FederationSyncAttempt.started_at)
Index("ix_federation_inbound_events_peer_position", FederationInboundEvent.source_peer_id, FederationInboundEvent.remote_event_position)


# ---------------------------------------------------------------------------
# Phase 5 — Increment 1: operational schema models
# ---------------------------------------------------------------------------


class FederationOperationalAudit(Base):
    """Append-only operational audit log.

    target_id stores stable UUIDs or key identifiers (max 256 chars).
    Canonical licence identifiers that exceed 256 chars must be stored
    truncated with their full form placed in redacted_details by
    AuditDetailBuilder. This is Option A per the approved design.

    peer_id uses ON DELETE RESTRICT: peers must be archived, not deleted.
    DB-level triggers reject UPDATE and DELETE on this table.
    """

    __tablename__ = "federation_operational_audit"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, server_default=FetchedValue())
    occurred_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, server_default=FetchedValue())
    request_id: Mapped[str | None] = mapped_column(String(128))
    actor_type: Mapped[str] = mapped_column(String(32), nullable=False)
    actor_id: Mapped[str | None] = mapped_column(String(256))
    action: Mapped[str] = mapped_column(String(64), nullable=False)
    target_type: Mapped[str] = mapped_column(String(64), nullable=False)
    target_id: Mapped[str] = mapped_column(String(256), nullable=False)
    peer_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("federation_trusted_peers.id", ondelete="RESTRICT", name="fk_foa_peer_id"),
    )
    outcome: Mapped[str] = mapped_column(String(32), nullable=False)
    reason: Mapped[str | None] = mapped_column(Text)
    redacted_details: Mapped[dict | None] = mapped_column(JSONB)


class FederationSyncLease(Base):
    """Persisted per-peer synchronization lease with monotonic fencing token.

    UNIQUE(peer_id): at most one active lease per peer.
    fencing_token: from global sequence federation_sync_lease_fencing_seq,
    never resets, strictly increasing across all claim/release cycles.
    Atomic claim via INSERT ... ON CONFLICT DO UPDATE WHERE expires_at < now().
    """

    __tablename__ = "federation_sync_leases"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, server_default=FetchedValue())
    peer_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("federation_trusted_peers.id", ondelete="RESTRICT", name="fk_fsl_peer_id"),
        nullable=False,
        unique=True,
    )
    owner_instance_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), nullable=False)
    fencing_token: Mapped[int] = mapped_column(BigInteger, nullable=False, server_default=FetchedValue())
    acquired_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, server_default=FetchedValue())
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    heartbeat_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    trigger_type: Mapped[str] = mapped_column(String(32), nullable=False)

    __table_args__ = (
        CheckConstraint(
            "trigger_type IN ('scheduled','manual','probe','cursor_recovery')",
            name="ck_fsl_trigger_type",
        ),
        CheckConstraint("expires_at > acquired_at", name="ck_fsl_expiry_after_acquired"),
    )


class FederationWorkerHeartbeat(Base):
    """Cross-container worker freshness signal via PostgreSQL.

    The API reads MAX(last_heartbeat_at) per worker_type to determine
    worker freshness for readiness reporting. No raw exception text is
    stored; last_error_class holds only a bounded error class string.
    """

    __tablename__ = "federation_worker_heartbeats"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, server_default=FetchedValue())
    worker_type: Mapped[str] = mapped_column(String(32), nullable=False)
    instance_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), nullable=False)
    hostname: Mapped[str | None] = mapped_column(String(256))
    started_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, server_default=FetchedValue())
    last_heartbeat_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, server_default=FetchedValue())
    last_success_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    status: Mapped[str] = mapped_column(String(32), nullable=False, server_default="running")
    last_error_class: Mapped[str | None] = mapped_column(String(64))
    lease_expires_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, server_default=FetchedValue())

    __table_args__ = (
        UniqueConstraint("worker_type", "instance_id", name="uq_fwh_worker_instance"),
        CheckConstraint("worker_type IN ('sync','rdf','probe')", name="ck_fwh_worker_type"),
        CheckConstraint("status IN ('running','idle','error','stopped')", name="ck_fwh_status"),
        CheckConstraint("hostname IS NULL OR char_length(hostname) <= 256", name="ck_fwh_hostname_len"),
        CheckConstraint("last_error_class IS NULL OR char_length(last_error_class) <= 64", name="ck_fwh_error_class_len"),
    )


class FederationPeerHealthSnapshot(Base):
    """Per-probe peer health snapshot.

    peer_id is nullable (ON DELETE SET NULL): snapshots are retained as
    historical evidence even after a peer is archived and its row is
    eventually cleared. peer_node_id provides immutable historical identity.
    No raw exception messages or remote response bodies are stored;
    error_detail is bounded to 1024 chars.
    """

    __tablename__ = "federation_peer_health_snapshots"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, server_default=FetchedValue())
    peer_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("federation_trusted_peers.id", ondelete="SET NULL", name="fk_fphs_peer_id"),
    )
    peer_node_id: Mapped[str] = mapped_column(Text, nullable=False)
    sampled_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, server_default=FetchedValue())
    discovery_reachable: Mapped[bool | None] = mapped_column(Boolean)
    jwks_reachable: Mapped[bool | None] = mapped_column(Boolean)
    feed_reachable: Mapped[bool | None] = mapped_column(Boolean)
    last_event_position: Mapped[int | None] = mapped_column(BigInteger)
    round_trip_ms: Mapped[int | None] = mapped_column(Integer)
    health_status: Mapped[str | None] = mapped_column(String(32))
    compatibility_status: Mapped[str | None] = mapped_column(String(32))
    error_code: Mapped[str | None] = mapped_column(String(64))
    error_detail: Mapped[str | None] = mapped_column(Text)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, server_default=FetchedValue())

    __table_args__ = (
        CheckConstraint(
            "health_status IS NULL OR health_status IN ('healthy','degraded','unreachable','unknown')",
            name="ck_fphs_health_status",
        ),
        CheckConstraint(
            "compatibility_status IS NULL OR compatibility_status IN ('compatible','incompatible','unknown','unchecked')",
            name="ck_fphs_compat_status",
        ),
        CheckConstraint("round_trip_ms IS NULL OR round_trip_ms >= 0", name="ck_fphs_round_trip_nonneg"),
        CheckConstraint("error_code IS NULL OR char_length(error_code) <= 64", name="ck_fphs_error_code_len"),
        CheckConstraint("error_detail IS NULL OR char_length(error_detail) <= 1024", name="ck_fphs_error_detail_len"),
        CheckConstraint("char_length(peer_node_id) <= 256", name="ck_fphs_peer_node_id_len"),
    )
