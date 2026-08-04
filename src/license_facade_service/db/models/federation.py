from __future__ import annotations

import uuid
from datetime import datetime

from sqlalchemy import BigInteger, Boolean, CheckConstraint, DateTime, ForeignKey, Index, Integer, String, Text, UniqueConstraint
from sqlalchemy.dialects.postgresql import JSONB, UUID
from sqlalchemy.orm import Mapped, mapped_column

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
    status: Mapped[str] = mapped_column(String(32), nullable=False, default="active")
    valid_from: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    valid_until: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)

    __table_args__ = (
        CheckConstraint("alg = 'EdDSA'", name="ck_federation_signing_keys_alg"),
        CheckConstraint("kty = 'OKP'", name="ck_federation_signing_keys_kty"),
        CheckConstraint("crv = 'Ed25519'", name="ck_federation_signing_keys_crv"),
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


Index("ix_federation_records_authority", FederationRecord.authority_node_id)
Index("ix_federation_records_canonical_id", FederationRecord.canonical_id)
Index("ix_federation_records_imported_peer", FederationRecord.imported_from_peer_id)
Index("ix_federation_record_aliases_record_id", FederationRecordAlias.record_id)
Index("ix_federation_representations_record_id", FederationRecordRepresentation.record_id)
Index("ix_federation_provenance_record_id", FederationRecordProvenance.record_id)
Index("ix_federation_change_events_occurred_at", FederationChangeEvent.occurred_at)
Index("ix_federation_sync_attempts_peer_started", FederationSyncAttempt.peer_id, FederationSyncAttempt.started_at)
Index("ix_federation_inbound_events_peer_position", FederationInboundEvent.source_peer_id, FederationInboundEvent.remote_event_position)
