from __future__ import annotations

import uuid
from datetime import datetime

from sqlalchemy import Boolean, CheckConstraint, DateTime, ForeignKey, Index, Integer, String, Text, UniqueConstraint
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
    event_sequence: Mapped[int] = mapped_column(Integer, nullable=False, unique=True)
    event_type: Mapped[str] = mapped_column(String(64), nullable=False)
    authority_node_id: Mapped[str] = mapped_column(String(128), nullable=False)
    record_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True), ForeignKey("federation_records.id", ondelete="SET NULL")
    )
    event_payload: Mapped[dict] = mapped_column(JSONB, nullable=False, default=dict)
    event_digest_sha256: Mapped[str] = mapped_column(String(128), nullable=False)
    occurred_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)


class FederationPeerCursor(Base):
    __tablename__ = "federation_peer_cursors"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    peer_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("federation_trusted_peers.id", ondelete="CASCADE"), nullable=False, unique=True
    )
    cursor: Mapped[str | None] = mapped_column(String(512))
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


Index("ix_federation_records_authority", FederationRecord.authority_node_id)
Index("ix_federation_records_canonical_id", FederationRecord.canonical_id)
Index("ix_federation_record_aliases_record_id", FederationRecordAlias.record_id)
Index("ix_federation_representations_record_id", FederationRecordRepresentation.record_id)
Index("ix_federation_provenance_record_id", FederationRecordProvenance.record_id)
Index("ix_federation_change_events_occurred_at", FederationChangeEvent.occurred_at)
Index("ix_federation_sync_attempts_peer_started", FederationSyncAttempt.peer_id, FederationSyncAttempt.started_at)
