from __future__ import annotations

import re
import unicodedata
import uuid
from datetime import datetime, timezone

from sqlalchemy import CheckConstraint, DateTime, ForeignKey, Index, Integer, String, Text, UniqueConstraint, text
from sqlalchemy.dialects.postgresql import JSONB, UUID
from sqlalchemy.orm import Mapped, mapped_column

from src.license_facade_service.db.base import Base

_ALLOWED_PUBLIC_SCOPES = ("local", "federated", "spdx-submission")
_ALLOWED_FEDERATION_STATUSES = ("not_published", "pending", "published", "publication_failed", "deprecated", "tombstoned")
_ALLOWED_SPDX_SUBMISSION_STATUSES = ("not_requested", "ready_for_review")
_ALLOWED_LIFECYCLE_STATUSES = ("registered", "deprecated", "withdrawn", "tombstoned")
_ALLOWED_ALIAS_TYPES = ("requested_id", "canonical_id", "resolving_uuid", "resolving_uri", "legacy")
_ALLOWED_CUSTOM_LICENCE_OUTBOX_OPERATIONS = ("upsert",)
_ALLOWED_CUSTOM_LICENCE_OUTBOX_STATUSES = (
    "pending",
    "processing",
    "published",
    "retryable_failed",
    "permanently_failed",
)


def normalize_alias(value: str) -> str:
    if not isinstance(value, str):
        raise TypeError("alias must be a string")
    normalized = unicodedata.normalize("NFKC", value)
    normalized = re.sub(r"\s+", " ", normalized.strip())
    normalized = normalized.casefold()
    if not normalized:
        raise ValueError("alias is empty after normalization")
    if "\x00" in normalized or any(ord(ch) < 32 or ord(ch) == 127 for ch in normalized):
        raise ValueError("alias contains control characters")
    if len(normalized) > 512:
        raise ValueError("alias exceeds maximum length")
    return normalized


class CustomLicence(Base):
    __tablename__ = "custom_licences"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    authority_id: Mapped[str] = mapped_column(String(128), nullable=False)
    requested_license_id: Mapped[str] = mapped_column(String(256), nullable=False)
    version: Mapped[str] = mapped_column(String(128), nullable=False)
    canonical_id: Mapped[str] = mapped_column(String(512), nullable=False)
    resolving_uuid: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), nullable=False)
    public_scope: Mapped[str] = mapped_column(String(32), nullable=False)
    federation_status: Mapped[str] = mapped_column(String(32), nullable=False, default="not_published")
    spdx_submission_status: Mapped[str] = mapped_column(String(32), nullable=False, default="not_requested")
    lifecycle_status: Mapped[str] = mapped_column(String(32), nullable=False, default="registered")
    name: Mapped[str] = mapped_column(String(512), nullable=False)
    summary: Mapped[str | None] = mapped_column(Text)
    description: Mapped[str | None] = mapped_column(Text)
    license_text: Mapped[str] = mapped_column(Text, nullable=False)
    normalized_text_digest: Mapped[str] = mapped_column(String(128), nullable=False)
    spdx_jsonld: Mapped[dict] = mapped_column(JSONB, nullable=False)
    creator_role: Mapped[str] = mapped_column(String(64), nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, server_default=text("now()"), default=lambda: datetime.now(timezone.utc))
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, server_default=text("now()"), default=lambda: datetime.now(timezone.utc))
    deprecated_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    withdrawn_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    tombstoned_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))

    __table_args__ = (
        UniqueConstraint("authority_id", "requested_license_id", "version", name="uq_custom_licences_authority_requested_version"),
        UniqueConstraint("canonical_id", name="uq_custom_licences_canonical_id"),
        UniqueConstraint("resolving_uuid", name="uq_custom_licences_resolving_uuid"),
        CheckConstraint("char_length(btrim(authority_id)) > 0", name="ck_custom_licences_authority_id_nonblank"),
        CheckConstraint("char_length(btrim(requested_license_id)) > 0", name="ck_custom_licences_requested_license_id_nonblank"),
        CheckConstraint("char_length(btrim(version)) > 0", name="ck_custom_licences_version_nonblank"),
        CheckConstraint("char_length(btrim(canonical_id)) > 0", name="ck_custom_licences_canonical_id_nonblank"),
        CheckConstraint("char_length(btrim(name)) > 0", name="ck_custom_licences_name_nonblank"),
        CheckConstraint("char_length(btrim(license_text)) > 0", name="ck_custom_licences_license_text_nonblank"),
        CheckConstraint("char_length(btrim(normalized_text_digest)) = 64", name="ck_custom_licences_digest_length"),
        CheckConstraint("normalized_text_digest ~ '^[0-9a-f]{64}$'", name="ck_custom_licences_digest_format"),
        CheckConstraint("public_scope IN ('local', 'federated', 'spdx-submission')", name="ck_custom_licences_public_scope"),
        CheckConstraint("federation_status IN ('not_published', 'pending', 'published', 'publication_failed', 'deprecated', 'tombstoned')", name="ck_custom_licences_federation_status"),
        CheckConstraint("spdx_submission_status IN ('not_requested', 'ready_for_review')", name="ck_custom_licences_spdx_submission_status"),
        CheckConstraint("lifecycle_status IN ('registered', 'deprecated', 'withdrawn', 'tombstoned')", name="ck_custom_licences_lifecycle_status"),
        CheckConstraint("char_length(btrim(creator_role)) > 0 AND creator_role = btrim(creator_role)", name="ck_custom_licences_creator_role_nonblank_trimmed"),
        Index("ix_custom_licences_authority_requested", "authority_id", "requested_license_id"),
        Index("ix_custom_licences_scope_status", "public_scope", "federation_status", "spdx_submission_status"),
        Index("ix_custom_licences_lifecycle_status", "lifecycle_status"),
    )


class CustomLicenceAlias(Base):
    __tablename__ = "custom_licence_aliases"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    custom_licence_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("custom_licences.id", ondelete="RESTRICT"), nullable=False
    )
    alias_type: Mapped[str] = mapped_column(String(32), nullable=False)
    alias: Mapped[str] = mapped_column(String(512), nullable=False)
    normalized_alias: Mapped[str] = mapped_column(String(512), nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, server_default=text("now()"), default=lambda: datetime.now(timezone.utc))

    __table_args__ = (
        UniqueConstraint("normalized_alias", name="uq_custom_licence_aliases_normalized_alias"),
        CheckConstraint("alias_type IN ('requested_id', 'canonical_id', 'resolving_uuid', 'resolving_uri', 'legacy')", name="ck_custom_licence_aliases_type"),
        CheckConstraint("char_length(btrim(alias)) > 0", name="ck_custom_licence_aliases_alias_nonblank"),
        CheckConstraint("char_length(btrim(normalized_alias)) > 0", name="ck_custom_licence_aliases_normalized_alias_nonblank"),
        Index("ix_custom_licence_aliases_custom_licence_type", "custom_licence_id", "alias_type"),
    )


class CustomLicenceAuditEvent(Base):
    __tablename__ = "custom_licence_audit_events"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    custom_licence_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("custom_licences.id", ondelete="RESTRICT"), nullable=False
    )
    event_type: Mapped[str] = mapped_column(String(64), nullable=False)
    actor_role: Mapped[str] = mapped_column(String(64), nullable=False)
    actor_identifier: Mapped[str | None] = mapped_column(Text, nullable=True)
    before_state: Mapped[dict | None] = mapped_column(JSONB, nullable=True)
    after_state: Mapped[dict | None] = mapped_column(JSONB, nullable=True)
    source: Mapped[str | None] = mapped_column(String(128), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, server_default=text("now()"), default=lambda: datetime.now(timezone.utc))

    __table_args__ = (
        CheckConstraint("char_length(btrim(event_type)) > 0", name="ck_custom_licence_audit_event_type_nonblank"),
        CheckConstraint("char_length(btrim(actor_role)) > 0", name="ck_custom_licence_audit_actor_role_nonblank"),
        Index("ix_custom_licence_audit_events_licence_created", "custom_licence_id", "created_at"),
    )


class CustomLicenceFederationOutbox(Base):
    __tablename__ = "custom_licence_federation_outbox"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    custom_licence_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("custom_licences.id", ondelete="RESTRICT"), nullable=False
    )
    operation: Mapped[str] = mapped_column(String(32), nullable=False, default="upsert")
    status: Mapped[str] = mapped_column(String(32), nullable=False, default="pending")
    attempt_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    available_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=text("now()")
    )
    lease_owner: Mapped[str | None] = mapped_column(String(128))
    lease_expires_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    last_error_class: Mapped[str | None] = mapped_column(String(128))
    last_error_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    federation_record_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True), ForeignKey("federation_records.id", ondelete="RESTRICT")
    )
    federation_event_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True), ForeignKey("federation_change_events.id", ondelete="RESTRICT")
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=text("now()")
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=text("now()")
    )
    published_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))

    __table_args__ = (
        UniqueConstraint("custom_licence_id", "operation", name="uq_custom_licence_federation_outbox_licence_operation"),
        CheckConstraint(
            "operation IN ('upsert')",
            name="ck_custom_licence_federation_outbox_operation",
        ),
        CheckConstraint(
            "status IN ('pending','processing','published','retryable_failed','permanently_failed')",
            name="ck_custom_licence_federation_outbox_status",
        ),
        CheckConstraint("attempt_count >= 0", name="ck_custom_licence_federation_outbox_attempt_count_nonneg"),
        CheckConstraint(
            "(status = 'processing') = (lease_owner IS NOT NULL)",
            name="ck_custom_licence_federation_outbox_processing_requires_owner",
        ),
        CheckConstraint(
            "(lease_owner IS NULL) = (lease_expires_at IS NULL)",
            name="ck_custom_licence_federation_outbox_lease_fields_consistent",
        ),
        CheckConstraint(
            "status != 'published' OR (federation_record_id IS NOT NULL AND federation_event_id IS NOT NULL AND published_at IS NOT NULL)",
            name="ck_custom_licence_federation_outbox_published_requires_linkage",
        ),
        CheckConstraint(
            "(published_at IS NULL) OR (status = 'published')",
            name="ck_custom_licence_federation_outbox_published_at_iff_published",
        ),
        CheckConstraint(
            "(last_error_class IS NULL) = (last_error_at IS NULL)",
            name="ck_custom_licence_federation_outbox_error_fields_consistent",
        ),
        Index(
            "ix_custom_licence_federation_outbox_status_available_at",
            "status",
            "available_at",
        ),
        Index(
            "ix_custom_licence_federation_outbox_status_lease_expires_at",
            "status",
            "lease_expires_at",
        ),
        Index(
            "ix_custom_licence_federation_outbox_custom_licence_id",
            "custom_licence_id",
        ),
        Index(
            "uix_custom_licence_federation_outbox_federation_record_id",
            "federation_record_id",
            unique=True,
            postgresql_where=text("federation_record_id IS NOT NULL"),
        ),
        Index(
            "uix_custom_licence_federation_outbox_federation_event_id",
            "federation_event_id",
            unique=True,
            postgresql_where=text("federation_event_id IS NOT NULL"),
        ),
    )


__all__ = [
    "CustomLicence",
    "CustomLicenceAlias",
    "CustomLicenceAuditEvent",
    "CustomLicenceFederationOutbox",
    "normalize_alias",
]
