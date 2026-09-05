from __future__ import annotations

import uuid
from datetime import datetime, timezone

from sqlalchemy import CheckConstraint, DateTime, ForeignKey, Index, String, Text, UniqueConstraint, text
from sqlalchemy.dialects.postgresql import JSONB, UUID
from sqlalchemy.orm import Mapped, mapped_column

from src.license_facade_service.db.base import Base

_ALLOWED_SOURCE_KINDS = ("spdx", "custom", "federation-authoritative", "federation-imported")
_ALLOWED_CLASSIFICATIONS = ("new", "historical")
_ALLOWED_POLICY_MODES = ("disabled", "dry-run", "active")
_ALLOWED_ACTIONS = ("none", "full-replacement", "historical-mapping")
_ALLOWED_STATUSES = ("planned", "pending-review", "approved", "applied", "rejected", "rolled-back", "failed")
_ALLOWED_EVENT_TYPES = ("planned", "review-approved", "review-rejected", "applied", "failed", "rolled-back")
_ALLOWED_ACTOR_TYPES = ("system", "admin", "curator", "worker")


class OpenRelPolicyState(Base):
    __tablename__ = "openrel_policy_states"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    canonical_license_id: Mapped[str] = mapped_column(String(512), nullable=False)
    source_kind: Mapped[str] = mapped_column(String(32), nullable=False)
    source_record_ref: Mapped[str | None] = mapped_column(String(512), nullable=True)
    classification: Mapped[str] = mapped_column(String(16), nullable=False)
    policy_mode: Mapped[str] = mapped_column(String(16), nullable=False)
    policy_version: Mapped[str] = mapped_column(String(32), nullable=False)
    effective_date: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    action: Mapped[str] = mapped_column(String(32), nullable=False)
    status: Mapped[str] = mapped_column(String(32), nullable=False)
    provider_url: Mapped[str] = mapped_column(String(2048), nullable=False)
    active_profile: Mapped[str | None] = mapped_column(String(1024), nullable=True)
    active_vocabulary: Mapped[str | None] = mapped_column(String(1024), nullable=True)
    original_profile: Mapped[str | None] = mapped_column(String(1024), nullable=True)
    mapping_profile: Mapped[str | None] = mapped_column(String(1024), nullable=True)
    mapping_provenance: Mapped[str | None] = mapped_column(Text, nullable=True)
    candidate_digest_sha256: Mapped[str] = mapped_column(String(64), nullable=False)
    original_content_digest_sha256: Mapped[str | None] = mapped_column(String(64), nullable=True)
    candidate_payload: Mapped[dict] = mapped_column(JSONB, nullable=False)
    original_representation: Mapped[dict | None] = mapped_column(JSONB, nullable=True)
    target_custom_licence_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True), ForeignKey("custom_licences.id", ondelete="RESTRICT"), nullable=True
    )
    target_snapshot_before: Mapped[dict | None] = mapped_column(JSONB, nullable=True)
    target_digest_before: Mapped[str | None] = mapped_column(String(64), nullable=True)
    target_snapshot_after: Mapped[dict | None] = mapped_column(JSONB, nullable=True)
    target_digest_after: Mapped[str | None] = mapped_column(String(64), nullable=True)
    apply_allowed: Mapped[bool] = mapped_column(nullable=False, default=False)
    review_required: Mapped[bool] = mapped_column(nullable=False, default=False)
    reason: Mapped[str] = mapped_column(Text, nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=text("now()"), default=lambda: datetime.now(timezone.utc)
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=text("now()"), default=lambda: datetime.now(timezone.utc)
    )
    reviewed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    reviewed_by: Mapped[str | None] = mapped_column(String(256), nullable=True)
    applied_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    applied_by: Mapped[str | None] = mapped_column(String(256), nullable=True)
    rolled_back_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    rolled_back_by: Mapped[str | None] = mapped_column(String(256), nullable=True)
    error_code: Mapped[str | None] = mapped_column(String(128), nullable=True)
    error_detail: Mapped[str | None] = mapped_column(Text, nullable=True)

    __table_args__ = (
        UniqueConstraint(
            "canonical_license_id",
            "policy_version",
            "candidate_digest_sha256",
            "action",
            name="uq_openrel_policy_states_license_policy_candidate_action",
        ),
        CheckConstraint(
            "source_kind IN ('spdx', 'custom', 'federation-authoritative', 'federation-imported')",
            name="ck_openrel_policy_states_source_kind",
        ),
        CheckConstraint(
            "classification IN ('new', 'historical')",
            name="ck_openrel_policy_states_classification",
        ),
        CheckConstraint(
            "policy_mode IN ('disabled', 'dry-run', 'active')",
            name="ck_openrel_policy_states_policy_mode",
        ),
        CheckConstraint(
            "action IN ('none', 'full-replacement', 'historical-mapping')",
            name="ck_openrel_policy_states_action",
        ),
        CheckConstraint(
            "status IN ('planned', 'pending-review', 'approved', 'applied', 'rejected', 'rolled-back', 'failed')",
            name="ck_openrel_policy_states_status",
        ),
        CheckConstraint(
            "char_length(btrim(canonical_license_id)) > 0",
            name="ck_openrel_policy_states_canonical_license_id_nonblank",
        ),
        CheckConstraint(
            "char_length(btrim(provider_url)) > 0",
            name="ck_openrel_policy_states_provider_url_nonblank",
        ),
        CheckConstraint(
            "candidate_digest_sha256 ~ '^[0-9a-f]{64}$'",
            name="ck_openrel_policy_states_candidate_digest_format",
        ),
        CheckConstraint(
            "original_content_digest_sha256 IS NULL OR original_content_digest_sha256 ~ '^[0-9a-f]{64}$'",
            name="ck_openrel_policy_states_original_content_digest_format",
        ),
        CheckConstraint(
            "target_digest_before IS NULL OR target_digest_before ~ '^[0-9a-f]{64}$'",
            name="ck_orps_target_digest_before_fmt",
        ),
        CheckConstraint(
            "target_digest_after IS NULL OR target_digest_after ~ '^[0-9a-f]{64}$'",
            name="ck_orps_target_digest_after_fmt",
        ),
        CheckConstraint(
            "(source_kind <> 'federation-imported') OR (apply_allowed = false AND review_required = true AND action = 'none' AND status NOT IN ('approved', 'applied', 'rolled-back'))",
            name="ck_openrel_policy_states_imported_record_safety",
        ),
        CheckConstraint(
            "(action <> 'historical-mapping') OR (classification = 'historical' AND review_required = true AND original_profile IS NOT NULL AND char_length(btrim(original_profile)) > 0 AND mapping_profile IS NOT NULL AND char_length(btrim(mapping_profile)) > 0 AND mapping_provenance IS NOT NULL AND char_length(btrim(mapping_provenance)) > 0)",
            name="ck_openrel_policy_states_historical_mapping_requires_fields",
        ),
        CheckConstraint(
            "(action <> 'full-replacement') OR (classification = 'new' AND source_kind <> 'federation-imported' AND candidate_payload IS NOT NULL)",
            name="ck_openrel_policy_states_full_replacement_requires_new",
        ),
        CheckConstraint(
            "(status <> 'applied') OR (applied_at IS NOT NULL AND applied_by IS NOT NULL AND target_custom_licence_id IS NOT NULL AND target_snapshot_before IS NOT NULL AND target_digest_before IS NOT NULL AND target_snapshot_after IS NOT NULL AND target_digest_after IS NOT NULL AND action <> 'none' AND apply_allowed = true AND policy_mode = 'active' AND source_kind <> 'federation-imported')",
            name="ck_orps_applied_fields",
        ),
        CheckConstraint(
            "(status <> 'rolled-back') OR (rolled_back_at IS NOT NULL AND rolled_back_by IS NOT NULL AND applied_at IS NOT NULL AND applied_by IS NOT NULL AND target_custom_licence_id IS NOT NULL AND target_snapshot_before IS NOT NULL AND target_digest_before IS NOT NULL AND target_snapshot_after IS NOT NULL AND target_digest_after IS NOT NULL AND original_representation IS NOT NULL)",
            name="ck_orps_rollback_fields",
        ),
        CheckConstraint(
            "(status IN ('applied','rolled-back')) OR (rolled_back_at IS NULL AND rolled_back_by IS NULL)",
            name="ck_orps_pre_rb_null",
        ),
        CheckConstraint(
            "(status NOT IN ('approved', 'rejected')) OR (reviewed_at IS NOT NULL AND reviewed_by IS NOT NULL AND char_length(btrim(reviewed_by)) > 0)",
            name="ck_openrel_policy_states_review_requires_actor",
        ),
        CheckConstraint(
            "(policy_mode <> 'dry-run') OR (apply_allowed = false AND status = 'planned')",
            name="ck_openrel_policy_states_dry_run_requires_planned",
        ),
        CheckConstraint(
            "char_length(btrim(reason)) > 0",
            name="ck_openrel_policy_states_reason_nonblank",
        ),
        CheckConstraint(
            "char_length(btrim(policy_version)) > 0",
            name="ck_openrel_policy_states_policy_version_nonblank",
        ),
        Index("ix_openrel_policy_states_canonical_license_id", "canonical_license_id"),
        Index("ix_openrel_policy_states_status", "status"),
        Index("ix_openrel_policy_states_policy_version", "policy_version"),
        Index("ix_openrel_policy_states_created_at", "created_at"),
        Index("ix_openrel_policy_states_target_custom_licence_id", "target_custom_licence_id"),
    )


class OpenRelPolicyEvent(Base):
    __tablename__ = "openrel_policy_events"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    policy_state_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("openrel_policy_states.id", ondelete="RESTRICT"), nullable=False
    )
    event_type: Mapped[str] = mapped_column(String(32), nullable=False)
    actor_type: Mapped[str] = mapped_column(String(16), nullable=False)
    actor_id: Mapped[str | None] = mapped_column(String(256), nullable=True)
    before_status: Mapped[str | None] = mapped_column(String(32), nullable=True)
    after_status: Mapped[str | None] = mapped_column(String(32), nullable=True)
    details: Mapped[dict] = mapped_column(JSONB, nullable=False)
    occurred_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, server_default=text("now()"))
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=text("now()"), default=lambda: datetime.now(timezone.utc)
    )

    __table_args__ = (
        CheckConstraint(
            "event_type IN ('planned', 'review-approved', 'review-rejected', 'applied', 'failed', 'rolled-back')",
            name="ck_openrel_policy_events_event_type",
        ),
        CheckConstraint(
            "actor_type IN ('system', 'admin', 'curator', 'worker')",
            name="ck_openrel_policy_events_actor_type",
        ),
        CheckConstraint(
            "char_length(btrim(event_type)) > 0",
            name="ck_openrel_policy_events_event_type_nonblank",
        ),
        Index("ix_openrel_policy_events_policy_state_id", "policy_state_id"),
        Index("ix_openrel_policy_events_occurred_at", "occurred_at"),
        Index("ix_openrel_policy_events_event_type", "event_type"),
    )


__all__ = ["OpenRelPolicyState", "OpenRelPolicyEvent"]
