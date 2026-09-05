"""Add OpenREL policy state and append-only audit tables.

Revision ID: 20260904_01
Revises: 20260828_01
Create Date: 2026-09-04
"""

from __future__ import annotations

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "20260904_01"
down_revision: Union[str, Sequence[str], None] = "20260828_01"
branch_labels = None
depends_on = None


_CREATE_POLICY_STATE_IMMUTABLE_FN = """\
CREATE OR REPLACE FUNCTION lfs_reject_openrel_policy_state_immutable_update()
RETURNS trigger AS $$
BEGIN
    IF (
        NEW.canonical_license_id IS DISTINCT FROM OLD.canonical_license_id OR
        NEW.source_kind IS DISTINCT FROM OLD.source_kind OR
        NEW.source_record_ref IS DISTINCT FROM OLD.source_record_ref OR
        NEW.policy_version IS DISTINCT FROM OLD.policy_version OR
        NEW.effective_date IS DISTINCT FROM OLD.effective_date OR
        NEW.candidate_digest_sha256 IS DISTINCT FROM OLD.candidate_digest_sha256 OR
        NEW.original_content_digest_sha256 IS DISTINCT FROM OLD.original_content_digest_sha256 OR
        NEW.original_profile IS DISTINCT FROM OLD.original_profile OR
        NEW.original_representation IS DISTINCT FROM OLD.original_representation OR
        NEW.created_at IS DISTINCT FROM OLD.created_at
    ) THEN
        RAISE EXCEPTION 'openrel_policy_states immutable fields cannot be updated';
    END IF;
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;
"""

_CREATE_POLICY_STATE_IMMUTABLE_TRIGGER = """\
CREATE TRIGGER trg_openrel_policy_states_no_immutable_update
    BEFORE UPDATE ON openrel_policy_states
    FOR EACH ROW EXECUTE FUNCTION lfs_reject_openrel_policy_state_immutable_update();
"""

_CREATE_EVENT_MUTATION_REJECT_FN = """\
CREATE OR REPLACE FUNCTION lfs_reject_openrel_policy_event_mutation()
RETURNS trigger AS $$
BEGIN
    RAISE EXCEPTION
        'openrel_policy_events is append-only: % is not permitted',
        TG_OP;
END;
$$ LANGUAGE plpgsql;
"""

_CREATE_EVENT_NO_UPDATE_TRIGGER = """\
CREATE TRIGGER trg_openrel_policy_events_no_update
    BEFORE UPDATE ON openrel_policy_events
    FOR EACH ROW EXECUTE FUNCTION lfs_reject_openrel_policy_event_mutation();
"""

_CREATE_EVENT_NO_DELETE_TRIGGER = """\
CREATE TRIGGER trg_openrel_policy_events_no_delete
    BEFORE DELETE ON openrel_policy_events
    FOR EACH ROW EXECUTE FUNCTION lfs_reject_openrel_policy_event_mutation();
"""

_DROP_STATE_IMMUTABLE_TRIGGER = "DROP TRIGGER IF EXISTS trg_openrel_policy_states_no_immutable_update ON openrel_policy_states;"
_DROP_STATE_IMMUTABLE_FN = "DROP FUNCTION IF EXISTS lfs_reject_openrel_policy_state_immutable_update();"

_DROP_EVENT_MUTATION_TRIGGERS = """\
DROP TRIGGER IF EXISTS trg_openrel_policy_events_no_update ON openrel_policy_events;
DROP TRIGGER IF EXISTS trg_openrel_policy_events_no_delete ON openrel_policy_events;
"""
_DROP_EVENT_MUTATION_FN = "DROP FUNCTION IF EXISTS lfs_reject_openrel_policy_event_mutation();"


def upgrade() -> None:
    op.create_table(
        "openrel_policy_states",
        sa.Column("id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("canonical_license_id", sa.String(length=512), nullable=False),
        sa.Column("source_kind", sa.String(length=32), nullable=False),
        sa.Column("source_record_ref", sa.String(length=512), nullable=True),
        sa.Column("classification", sa.String(length=16), nullable=False),
        sa.Column("policy_mode", sa.String(length=16), nullable=False),
        sa.Column("policy_version", sa.String(length=32), nullable=False),
        sa.Column("effective_date", sa.Date(), nullable=False),
        sa.Column("action", sa.String(length=32), nullable=False),
        sa.Column("status", sa.String(length=32), nullable=False),
        sa.Column("provider_url", sa.String(length=2048), nullable=False),
        sa.Column("active_profile", sa.String(length=1024), nullable=True),
        sa.Column("active_vocabulary", sa.String(length=1024), nullable=True),
        sa.Column("original_profile", sa.String(length=1024), nullable=True),
        sa.Column("mapping_profile", sa.String(length=1024), nullable=True),
        sa.Column("mapping_provenance", sa.Text(), nullable=True),
        sa.Column("candidate_digest_sha256", sa.String(length=64), nullable=False),
        sa.Column("original_content_digest_sha256", sa.String(length=64), nullable=True),
        sa.Column("candidate_payload", postgresql.JSONB(astext_type=sa.Text()), nullable=False),
        sa.Column("original_representation", postgresql.JSONB(astext_type=sa.Text()), nullable=True),
        sa.Column("apply_allowed", sa.Boolean(), nullable=False),
        sa.Column("review_required", sa.Boolean(), nullable=False),
        sa.Column("reason", sa.Text(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.text("now()"), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.text("now()"), nullable=False),
        sa.Column("reviewed_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("reviewed_by", sa.String(length=256), nullable=True),
        sa.Column("applied_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("rolled_back_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("error_code", sa.String(length=128), nullable=True),
        sa.Column("error_detail", sa.Text(), nullable=True),
        sa.CheckConstraint(
            "source_kind IN ('spdx', 'custom', 'federation-authoritative', 'federation-imported')",
            name="ck_openrel_policy_states_source_kind",
        ),
        sa.CheckConstraint(
            "classification IN ('new', 'historical')",
            name="ck_openrel_policy_states_classification",
        ),
        sa.CheckConstraint(
            "policy_mode IN ('disabled', 'dry-run', 'active')",
            name="ck_openrel_policy_states_policy_mode",
        ),
        sa.CheckConstraint(
            "action IN ('none', 'full-replacement', 'historical-mapping')",
            name="ck_openrel_policy_states_action",
        ),
        sa.CheckConstraint(
            "status IN ('planned', 'pending-review', 'approved', 'applied', 'rejected', 'rolled-back', 'failed')",
            name="ck_openrel_policy_states_status",
        ),
        sa.CheckConstraint(
            "char_length(btrim(canonical_license_id)) > 0",
            name="ck_openrel_policy_states_canonical_license_id_nonblank",
        ),
        sa.CheckConstraint(
            "char_length(btrim(provider_url)) > 0",
            name="ck_openrel_policy_states_provider_url_nonblank",
        ),
        sa.CheckConstraint(
            "candidate_digest_sha256 ~ '^[0-9a-f]{64}$'",
            name="ck_openrel_policy_states_candidate_digest_format",
        ),
        sa.CheckConstraint(
            "original_content_digest_sha256 IS NULL OR original_content_digest_sha256 ~ '^[0-9a-f]{64}$'",
            name="ck_openrel_policy_states_original_content_digest_format",
        ),
        sa.CheckConstraint(
            "(source_kind <> 'federation-imported') OR (apply_allowed = false AND review_required = true AND action = 'none' AND status NOT IN ('approved', 'applied', 'rolled-back'))",
            name="ck_openrel_policy_states_imported_record_safety",
        ),
        sa.CheckConstraint(
            "(action <> 'historical-mapping') OR (classification = 'historical' AND review_required = true AND original_profile IS NOT NULL AND char_length(btrim(original_profile)) > 0 AND mapping_profile IS NOT NULL AND char_length(btrim(mapping_profile)) > 0 AND mapping_provenance IS NOT NULL AND char_length(btrim(mapping_provenance)) > 0)",
            name="ck_openrel_policy_states_historical_mapping_requires_fields",
        ),
        sa.CheckConstraint(
            "(action <> 'full-replacement') OR (classification = 'new' AND source_kind <> 'federation-imported' AND candidate_payload IS NOT NULL)",
            name="ck_openrel_policy_states_full_replacement_requires_new",
        ),
        sa.CheckConstraint(
            "(status <> 'applied') OR (applied_at IS NOT NULL AND action <> 'none' AND apply_allowed = true AND policy_mode = 'active' AND source_kind <> 'federation-imported')",
            name="ck_openrel_policy_states_applied_requires_timestamps",
        ),
        sa.CheckConstraint(
            "(status <> 'rolled-back') OR (rolled_back_at IS NOT NULL AND original_representation IS NOT NULL)",
            name="ck_openrel_policy_states_rollback_requires_original",
        ),
        sa.CheckConstraint(
            "(status NOT IN ('approved', 'rejected')) OR (reviewed_at IS NOT NULL AND reviewed_by IS NOT NULL AND char_length(btrim(reviewed_by)) > 0)",
            name="ck_openrel_policy_states_review_requires_actor",
        ),
        sa.CheckConstraint(
            "(policy_mode <> 'dry-run') OR (apply_allowed = false AND status = 'planned')",
            name="ck_openrel_policy_states_dry_run_requires_planned",
        ),
        sa.CheckConstraint(
            "char_length(btrim(reason)) > 0",
            name="ck_openrel_policy_states_reason_nonblank",
        ),
        sa.CheckConstraint(
            "char_length(btrim(policy_version)) > 0",
            name="ck_openrel_policy_states_policy_version_nonblank",
        ),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint(
            "canonical_license_id",
            "policy_version",
            "candidate_digest_sha256",
            "action",
            name="uq_openrel_policy_states_license_policy_candidate_action",
        ),
    )
    op.create_index("ix_openrel_policy_states_canonical_license_id", "openrel_policy_states", ["canonical_license_id"], unique=False)
    op.create_index("ix_openrel_policy_states_status", "openrel_policy_states", ["status"], unique=False)
    op.create_index("ix_openrel_policy_states_policy_version", "openrel_policy_states", ["policy_version"], unique=False)
    op.create_index("ix_openrel_policy_states_created_at", "openrel_policy_states", ["created_at"], unique=False)

    op.execute(_CREATE_POLICY_STATE_IMMUTABLE_FN)
    op.execute(_CREATE_POLICY_STATE_IMMUTABLE_TRIGGER)

    op.create_table(
        "openrel_policy_events",
        sa.Column("id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("policy_state_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("event_type", sa.String(length=32), nullable=False),
        sa.Column("actor_type", sa.String(length=16), nullable=False),
        sa.Column("actor_id", sa.String(length=256), nullable=True),
        sa.Column("before_status", sa.String(length=32), nullable=True),
        sa.Column("after_status", sa.String(length=32), nullable=True),
        sa.Column("details", postgresql.JSONB(astext_type=sa.Text()), nullable=False),
        sa.Column("occurred_at", sa.DateTime(timezone=True), server_default=sa.text("now()"), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.text("now()"), nullable=False),
        sa.CheckConstraint(
            "event_type IN ('planned', 'review-approved', 'review-rejected', 'applied', 'failed', 'rolled-back')",
            name="ck_openrel_policy_events_event_type",
        ),
        sa.CheckConstraint(
            "actor_type IN ('system', 'admin', 'curator', 'worker')",
            name="ck_openrel_policy_events_actor_type",
        ),
        sa.CheckConstraint(
            "char_length(btrim(event_type)) > 0",
            name="ck_openrel_policy_events_event_type_nonblank",
        ),
        sa.ForeignKeyConstraint(
            ["policy_state_id"],
            ["openrel_policy_states.id"],
            name="fk_openrel_policy_events_policy_state_id",
            ondelete="RESTRICT",
        ),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index("ix_openrel_policy_events_policy_state_id", "openrel_policy_events", ["policy_state_id"], unique=False)
    op.create_index("ix_openrel_policy_events_occurred_at", "openrel_policy_events", ["occurred_at"], unique=False)
    op.create_index("ix_openrel_policy_events_event_type", "openrel_policy_events", ["event_type"], unique=False)

    op.execute(_CREATE_EVENT_MUTATION_REJECT_FN)
    op.execute(_CREATE_EVENT_NO_UPDATE_TRIGGER)
    op.execute(_CREATE_EVENT_NO_DELETE_TRIGGER)


def downgrade() -> None:
    op.execute(_DROP_EVENT_MUTATION_TRIGGERS)
    op.execute(_DROP_EVENT_MUTATION_FN)
    op.drop_index("ix_openrel_policy_events_event_type", table_name="openrel_policy_events")
    op.drop_index("ix_openrel_policy_events_occurred_at", table_name="openrel_policy_events")
    op.drop_index("ix_openrel_policy_events_policy_state_id", table_name="openrel_policy_events")
    op.drop_table("openrel_policy_events")

    op.execute(_DROP_STATE_IMMUTABLE_TRIGGER)
    op.execute(_DROP_STATE_IMMUTABLE_FN)
    op.drop_index("ix_openrel_policy_states_created_at", table_name="openrel_policy_states")
    op.drop_index("ix_openrel_policy_states_policy_version", table_name="openrel_policy_states")
    op.drop_index("ix_openrel_policy_states_status", table_name="openrel_policy_states")
    op.drop_index("ix_openrel_policy_states_canonical_license_id", table_name="openrel_policy_states")
    op.drop_table("openrel_policy_states")
