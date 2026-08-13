"""Phase 3 custom licence federation publication outbox

Revision ID: 20260813_01_custom_lic_outbox
Revises: 20260812_01_custom_licences
Create Date: 2026-08-13 14:30:00.000000
"""

from __future__ import annotations

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "20260813_01_custom_lic_outbox"
down_revision: Union[str, Sequence[str], None] = "20260812_01_custom_licences"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        "custom_licence_federation_outbox",
        sa.Column("id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("custom_licence_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("operation", sa.String(length=32), nullable=False, server_default="upsert"),
        sa.Column("status", sa.String(length=32), nullable=False, server_default="pending"),
        sa.Column("attempt_count", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("available_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.text("now()")),
        sa.Column("lease_owner", sa.String(length=128), nullable=True),
        sa.Column("lease_expires_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("last_error_class", sa.String(length=128), nullable=True),
        sa.Column("last_error_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("federation_record_id", postgresql.UUID(as_uuid=True), nullable=True),
        sa.Column("federation_event_id", postgresql.UUID(as_uuid=True), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.text("now()")),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.text("now()")),
        sa.Column("published_at", sa.DateTime(timezone=True), nullable=True),
        # valid operation values
        sa.CheckConstraint(
            "operation IN ('upsert')",
            name="ck_custom_licence_federation_outbox_operation",
        ),
        # valid status values
        sa.CheckConstraint(
            "status IN ('pending','processing','published','retryable_failed','permanently_failed')",
            name="ck_custom_licence_federation_outbox_status",
        ),
        # attempt count is non-negative
        sa.CheckConstraint(
            "attempt_count >= 0",
            name="ck_custom_licence_federation_outbox_attempt_count_nonneg",
        ),
        # processing status iff lease_owner is set; non-processing must have no lease
        sa.CheckConstraint(
            "(status = 'processing') = (lease_owner IS NOT NULL)",
            name="ck_custom_licence_federation_outbox_processing_requires_owner",
        ),
        # lease_owner and lease_expires_at are always set/unset together
        sa.CheckConstraint(
            "(lease_owner IS NULL) = (lease_expires_at IS NULL)",
            name="ck_custom_licence_federation_outbox_lease_fields_consistent",
        ),
        # published status requires all three linkage fields
        sa.CheckConstraint(
            "status != 'published' OR (federation_record_id IS NOT NULL AND federation_event_id IS NOT NULL AND published_at IS NOT NULL)",
            name="ck_custom_licence_federation_outbox_published_requires_linkage",
        ),
        # only published status may carry published_at
        sa.CheckConstraint(
            "(published_at IS NULL) OR (status = 'published')",
            name="ck_custom_licence_federation_outbox_published_at_iff_published",
        ),
        # error class and error time are co-consistent
        sa.CheckConstraint(
            "(last_error_class IS NULL) = (last_error_at IS NULL)",
            name="ck_custom_licence_federation_outbox_error_fields_consistent",
        ),
        # FK: custom licence (non-destructive: restrict deletion of parent while outbox row exists)
        sa.ForeignKeyConstraint(["custom_licence_id"], ["custom_licences.id"], ondelete="RESTRICT"),
        # FKs: published linkage is immutable history; linked record/event deletes are restricted.
        sa.ForeignKeyConstraint(["federation_record_id"], ["federation_records.id"], ondelete="RESTRICT"),
        sa.ForeignKeyConstraint(["federation_event_id"], ["federation_change_events.id"], ondelete="RESTRICT"),
        sa.PrimaryKeyConstraint("id"),
        # at most one active upsert intent per custom licence
        sa.UniqueConstraint(
            "custom_licence_id",
            "operation",
            name="uq_custom_licence_federation_outbox_licence_operation",
        ),
    )
    # job acquisition: find pending/retryable jobs by availability time
    op.create_index(
        "ix_custom_licence_federation_outbox_status_available_at",
        "custom_licence_federation_outbox",
        ["status", "available_at"],
        unique=False,
    )
    # lease recovery: find stale processing jobs
    op.create_index(
        "ix_custom_licence_federation_outbox_status_lease_expires_at",
        "custom_licence_federation_outbox",
        ["status", "lease_expires_at"],
        unique=False,
    )
    # lookup by custom licence
    op.create_index(
        "ix_custom_licence_federation_outbox_custom_licence_id",
        "custom_licence_federation_outbox",
        ["custom_licence_id"],
        unique=False,
    )
    # unique linkage: one outbox job per federation record (non-null only)
    op.create_index(
        "uix_custom_licence_federation_outbox_federation_record_id",
        "custom_licence_federation_outbox",
        ["federation_record_id"],
        unique=True,
        postgresql_where=sa.text("federation_record_id IS NOT NULL"),
    )
    # unique linkage: one outbox job per federation event (non-null only)
    op.create_index(
        "uix_custom_licence_federation_outbox_federation_event_id",
        "custom_licence_federation_outbox",
        ["federation_event_id"],
        unique=True,
        postgresql_where=sa.text("federation_event_id IS NOT NULL"),
    )


def downgrade() -> None:
    op.drop_index(
        "uix_custom_licence_federation_outbox_federation_event_id",
        table_name="custom_licence_federation_outbox",
    )
    op.drop_index(
        "uix_custom_licence_federation_outbox_federation_record_id",
        table_name="custom_licence_federation_outbox",
    )
    op.drop_index(
        "ix_custom_licence_federation_outbox_custom_licence_id",
        table_name="custom_licence_federation_outbox",
    )
    op.drop_index(
        "ix_custom_licence_federation_outbox_status_lease_expires_at",
        table_name="custom_licence_federation_outbox",
    )
    op.drop_index(
        "ix_custom_licence_federation_outbox_status_available_at",
        table_name="custom_licence_federation_outbox",
    )
    op.drop_table("custom_licence_federation_outbox")
