"""Add OpenREL apply/rollback persistence foundations.

Revision ID: 20260904_02
Revises: 20260904_01
Create Date: 2026-09-04
"""

from __future__ import annotations

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "20260904_02"
down_revision: Union[str, Sequence[str], None] = "20260904_01"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column("openrel_policy_states", sa.Column("target_custom_licence_id", postgresql.UUID(as_uuid=True), nullable=True))
    op.add_column("openrel_policy_states", sa.Column("target_snapshot_before", postgresql.JSONB(astext_type=sa.Text()), nullable=True))
    op.add_column("openrel_policy_states", sa.Column("target_digest_before", sa.String(length=64), nullable=True))
    op.add_column("openrel_policy_states", sa.Column("target_snapshot_after", postgresql.JSONB(astext_type=sa.Text()), nullable=True))
    op.add_column("openrel_policy_states", sa.Column("target_digest_after", sa.String(length=64), nullable=True))
    op.add_column("openrel_policy_states", sa.Column("applied_by", sa.String(length=256), nullable=True))
    op.add_column("openrel_policy_states", sa.Column("rolled_back_by", sa.String(length=256), nullable=True))
    op.create_foreign_key(
        "fk_orps_target_custom_licence",
        "openrel_policy_states",
        "custom_licences",
        ["target_custom_licence_id"],
        ["id"],
        ondelete="RESTRICT",
    )
    op.create_index("ix_orps_target_custom_licence_id", "openrel_policy_states", ["target_custom_licence_id"], unique=False)
    op.create_check_constraint("ck_orps_target_digest_before_fmt", "openrel_policy_states", "target_digest_before IS NULL OR target_digest_before ~ '^[0-9a-f]{64}$'")
    op.create_check_constraint("ck_orps_target_digest_after_fmt", "openrel_policy_states", "target_digest_after IS NULL OR target_digest_after ~ '^[0-9a-f]{64}$'")
    op.drop_constraint("ck_openrel_policy_states_applied_requires_timestamps", "openrel_policy_states", type_="check")
    op.drop_constraint("ck_openrel_policy_states_rollback_requires_original", "openrel_policy_states", type_="check")
    op.create_check_constraint(
        "ck_orps_applied_fields",
        "openrel_policy_states",
        "(status <> 'applied') OR (applied_at IS NOT NULL AND applied_by IS NOT NULL AND target_custom_licence_id IS NOT NULL AND target_snapshot_before IS NOT NULL AND target_digest_before IS NOT NULL AND target_snapshot_after IS NOT NULL AND target_digest_after IS NOT NULL AND action <> 'none' AND apply_allowed = true AND policy_mode = 'active' AND source_kind <> 'federation-imported')",
    )
    op.create_check_constraint(
        "ck_orps_rollback_fields",
        "openrel_policy_states",
        "(status <> 'rolled-back') OR (rolled_back_at IS NOT NULL AND rolled_back_by IS NOT NULL AND applied_at IS NOT NULL AND applied_by IS NOT NULL AND target_custom_licence_id IS NOT NULL AND target_snapshot_before IS NOT NULL AND target_digest_before IS NOT NULL AND target_snapshot_after IS NOT NULL AND target_digest_after IS NOT NULL AND original_representation IS NOT NULL)",
    )
    op.create_check_constraint(
        "ck_orps_pre_rb_null",
        "openrel_policy_states",
        "(status IN ('applied','rolled-back')) OR (rolled_back_at IS NULL AND rolled_back_by IS NULL)",
    )

    op.create_table(
        "custom_licence_representations",
        sa.Column("id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("custom_licence_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("representation_type", sa.String(length=32), nullable=False),
        sa.Column("status", sa.String(length=16), nullable=False),
        sa.Column("media_type", sa.String(length=128), nullable=False),
        sa.Column("profile_uri", sa.String(length=1024), nullable=False),
        sa.Column("vocabulary_uri", sa.String(length=1024), nullable=False),
        sa.Column("content", postgresql.JSONB(astext_type=sa.Text()), nullable=True),
        sa.Column("href", sa.String(length=2048), nullable=True),
        sa.Column("content_digest_sha256", sa.String(length=64), nullable=False),
        sa.Column("mapping_profile", sa.String(length=1024), nullable=False),
        sa.Column("mapping_provenance", postgresql.JSONB(astext_type=sa.Text()), nullable=False),
        sa.Column("source_policy_state_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.text("now()"), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.text("now()"), nullable=False),
        sa.Column("rolled_back_at", sa.DateTime(timezone=True), nullable=True),
        sa.CheckConstraint("representation_type = 'openrel-mapping'", name="ck_clr_repr_type"),
        sa.CheckConstraint("status IN ('active','rolled-back')", name="ck_clr_status"),
        sa.CheckConstraint("(content IS NOT NULL) OR (href IS NOT NULL)", name="ck_clr_content_or_href"),
        sa.CheckConstraint("(href IS NULL) OR (href ~ '^https://[^/].*')", name="ck_clr_href_https"),
        sa.CheckConstraint("content_digest_sha256 ~ '^[0-9a-f]{64}$'", name="ck_clr_digest"),
        sa.CheckConstraint(
            "(status = 'active' AND rolled_back_at IS NULL) OR (status = 'rolled-back' AND rolled_back_at IS NOT NULL)",
            name="ck_clr_rb_consistent",
        ),
        sa.ForeignKeyConstraint(["custom_licence_id"], ["custom_licences.id"], ondelete="CASCADE", name="fk_clr_custom_licence"),
        sa.ForeignKeyConstraint(["source_policy_state_id"], ["openrel_policy_states.id"], ondelete="RESTRICT", name="fk_clr_policy_state"),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("source_policy_state_id", "representation_type", name="uq_clr_policy_repr"),
    )
    op.create_index("ix_clr_custom_licence_id", "custom_licence_representations", ["custom_licence_id"], unique=False)
    op.create_index("ix_clr_source_policy_state_id", "custom_licence_representations", ["source_policy_state_id"], unique=False)


def downgrade() -> None:
    op.drop_index("ix_clr_source_policy_state_id", table_name="custom_licence_representations")
    op.drop_index("ix_clr_custom_licence_id", table_name="custom_licence_representations")
    op.drop_table("custom_licence_representations")
    op.drop_constraint("ck_orps_pre_rb_null", "openrel_policy_states", type_="check")
    op.drop_constraint("ck_orps_rollback_fields", "openrel_policy_states", type_="check")
    op.drop_constraint("ck_orps_applied_fields", "openrel_policy_states", type_="check")
    op.create_check_constraint(
        "ck_openrel_policy_states_rollback_requires_original",
        "openrel_policy_states",
        "(status <> 'rolled-back') OR (rolled_back_at IS NOT NULL AND original_representation IS NOT NULL)",
    )
    op.create_check_constraint(
        "ck_openrel_policy_states_applied_requires_timestamps",
        "openrel_policy_states",
        "(status <> 'applied') OR (applied_at IS NOT NULL AND action <> 'none' AND apply_allowed = true AND policy_mode = 'active' AND source_kind <> 'federation-imported')",
    )
    op.drop_constraint("ck_orps_target_digest_after_fmt", "openrel_policy_states", type_="check")
    op.drop_constraint("ck_orps_target_digest_before_fmt", "openrel_policy_states", type_="check")
    op.drop_index("ix_orps_target_custom_licence_id", table_name="openrel_policy_states")
    op.drop_constraint("fk_orps_target_custom_licence", "openrel_policy_states", type_="foreignkey")
    op.drop_column("openrel_policy_states", "rolled_back_by")
    op.drop_column("openrel_policy_states", "applied_by")
    op.drop_column("openrel_policy_states", "target_digest_after")
    op.drop_column("openrel_policy_states", "target_snapshot_after")
    op.drop_column("openrel_policy_states", "target_digest_before")
    op.drop_column("openrel_policy_states", "target_snapshot_before")
    op.drop_column("openrel_policy_states", "target_custom_licence_id")
