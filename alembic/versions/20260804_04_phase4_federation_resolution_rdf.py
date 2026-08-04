"""phase4 federation resolution and rdf outbox

Revision ID: 20260804_04
Revises: 20260804_03
Create Date: 2026-08-04 13:05:00
"""

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

# revision identifiers, used by Alembic.
revision: str = "20260804_04"
down_revision: Union[str, Sequence[str], None] = "20260804_03"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.add_column(
        "federation_records",
        sa.Column("materialized_generation", sa.BigInteger(), nullable=False, server_default="0"),
    )

    op.create_table(
        "federation_resolution_aliases",
        sa.Column("id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("normalized_identifier", sa.String(length=1024), nullable=False),
        sa.Column("alias_value", sa.String(length=2048), nullable=False),
        sa.Column("alias_kind", sa.String(length=64), nullable=False),
        sa.Column("record_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("authority_node_id", sa.String(length=128), nullable=True),
        sa.Column("source_peer_id", postgresql.UUID(as_uuid=True), nullable=True),
        sa.Column("is_authoritative", sa.Boolean(), nullable=False, server_default=sa.text("false")),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(["record_id"], ["federation_records.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["source_peer_id"], ["federation_trusted_peers.id"], ondelete="SET NULL"),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("normalized_identifier", "record_id", "alias_kind", name="uq_federation_resolution_alias"),
    )
    op.create_index(
        "ix_federation_resolution_aliases_normalized_identifier",
        "federation_resolution_aliases",
        ["normalized_identifier"],
        unique=False,
    )

    op.create_table(
        "federation_resolution_conflicts",
        sa.Column("id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("normalized_identifier", sa.String(length=1024), nullable=False),
        sa.Column("conflict_type", sa.String(length=64), nullable=False),
        sa.Column("status", sa.String(length=32), nullable=False, server_default="open"),
        sa.Column("version", sa.Integer(), nullable=False, server_default="1"),
        sa.Column("decision_effectiveness", sa.String(length=32), nullable=True),
        sa.Column("candidate_summary", postgresql.JSONB(astext_type=sa.Text()), nullable=False),
        sa.Column("resolved_record_id", postgresql.UUID(as_uuid=True), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("resolved_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("reopened_at", sa.DateTime(timezone=True), nullable=True),
        sa.ForeignKeyConstraint(["resolved_record_id"], ["federation_records.id"], ondelete="SET NULL"),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("normalized_identifier", name="uq_federation_resolution_conflicts_normalized_identifier"),
    )
    op.create_index(
        "ix_federation_resolution_conflicts_normalized_identifier",
        "federation_resolution_conflicts",
        ["normalized_identifier"],
        unique=False,
    )

    op.create_table(
        "federation_conflict_decision_events",
        sa.Column("id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("conflict_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("expected_version", sa.Integer(), nullable=False),
        sa.Column("version", sa.Integer(), nullable=False),
        sa.Column("decision_type", sa.String(length=32), nullable=False),
        sa.Column("decision_effectiveness", sa.String(length=32), nullable=False),
        sa.Column("actor_role", sa.String(length=32), nullable=False),
        sa.Column("actor_identifier", sa.String(length=256), nullable=True),
        sa.Column("rationale", sa.Text(), nullable=True),
        sa.Column("before_state", postgresql.JSONB(astext_type=sa.Text()), nullable=False),
        sa.Column("after_state", postgresql.JSONB(astext_type=sa.Text()), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(["conflict_id"], ["federation_resolution_conflicts.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("conflict_id", "version", name="uq_federation_conflict_decisions_conflict_version"),
    )
    op.create_index(
        "ix_federation_conflict_decisions_conflict_version",
        "federation_conflict_decision_events",
        ["conflict_id", "version"],
        unique=False,
    )

    op.create_table(
        "federation_resolution_audit_log",
        sa.Column("id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("subject_type", sa.String(length=64), nullable=False),
        sa.Column("subject_id", sa.String(length=256), nullable=False),
        sa.Column("action", sa.String(length=64), nullable=False),
        sa.Column("actor_role", sa.String(length=32), nullable=False),
        sa.Column("actor_identifier", sa.String(length=256), nullable=True),
        sa.Column("rationale", sa.Text(), nullable=True),
        sa.Column("before_state", postgresql.JSONB(astext_type=sa.Text()), nullable=False),
        sa.Column("after_state", postgresql.JSONB(astext_type=sa.Text()), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.PrimaryKeyConstraint("id"),
    )

    op.create_table(
        "federation_rdf_outbox_jobs",
        sa.Column("id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("dedupe_key", sa.String(length=512), nullable=False),
        sa.Column("job_type", sa.String(length=64), nullable=False),
        sa.Column("status", sa.String(length=32), nullable=False, server_default="pending"),
        sa.Column("record_id", postgresql.UUID(as_uuid=True), nullable=True),
        sa.Column("authority_node_id", sa.String(length=128), nullable=True),
        sa.Column("source_peer_id", postgresql.UUID(as_uuid=True), nullable=True),
        sa.Column("graph_uri", sa.String(length=2048), nullable=False),
        sa.Column("expected_generation", sa.BigInteger(), nullable=False),
        sa.Column("expected_digest_sha256", sa.String(length=128), nullable=False),
        sa.Column("payload_json", postgresql.JSONB(astext_type=sa.Text()), nullable=False),
        sa.Column("attempt_count", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("leased_until", sa.DateTime(timezone=True), nullable=True),
        sa.Column("leased_by", sa.String(length=128), nullable=True),
        sa.Column("next_attempt_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("last_error_code", sa.String(length=128), nullable=True),
        sa.Column("last_error_detail", sa.Text(), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("dead_lettered_at", sa.DateTime(timezone=True), nullable=True),
        sa.ForeignKeyConstraint(["record_id"], ["federation_records.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["source_peer_id"], ["federation_trusted_peers.id"], ondelete="SET NULL"),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("dedupe_key", name="uq_federation_rdf_outbox_jobs_dedupe_key"),
        sa.CheckConstraint(
            "status IN ('pending','running','succeeded','retryable_failed','dead_lettered','superseded')",
            name="ck_federation_rdf_outbox_status",
        ),
    )
    op.create_index(
        "ix_federation_rdf_outbox_status_next_attempt",
        "federation_rdf_outbox_jobs",
        ["status", "next_attempt_at"],
        unique=False,
    )
    op.create_index(
        "ix_federation_rdf_outbox_record_generation",
        "federation_rdf_outbox_jobs",
        ["record_id", "expected_generation"],
        unique=False,
    )
    op.create_index(
        "ix_federation_rdf_outbox_graph_uri",
        "federation_rdf_outbox_jobs",
        ["graph_uri"],
        unique=False,
    )

    op.create_table(
        "federation_rdf_graph_state",
        sa.Column("graph_uri", sa.String(length=2048), nullable=False),
        sa.Column("graph_kind", sa.String(length=64), nullable=False),
        sa.Column("record_id", postgresql.UUID(as_uuid=True), nullable=True),
        sa.Column("authority_node_id", sa.String(length=128), nullable=True),
        sa.Column("source_peer_id", postgresql.UUID(as_uuid=True), nullable=True),
        sa.Column("expected_generation", sa.BigInteger(), nullable=False, server_default="0"),
        sa.Column("expected_digest_sha256", sa.String(length=128), nullable=True),
        sa.Column("current_generation", sa.BigInteger(), nullable=False, server_default="0"),
        sa.Column("current_digest_sha256", sa.String(length=128), nullable=True),
        sa.Column("status", sa.String(length=32), nullable=False, server_default="pending"),
        sa.Column("last_success_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("last_attempt_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("last_error_code", sa.String(length=128), nullable=True),
        sa.Column("last_error_detail", sa.Text(), nullable=True),
        sa.Column("owned_by_service", sa.Boolean(), nullable=False, server_default=sa.text("true")),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(["record_id"], ["federation_records.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["source_peer_id"], ["federation_trusted_peers.id"], ondelete="SET NULL"),
        sa.PrimaryKeyConstraint("graph_uri"),
    )

def downgrade() -> None:
    op.drop_table("federation_rdf_graph_state")
    op.drop_index("ix_federation_rdf_outbox_graph_uri", table_name="federation_rdf_outbox_jobs")
    op.drop_index("ix_federation_rdf_outbox_record_generation", table_name="federation_rdf_outbox_jobs")
    op.drop_index("ix_federation_rdf_outbox_status_next_attempt", table_name="federation_rdf_outbox_jobs")
    op.drop_table("federation_rdf_outbox_jobs")
    op.drop_table("federation_resolution_audit_log")
    op.drop_index("ix_federation_conflict_decisions_conflict_version", table_name="federation_conflict_decision_events")
    op.drop_table("federation_conflict_decision_events")
    op.drop_index("ix_federation_resolution_conflicts_normalized_identifier", table_name="federation_resolution_conflicts")
    op.drop_table("federation_resolution_conflicts")
    op.drop_index("ix_federation_resolution_aliases_normalized_identifier", table_name="federation_resolution_aliases")
    op.drop_table("federation_resolution_aliases")
    op.drop_column("federation_records", "materialized_generation")
