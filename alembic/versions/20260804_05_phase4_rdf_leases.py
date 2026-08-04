"""Phase 4 RDF graph lease fields.

Revision ID: 20260804_05_phase4_rdf_leases
Revises: 20260804_04_phase4_federation_resolution_rdf
Create Date: 2026-08-04 13:30:00.000000
"""

from __future__ import annotations

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql


revision = "20260804_05_phase4_rdf_leases"
down_revision = "20260804_04"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column("federation_rdf_graph_state", sa.Column("active_lease_job_id", postgresql.UUID(as_uuid=True), nullable=True))
    op.add_column("federation_rdf_graph_state", sa.Column("active_lease_by", sa.String(length=128), nullable=True))
    op.add_column("federation_rdf_graph_state", sa.Column("active_lease_until", sa.DateTime(timezone=True), nullable=True))


def downgrade() -> None:
    op.drop_column("federation_rdf_graph_state", "active_lease_until")
    op.drop_column("federation_rdf_graph_state", "active_lease_by")
    op.drop_column("federation_rdf_graph_state", "active_lease_job_id")
