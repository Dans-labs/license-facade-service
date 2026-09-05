"""Add federation change-event idempotency key support.

Revision ID: 20260904_03
Revises: 20260904_02
Create Date: 2026-09-04
"""

from __future__ import annotations

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "20260904_03"
down_revision: Union[str, Sequence[str], None] = "20260904_02"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column("federation_change_events", sa.Column("idempotency_key", postgresql.UUID(as_uuid=True), nullable=True))
    op.create_index(
        "uix_fce_authority_idempotency",
        "federation_change_events",
        ["authority_node_id", "idempotency_key"],
        unique=True,
        postgresql_where=sa.text("idempotency_key IS NOT NULL"),
    )


def downgrade() -> None:
    op.drop_index("uix_fce_authority_idempotency", table_name="federation_change_events", postgresql_where=sa.text("idempotency_key IS NOT NULL"))
    op.drop_column("federation_change_events", "idempotency_key")
