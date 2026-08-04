"""phase2 federation outbound

Revision ID: 20260804_02
Revises: 20260804_01
Create Date: 2026-08-04 10:45:00
"""

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

# revision identifiers, used by Alembic.
revision: str = "20260804_02"
down_revision: Union[str, Sequence[str], None] = "20260804_01"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.execute("CREATE SEQUENCE IF NOT EXISTS federation_change_event_sequence AS BIGINT")
    op.execute(
        """
        DO $$
        DECLARE max_seq BIGINT;
        BEGIN
            SELECT MAX(event_sequence) INTO max_seq FROM federation_change_events;
            IF max_seq IS NULL THEN
                PERFORM setval('federation_change_event_sequence', 1, false);
            ELSE
                PERFORM setval('federation_change_event_sequence', max_seq, true);
            END IF;
        END $$;
        """
    )
    op.alter_column("federation_change_events", "event_sequence", type_=sa.BigInteger(), existing_nullable=False)
    op.execute(
        "ALTER TABLE federation_change_events ALTER COLUMN event_sequence SET DEFAULT nextval('federation_change_event_sequence')"
    )

    op.add_column(
        "federation_change_events",
        sa.Column("operation", sa.String(length=32), nullable=False, server_default="upsert"),
    )
    op.add_column(
        "federation_change_events",
        sa.Column("generated_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.text("now()")),
    )
    op.add_column(
        "federation_change_events",
        sa.Column("payload_schema_version", sa.String(length=16), nullable=False, server_default="1"),
    )
    op.add_column(
        "federation_change_events",
        sa.Column("signed_payload", postgresql.JSONB(astext_type=sa.Text()), nullable=False, server_default=sa.text("'{}'::jsonb")),
    )
    op.add_column(
        "federation_change_events",
        sa.Column("signed_payload_digest_sha256", sa.String(length=128), nullable=False, server_default=""),
    )
    op.add_column(
        "federation_change_events",
        sa.Column("signature_base64url", sa.String(length=512), nullable=False, server_default=""),
    )
    op.add_column(
        "federation_change_events",
        sa.Column("signature_kid", sa.String(length=128), nullable=False, server_default=""),
    )
    op.add_column(
        "federation_change_events",
        sa.Column("signature_alg", sa.String(length=32), nullable=False, server_default="EdDSA"),
    )
    op.add_column(
        "federation_change_events",
        sa.Column("provenance_type", sa.String(length=32), nullable=False, server_default="publication"),
    )
    op.add_column(
        "federation_change_events",
        sa.Column("backfill_created_at", sa.DateTime(timezone=True), nullable=True),
    )

    op.create_unique_constraint(
        "uq_federation_change_events_authority_sequence",
        "federation_change_events",
        ["authority_node_id", "event_sequence"],
    )
    op.create_check_constraint(
        "ck_federation_change_events_operation",
        "federation_change_events",
        "operation IN ('upsert','deprecate','tombstone')",
    )
    op.create_check_constraint(
        "ck_federation_change_events_signature_alg",
        "federation_change_events",
        "signature_alg = 'EdDSA'",
    )

    op.execute(
        """
        CREATE OR REPLACE FUNCTION lfs_reject_published_record_mutation()
        RETURNS trigger AS $$
        BEGIN
            IF OLD.published_at IS NOT NULL AND (
                NEW.payload IS DISTINCT FROM OLD.payload OR
                NEW.payload_digest_sha256 <> OLD.payload_digest_sha256 OR
                NEW.canonical_id <> OLD.canonical_id OR
                NEW.authority_node_id <> OLD.authority_node_id OR
                NEW.local_id <> OLD.local_id OR
                NEW.version <> OLD.version OR
                NEW.published_at IS DISTINCT FROM OLD.published_at
            ) THEN
                RAISE EXCEPTION 'Published record content and identity are immutable';
            END IF;
            RETURN NEW;
        END;
        $$ LANGUAGE plpgsql;
        """
    )
    op.execute(
        """
        CREATE TRIGGER trg_federation_records_immutable_published_content
        BEFORE UPDATE ON federation_records
        FOR EACH ROW
        EXECUTE FUNCTION lfs_reject_published_record_mutation();
        """
    )

    op.execute(
        """
        CREATE OR REPLACE FUNCTION lfs_reject_federation_change_events_mutation()
        RETURNS trigger AS $$
        BEGIN
            RAISE EXCEPTION 'federation_change_events is append-only';
        END;
        $$ LANGUAGE plpgsql;
        """
    )
    op.execute(
        """
        DROP TRIGGER IF EXISTS trg_federation_change_events_no_update ON federation_change_events;
        CREATE TRIGGER trg_federation_change_events_no_update
        BEFORE UPDATE ON federation_change_events
        FOR EACH ROW
        EXECUTE FUNCTION lfs_reject_federation_change_events_mutation();
        """
    )
    op.execute(
        """
        DROP TRIGGER IF EXISTS trg_federation_change_events_no_delete ON federation_change_events;
        CREATE TRIGGER trg_federation_change_events_no_delete
        BEFORE DELETE ON federation_change_events
        FOR EACH ROW
        EXECUTE FUNCTION lfs_reject_federation_change_events_mutation();
        """
    )


def downgrade() -> None:
    op.execute("DROP TRIGGER IF EXISTS trg_federation_change_events_no_update ON federation_change_events")
    op.execute("DROP TRIGGER IF EXISTS trg_federation_change_events_no_delete ON federation_change_events")
    op.execute("DROP FUNCTION IF EXISTS lfs_reject_federation_change_events_mutation")
    op.execute("DROP TRIGGER IF EXISTS trg_federation_records_immutable_published_content ON federation_records")
    op.execute("DROP FUNCTION IF EXISTS lfs_reject_published_record_mutation")
    op.drop_constraint("ck_federation_change_events_signature_alg", "federation_change_events", type_="check")
    op.drop_constraint("ck_federation_change_events_operation", "federation_change_events", type_="check")
    op.drop_constraint("uq_federation_change_events_authority_sequence", "federation_change_events", type_="unique")
    op.drop_column("federation_change_events", "backfill_created_at")
    op.drop_column("federation_change_events", "provenance_type")
    op.drop_column("federation_change_events", "signature_alg")
    op.drop_column("federation_change_events", "signature_kid")
    op.drop_column("federation_change_events", "signature_base64url")
    op.drop_column("federation_change_events", "signed_payload_digest_sha256")
    op.drop_column("federation_change_events", "signed_payload")
    op.drop_column("federation_change_events", "payload_schema_version")
    op.drop_column("federation_change_events", "generated_at")
    op.drop_column("federation_change_events", "operation")
    op.execute("ALTER TABLE federation_change_events ALTER COLUMN event_sequence DROP DEFAULT")
    op.alter_column("federation_change_events", "event_sequence", type_=sa.Integer(), existing_nullable=False)
    op.execute("DROP SEQUENCE IF EXISTS federation_change_event_sequence")
    op.execute(
        """
        CREATE TRIGGER trg_federation_change_events_no_update
        BEFORE UPDATE ON federation_change_events
        FOR EACH ROW
        EXECUTE FUNCTION lfs_reject_change_events_mutation();
        """
    )
    op.execute(
        """
        CREATE TRIGGER trg_federation_change_events_no_delete
        BEFORE DELETE ON federation_change_events
        FOR EACH ROW
        EXECUTE FUNCTION lfs_reject_change_events_mutation();
        """
    )
