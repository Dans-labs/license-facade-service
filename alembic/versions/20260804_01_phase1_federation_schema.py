"""phase1 federation schema

Revision ID: 20260804_01
Revises:
Create Date: 2026-08-04 10:05:00
"""

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

# revision identifiers, used by Alembic.
revision: str = "20260804_01"
down_revision: Union[str, Sequence[str], None] = None
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def _create_timestamps(*, nullable: bool = False) -> list[sa.Column]:
    return [
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=nullable, server_default=sa.text("now()")),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=nullable, server_default=sa.text("now()")),
    ]


def upgrade() -> None:
    op.create_table(
        "federation_node_identity_state",
        sa.Column("id", sa.Integer(), nullable=False, server_default="1"),
        sa.Column("node_id", sa.String(length=128), nullable=False),
        sa.Column("public_base_url", sa.String(length=1024), nullable=False),
        sa.Column("node_name", sa.String(length=256), nullable=False),
        sa.Column("operator_name", sa.String(length=256), nullable=False),
        sa.Column("config_fingerprint", sa.String(length=128), nullable=False),
        *_create_timestamps(),
        sa.CheckConstraint("id = 1", name="ck_federation_node_identity_singleton"),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("node_id"),
    )

    op.create_table(
        "federation_signing_keys",
        sa.Column("id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("kid", sa.String(length=128), nullable=False),
        sa.Column("alg", sa.String(length=32), nullable=False),
        sa.Column("kty", sa.String(length=16), nullable=False),
        sa.Column("crv", sa.String(length=32), nullable=False),
        sa.Column("x", sa.String(length=1024), nullable=False),
        sa.Column("is_active", sa.Boolean(), nullable=False, server_default=sa.text("false")),
        sa.Column("status", sa.String(length=32), nullable=False, server_default="active"),
        sa.Column("valid_from", sa.DateTime(timezone=True), nullable=True),
        sa.Column("valid_until", sa.DateTime(timezone=True), nullable=True),
        *_create_timestamps(),
        sa.CheckConstraint("alg = 'EdDSA'", name="ck_federation_signing_keys_alg"),
        sa.CheckConstraint("kty = 'OKP'", name="ck_federation_signing_keys_kty"),
        sa.CheckConstraint("crv = 'Ed25519'", name="ck_federation_signing_keys_crv"),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("kid"),
    )
    op.create_index(
        "uq_federation_signing_keys_single_active",
        "federation_signing_keys",
        ["is_active"],
        unique=True,
        postgresql_where=sa.text("is_active = true"),
    )

    op.create_table(
        "federation_trusted_peers",
        sa.Column("id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("peer_node_id", sa.String(length=128), nullable=False),
        sa.Column("base_url", sa.String(length=1024), nullable=False),
        sa.Column("jwks_url", sa.String(length=1024), nullable=False),
        sa.Column("peer_name", sa.String(length=256), nullable=False),
        sa.Column("operator_name", sa.String(length=256), nullable=True),
        sa.Column("trust_status", sa.String(length=32), nullable=False, server_default="trusted"),
        *_create_timestamps(),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("peer_node_id"),
    )

    op.create_table(
        "federation_records",
        sa.Column("id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("authority_node_id", sa.String(length=128), nullable=False),
        sa.Column("local_id", sa.String(length=256), nullable=False),
        sa.Column("version", sa.String(length=128), nullable=False),
        sa.Column("canonical_id", sa.String(length=512), nullable=False),
        sa.Column("resolving_uuid", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("is_authoritative", sa.Boolean(), nullable=False, server_default=sa.text("false")),
        sa.Column("payload", postgresql.JSONB(astext_type=sa.Text()), nullable=False, server_default=sa.text("'{}'::jsonb")),
        sa.Column("payload_digest_sha256", sa.String(length=128), nullable=False),
        sa.Column("published_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("imported_from_peer_id", postgresql.UUID(as_uuid=True), nullable=True),
        *_create_timestamps(),
        sa.ForeignKeyConstraint(["imported_from_peer_id"], ["federation_trusted_peers.id"], ondelete="SET NULL"),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("canonical_id", name="uq_federation_record_canonical_id"),
        sa.UniqueConstraint("resolving_uuid"),
        sa.UniqueConstraint(
            "authority_node_id",
            "local_id",
            "version",
            name="uq_federation_record_authority_local_version",
        ),
    )
    op.create_index("ix_federation_records_authority", "federation_records", ["authority_node_id"], unique=False)
    op.create_index("ix_federation_records_canonical_id", "federation_records", ["canonical_id"], unique=False)

    op.create_table(
        "federation_record_aliases",
        sa.Column("id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("record_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("alias", sa.String(length=512), nullable=False),
        sa.Column("alias_type", sa.String(length=64), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.text("now()")),
        sa.ForeignKeyConstraint(["record_id"], ["federation_records.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("alias", name="uq_federation_record_alias"),
    )
    op.create_index("ix_federation_record_aliases_record_id", "federation_record_aliases", ["record_id"], unique=False)

    op.create_table(
        "federation_record_representations",
        sa.Column("id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("record_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("representation_type", sa.String(length=64), nullable=False),
        sa.Column("media_type", sa.String(length=128), nullable=False),
        sa.Column("profile_uri", sa.String(length=1024), nullable=True),
        sa.Column("vocabulary_uri", sa.String(length=1024), nullable=True),
        sa.Column("href", sa.String(length=2048), nullable=True),
        sa.Column("content", sa.Text(), nullable=True),
        sa.Column("content_digest_sha256", sa.String(length=128), nullable=True),
        *_create_timestamps(),
        sa.ForeignKeyConstraint(["record_id"], ["federation_records.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("record_id", "representation_type", "media_type", name="uq_federation_representation_kind"),
    )
    op.create_index("ix_federation_representations_record_id", "federation_record_representations", ["record_id"], unique=False)

    op.create_table(
        "federation_record_provenance",
        sa.Column("id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("record_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("source_node_id", sa.String(length=128), nullable=True),
        sa.Column("source_uri", sa.String(length=2048), nullable=True),
        sa.Column("source_digest_sha256", sa.String(length=128), nullable=True),
        sa.Column("provenance_type", sa.String(length=64), nullable=False),
        sa.Column("imported_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("asserted_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("metadata", postgresql.JSONB(astext_type=sa.Text()), nullable=False, server_default=sa.text("'{}'::jsonb")),
        sa.ForeignKeyConstraint(["record_id"], ["federation_records.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index("ix_federation_provenance_record_id", "federation_record_provenance", ["record_id"], unique=False)

    op.create_table(
        "federation_change_events",
        sa.Column("id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("event_sequence", sa.Integer(), nullable=False),
        sa.Column("event_type", sa.String(length=64), nullable=False),
        sa.Column("authority_node_id", sa.String(length=128), nullable=False),
        sa.Column("record_id", postgresql.UUID(as_uuid=True), nullable=True),
        sa.Column("event_payload", postgresql.JSONB(astext_type=sa.Text()), nullable=False, server_default=sa.text("'{}'::jsonb")),
        sa.Column("event_digest_sha256", sa.String(length=128), nullable=False),
        sa.Column("occurred_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.text("now()")),
        sa.ForeignKeyConstraint(["record_id"], ["federation_records.id"], ondelete="SET NULL"),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("event_sequence"),
    )
    op.create_index("ix_federation_change_events_occurred_at", "federation_change_events", ["occurred_at"], unique=False)

    op.create_table(
        "federation_peer_cursors",
        sa.Column("id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("peer_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("cursor", sa.String(length=512), nullable=True),
        sa.Column("synced_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.text("now()")),
        sa.ForeignKeyConstraint(["peer_id"], ["federation_trusted_peers.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("peer_id"),
    )

    op.create_table(
        "federation_sync_attempts",
        sa.Column("id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("peer_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("started_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("completed_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("status", sa.String(length=32), nullable=False),
        sa.Column("error_code", sa.String(length=128), nullable=True),
        sa.Column("error_detail", sa.Text(), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.text("now()")),
        sa.ForeignKeyConstraint(["peer_id"], ["federation_trusted_peers.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index(
        "ix_federation_sync_attempts_peer_started",
        "federation_sync_attempts",
        ["peer_id", "started_at"],
        unique=False,
    )

    op.create_table(
        "federation_conflicts",
        sa.Column("id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("record_key", sa.String(length=512), nullable=False),
        sa.Column("local_record_id", postgresql.UUID(as_uuid=True), nullable=True),
        sa.Column("remote_peer_id", postgresql.UUID(as_uuid=True), nullable=True),
        sa.Column("remote_record_ref", sa.String(length=512), nullable=True),
        sa.Column("reason", sa.Text(), nullable=False),
        sa.Column("status", sa.String(length=32), nullable=False, server_default="open"),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.text("now()")),
        sa.Column("resolved_at", sa.DateTime(timezone=True), nullable=True),
        sa.ForeignKeyConstraint(["local_record_id"], ["federation_records.id"], ondelete="SET NULL"),
        sa.ForeignKeyConstraint(["remote_peer_id"], ["federation_trusted_peers.id"], ondelete="SET NULL"),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index("ix_federation_conflicts_record_key", "federation_conflicts", ["record_key"], unique=False)

    op.execute(
        """
        CREATE OR REPLACE FUNCTION lfs_reject_change_events_mutation()
        RETURNS trigger AS $$
        BEGIN
            RAISE EXCEPTION 'federation_change_events is append-only';
        END;
        $$ LANGUAGE plpgsql;
        """
    )
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

    op.execute(
        """
        CREATE OR REPLACE FUNCTION lfs_reject_record_identifier_mutation()
        RETURNS trigger AS $$
        BEGIN
            IF OLD.published_at IS NOT NULL AND (
                NEW.authority_node_id <> OLD.authority_node_id OR
                NEW.local_id <> OLD.local_id OR
                NEW.version <> OLD.version OR
                NEW.resolving_uuid <> OLD.resolving_uuid
            ) THEN
                RAISE EXCEPTION 'Published record identifiers are immutable';
            END IF;
            RETURN NEW;
        END;
        $$ LANGUAGE plpgsql;
        """
    )
    op.execute(
        """
        CREATE TRIGGER trg_federation_records_immutable_published_identifier
        BEFORE UPDATE ON federation_records
        FOR EACH ROW
        EXECUTE FUNCTION lfs_reject_record_identifier_mutation();
        """
    )


def downgrade() -> None:
    op.execute("DROP TRIGGER IF EXISTS trg_federation_records_immutable_published_identifier ON federation_records")
    op.execute("DROP FUNCTION IF EXISTS lfs_reject_record_identifier_mutation")
    op.execute("DROP TRIGGER IF EXISTS trg_federation_change_events_no_delete ON federation_change_events")
    op.execute("DROP TRIGGER IF EXISTS trg_federation_change_events_no_update ON federation_change_events")
    op.execute("DROP FUNCTION IF EXISTS lfs_reject_change_events_mutation")

    op.drop_index("ix_federation_conflicts_record_key", table_name="federation_conflicts")
    op.drop_table("federation_conflicts")
    op.drop_index("ix_federation_sync_attempts_peer_started", table_name="federation_sync_attempts")
    op.drop_table("federation_sync_attempts")
    op.drop_table("federation_peer_cursors")
    op.drop_index("ix_federation_change_events_occurred_at", table_name="federation_change_events")
    op.drop_table("federation_change_events")
    op.drop_index("ix_federation_provenance_record_id", table_name="federation_record_provenance")
    op.drop_table("federation_record_provenance")
    op.drop_index("ix_federation_representations_record_id", table_name="federation_record_representations")
    op.drop_table("federation_record_representations")
    op.drop_index("ix_federation_record_aliases_record_id", table_name="federation_record_aliases")
    op.drop_table("federation_record_aliases")
    op.drop_index("ix_federation_records_canonical_id", table_name="federation_records")
    op.drop_index("ix_federation_records_authority", table_name="federation_records")
    op.drop_table("federation_records")
    op.drop_table("federation_trusted_peers")
    op.drop_index("uq_federation_signing_keys_single_active", table_name="federation_signing_keys")
    op.drop_table("federation_signing_keys")
    op.drop_table("federation_node_identity_state")
