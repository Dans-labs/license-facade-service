"""phase3 federation inbound sync

Revision ID: 20260804_03
Revises: 20260804_02
Create Date: 2026-08-04 12:20:00
"""

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

# revision identifiers, used by Alembic.
revision: str = "20260804_03"
down_revision: Union[str, Sequence[str], None] = "20260804_02"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.add_column("federation_trusted_peers", sa.Column("sync_enabled", sa.Boolean(), nullable=False, server_default=sa.text("true")))
    op.add_column(
        "federation_trusted_peers",
        sa.Column("allow_private_network", sa.Boolean(), nullable=False, server_default=sa.text("false")),
    )
    op.add_column("federation_trusted_peers", sa.Column("allowed_hostnames", sa.Text(), nullable=True))
    op.add_column("federation_trusted_peers", sa.Column("allowed_cidrs", sa.Text(), nullable=True))
    op.add_column(
        "federation_trusted_peers",
        sa.Column("enrollment_mode", sa.String(length=32), nullable=False, server_default="strict"),
    )
    op.add_column("federation_trusted_peers", sa.Column("expected_key_fingerprint", sa.String(length=128), nullable=True))
    op.add_column("federation_trusted_peers", sa.Column("expected_key_kid", sa.String(length=128), nullable=True))
    op.add_column("federation_trusted_peers", sa.Column("last_sync_attempt_at", sa.DateTime(timezone=True), nullable=True))
    op.add_column("federation_trusted_peers", sa.Column("last_sync_success_at", sa.DateTime(timezone=True), nullable=True))
    op.add_column("federation_trusted_peers", sa.Column("last_sync_status", sa.String(length=32), nullable=True))
    op.add_column("federation_trusted_peers", sa.Column("last_sync_error_code", sa.String(length=128), nullable=True))
    op.add_column("federation_trusted_peers", sa.Column("last_sync_error_detail", sa.Text(), nullable=True))
    op.add_column("federation_trusted_peers", sa.Column("archived_at", sa.DateTime(timezone=True), nullable=True))

    op.add_column(
        "federation_records",
        sa.Column("lifecycle_state", sa.String(length=32), nullable=False, server_default="published"),
    )
    op.add_column("federation_records", sa.Column("source_record_url", sa.String(length=2048), nullable=True))
    op.add_column("federation_records", sa.Column("source_event_id", postgresql.UUID(as_uuid=True), nullable=True))
    op.add_column("federation_records", sa.Column("source_event_position", sa.BigInteger(), nullable=True))
    op.add_column("federation_records", sa.Column("source_signature_kid", sa.String(length=128), nullable=True))
    op.add_column("federation_records", sa.Column("source_signed_payload_digest_sha256", sa.String(length=128), nullable=True))
    op.add_column("federation_records", sa.Column("verification_status", sa.String(length=32), nullable=True))
    op.add_column("federation_records", sa.Column("last_verified_at", sa.DateTime(timezone=True), nullable=True))
    op.create_index("ix_federation_records_imported_peer", "federation_records", ["imported_from_peer_id"], unique=False)

    op.add_column("federation_peer_cursors", sa.Column("last_remote_position", sa.BigInteger(), nullable=True))

    op.add_column(
        "federation_sync_attempts",
        sa.Column("trigger_type", sa.String(length=32), nullable=False, server_default="manual"),
    )
    op.add_column(
        "federation_sync_attempts",
        sa.Column("pages_processed", sa.Integer(), nullable=False, server_default="0"),
    )
    op.add_column(
        "federation_sync_attempts",
        sa.Column("events_processed", sa.Integer(), nullable=False, server_default="0"),
    )
    op.add_column("federation_sync_attempts", sa.Column("cursor_before", sa.String(length=1024), nullable=True))
    op.add_column("federation_sync_attempts", sa.Column("cursor_after", sa.String(length=1024), nullable=True))

    op.create_table(
        "federation_peer_signing_keys",
        sa.Column("id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("peer_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("kid", sa.String(length=128), nullable=False),
        sa.Column("alg", sa.String(length=32), nullable=False),
        sa.Column("kty", sa.String(length=16), nullable=False),
        sa.Column("crv", sa.String(length=32), nullable=False),
        sa.Column("x", sa.String(length=1024), nullable=False),
        sa.Column("key_fingerprint", sa.String(length=128), nullable=False),
        sa.Column("key_status", sa.String(length=32), nullable=False, server_default="active"),
        sa.Column("first_seen_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("last_seen_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("valid_from", sa.DateTime(timezone=True), nullable=True),
        sa.Column("valid_until", sa.DateTime(timezone=True), nullable=True),
        sa.Column("approved_by", sa.String(length=128), nullable=True),
        sa.Column("approved_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.CheckConstraint("alg = 'EdDSA'", name="ck_federation_peer_signing_keys_alg"),
        sa.CheckConstraint("kty = 'OKP'", name="ck_federation_peer_signing_keys_kty"),
        sa.CheckConstraint("crv = 'Ed25519'", name="ck_federation_peer_signing_keys_crv"),
        sa.CheckConstraint("key_status IN ('active','retired','revoked')", name="ck_federation_peer_signing_keys_status"),
        sa.ForeignKeyConstraint(["peer_id"], ["federation_trusted_peers.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("peer_id", "kid", name="uq_federation_peer_signing_keys_peer_kid"),
    )

    op.create_table(
        "federation_inbound_events",
        sa.Column("id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("source_peer_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("authority_node_id", sa.String(length=128), nullable=False),
        sa.Column("remote_event_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("remote_event_position", sa.BigInteger(), nullable=False),
        sa.Column("remote_operation", sa.String(length=32), nullable=False),
        sa.Column("signed_payload", postgresql.JSONB(astext_type=sa.Text()), nullable=False),
        sa.Column("signed_payload_digest_sha256", sa.String(length=128), nullable=False),
        sa.Column("signature_kid", sa.String(length=128), nullable=False),
        sa.Column("signature_alg", sa.String(length=32), nullable=False),
        sa.Column("signature_base64url", sa.String(length=512), nullable=False),
        sa.Column("generated_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("received_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("processing_status", sa.String(length=32), nullable=False),
        sa.Column("record_canonical_id", sa.String(length=512), nullable=False),
        sa.Column("record_payload_digest_sha256", sa.String(length=128), nullable=False),
        sa.Column("error_code", sa.String(length=128), nullable=True),
        sa.Column("error_detail", sa.Text(), nullable=True),
        sa.ForeignKeyConstraint(["source_peer_id"], ["federation_trusted_peers.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("authority_node_id", "remote_event_id", name="uq_federation_inbound_events_authority_event_id"),
        sa.UniqueConstraint(
            "authority_node_id",
            "remote_event_position",
            name="uq_federation_inbound_events_authority_event_position",
        ),
        sa.UniqueConstraint("source_peer_id", "signed_payload_digest_sha256", name="uq_federation_inbound_events_peer_digest"),
    )
    op.create_index(
        "ix_federation_inbound_events_peer_position",
        "federation_inbound_events",
        ["source_peer_id", "remote_event_position"],
        unique=False,
    )

    op.create_table(
        "federation_peer_audit_log",
        sa.Column("id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("peer_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("action", sa.String(length=64), nullable=False),
        sa.Column("actor", sa.String(length=128), nullable=False),
        sa.Column("details", postgresql.JSONB(astext_type=sa.Text()), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(["peer_id"], ["federation_trusted_peers.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
    )


def downgrade() -> None:
    op.drop_table("federation_peer_audit_log")
    op.drop_index("ix_federation_inbound_events_peer_position", table_name="federation_inbound_events")
    op.drop_table("federation_inbound_events")
    op.drop_table("federation_peer_signing_keys")

    op.drop_column("federation_sync_attempts", "cursor_after")
    op.drop_column("federation_sync_attempts", "cursor_before")
    op.drop_column("federation_sync_attempts", "events_processed")
    op.drop_column("federation_sync_attempts", "pages_processed")
    op.drop_column("federation_sync_attempts", "trigger_type")

    op.drop_column("federation_peer_cursors", "last_remote_position")

    op.drop_index("ix_federation_records_imported_peer", table_name="federation_records")
    op.drop_column("federation_records", "last_verified_at")
    op.drop_column("federation_records", "verification_status")
    op.drop_column("federation_records", "source_signed_payload_digest_sha256")
    op.drop_column("federation_records", "source_signature_kid")
    op.drop_column("federation_records", "source_event_position")
    op.drop_column("federation_records", "source_event_id")
    op.drop_column("federation_records", "source_record_url")
    op.drop_column("federation_records", "lifecycle_state")

    op.drop_column("federation_trusted_peers", "archived_at")
    op.drop_column("federation_trusted_peers", "last_sync_error_detail")
    op.drop_column("federation_trusted_peers", "last_sync_error_code")
    op.drop_column("federation_trusted_peers", "last_sync_status")
    op.drop_column("federation_trusted_peers", "last_sync_success_at")
    op.drop_column("federation_trusted_peers", "last_sync_attempt_at")
    op.drop_column("federation_trusted_peers", "expected_key_kid")
    op.drop_column("federation_trusted_peers", "expected_key_fingerprint")
    op.drop_column("federation_trusted_peers", "enrollment_mode")
    op.drop_column("federation_trusted_peers", "allowed_cidrs")
    op.drop_column("federation_trusted_peers", "allowed_hostnames")
    op.drop_column("federation_trusted_peers", "allow_private_network")
    op.drop_column("federation_trusted_peers", "sync_enabled")
