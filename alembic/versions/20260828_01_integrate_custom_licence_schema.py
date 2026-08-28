"""Integrate production custom-licence schema under Alembic ownership.

Revision ID: 20260828_01
Revises: c8b534db4b5c
Create Date: 2026-08-28
"""

from __future__ import annotations

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "20260828_01"
down_revision: Union[str, Sequence[str], None] = "c8b534db4b5c"
branch_labels = None
depends_on = None

_CREATE_AUDIT_MUTATION_REJECT_FN = """\
CREATE OR REPLACE FUNCTION lfs_reject_custom_licence_audit_mutation()
RETURNS trigger AS $$
BEGIN
    RAISE EXCEPTION
        'custom_licence_audit_events is append-only: % is not permitted',
        TG_OP;
END;
$$ LANGUAGE plpgsql;
"""

_CREATE_AUDIT_NO_UPDATE_TRIGGER = """\
CREATE TRIGGER trg_custom_licence_audit_events_no_update
    BEFORE UPDATE ON custom_licence_audit_events
    FOR EACH ROW EXECUTE FUNCTION lfs_reject_custom_licence_audit_mutation();
"""

_CREATE_AUDIT_NO_DELETE_TRIGGER = """\
CREATE TRIGGER trg_custom_licence_audit_events_no_delete
    BEFORE DELETE ON custom_licence_audit_events
    FOR EACH ROW EXECUTE FUNCTION lfs_reject_custom_licence_audit_mutation();
"""

_DROP_AUDIT_MUTATION_TRIGGERS = """\
DROP TRIGGER IF EXISTS trg_custom_licence_audit_events_no_update ON custom_licence_audit_events;
DROP TRIGGER IF EXISTS trg_custom_licence_audit_events_no_delete ON custom_licence_audit_events;
"""

_DROP_AUDIT_MUTATION_FN = "DROP FUNCTION IF EXISTS lfs_reject_custom_licence_audit_mutation;"


def upgrade() -> None:
    op.create_table(
        "custom_licences",
        sa.Column("id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("authority_id", sa.String(length=128), nullable=False),
        sa.Column("requested_license_id", sa.String(length=256), nullable=False),
        sa.Column("version", sa.String(length=128), nullable=False),
        sa.Column("canonical_id", sa.String(length=512), nullable=False),
        sa.Column("resolving_uuid", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("public_scope", sa.String(length=32), nullable=False),
        sa.Column("federation_status", sa.String(length=32), nullable=False),
        sa.Column("spdx_submission_status", sa.String(length=32), nullable=False),
        sa.Column("lifecycle_status", sa.String(length=32), nullable=False),
        sa.Column("name", sa.String(length=512), nullable=False),
        sa.Column("summary", sa.Text(), nullable=True),
        sa.Column("description", sa.Text(), nullable=True),
        sa.Column("license_text", sa.Text(), nullable=False),
        sa.Column("normalized_text_digest", sa.String(length=128), nullable=False),
        sa.Column("spdx_jsonld", postgresql.JSONB(astext_type=sa.Text()), nullable=False),
        sa.Column("creator_role", sa.String(length=64), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.text("now()"), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.text("now()"), nullable=False),
        sa.Column("deprecated_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("withdrawn_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("tombstoned_at", sa.DateTime(timezone=True), nullable=True),
        sa.CheckConstraint(
            "char_length(btrim(authority_id)) > 0",
            name="ck_custom_licences_authority_id_nonblank",
        ),
        sa.CheckConstraint(
            "char_length(btrim(requested_license_id)) > 0",
            name="ck_custom_licences_requested_license_id_nonblank",
        ),
        sa.CheckConstraint("char_length(btrim(version)) > 0", name="ck_custom_licences_version_nonblank"),
        sa.CheckConstraint("char_length(btrim(canonical_id)) > 0", name="ck_custom_licences_canonical_id_nonblank"),
        sa.CheckConstraint("char_length(btrim(name)) > 0", name="ck_custom_licences_name_nonblank"),
        sa.CheckConstraint("char_length(btrim(license_text)) > 0", name="ck_custom_licences_license_text_nonblank"),
        sa.CheckConstraint("char_length(btrim(normalized_text_digest)) = 64", name="ck_custom_licences_digest_length"),
        sa.CheckConstraint("normalized_text_digest ~ '^[0-9a-f]{64}$'", name="ck_custom_licences_digest_format"),
        sa.CheckConstraint(
            "public_scope IN ('local', 'federated', 'spdx-submission')",
            name="ck_custom_licences_public_scope",
        ),
        sa.CheckConstraint(
            "federation_status IN ('not_published', 'pending', 'published', 'publication_failed', 'deprecated', 'tombstoned')",
            name="ck_custom_licences_federation_status",
        ),
        sa.CheckConstraint(
            "spdx_submission_status IN ('not_requested', 'ready_for_review')",
            name="ck_custom_licences_spdx_submission_status",
        ),
        sa.CheckConstraint(
            "lifecycle_status IN ('registered', 'deprecated', 'withdrawn', 'tombstoned')",
            name="ck_custom_licences_lifecycle_status",
        ),
        sa.CheckConstraint(
            "char_length(btrim(creator_role)) > 0 AND creator_role = btrim(creator_role)",
            name="ck_custom_licences_creator_role_nonblank_trimmed",
        ),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("authority_id", "requested_license_id", "version", name="uq_custom_licences_authority_requested_version"),
        sa.UniqueConstraint("canonical_id", name="uq_custom_licences_canonical_id"),
        sa.UniqueConstraint("resolving_uuid", name="uq_custom_licences_resolving_uuid"),
    )
    op.create_index("ix_custom_licences_authority_requested", "custom_licences", ["authority_id", "requested_license_id"], unique=False)
    op.create_index(
        "ix_custom_licences_scope_status",
        "custom_licences",
        ["public_scope", "federation_status", "spdx_submission_status"],
        unique=False,
    )
    op.create_index("ix_custom_licences_lifecycle_status", "custom_licences", ["lifecycle_status"], unique=False)

    op.create_table(
        "custom_licence_aliases",
        sa.Column("id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("custom_licence_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("alias_type", sa.String(length=32), nullable=False),
        sa.Column("alias", sa.String(length=512), nullable=False),
        sa.Column("normalized_alias", sa.String(length=512), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.text("now()"), nullable=False),
        sa.CheckConstraint(
            "alias_type IN ('requested_id', 'canonical_id', 'resolving_uuid', 'resolving_uri', 'legacy')",
            name="ck_custom_licence_aliases_type",
        ),
        sa.CheckConstraint("char_length(btrim(alias)) > 0", name="ck_custom_licence_aliases_alias_nonblank"),
        sa.CheckConstraint(
            "char_length(btrim(normalized_alias)) > 0",
            name="ck_custom_licence_aliases_normalized_alias_nonblank",
        ),
        sa.ForeignKeyConstraint(
            ["custom_licence_id"],
            ["custom_licences.id"],
            name="fk_custom_licence_aliases_custom_licence_id",
            ondelete="RESTRICT",
        ),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("normalized_alias", name="uq_custom_licence_aliases_normalized_alias"),
    )
    op.create_index(
        "ix_custom_licence_aliases_custom_licence_type",
        "custom_licence_aliases",
        ["custom_licence_id", "alias_type"],
        unique=False,
    )

    op.create_table(
        "custom_licence_audit_events",
        sa.Column("id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("custom_licence_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("event_type", sa.String(length=64), nullable=False),
        sa.Column("actor_role", sa.String(length=64), nullable=False),
        sa.Column("actor_identifier", sa.Text(), nullable=True),
        sa.Column("before_state", postgresql.JSONB(astext_type=sa.Text()), nullable=True),
        sa.Column("after_state", postgresql.JSONB(astext_type=sa.Text()), nullable=True),
        sa.Column("source", sa.String(length=128), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.text("now()"), nullable=False),
        sa.CheckConstraint("char_length(btrim(event_type)) > 0", name="ck_custom_licence_audit_event_type_nonblank"),
        sa.CheckConstraint("char_length(btrim(actor_role)) > 0", name="ck_custom_licence_audit_actor_role_nonblank"),
        sa.ForeignKeyConstraint(
            ["custom_licence_id"],
            ["custom_licences.id"],
            name="fk_custom_licence_audit_events_custom_licence_id",
            ondelete="RESTRICT",
        ),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index(
        "ix_custom_licence_audit_events_licence_created",
        "custom_licence_audit_events",
        ["custom_licence_id", "created_at"],
        unique=False,
    )

    op.execute(_CREATE_AUDIT_MUTATION_REJECT_FN)
    op.execute(_CREATE_AUDIT_NO_UPDATE_TRIGGER)
    op.execute(_CREATE_AUDIT_NO_DELETE_TRIGGER)

    op.create_table(
        "custom_licence_federation_outbox",
        sa.Column("id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("custom_licence_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("operation", sa.String(length=32), nullable=False),
        sa.Column("status", sa.String(length=32), nullable=False),
        sa.Column("attempt_count", sa.Integer(), nullable=False),
        sa.Column("available_at", sa.DateTime(timezone=True), server_default=sa.text("now()"), nullable=False),
        sa.Column("lease_owner", sa.String(length=128), nullable=True),
        sa.Column("lease_expires_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("last_error_class", sa.String(length=128), nullable=True),
        sa.Column("last_error_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("federation_record_id", postgresql.UUID(as_uuid=True), nullable=True),
        sa.Column("federation_event_id", postgresql.UUID(as_uuid=True), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.text("now()"), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.text("now()"), nullable=False),
        sa.Column("published_at", sa.DateTime(timezone=True), nullable=True),
        sa.CheckConstraint(
            "operation IN ('upsert')",
            name="ck_custom_licence_federation_outbox_operation",
        ),
        sa.CheckConstraint(
            "status IN ('pending','processing','published','retryable_failed','permanently_failed')",
            name="ck_custom_licence_federation_outbox_status",
        ),
        sa.CheckConstraint("attempt_count >= 0", name="ck_custom_licence_federation_outbox_attempt_count_nonneg"),
        sa.CheckConstraint(
            "(status = 'processing') = (lease_owner IS NOT NULL)",
            name="ck_custom_licence_federation_outbox_processing_requires_owner",
        ),
        sa.CheckConstraint(
            "(lease_owner IS NULL) = (lease_expires_at IS NULL)",
            name="ck_custom_licence_federation_outbox_lease_fields_consistent",
        ),
        sa.CheckConstraint(
            "status != 'published' OR (federation_record_id IS NOT NULL AND federation_event_id IS NOT NULL AND published_at IS NOT NULL)",
            name="ck_custom_licence_federation_outbox_published_requires_linkage",
        ),
        sa.CheckConstraint(
            "(published_at IS NULL) OR (status = 'published')",
            name="ck_custom_licence_federation_outbox_published_at_iff_published",
        ),
        sa.CheckConstraint(
            "(last_error_class IS NULL) = (last_error_at IS NULL)",
            name="ck_custom_licence_federation_outbox_error_fields_consistent",
        ),
        sa.ForeignKeyConstraint(
            ["custom_licence_id"],
            ["custom_licences.id"],
            name="fk_custom_licence_federation_outbox_custom_licence_id",
            ondelete="RESTRICT",
        ),
        sa.ForeignKeyConstraint(
            ["federation_event_id"],
            ["federation_change_events.id"],
            name="fk_custom_licence_federation_outbox_federation_event_id",
            ondelete="RESTRICT",
        ),
        sa.ForeignKeyConstraint(
            ["federation_record_id"],
            ["federation_records.id"],
            name="fk_custom_licence_federation_outbox_federation_record_id",
            ondelete="RESTRICT",
        ),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint(
            "custom_licence_id",
            "operation",
            name="uq_custom_licence_federation_outbox_licence_operation",
        ),
    )
    op.create_index(
        "ix_custom_licence_federation_outbox_status_available_at",
        "custom_licence_federation_outbox",
        ["status", "available_at"],
        unique=False,
    )
    op.create_index(
        "ix_custom_licence_federation_outbox_status_lease_expires_at",
        "custom_licence_federation_outbox",
        ["status", "lease_expires_at"],
        unique=False,
    )
    op.create_index(
        "ix_custom_licence_federation_outbox_custom_licence_id",
        "custom_licence_federation_outbox",
        ["custom_licence_id"],
        unique=False,
    )
    op.create_index(
        "uix_custom_licence_federation_outbox_federation_record_id",
        "custom_licence_federation_outbox",
        ["federation_record_id"],
        unique=True,
        postgresql_where=sa.text("federation_record_id IS NOT NULL"),
    )
    op.create_index(
        "uix_custom_licence_federation_outbox_federation_event_id",
        "custom_licence_federation_outbox",
        ["federation_event_id"],
        unique=True,
        postgresql_where=sa.text("federation_event_id IS NOT NULL"),
    )
    op.execute("DROP FUNCTION IF EXISTS lfs_reject_change_events_mutation()")


def downgrade() -> None:
    op.execute(
        """
        DO $$
        DECLARE
            custom_rows bigint;
        BEGIN
            SELECT
                (SELECT COUNT(*) FROM custom_licence_federation_outbox)
              + (SELECT COUNT(*) FROM custom_licence_audit_events)
              + (SELECT COUNT(*) FROM custom_licence_aliases)
              + (SELECT COUNT(*) FROM custom_licences)
            INTO custom_rows;
            IF custom_rows > 0 THEN
                RAISE EXCEPTION
                    'Cannot downgrade 20260828_01 while custom-licence tables contain data. Archive or remove custom-licence rows first.';
            END IF;
        END
        $$;
        """
    )

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

    op.execute(_DROP_AUDIT_MUTATION_TRIGGERS)
    op.execute(_DROP_AUDIT_MUTATION_FN)
    op.drop_index(
        "ix_custom_licence_audit_events_licence_created",
        table_name="custom_licence_audit_events",
    )
    op.drop_table("custom_licence_audit_events")

    op.drop_index(
        "ix_custom_licence_aliases_custom_licence_type",
        table_name="custom_licence_aliases",
    )
    op.drop_table("custom_licence_aliases")

    op.drop_index("ix_custom_licences_lifecycle_status", table_name="custom_licences")
    op.drop_index("ix_custom_licences_scope_status", table_name="custom_licences")
    op.drop_index("ix_custom_licences_authority_requested", table_name="custom_licences")
    op.drop_table("custom_licences")
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
