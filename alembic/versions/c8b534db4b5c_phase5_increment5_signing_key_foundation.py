"""phase5 increment5 signing key foundation

Revision ID: c8b534db4b5c
Revises: 20260814_01
Create Date: 2026-08-28 14:54:09.768889
"""

from __future__ import annotations

from typing import Sequence, Union

from alembic import op

# revision identifiers, used by Alembic.
revision: str = "c8b534db4b5c"
down_revision: Union[str, Sequence[str], None] = "20260814_01"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None

_LOCAL_KEY_ACTIONS = (
    "'local_key.inspect','local_key.stage','local_key.schedule',"
    "'local_key.schedule_cancel','local_key.activate','local_key.retire',"
    "'local_key.revoke','local_key.activation_failed','local_key.material_mismatch'"
)

_OLD_AUDIT_ACTIONS = (
    "'peer.enroll','peer.update','peer.disable','peer.archive',"
    "'peer.suspend','peer.resume','peer.circuit_reset','peer.probe',"
    "'peer_key.inspect','peer_key.approve','peer_key.retire',"
    "'peer_key.revoke','peer_key.collision_rejected',"
    "'signing_key.rotation_prepared','signing_key.rotation_activated',"
    "'signing_key.rotation_completed','signing_key.rotation_aborted',"
    "'cursor.inspect','cursor.checkpoint_requested',"
    "'cursor.checkpoint_applied','cursor.forward_jump_rejected',"
    "'sync.manual_triggered','sync.circuit_opened',"
    "'sync.circuit_half_opened','sync.circuit_closed',"
    "'conflict.decision_recorded','conflict.reopened',"
    "'conflict.stale_dismissed',"
    "'rdf.requeue','rdf.dead_letter_drained',"
    "'rdf.rebuild_triggered','rdf.reconcile_run',"
    "'worker.started','worker.stopped','worker.failed'"
)

_NEW_AUDIT_ACTIONS = (
    "'peer.enroll','peer.update','peer.disable','peer.archive',"
    "'peer.suspend','peer.resume','peer.circuit_reset','peer.probe',"
    "'peer_key.inspect','peer_key.approve','peer_key.retire',"
    "'peer_key.revoke','peer_key.collision_rejected',"
    "'signing_key.rotation_prepared','signing_key.rotation_activated',"
    "'signing_key.rotation_completed','signing_key.rotation_aborted',"
    "'local_key.inspect','local_key.stage','local_key.schedule',"
    "'local_key.schedule_cancel','local_key.activate','local_key.retire',"
    "'local_key.revoke','local_key.activation_failed','local_key.material_mismatch',"
    "'cursor.inspect','cursor.checkpoint_requested',"
    "'cursor.checkpoint_applied','cursor.forward_jump_rejected',"
    "'sync.manual_triggered','sync.circuit_opened',"
    "'sync.circuit_half_opened','sync.circuit_closed',"
    "'conflict.decision_recorded','conflict.reopened',"
    "'conflict.stale_dismissed',"
    "'rdf.requeue','rdf.dead_letter_drained',"
    "'rdf.rebuild_triggered','rdf.reconcile_run',"
    "'worker.started','worker.stopped','worker.failed'"
)


def upgrade() -> None:
    # Backfill and normalize pre-existing statuses before constraints.
    op.execute(
        """
        DO $$
        DECLARE
            unknown_count integer;
        BEGIN
            SELECT COUNT(*) INTO unknown_count
            FROM federation_signing_keys
            WHERE status NOT IN ('inactive','active','retired','revoked');
            IF unknown_count > 0 THEN
                RAISE EXCEPTION
                    'Unknown federation_signing_keys.status values found (%). Migration requires explicit cleanup first.',
                    unknown_count;
            END IF;
        END
        $$;
        """
    )
    op.execute("UPDATE federation_signing_keys SET status = 'staged' WHERE status = 'inactive'")
    op.execute("UPDATE federation_signing_keys SET is_active = false WHERE status IN ('retired','revoked')")
    op.execute(
        """
        WITH active_candidates AS (
            SELECT
                id,
                ROW_NUMBER() OVER (
                    ORDER BY updated_at DESC, created_at DESC, kid ASC
                ) AS rn
            FROM federation_signing_keys
            WHERE status = 'active' OR (is_active = true AND status = 'staged')
        )
        UPDATE federation_signing_keys AS fsk
        SET
            status = CASE WHEN c.rn = 1 THEN 'active' ELSE 'staged' END,
            is_active = CASE WHEN c.rn = 1 THEN true ELSE false END
        FROM active_candidates AS c
        WHERE fsk.id = c.id
        """
    )
    op.execute("UPDATE federation_signing_keys SET is_active = false WHERE status <> 'active'")

    # Schedule cleanup before uniqueness and staged-only constraints.
    op.execute("UPDATE federation_signing_keys SET rotation_scheduled_at = NULL WHERE status <> 'staged'")
    op.execute(
        """
        WITH scheduled AS (
            SELECT
                id,
                ROW_NUMBER() OVER (
                    ORDER BY rotation_scheduled_at ASC, kid ASC
                ) AS rn
            FROM federation_signing_keys
            WHERE rotation_scheduled_at IS NOT NULL
        )
        UPDATE federation_signing_keys AS fsk
        SET rotation_scheduled_at = NULL
        FROM scheduled AS s
        WHERE fsk.id = s.id
          AND s.rn > 1
        """
    )

    # Prevent invalid rotated_to_kid data before FK.
    op.execute(
        """
        DO $$
        DECLARE
            bad_fk_count integer;
        BEGIN
            SELECT COUNT(*) INTO bad_fk_count
            FROM federation_signing_keys k
            WHERE k.rotated_to_kid IS NOT NULL
              AND NOT EXISTS (
                  SELECT 1
                  FROM federation_signing_keys target
                  WHERE target.kid = k.rotated_to_kid
              );
            IF bad_fk_count > 0 THEN
                RAISE EXCEPTION
                    'Invalid rotated_to_kid references found (%). Migration requires explicit cleanup first.',
                    bad_fk_count;
            END IF;
        END
        $$;
        """
    )

    op.alter_column("federation_signing_keys", "status", server_default="staged")

    op.create_check_constraint(
        "ck_fsk_status_v5",
        "federation_signing_keys",
        "status IN ('staged','active','retired','revoked')",
    )
    op.create_check_constraint(
        "ck_fsk_active_status_equivalence_v5",
        "federation_signing_keys",
        "is_active = (status = 'active')",
    )
    op.create_check_constraint(
        "ck_fsk_schedule_only_staged_v5",
        "federation_signing_keys",
        "rotation_scheduled_at IS NULL OR status = 'staged'",
    )
    op.create_check_constraint(
        "ck_fsk_rotated_to_status_v5",
        "federation_signing_keys",
        "rotated_to_kid IS NULL OR status IN ('retired','revoked')",
    )
    op.create_check_constraint(
        "ck_fsk_rotated_to_self_v5",
        "federation_signing_keys",
        "rotated_to_kid IS NULL OR rotated_to_kid <> kid",
    )
    op.create_check_constraint(
        "ck_fsk_validity_bounds_v5",
        "federation_signing_keys",
        "valid_from IS NULL OR valid_until IS NULL OR valid_from < valid_until",
    )
    op.create_foreign_key(
        "fk_fsk_rotated_to_kid_v5",
        "federation_signing_keys",
        "federation_signing_keys",
        ["rotated_to_kid"],
        ["kid"],
        ondelete="RESTRICT",
    )

    op.execute(
        "CREATE UNIQUE INDEX uq_fsk_single_scheduled_v5 "
        "ON federation_signing_keys ((1)) "
        "WHERE rotation_scheduled_at IS NOT NULL"
    )

    op.drop_constraint("ck_foa_action", "federation_operational_audit", type_="check")
    op.create_check_constraint(
        "ck_foa_action",
        "federation_operational_audit",
        f"action IN ({_NEW_AUDIT_ACTIONS})",
    )


def downgrade() -> None:
    op.execute(
        f"""
        DO $$
        DECLARE
            local_key_rows integer;
        BEGIN
            SELECT COUNT(*) INTO local_key_rows
            FROM federation_operational_audit
            WHERE action IN ({_LOCAL_KEY_ACTIONS});
            IF local_key_rows > 0 THEN
                RAISE EXCEPTION
                    'Cannot downgrade Increment 5: federation_operational_audit contains local_key.* history. Keep current schema or archive those rows externally before downgrade.';
            END IF;
        END
        $$;
        """
    )

    op.drop_constraint("ck_foa_action", "federation_operational_audit", type_="check")
    op.create_check_constraint(
        "ck_foa_action",
        "federation_operational_audit",
        f"action IN ({_OLD_AUDIT_ACTIONS})",
    )

    op.execute("DROP INDEX IF EXISTS uq_fsk_single_scheduled_v5")
    op.drop_constraint("fk_fsk_rotated_to_kid_v5", "federation_signing_keys", type_="foreignkey")
    op.drop_constraint("ck_fsk_validity_bounds_v5", "federation_signing_keys", type_="check")
    op.drop_constraint("ck_fsk_rotated_to_self_v5", "federation_signing_keys", type_="check")
    op.drop_constraint("ck_fsk_rotated_to_status_v5", "federation_signing_keys", type_="check")
    op.drop_constraint("ck_fsk_schedule_only_staged_v5", "federation_signing_keys", type_="check")
    op.drop_constraint("ck_fsk_active_status_equivalence_v5", "federation_signing_keys", type_="check")
    op.drop_constraint("ck_fsk_status_v5", "federation_signing_keys", type_="check")

    # Preserve rows and public key material; only map staged back to inactive
    # for compatibility with pre-Increment-5 runtime assumptions.
    op.execute("UPDATE federation_signing_keys SET status = 'inactive' WHERE status = 'staged'")
    op.execute("UPDATE federation_signing_keys SET is_active = false WHERE status <> 'active'")

    op.alter_column("federation_signing_keys", "status", server_default="active")
