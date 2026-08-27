"""Phase 5 Increment 1: operational schema and general audit foundation.

Creates:
  - federation_operational_audit (append-only, DB-level triggers)
  - federation_sync_leases (persisted expiring lease with monotonic fencing token)
  - federation_worker_heartbeats (cross-container freshness via DB)
  - federation_peer_health_snapshots (per-probe health history)
  - Sequence: federation_sync_lease_fencing_seq

Alters:
  - federation_signing_keys: rotation_scheduled_at, rotated_to_kid
  - federation_trusted_peers: circuit breaker columns, suspension columns,
    last_key_refresh_at

Downgrading removes all Phase 5 operational data. Phase 1-4 data is unaffected.

Revision ID: 20260814_01
Revises: 20260804_05_phase4_rdf_leases
Create Date: 2026-08-14
"""

from __future__ import annotations

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "20260814_01"
down_revision: Union[str, Sequence[str], None] = "20260804_05_phase4_rdf_leases"
branch_labels = None
depends_on = None


# ---------------------------------------------------------------------------
# Bounded vocabulary constants (kept in sync with Python enums in audit.py)
# ---------------------------------------------------------------------------

_AUDIT_ACTOR_TYPES = (
    "'human_operator','worker','system','api_client'"
)

_AUDIT_ACTIONS = (
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

_AUDIT_TARGET_TYPES = (
    "'peer','peer_key','signing_key','cursor','conflict',"
    "'rdf_job','sync_attempt','record','worker'"
)

_AUDIT_OUTCOMES = (
    "'success','rejected','failed','blocked','dry_run','partial'"
)

_CIRCUIT_STATES = "'closed','open','half_open'"

_CIRCUIT_FAILURE_REASONS = (
    "'network_unreachable','tls_error','remote_5xx','clock_skew',"
    "'discovery_parse_failure','jwks_parse_failure',"
    "'signature_invalid','identity_mismatch',"
    "'revoked_key_detected','key_collision','protocol_incompatible'"
)

_WORKER_TYPES = "'sync','rdf','probe'"

_WORKER_STATUSES = "'running','idle','error','stopped'"

_LEASE_TRIGGER_TYPES = "'scheduled','manual','probe','cursor_recovery'"

_HEALTH_STATUSES = "'healthy','degraded','unreachable','unknown'"

_COMPAT_STATUSES = "'compatible','incompatible','unknown','unchecked'"


# ---------------------------------------------------------------------------
# Trigger SQL
# ---------------------------------------------------------------------------

_CREATE_TRIGGER_FN = """\
CREATE OR REPLACE FUNCTION lfs_foa_reject_mutation()
RETURNS trigger AS $$
BEGIN
    RAISE EXCEPTION
        'federation_operational_audit is append-only: % is not permitted',
        TG_OP;
END;
$$ LANGUAGE plpgsql;
"""

_CREATE_TRIGGER_NO_UPDATE = """\
CREATE TRIGGER trg_foa_no_update
    BEFORE UPDATE ON federation_operational_audit
    FOR EACH ROW EXECUTE FUNCTION lfs_foa_reject_mutation();
"""

_CREATE_TRIGGER_NO_DELETE = """\
CREATE TRIGGER trg_foa_no_delete
    BEFORE DELETE ON federation_operational_audit
    FOR EACH ROW EXECUTE FUNCTION lfs_foa_reject_mutation();
"""

_DROP_TRIGGERS = """\
DROP TRIGGER IF EXISTS trg_foa_no_update ON federation_operational_audit;
DROP TRIGGER IF EXISTS trg_foa_no_delete ON federation_operational_audit;
"""

_DROP_TRIGGER_FN = "DROP FUNCTION IF EXISTS lfs_foa_reject_mutation;"


# ---------------------------------------------------------------------------
# Upgrade
# ---------------------------------------------------------------------------


def upgrade() -> None:
    # ------------------------------------------------------------------
    # 1. Create monotonic fencing-token sequence
    # ------------------------------------------------------------------
    op.execute("CREATE SEQUENCE federation_sync_lease_fencing_seq AS BIGINT START 1 INCREMENT 1 NO CYCLE;")

    # ------------------------------------------------------------------
    # 2. federation_operational_audit
    #    - append-only (triggers below)
    #    - peer_id: ON DELETE RESTRICT (archive-only peer management)
    #    - target_id: VARCHAR(256) stores stable UUIDs/kids; canonical
    #      identifiers exceeding this are stored truncated in
    #      redacted_details by the application (see audit.py)
    # ------------------------------------------------------------------
    op.create_table(
        "federation_operational_audit",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True, server_default=sa.text("gen_random_uuid()")),
        sa.Column("occurred_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.text("now()")),
        sa.Column("request_id", sa.String(128), nullable=True),
        sa.Column("actor_type", sa.String(32), nullable=False),
        sa.Column("actor_id", sa.String(256), nullable=True),
        sa.Column("action", sa.String(64), nullable=False),
        sa.Column("target_type", sa.String(64), nullable=False),
        sa.Column("target_id", sa.String(256), nullable=False),
        sa.Column(
            "peer_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("federation_trusted_peers.id", ondelete="RESTRICT", name="fk_foa_peer_id"),
            nullable=True,
        ),
        sa.Column("outcome", sa.String(32), nullable=False),
        sa.Column("reason", sa.Text(), nullable=True),
        sa.Column("redacted_details", postgresql.JSONB(), nullable=True),
        sa.CheckConstraint(f"actor_type IN ({_AUDIT_ACTOR_TYPES})", name="ck_foa_actor_type"),
        sa.CheckConstraint(f"action IN ({_AUDIT_ACTIONS})", name="ck_foa_action"),
        sa.CheckConstraint(f"target_type IN ({_AUDIT_TARGET_TYPES})", name="ck_foa_target_type"),
        sa.CheckConstraint(f"outcome IN ({_AUDIT_OUTCOMES})", name="ck_foa_outcome"),
        sa.CheckConstraint("reason IS NULL OR char_length(reason) <= 1024", name="ck_foa_reason_len"),
        sa.CheckConstraint("actor_id IS NULL OR char_length(actor_id) <= 256", name="ck_foa_actor_id_len"),
        sa.CheckConstraint("target_id IS NOT NULL AND char_length(target_id) <= 256", name="ck_foa_target_id_len"),
        sa.CheckConstraint("request_id IS NULL OR char_length(request_id) <= 128", name="ck_foa_request_id_len"),
    )
    op.create_index("idx_foa_occurred_at", "federation_operational_audit", ["occurred_at"])
    op.create_index("idx_foa_peer_id", "federation_operational_audit", ["peer_id"])
    op.create_index("idx_foa_action", "federation_operational_audit", ["action"])
    op.create_index("idx_foa_request_id", "federation_operational_audit", ["request_id"])

    # Append-only triggers
    op.execute(_CREATE_TRIGGER_FN)
    op.execute(_CREATE_TRIGGER_NO_UPDATE)
    op.execute(_CREATE_TRIGGER_NO_DELETE)

    # ------------------------------------------------------------------
    # 3. federation_sync_leases
    #    UNIQUE(peer_id): one active lease per peer.
    #    Atomic claim via INSERT ... ON CONFLICT DO UPDATE WHERE expires_at < now()
    #    fencing_token from global monotonic sequence (never resets).
    # ------------------------------------------------------------------
    op.create_table(
        "federation_sync_leases",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True, server_default=sa.text("gen_random_uuid()")),
        sa.Column(
            "peer_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("federation_trusted_peers.id", ondelete="RESTRICT", name="fk_fsl_peer_id"),
            nullable=False,
            unique=True,
        ),
        sa.Column("owner_instance_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column(
            "fencing_token",
            sa.BigInteger(),
            nullable=False,
            server_default=sa.text("nextval('federation_sync_lease_fencing_seq')"),
        ),
        sa.Column("acquired_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.text("now()")),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("heartbeat_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("trigger_type", sa.String(32), nullable=False),
        sa.CheckConstraint(f"trigger_type IN ({_LEASE_TRIGGER_TYPES})", name="ck_fsl_trigger_type"),
        sa.CheckConstraint("expires_at > acquired_at", name="ck_fsl_expiry_after_acquired"),
    )
    op.create_index("idx_fsl_peer_id", "federation_sync_leases", ["peer_id"])
    op.create_index("idx_fsl_expires_at", "federation_sync_leases", ["expires_at"])

    # ------------------------------------------------------------------
    # 4. federation_worker_heartbeats
    #    Cross-container freshness via DB. Workers write here; API reads here.
    #    No raw exception text stored (last_error_class is bounded enum-like).
    # ------------------------------------------------------------------
    op.create_table(
        "federation_worker_heartbeats",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True, server_default=sa.text("gen_random_uuid()")),
        sa.Column("worker_type", sa.String(32), nullable=False),
        sa.Column("instance_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("hostname", sa.String(256), nullable=True),
        sa.Column("started_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.text("now()")),
        sa.Column("last_heartbeat_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.text("now()")),
        sa.Column("last_success_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("status", sa.String(32), nullable=False, server_default=sa.text("'running'")),
        sa.Column("last_error_class", sa.String(64), nullable=True),
        sa.Column("lease_expires_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.text("now()")),
        sa.UniqueConstraint("worker_type", "instance_id", name="uq_fwh_worker_instance"),
        sa.CheckConstraint(f"worker_type IN ({_WORKER_TYPES})", name="ck_fwh_worker_type"),
        sa.CheckConstraint(f"status IN ({_WORKER_STATUSES})", name="ck_fwh_status"),
        sa.CheckConstraint("hostname IS NULL OR char_length(hostname) <= 256", name="ck_fwh_hostname_len"),
        sa.CheckConstraint("last_error_class IS NULL OR char_length(last_error_class) <= 64", name="ck_fwh_error_class_len"),
    )
    op.create_index("idx_fwh_worker_type", "federation_worker_heartbeats", ["worker_type"])
    op.create_index("idx_fwh_last_heartbeat_at", "federation_worker_heartbeats", ["last_heartbeat_at"])

    # ------------------------------------------------------------------
    # 5. federation_peer_health_snapshots
    #    peer_id nullable: ON DELETE SET NULL preserves historical snapshots.
    #    peer_node_id TEXT: immutable historical identity even after SET NULL.
    # ------------------------------------------------------------------
    op.create_table(
        "federation_peer_health_snapshots",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True, server_default=sa.text("gen_random_uuid()")),
        sa.Column(
            "peer_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("federation_trusted_peers.id", ondelete="SET NULL", name="fk_fphs_peer_id"),
            nullable=True,
        ),
        sa.Column("peer_node_id", sa.Text(), nullable=False),
        sa.Column("sampled_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.text("now()")),
        sa.Column("discovery_reachable", sa.Boolean(), nullable=True),
        sa.Column("jwks_reachable", sa.Boolean(), nullable=True),
        sa.Column("feed_reachable", sa.Boolean(), nullable=True),
        sa.Column("last_event_position", sa.BigInteger(), nullable=True),
        sa.Column("round_trip_ms", sa.Integer(), nullable=True),
        sa.Column("health_status", sa.String(32), nullable=True),
        sa.Column("compatibility_status", sa.String(32), nullable=True),
        sa.Column("error_code", sa.String(64), nullable=True),
        sa.Column("error_detail", sa.Text(), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.text("now()")),
        sa.CheckConstraint(f"health_status IS NULL OR health_status IN ({_HEALTH_STATUSES})", name="ck_fphs_health_status"),
        sa.CheckConstraint(f"compatibility_status IS NULL OR compatibility_status IN ({_COMPAT_STATUSES})", name="ck_fphs_compat_status"),
        sa.CheckConstraint("round_trip_ms IS NULL OR round_trip_ms >= 0", name="ck_fphs_round_trip_nonneg"),
        sa.CheckConstraint("error_code IS NULL OR char_length(error_code) <= 64", name="ck_fphs_error_code_len"),
        sa.CheckConstraint("error_detail IS NULL OR char_length(error_detail) <= 1024", name="ck_fphs_error_detail_len"),
        sa.CheckConstraint("char_length(peer_node_id) <= 256", name="ck_fphs_peer_node_id_len"),
    )
    op.create_index("idx_fphs_peer_id", "federation_peer_health_snapshots", ["peer_id"])
    op.create_index("idx_fphs_sampled_at", "federation_peer_health_snapshots", ["sampled_at"])

    # ------------------------------------------------------------------
    # 6. Alter federation_signing_keys: rotation tracking columns
    # ------------------------------------------------------------------
    op.add_column("federation_signing_keys", sa.Column("rotation_scheduled_at", sa.DateTime(timezone=True), nullable=True))
    op.add_column("federation_signing_keys", sa.Column("rotated_to_kid", sa.String(128), nullable=True))

    # ------------------------------------------------------------------
    # 7. Alter federation_trusted_peers: circuit breaker + suspension +
    #    key-refresh tracking columns
    # ------------------------------------------------------------------
    op.add_column("federation_trusted_peers", sa.Column("circuit_state", sa.String(16), nullable=False, server_default=sa.text("'closed'")))
    op.add_column("federation_trusted_peers", sa.Column("circuit_requires_admin_reset", sa.Boolean(), nullable=False, server_default=sa.text("false")))
    op.add_column("federation_trusted_peers", sa.Column("circuit_failure_count", sa.Integer(), nullable=False, server_default=sa.text("0")))
    op.add_column("federation_trusted_peers", sa.Column("circuit_opened_at", sa.DateTime(timezone=True), nullable=True))
    op.add_column("federation_trusted_peers", sa.Column("circuit_next_attempt_at", sa.DateTime(timezone=True), nullable=True))
    op.add_column("federation_trusted_peers", sa.Column("circuit_half_open_probe_count", sa.Integer(), nullable=False, server_default=sa.text("0")))
    op.add_column("federation_trusted_peers", sa.Column("circuit_last_failure_reason", sa.String(64), nullable=True))
    op.add_column("federation_trusted_peers", sa.Column("suspended_until", sa.DateTime(timezone=True), nullable=True))
    op.add_column("federation_trusted_peers", sa.Column("suspension_reason", sa.String(1024), nullable=True))
    op.add_column("federation_trusted_peers", sa.Column("last_key_refresh_at", sa.DateTime(timezone=True), nullable=True))

    op.create_check_constraint("ck_ftp_circuit_state", "federation_trusted_peers", f"circuit_state IN ({_CIRCUIT_STATES})")
    op.create_check_constraint(
        "ck_ftp_circuit_reason",
        "federation_trusted_peers",
        f"circuit_last_failure_reason IS NULL OR circuit_last_failure_reason IN ({_CIRCUIT_FAILURE_REASONS})",
    )
    op.create_check_constraint(
        "ck_ftp_suspension_reason_len",
        "federation_trusted_peers",
        "suspension_reason IS NULL OR char_length(suspension_reason) <= 1024",
    )


# ---------------------------------------------------------------------------
# Downgrade
# ---------------------------------------------------------------------------


def downgrade() -> None:
    # Remove CHECK constraints from federation_trusted_peers
    op.drop_constraint("ck_ftp_suspension_reason_len", "federation_trusted_peers", type_="check")
    op.drop_constraint("ck_ftp_circuit_reason", "federation_trusted_peers", type_="check")
    op.drop_constraint("ck_ftp_circuit_state", "federation_trusted_peers", type_="check")

    # Remove new columns from federation_trusted_peers
    for col in [
        "last_key_refresh_at",
        "suspension_reason",
        "suspended_until",
        "circuit_last_failure_reason",
        "circuit_half_open_probe_count",
        "circuit_next_attempt_at",
        "circuit_opened_at",
        "circuit_failure_count",
        "circuit_requires_admin_reset",
        "circuit_state",
    ]:
        op.drop_column("federation_trusted_peers", col)

    # Remove new columns from federation_signing_keys
    op.drop_column("federation_signing_keys", "rotated_to_kid")
    op.drop_column("federation_signing_keys", "rotation_scheduled_at")

    # Drop triggers and function before dropping audit table
    op.execute(_DROP_TRIGGERS)
    op.execute(_DROP_TRIGGER_FN)

    # Drop new tables (reverse dependency order)
    op.drop_table("federation_peer_health_snapshots")
    op.drop_table("federation_worker_heartbeats")
    op.drop_table("federation_sync_leases")
    op.drop_table("federation_operational_audit")

    # Drop sequence
    op.execute("DROP SEQUENCE IF EXISTS federation_sync_lease_fencing_seq;")
