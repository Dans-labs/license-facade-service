"""federation/operational_queries.py — Read-only synchronous query functions for Phase 5 Increment 2 operational status APIs.

All functions use Database.transaction() (sync SQLAlchemy Session via psycopg2).
No network I/O, no table locks, no mutations.
"""

from __future__ import annotations

import uuid
from collections import defaultdict
from datetime import datetime, timedelta, timezone
from typing import Any

from sqlalchemy import and_, func, or_, select, text

from src.license_facade_service.config.federation import FederationSettings
from src.license_facade_service.db.models.federation import (
    FederationPeerCursor,
    FederationPeerHealthSnapshot,
    FederationRdfOutboxJob,
    FederationResolutionConflict,
    FederationSigningKey,
    FederationSyncAttempt,
    FederationTrustedPeer,
    FederationWorkerHeartbeat,
)
from src.license_facade_service.db.session import Database
from src.license_facade_service.federation.operational_models import build_cursor, filters_hash

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

_RDF_VALID_STATUSES = frozenset({"pending", "running", "succeeded", "retryable_failed", "dead_lettered", "superseded"})


def _health_snapshot_to_dict(row: FederationPeerHealthSnapshot) -> dict:
    return {
        "id": row.id,
        "peer_id": row.peer_id,
        "peer_node_id": row.peer_node_id,
        "sampled_at": row.sampled_at,
        "discovery_reachable": row.discovery_reachable,
        "jwks_reachable": row.jwks_reachable,
        "feed_reachable": row.feed_reachable,
        "last_event_position": row.last_event_position,
        "round_trip_ms": row.round_trip_ms,
        "health_status": row.health_status,
        "compatibility_status": row.compatibility_status,
        "error_code": row.error_code,
        "error_detail": row.error_detail,
    }


def _rdf_job_to_dict(row: FederationRdfOutboxJob) -> dict:
    return {
        "id": row.id,
        "record_id": row.record_id,
        "authority_node_id": row.authority_node_id,
        "job_type": row.job_type,
        "status": row.status,
        "attempt_count": row.attempt_count,
        "next_attempt_at": row.next_attempt_at,
        "leased_until": row.leased_until,
        "last_error_code": row.last_error_code,
        "dead_lettered_at": row.dead_lettered_at,
        "created_at": row.created_at,
        "updated_at": row.updated_at,
    }


def _sync_attempt_to_dict(row: FederationSyncAttempt) -> dict:
    return {
        "id": row.id,
        "peer_id": row.peer_id,
        "started_at": row.started_at,
        "completed_at": row.completed_at,
        "status": row.status,
        "trigger_type": row.trigger_type,
        "pages_processed": row.pages_processed,
        "events_processed": row.events_processed,
        "error_code": row.error_code,
        "created_at": row.created_at,
    }


# ---------------------------------------------------------------------------
# Operational status extension
# ---------------------------------------------------------------------------


def query_operational_status_extension(db: Database, settings: FederationSettings) -> dict:
    """Returns dict with keys matching new optional AdminStatusResponse fields."""
    with db.transaction() as session:
        # --- Signing keys ---
        sk_status_rows = session.execute(
            select(FederationSigningKey.status, func.count().label("cnt")).group_by(FederationSigningKey.status)
        ).all()
        sk_active_kid = session.execute(
            select(FederationSigningKey.kid).where(FederationSigningKey.is_active.is_(True))
        ).scalar_one_or_none()
        sk_counts: dict[str, int] = {r.status: r.cnt for r in sk_status_rows}

        # --- Peers ---
        peer_trust_rows = session.execute(
            select(FederationTrustedPeer.trust_status, func.count().label("cnt")).group_by(
                FederationTrustedPeer.trust_status
            )
        ).all()
        peer_circuit_rows = session.execute(
            select(FederationTrustedPeer.circuit_state, func.count().label("cnt")).group_by(
                FederationTrustedPeer.circuit_state
            )
        ).all()
        sync_enabled_cnt = int(
            session.execute(
                select(func.count()).select_from(FederationTrustedPeer).where(
                    FederationTrustedPeer.sync_enabled.is_(True)
                )
            ).scalar_one()
        )
        sync_disabled_cnt = int(
            session.execute(
                select(func.count()).select_from(FederationTrustedPeer).where(
                    FederationTrustedPeer.sync_enabled.is_(False)
                )
            ).scalar_one()
        )
        now_utc = datetime.now(timezone.utc)
        suspended_cnt = int(
            session.execute(
                select(func.count()).select_from(FederationTrustedPeer).where(
                    FederationTrustedPeer.suspended_until > now_utc
                )
            ).scalar_one()
        )

        # --- Sync attempts ---
        sa_rows = session.execute(
            select(FederationSyncAttempt.status, func.count().label("cnt")).group_by(
                FederationSyncAttempt.status
            )
        ).all()
        most_recent_attempt = session.execute(
            select(func.max(FederationSyncAttempt.started_at))
        ).scalar_one_or_none()
        most_recent_success = session.execute(
            select(func.max(FederationTrustedPeer.last_sync_success_at))
        ).scalar_one_or_none()

        # --- Conflicts ---
        conflict_rows = session.execute(
            select(FederationResolutionConflict.status, func.count().label("cnt")).group_by(
                FederationResolutionConflict.status
            )
        ).all()

        # --- RDF outbox ---
        rdf_rows = session.execute(
            select(FederationRdfOutboxJob.status, func.count().label("cnt")).group_by(
                FederationRdfOutboxJob.status
            )
        ).all()

        # --- Worker heartbeats ---
        wh_rows = session.execute(
            select(FederationWorkerHeartbeat).order_by(FederationWorkerHeartbeat.worker_type)
        ).scalars().all()

        # --- Health snapshots summary ---
        hs_health_rows = session.execute(
            select(FederationPeerHealthSnapshot.health_status, func.count().label("cnt")).group_by(
                FederationPeerHealthSnapshot.health_status
            )
        ).all()
        hs_compat_rows = session.execute(
            select(FederationPeerHealthSnapshot.compatibility_status, func.count().label("cnt")).group_by(
                FederationPeerHealthSnapshot.compatibility_status
            )
        ).all()

    # --- Worker summary (post-query, no DB access) ---
    stale_threshold = now_utc - timedelta(minutes=5)
    wh_by_type: dict[str, list[Any]] = defaultdict(list)
    for wh in wh_rows:
        wh_by_type[wh.worker_type].append(wh)

    worker_summaries = []
    for wt, instances in sorted(wh_by_type.items()):
        fresh = sum(
            1 for w in instances
            if w.last_heartbeat_at and w.last_heartbeat_at.replace(tzinfo=timezone.utc) > stale_threshold
            if w.last_heartbeat_at
        )
        stale = len(instances) - fresh
        hb_times = [w.last_heartbeat_at for w in instances if w.last_heartbeat_at]
        succ_times = [w.last_success_at for w in instances if w.last_success_at]
        worker_summaries.append({
            "workerType": wt,
            "registeredInstances": len(instances),
            "freshInstances": fresh,
            "staleInstances": stale,
            "mostRecentHeartbeatAt": max(hb_times) if hb_times else None,
            "mostRecentSuccessAt": max(succ_times) if succ_times else None,
        })

    # --- Operational state ---
    circuit_counts: dict[str, int] = {r.circuit_state: r.cnt for r in peer_circuit_rows}
    non_closed = sum(v for k, v in circuit_counts.items() if k != "closed")
    has_data = bool(sa_rows or peer_trust_rows)
    if not has_data:
        op_state = "unknown"
    elif non_closed > 0 or suspended_cnt > 0:
        op_state = "degraded"
    else:
        op_state = "healthy"

    return {
        "protocolVersion": "1.0",
        "signingKeySummary": {"activeKid": sk_active_kid, "countByStatus": sk_counts},
        "peerSummary": {
            "byTrustStatus": {r.trust_status: r.cnt for r in peer_trust_rows},
            "syncEnabled": sync_enabled_cnt,
            "syncDisabled": sync_disabled_cnt,
            "byCircuitState": circuit_counts,
            "administrativelySuspended": suspended_cnt,
        },
        "syncSummary": {
            "totalAttempts": sum(r.cnt for r in sa_rows),
            "byStatus": {r.status: r.cnt for r in sa_rows},
            "mostRecentAttemptAt": most_recent_attempt,
            "mostRecentSuccessAt": most_recent_success,
        },
        "conflictsByStatus": {r.status: r.cnt for r in conflict_rows},
        "rdfOutboxByStatus": {r.status: r.cnt for r in rdf_rows},
        "workerHeartbeatSummary": worker_summaries,
        "healthSnapshotSummary": {
            "byHealthStatus": {str(r.health_status): r.cnt for r in hs_health_rows if r.health_status},
            "byCompatibilityStatus": {str(r.compatibility_status): r.cnt for r in hs_compat_rows if r.compatibility_status},
        },
        "operationalState": op_state,
    }


# ---------------------------------------------------------------------------
# Latest peer health
# ---------------------------------------------------------------------------


def query_latest_peer_health(db: Database, peer_id: uuid.UUID) -> dict | None:
    """Returns latest health snapshot dict for a peer, or None."""
    with db.transaction() as session:
        row = session.execute(
            select(FederationPeerHealthSnapshot)
            .where(FederationPeerHealthSnapshot.peer_id == peer_id)
            .order_by(FederationPeerHealthSnapshot.sampled_at.desc(), FederationPeerHealthSnapshot.id.desc())
            .limit(1)
        ).scalar_one_or_none()
    if row is None:
        return None
    return _health_snapshot_to_dict(row)


# ---------------------------------------------------------------------------
# Health history with keyset pagination
# ---------------------------------------------------------------------------


def query_health_history(
    db: Database,
    peer_id: uuid.UUID,
    *,
    limit: int,
    cursor_data: dict | None,
    health_status_filter: str | None,
    compat_status_filter: str | None,
    cursor_audience: str | None = None,
    cursor_secret: bytes | None = None,
) -> tuple[list[dict], str | None]:
    """Keyset paginated health snapshots, descending sampled_at + id tie-breaker."""
    with db.transaction() as session:
        stmt = select(FederationPeerHealthSnapshot).where(
            FederationPeerHealthSnapshot.peer_id == peer_id
        )
        if health_status_filter:
            stmt = stmt.where(FederationPeerHealthSnapshot.health_status == health_status_filter)
        if compat_status_filter:
            stmt = stmt.where(FederationPeerHealthSnapshot.compatibility_status == compat_status_filter)
        if cursor_data:
            cursor_ts = datetime.fromisoformat(cursor_data["ts"])
            cursor_id = uuid.UUID(cursor_data["id"])
            stmt = stmt.where(
                or_(
                    FederationPeerHealthSnapshot.sampled_at < cursor_ts,
                    and_(
                        FederationPeerHealthSnapshot.sampled_at == cursor_ts,
                        FederationPeerHealthSnapshot.id < cursor_id,
                    ),
                )
            )
        stmt = stmt.order_by(
            FederationPeerHealthSnapshot.sampled_at.desc(),
            FederationPeerHealthSnapshot.id.desc(),
        ).limit(limit + 1)

        rows = session.execute(stmt).scalars().all()

    has_more = len(rows) > limit
    rows = list(rows[:limit])

    next_cursor = None
    if has_more and rows:
        last = rows[-1]
        fh = filters_hash(peer_id, health_status_filter, compat_status_filter, limit, "desc")
        next_cursor = build_cursor(
            kind="health",
            filters_hash=fh,
            last_ts=last.sampled_at.isoformat(),
            last_id=str(last.id),
            limit=limit,
            audience=cursor_audience,
            secret=cursor_secret,
        )

    return [_health_snapshot_to_dict(r) for r in rows], next_cursor


# ---------------------------------------------------------------------------
# Peer cursor state
# ---------------------------------------------------------------------------


def query_peer_cursor_data(db: Database, peer_id: uuid.UUID) -> dict | None:
    """Returns cursor row data dict, including whether the peer exists."""
    with db.transaction() as session:
        # First check peer exists
        peer = session.execute(
            select(FederationTrustedPeer).where(FederationTrustedPeer.id == peer_id)
        ).scalar_one_or_none()
        if peer is None:
            return {"peer_exists": False}

        cursor_row = session.execute(
            select(FederationPeerCursor).where(FederationPeerCursor.peer_id == peer_id)
        ).scalar_one_or_none()

        return {
            "peer_exists": True,
            "peer_id": peer.id,
            "peer_node_id": peer.peer_node_id,
            "last_sync_success_at": peer.last_sync_success_at,
            "cursor_exists": cursor_row is not None,
            "cursor": cursor_row.cursor if cursor_row else None,
            "last_remote_position": cursor_row.last_remote_position if cursor_row else None,
            "updated_at": cursor_row.updated_at if cursor_row else None,
        }


# ---------------------------------------------------------------------------
# Signing keys
# ---------------------------------------------------------------------------


def query_signing_keys(db: Database) -> list[dict]:
    """Returns all local signing keys, no private material."""
    with db.transaction() as session:
        rows = session.execute(
            select(FederationSigningKey).order_by(FederationSigningKey.created_at)
        ).scalars().all()
    return [
        {
            "id": row.id,
            "kid": row.kid,
            "alg": row.alg,
            "kty": row.kty,
            "crv": row.crv,
            "x": row.x,
            "is_active": row.is_active,
            "status": row.status,
            "valid_from": row.valid_from,
            "valid_until": row.valid_until,
            "rotation_scheduled_at": row.rotation_scheduled_at,
            "rotated_to_kid": row.rotated_to_kid,
            "created_at": row.created_at,
            "updated_at": row.updated_at,
        }
        for row in rows
    ]


# ---------------------------------------------------------------------------
# RDF outbox with keyset pagination
# ---------------------------------------------------------------------------


def query_rdf_outbox(
    db: Database,
    *,
    limit: int,
    cursor_data: dict | None,
    status_filter: str | None,
    record_id_filter: uuid.UUID | None,
    cursor_audience: str | None = None,
    cursor_secret: bytes | None = None,
) -> tuple[list[dict], str | None]:
    """Keyset paginated RDF outbox jobs, descending updated_at + id."""
    with db.transaction() as session:
        stmt = select(FederationRdfOutboxJob)
        if status_filter:
            stmt = stmt.where(FederationRdfOutboxJob.status == status_filter)
        if record_id_filter:
            stmt = stmt.where(FederationRdfOutboxJob.record_id == record_id_filter)
        if cursor_data:
            cursor_ts = datetime.fromisoformat(cursor_data["ts"])
            cursor_id = uuid.UUID(cursor_data["id"])
            stmt = stmt.where(
                or_(
                    FederationRdfOutboxJob.updated_at < cursor_ts,
                    and_(
                        FederationRdfOutboxJob.updated_at == cursor_ts,
                        FederationRdfOutboxJob.id < cursor_id,
                    ),
                )
            )
        stmt = stmt.order_by(
            FederationRdfOutboxJob.updated_at.desc(),
            FederationRdfOutboxJob.id.desc(),
        ).limit(limit + 1)

        rows = session.execute(stmt).scalars().all()

    has_more = len(rows) > limit
    rows = list(rows[:limit])

    next_cursor = None
    if has_more and rows:
        last = rows[-1]
        fh = filters_hash(status_filter, record_id_filter, limit, "desc")
        next_cursor = build_cursor(
            kind="rdf",
            filters_hash=fh,
            last_ts=last.updated_at.isoformat(),
            last_id=str(last.id),
            limit=limit,
            audience=cursor_audience,
            secret=cursor_secret,
        )

    return [_rdf_job_to_dict(r) for r in rows], next_cursor


# ---------------------------------------------------------------------------
# Sync attempts with keyset pagination
# ---------------------------------------------------------------------------


def query_sync_attempts(
    db: Database,
    *,
    limit: int,
    cursor_data: dict | None,
    peer_id_filter: uuid.UUID | None,
    status_filter: str | None,
    error_class_filter: str | None,
    started_after: datetime | None,
    started_before: datetime | None,
    cursor_audience: str | None = None,
    cursor_secret: bytes | None = None,
) -> tuple[list[dict], str | None]:
    """Keyset paginated sync attempts, descending started_at + id."""
    with db.transaction() as session:
        stmt = select(FederationSyncAttempt)
        if peer_id_filter:
            stmt = stmt.where(FederationSyncAttempt.peer_id == peer_id_filter)
        if status_filter:
            stmt = stmt.where(FederationSyncAttempt.status == status_filter)
        if error_class_filter:
            stmt = stmt.where(FederationSyncAttempt.error_code == error_class_filter)
        if started_after:
            stmt = stmt.where(FederationSyncAttempt.started_at > started_after)
        if started_before:
            stmt = stmt.where(FederationSyncAttempt.started_at < started_before)
        if cursor_data:
            cursor_ts = datetime.fromisoformat(cursor_data["ts"])
            cursor_id = uuid.UUID(cursor_data["id"])
            stmt = stmt.where(
                or_(
                    FederationSyncAttempt.started_at < cursor_ts,
                    and_(
                        FederationSyncAttempt.started_at == cursor_ts,
                        FederationSyncAttempt.id < cursor_id,
                    ),
                )
            )
        stmt = stmt.order_by(
            FederationSyncAttempt.started_at.desc(),
            FederationSyncAttempt.id.desc(),
        ).limit(limit + 1)

        rows = session.execute(stmt).scalars().all()

    has_more = len(rows) > limit
    rows = list(rows[:limit])

    next_cursor = None
    if has_more and rows:
        last = rows[-1]
        fh = filters_hash(peer_id_filter, status_filter, error_class_filter, started_after, started_before, limit, "desc")
        next_cursor = build_cursor(
            kind="sync",
            filters_hash=fh,
            last_ts=last.started_at.isoformat(),
            last_id=str(last.id),
            limit=limit,
            audience=cursor_audience,
            secret=cursor_secret,
        )

    return [_sync_attempt_to_dict(r) for r in rows], next_cursor


# ---------------------------------------------------------------------------
# Compatibility report
# ---------------------------------------------------------------------------


def query_compatibility_report(db: Database, settings: FederationSettings) -> dict:
    """Returns compatibility report data. No network calls."""
    with db.transaction() as session:
        peers = session.execute(
            select(FederationTrustedPeer).order_by(FederationTrustedPeer.created_at)
        ).scalars().all()

        # Get latest health snapshot per peer for compat status
        # Use a subquery to get max sampled_at per peer, then join
        peer_ids = [p.id for p in peers]
        latest_compat: dict[uuid.UUID, tuple[str, datetime | None]] = {}
        if peer_ids:
            for pid in peer_ids:
                snap = session.execute(
                    select(FederationPeerHealthSnapshot)
                    .where(FederationPeerHealthSnapshot.peer_id == pid)
                    .order_by(
                        FederationPeerHealthSnapshot.sampled_at.desc(),
                        FederationPeerHealthSnapshot.id.desc(),
                    )
                    .limit(1)
                ).scalar_one_or_none()
                if snap:
                    latest_compat[pid] = (snap.compatibility_status or "unchecked", snap.sampled_at)
                else:
                    latest_compat[pid] = ("unchecked", None)

    peer_entries = []
    for peer in peers:
        compat_status, last_checked = latest_compat.get(peer.id, ("unchecked", None))
        peer_entries.append({
            "peer_id": peer.id,
            "peer_node_id": peer.peer_node_id,
            "peer_name": peer.peer_name,
            "compatibility_status": compat_status,
            "last_checked_at": last_checked,
        })

    local_caps = list(getattr(settings, "conformance", None) or [])
    if not local_caps:
        local_caps = ["federation/v1"]

    return {
        "local_protocol_version": "1.0",
        "local_capabilities": local_caps,
        "supported_major_versions": ["1"],
        "peers": peer_entries,
        "note": (
            "'unchecked' means no health probe has been run for this peer yet. "
            "'unknown' means the last probe could not determine compatibility."
        ),
    }
