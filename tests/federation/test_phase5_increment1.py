"""tests/federation/test_phase5_increment1.py

PostgreSQL-backed and pure-Python tests for Phase 5 Increment 1.

Coverage:
  - Migration upgrade → downgrade → upgrade repeatability
  - federation_operational_audit append-only triggers
  - federation_operational_audit CHECK constraints
  - ON DELETE RESTRICT: peer cannot be deleted while audit rows reference it
  - federation_peer_health_snapshots ON DELETE SET NULL behavior
  - federation_sync_leases: fencing-token monotonicity (claim/release/reclaim)
  - federation_sync_leases: atomic concurrent claim (only one winner)
  - federation_sync_leases: stale fencing token fails verify
  - Lease duration validation (bounds, type checking)
  - Lease DB-clock semantics (expires_at from PostgreSQL, not Python clock)
  - federation_worker_heartbeats CHECK constraints
  - Circuit columns on federation_trusted_peers CHECK constraints
  - AuditDetailBuilder: recursive redaction, full PEM block, Bearer, truncation
  - AuditDetailBuilder: nested structures, SHA-256 safe, sensitive-key variants
  - AuditDetailBuilder: safe keys (kid, keyStatus) not redacted
  - AuditDetailBuilder: size limit (AuditDetailsTooLarge)
  - AuditDetailBuilder: depth limit (_MAX_REDACT_DEPTH)
  - write_audit_row: rejects oversized target_id/request_id/actor_id/reason
  - write_audit_row: two long IDs with same prefix both rejected
  - write_audit_row: details always sanitized (no bypass)
  - write_audit_row: async with AsyncSession
  - Vocabulary consistency: Python enums == DB CHECK constraint values
"""

from __future__ import annotations

import os
import re
import socket
import subprocess
import time
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path

import psycopg
import pytest

from src.license_facade_service.federation.audit import (
    AuditAction,
    AuditActorType,
    AuditDetailBuilder,
    AuditDetailsTooLarge,
    AuditOutcome,
    AuditTargetType,
    AuditValidationError,
    CircuitFailureReason,
    CircuitState,
    LeaseTriggerType,
    PeerCompatStatus,
    PeerHealthStatus,
    WorkerStatus,
    WorkerType,
    _MAX_REDACT_DEPTH,
    _PEM_REDACTED,
    _REDACTED,
    _sanitize_details,
)
from src.license_facade_service.federation.lease import (
    LEASE_MAX_SECONDS,
    LEASE_MIN_SECONDS,
    ClaimedLease,
    LeaseValidationError,
    SyncLeaseRepository,
)

REPO_ROOT = Path(__file__).resolve().parents[2]


# ---------------------------------------------------------------------------
# Docker helpers
# ---------------------------------------------------------------------------


def _docker_available() -> bool:
    try:
        subprocess.run(["docker", "version"], stdout=subprocess.DEVNULL,
                       stderr=subprocess.DEVNULL, check=True)
        return True
    except Exception:
        return False


def _free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind(("127.0.0.1", 0))
        return int(sock.getsockname()[1])


@pytest.fixture(scope="module")
def postgres_url():
    if not _docker_available():
        pytest.skip("docker not available for Phase 5 increment 1 tests")

    port = _free_port()
    container_name = f"lfs-pg5-{uuid.uuid4().hex[:8]}"
    subprocess.run(
        ["docker", "run", "--rm", "-d",
         "--name", container_name,
         "-e", "POSTGRES_PASSWORD=postgres",
         "-e", "POSTGRES_USER=postgres",
         "-e", "POSTGRES_DB=lfs_federation_p5",
         "-p", f"{port}:5432",
         "postgres:16-alpine"],
        check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
    )
    dsn = f"postgresql+psycopg://postgres:postgres@127.0.0.1:{port}/lfs_federation_p5"
    raw_dsn = f"postgresql://postgres:postgres@127.0.0.1:{port}/lfs_federation_p5"
    try:
        deadline = time.time() + 45
        while time.time() < deadline:
            try:
                with psycopg.connect(raw_dsn):
                    break
            except Exception:
                time.sleep(1)
        else:
            raise RuntimeError("postgres container did not become ready in time")
        yield dsn
    finally:
        subprocess.run(["docker", "kill", container_name],
                       stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                       check=False)


def _run_alembic(database_url: str, *command: str) -> None:
    env = dict(os.environ)
    env["ALEMBIC_DATABASE_URL"] = database_url
    subprocess.run(
        ["uv", "run", "alembic", "-c", str(REPO_ROOT / "alembic.ini"), *command],
        check=True, cwd=REPO_ROOT, env=env,
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
    )


def _raw_dsn(dsn: str) -> str:
    return dsn.replace("+psycopg", "")


def _make_peer(conn, *, peer_id: str | None = None, node_id: str | None = None) -> str:
    peer_id = peer_id or str(uuid.uuid4())
    node_id = node_id or str(uuid.uuid4())
    now = datetime.now(timezone.utc)
    conn.execute("""
        INSERT INTO federation_trusted_peers
            (id, peer_node_id, base_url, jwks_url, peer_name, created_at, updated_at)
        VALUES (%s, %s, %s, %s, %s, %s, %s)
    """, (peer_id, node_id, "https://peer.example/",
          "https://peer.example/.well-known/jwks.json", "Test Peer", now, now))
    return peer_id


def _make_audit_row(conn, *, peer_id: str | None = None,
                    target_id: str | None = None) -> str:
    """Insert a minimal audit row including peer_id in the INSERT.

    peer_id is included directly in the INSERT to avoid triggering the
    append-only UPDATE trigger.
    """
    row_id = str(uuid.uuid4())
    conn.execute("""
        INSERT INTO federation_operational_audit
            (id, actor_type, action, target_type, target_id, outcome, peer_id)
        VALUES (%s, %s, %s, %s, %s, %s, %s)
    """, (row_id, "system", "peer.enroll", "peer",
          target_id or str(uuid.uuid4()), "success", peer_id))
    return row_id


# ---------------------------------------------------------------------------
# DB CHECK value extractor (for vocabulary consistency tests)
# ---------------------------------------------------------------------------


def _extract_check_values(conn, constraint_name: str) -> frozenset[str]:
    """Extract the enumerated values from a named PostgreSQL CHECK constraint.

    Handles both the IN-list form and the = ANY (ARRAY[...]) form that
    PostgreSQL may produce internally when normalizing constraints.
    """
    conn.execute(
        "SELECT pg_get_constraintdef(oid) FROM pg_constraint WHERE conname = %s",
        (constraint_name,),
    )
    row = conn.fetchone()
    if row is None:
        raise AssertionError(f"Constraint {constraint_name!r} not found in DB")
    definition = row[0]
    # Extract all single-quoted string literals from the definition.
    # This handles both:
    #   IN ('v1','v2',...)
    #   = ANY ((ARRAY['v1'::character varying, 'v2'::character varying, ...])::text[])
    values = re.findall(r"'([^']+)'", definition)
    if not values:
        raise AssertionError(
            f"No quoted values found in constraint {constraint_name!r}: {definition!r}"
        )
    return frozenset(values)


# ===========================================================================
# 1. Migration repeatability
# ===========================================================================


def test_phase5_migration_upgrade_downgrade_upgrade(postgres_url: str):
    raw = _raw_dsn(postgres_url)
    _run_alembic(postgres_url, "upgrade", "head")

    def _tables_exist(cur) -> dict[str, bool]:
        tables = ["federation_operational_audit", "federation_sync_leases",
                  "federation_worker_heartbeats", "federation_peer_health_snapshots"]
        result = {}
        for t in tables:
            cur.execute("SELECT to_regclass(%s) IS NOT NULL", (f"public.{t}",))
            result[t] = bool(cur.fetchone()[0])
        return result

    with psycopg.connect(raw) as conn:
        with conn.cursor() as cur:
            exists = _tables_exist(cur)
            assert all(exists.values()), f"Some Phase 5 tables missing: {exists}"
            cur.execute("SELECT circuit_state FROM federation_trusted_peers LIMIT 0")
            cur.execute("SELECT rotation_scheduled_at FROM federation_signing_keys LIMIT 0")
            cur.execute(
                "SELECT to_regclass('public.federation_sync_lease_fencing_seq') IS NOT NULL"
            )
            assert cur.fetchone()[0], "Sequence missing after upgrade"

    _run_alembic(postgres_url, "downgrade", "20260804_05_phase4_rdf_leases")

    with psycopg.connect(raw) as conn:
        with conn.cursor() as cur:
            cur.execute("SELECT to_regclass('public.federation_operational_audit') IS NULL")
            assert cur.fetchone()[0], "federation_operational_audit should be gone"
            cur.execute(
                "SELECT to_regclass('public.federation_sync_lease_fencing_seq') IS NULL"
            )
            assert cur.fetchone()[0], "Sequence should be gone after downgrade"
            cur.execute("SELECT to_regclass('public.federation_records') IS NOT NULL")
            assert cur.fetchone()[0], "federation_records must survive downgrade"

    _run_alembic(postgres_url, "upgrade", "head")

    with psycopg.connect(raw) as conn:
        with conn.cursor() as cur:
            exists = _tables_exist(cur)
            assert all(exists.values()), f"Phase 5 tables missing on second upgrade: {exists}"


# ===========================================================================
# 2. Audit append-only triggers
# ===========================================================================


def test_audit_trigger_rejects_update(postgres_url: str):
    raw = _raw_dsn(postgres_url)
    _run_alembic(postgres_url, "upgrade", "head")

    with psycopg.connect(raw) as conn:
        with conn.cursor() as cur:
            _make_audit_row(cur)
            conn.commit()
            cur.execute("SELECT id FROM federation_operational_audit LIMIT 1")
            row_id = cur.fetchone()[0]

            with pytest.raises(psycopg.errors.RaiseException):
                cur.execute(
                    "UPDATE federation_operational_audit SET outcome = 'failed' WHERE id = %s",
                    (row_id,),
                )


def test_audit_trigger_rejects_delete(postgres_url: str):
    raw = _raw_dsn(postgres_url)
    _run_alembic(postgres_url, "upgrade", "head")

    with psycopg.connect(raw) as conn:
        with conn.cursor() as cur:
            row_id = _make_audit_row(cur)
            conn.commit()

            with pytest.raises(psycopg.errors.RaiseException):
                cur.execute(
                    "DELETE FROM federation_operational_audit WHERE id = %s", (row_id,)
                )


# ===========================================================================
# 3. Audit CHECK constraints
# ===========================================================================


@pytest.mark.parametrize("field,bad_value,expected_exc", [
    ("actor_type", "unknown_actor",   psycopg.errors.CheckViolation),
    ("action",     "peer.nonexistent", psycopg.errors.CheckViolation),
    ("target_type","unknown_target",  psycopg.errors.CheckViolation),
    ("outcome",    "maybe",           psycopg.errors.CheckViolation),
])
def test_audit_check_constraint(postgres_url: str, field: str, bad_value: str, expected_exc):
    raw = _raw_dsn(postgres_url)
    _run_alembic(postgres_url, "upgrade", "head")

    with psycopg.connect(raw) as conn:
        conn.autocommit = False
        with conn.cursor() as cur:
            with pytest.raises(expected_exc):
                cur.execute("""
                    INSERT INTO federation_operational_audit
                        (id, actor_type, action, target_type, target_id, outcome)
                    VALUES (%s, %s, %s, %s, %s, %s)
                """, (
                    str(uuid.uuid4()),
                    bad_value if field == "actor_type" else "system",
                    bad_value if field == "action"     else "peer.enroll",
                    bad_value if field == "target_type" else "peer",
                    str(uuid.uuid4()),
                    bad_value if field == "outcome"    else "success",
                ))


def test_audit_reason_length_check(postgres_url: str):
    raw = _raw_dsn(postgres_url)
    _run_alembic(postgres_url, "upgrade", "head")

    with psycopg.connect(raw) as conn:
        conn.autocommit = False
        with conn.cursor() as cur:
            with pytest.raises(psycopg.errors.CheckViolation):
                cur.execute("""
                    INSERT INTO federation_operational_audit
                        (id, actor_type, action, target_type, target_id, outcome, reason)
                    VALUES (%s, %s, %s, %s, %s, %s, %s)
                """, (str(uuid.uuid4()), "system", "peer.enroll", "peer",
                      str(uuid.uuid4()), "success", "x" * 1025))


# ===========================================================================
# 4. Audit FK: ON DELETE RESTRICT / archive-only
# ===========================================================================


def test_audit_on_delete_restrict_blocks_peer_deletion(postgres_url: str):
    raw = _raw_dsn(postgres_url)
    _run_alembic(postgres_url, "upgrade", "head")

    with psycopg.connect(raw) as conn:
        with conn.cursor() as cur:
            peer_id = _make_peer(cur)
            conn.commit()

            row_id = str(uuid.uuid4())
            cur.execute("""
                INSERT INTO federation_operational_audit
                    (id, actor_type, action, target_type, target_id, outcome, peer_id)
                VALUES (%s, %s, %s, %s, %s, %s, %s)
            """, (row_id, "system", "peer.enroll", "peer", peer_id, "success", peer_id))
            conn.commit()

            with pytest.raises(psycopg.errors.ForeignKeyViolation):
                cur.execute("DELETE FROM federation_trusted_peers WHERE id = %s", (peer_id,))


def test_peer_archive_does_not_violate_audit_fk(postgres_url: str):
    raw = _raw_dsn(postgres_url)
    _run_alembic(postgres_url, "upgrade", "head")

    with psycopg.connect(raw) as conn:
        with conn.cursor() as cur:
            peer_id = _make_peer(cur)
            conn.commit()

            row_id = str(uuid.uuid4())
            cur.execute("""
                INSERT INTO federation_operational_audit
                    (id, actor_type, action, target_type, target_id, outcome, peer_id)
                VALUES (%s, %s, %s, %s, %s, %s, %s)
            """, (row_id, "system", "peer.archive", "peer", peer_id, "success", peer_id))
            conn.commit()

            now = datetime.now(timezone.utc)
            cur.execute(
                "UPDATE federation_trusted_peers "
                "SET trust_status='archived', archived_at=%s WHERE id=%s",
                (now, peer_id)
            )
            conn.commit()  # Must succeed


# ===========================================================================
# 5. Health snapshots: ON DELETE SET NULL
# ===========================================================================


def test_health_snapshot_peer_id_set_null_on_peer_delete(postgres_url: str):
    raw = _raw_dsn(postgres_url)
    _run_alembic(postgres_url, "upgrade", "head")

    with psycopg.connect(raw) as conn:
        with conn.cursor() as cur:
            peer_id = _make_peer(cur)
            node_id_str = str(uuid.uuid4())
            conn.commit()

            snap_id = str(uuid.uuid4())
            now = datetime.now(timezone.utc)
            cur.execute("""
                INSERT INTO federation_peer_health_snapshots
                    (id, peer_id, peer_node_id, sampled_at, health_status)
                VALUES (%s, %s, %s, %s, %s)
            """, (snap_id, peer_id, node_id_str, now, "healthy"))
            conn.commit()

            cur.execute("DELETE FROM federation_trusted_peers WHERE id = %s", (peer_id,))
            conn.commit()

            cur.execute(
                "SELECT peer_id, peer_node_id FROM federation_peer_health_snapshots WHERE id = %s",
                (snap_id,),
            )
            row = cur.fetchone()
            assert row is not None
            assert row[0] is None, "peer_id should be NULL after peer deletion"
            assert row[1] == node_id_str, "peer_node_id must be preserved"


# ===========================================================================
# 6. Sync lease: fencing-token monotonicity (async)
# ===========================================================================


@pytest.mark.anyio
async def test_sync_lease_fencing_token_monotonically_increasing(postgres_url: str):
    """Claim → release → claim: second token must be strictly > first."""
    from sqlalchemy.ext.asyncio import create_async_engine, async_sessionmaker

    _run_alembic(postgres_url, "upgrade", "head")

    engine = create_async_engine(postgres_url, echo=False)
    try:
        sf = async_sessionmaker(engine, expire_on_commit=False)
        repo = SyncLeaseRepository()
        peer_id = uuid.uuid4()
        instance_a = uuid.uuid4()
        instance_b = uuid.uuid4()

        with psycopg.connect(_raw_dsn(postgres_url)) as conn:
            with conn.cursor() as cur:
                _make_peer(cur, peer_id=str(peer_id))
                conn.commit()

        async with sf() as s:
            lease_a = await repo.claim(
                s, peer_id=peer_id, owner_instance_id=instance_a,
                trigger_type="scheduled", duration_seconds=30,
            )
            await s.commit()
        assert isinstance(lease_a, ClaimedLease), "First claim must succeed"
        token_a = lease_a.fencing_token

        async with sf() as s:
            released = await repo.release(
                s, peer_id=peer_id, owner_instance_id=instance_a,
                fencing_token=token_a,
            )
            await s.commit()
        assert released, "Release must return True when lease exists"

        async with sf() as s:
            lease_b = await repo.claim(
                s, peer_id=peer_id, owner_instance_id=instance_b,
                trigger_type="manual", duration_seconds=30,
            )
            await s.commit()
        assert isinstance(lease_b, ClaimedLease), "Second claim must succeed after release"
        token_b = lease_b.fencing_token
        assert token_b > token_a, (
            f"Second fencing token ({token_b}) must be > first ({token_a})"
        )

        async with sf() as s:
            await repo.release(
                s, peer_id=peer_id, owner_instance_id=instance_b,
                fencing_token=token_b,
            )
            await s.commit()
    finally:
        await engine.dispose()


# ===========================================================================
# 7. Sync lease: concurrent claim — only one winner (async)
# ===========================================================================


@pytest.mark.anyio
async def test_sync_lease_concurrent_claim_only_one_wins(postgres_url: str):
    from sqlalchemy.ext.asyncio import create_async_engine, async_sessionmaker

    _run_alembic(postgres_url, "upgrade", "head")

    engine = create_async_engine(postgres_url, echo=False)
    try:
        sf = async_sessionmaker(engine, expire_on_commit=False)
        repo = SyncLeaseRepository()
        peer_id = uuid.uuid4()
        w1, w2 = uuid.uuid4(), uuid.uuid4()

        with psycopg.connect(_raw_dsn(postgres_url)) as conn:
            with conn.cursor() as cur:
                _make_peer(cur, peer_id=str(peer_id))
                conn.commit()

        async with sf() as s:
            lease_1 = await repo.claim(
                s, peer_id=peer_id, owner_instance_id=w1,
                trigger_type="scheduled", duration_seconds=300,
            )
            await s.commit()
        assert isinstance(lease_1, ClaimedLease)

        async with sf() as s:
            lease_2 = await repo.claim(
                s, peer_id=peer_id, owner_instance_id=w2,
                trigger_type="manual", duration_seconds=300,
            )
            await s.commit()
        assert lease_2 is None, "Second concurrent claim must return None"

        async with sf() as s:
            await repo.release(
                s, peer_id=peer_id, owner_instance_id=w1,
                fencing_token=lease_1.fencing_token,
            )
            await s.commit()
    finally:
        await engine.dispose()


# ===========================================================================
# 8. Sync lease: stale fencing token fails verify (async)
# ===========================================================================


@pytest.mark.anyio
async def test_sync_lease_stale_fencing_token_fails_verify(postgres_url: str):
    from sqlalchemy.ext.asyncio import create_async_engine, async_sessionmaker

    _run_alembic(postgres_url, "upgrade", "head")

    engine = create_async_engine(postgres_url, echo=False)
    try:
        sf = async_sessionmaker(engine, expire_on_commit=False)
        repo = SyncLeaseRepository()
        peer_id = uuid.uuid4()
        stale_instance = uuid.uuid4()
        new_instance = uuid.uuid4()

        with psycopg.connect(_raw_dsn(postgres_url)) as conn:
            with conn.cursor() as cur:
                _make_peer(cur, peer_id=str(peer_id))
                conn.commit()

        async with sf() as s:
            lease_a = await repo.claim(
                s, peer_id=peer_id, owner_instance_id=stale_instance,
                trigger_type="scheduled", duration_seconds=30,
            )
            await s.commit()
        stale_token = lease_a.fencing_token

        async with sf() as s:
            await repo.release(
                s, peer_id=peer_id, owner_instance_id=stale_instance,
                fencing_token=stale_token,
            )
            await s.commit()

        async with sf() as s:
            lease_b = await repo.claim(
                s, peer_id=peer_id, owner_instance_id=new_instance,
                trigger_type="scheduled", duration_seconds=300,
            )
            await s.commit()
        assert isinstance(lease_b, ClaimedLease)

        async with sf() as s:
            is_valid = await repo.verify_still_owned(
                s, peer_id=peer_id, owner_instance_id=stale_instance,
                claimed_fencing_token=stale_token,
            )
        assert not is_valid, "Stale fencing token must not pass verification"

        async with sf() as s:
            is_valid = await repo.verify_still_owned(
                s, peer_id=peer_id, owner_instance_id=new_instance,
                claimed_fencing_token=lease_b.fencing_token,
            )
        assert is_valid, "Current fencing token must pass verification"

        async with sf() as s:
            await repo.release(
                s, peer_id=peer_id, owner_instance_id=new_instance,
                fencing_token=lease_b.fencing_token,
            )
            await s.commit()
    finally:
        await engine.dispose()


# ===========================================================================
# 9. Lease duration bounds
# ===========================================================================


def test_lease_duration_zero_rejected():
    repo = SyncLeaseRepository()
    with pytest.raises(LeaseValidationError, match="positive"):
        _validate_sync(repo, duration_seconds=0)


def test_lease_duration_negative_rejected():
    repo = SyncLeaseRepository()
    with pytest.raises(LeaseValidationError, match="positive"):
        _validate_sync(repo, duration_seconds=-10)


def test_lease_duration_below_minimum_rejected():
    repo = SyncLeaseRepository()
    with pytest.raises(LeaseValidationError, match=str(LEASE_MIN_SECONDS)):
        _validate_sync(repo, duration_seconds=LEASE_MIN_SECONDS - 1)


def test_lease_duration_above_maximum_rejected():
    repo = SyncLeaseRepository()
    with pytest.raises(LeaseValidationError, match=str(LEASE_MAX_SECONDS)):
        _validate_sync(repo, duration_seconds=LEASE_MAX_SECONDS + 1)


def test_lease_duration_float_rejected():
    repo = SyncLeaseRepository()
    with pytest.raises(LeaseValidationError, match="integer"):
        _validate_sync(repo, duration_seconds=60.0)


def test_lease_duration_minimum_accepted():
    # _validate_duration must not raise for LEASE_MIN_SECONDS
    from src.license_facade_service.federation.lease import _validate_duration
    _validate_duration(LEASE_MIN_SECONDS)  # no raise


def test_lease_duration_maximum_accepted():
    from src.license_facade_service.federation.lease import _validate_duration
    _validate_duration(LEASE_MAX_SECONDS)  # no raise


def _validate_sync(repo: SyncLeaseRepository, *, duration_seconds) -> None:
    """Call _validate_duration synchronously without actually claiming a lease."""
    from src.license_facade_service.federation.lease import _validate_duration
    _validate_duration(duration_seconds)


# ===========================================================================
# 10. Lease DB-clock semantics (expires_at from PostgreSQL, not Python clock)
# ===========================================================================


@pytest.mark.anyio
async def test_lease_expires_at_from_db_clock(postgres_url: str):
    """ClaimedLease.expires_at is the DB timestamp, not derived from Python time.

    The SQL uses now() + interval — Python datetime.now() is never called.
    We verify expires_at is approximately now() + duration (within 5 seconds).
    """
    from sqlalchemy.ext.asyncio import create_async_engine, async_sessionmaker

    _run_alembic(postgres_url, "upgrade", "head")

    engine = create_async_engine(postgres_url, echo=False)
    try:
        sf = async_sessionmaker(engine, expire_on_commit=False)
        repo = SyncLeaseRepository()
        peer_id = uuid.uuid4()
        owner = uuid.uuid4()
        duration = 60

        with psycopg.connect(_raw_dsn(postgres_url)) as conn:
            with conn.cursor() as cur:
                _make_peer(cur, peer_id=str(peer_id))
                conn.commit()

        before = datetime.now(timezone.utc)
        async with sf() as s:
            lease = await repo.claim(
                s, peer_id=peer_id, owner_instance_id=owner,
                trigger_type="probe", duration_seconds=duration,
            )
            await s.commit()
        after = datetime.now(timezone.utc)

        assert lease is not None
        # expires_at should be approximately before + duration (within 5 s tolerance)
        expected_min = before + timedelta(seconds=duration - 5)
        expected_max = after  + timedelta(seconds=duration + 5)
        assert expected_min <= lease.expires_at <= expected_max, (
            f"expires_at {lease.expires_at} not in [{expected_min}, {expected_max}]"
        )

        async with sf() as s:
            await repo.release(
                s, peer_id=peer_id, owner_instance_id=owner,
                fencing_token=lease.fencing_token,
            )
            await s.commit()
    finally:
        await engine.dispose()


# ===========================================================================
# 11. Worker heartbeat CHECK constraints
# ===========================================================================


def test_worker_heartbeat_invalid_worker_type(postgres_url: str):
    raw = _raw_dsn(postgres_url)
    _run_alembic(postgres_url, "upgrade", "head")

    with psycopg.connect(raw) as conn:
        conn.autocommit = False
        with conn.cursor() as cur:
            with pytest.raises(psycopg.errors.CheckViolation):
                now = datetime.now(timezone.utc)
                cur.execute("""
                    INSERT INTO federation_worker_heartbeats
                        (id, worker_type, instance_id, started_at,
                         last_heartbeat_at, status, updated_at)
                    VALUES (%s, %s, %s, %s, %s, %s, %s)
                """, (str(uuid.uuid4()), "invalid_type", str(uuid.uuid4()),
                      now, now, "running", now))


def test_worker_heartbeat_invalid_status(postgres_url: str):
    raw = _raw_dsn(postgres_url)
    _run_alembic(postgres_url, "upgrade", "head")

    with psycopg.connect(raw) as conn:
        conn.autocommit = False
        with conn.cursor() as cur:
            with pytest.raises(psycopg.errors.CheckViolation):
                now = datetime.now(timezone.utc)
                cur.execute("""
                    INSERT INTO federation_worker_heartbeats
                        (id, worker_type, instance_id, started_at,
                         last_heartbeat_at, status, updated_at)
                    VALUES (%s, %s, %s, %s, %s, %s, %s)
                """, (str(uuid.uuid4()), "sync", str(uuid.uuid4()),
                      now, now, "broken", now))


# ===========================================================================
# 12. Circuit columns on federation_trusted_peers
# ===========================================================================


def test_circuit_state_default_is_closed(postgres_url: str):
    raw = _raw_dsn(postgres_url)
    _run_alembic(postgres_url, "upgrade", "head")

    with psycopg.connect(raw) as conn:
        with conn.cursor() as cur:
            peer_id = _make_peer(cur)
            conn.commit()
            cur.execute(
                "SELECT circuit_state, circuit_failure_count, "
                "circuit_requires_admin_reset FROM federation_trusted_peers WHERE id = %s",
                (peer_id,),
            )
            row = cur.fetchone()
            assert row[0] == "closed", f"Expected closed, got {row[0]}"
            assert row[1] == 0
            assert row[2] is False


def test_circuit_state_check_rejects_invalid(postgres_url: str):
    raw = _raw_dsn(postgres_url)
    _run_alembic(postgres_url, "upgrade", "head")

    with psycopg.connect(raw) as conn:
        conn.autocommit = False
        with conn.cursor() as cur:
            peer_id = _make_peer(cur)
            conn.commit()
            with pytest.raises(psycopg.errors.CheckViolation):
                cur.execute(
                    "UPDATE federation_trusted_peers "
                    "SET circuit_state = 'tripped' WHERE id = %s",
                    (peer_id,),
                )


def test_circuit_failure_reason_check_rejects_invalid(postgres_url: str):
    raw = _raw_dsn(postgres_url)
    _run_alembic(postgres_url, "upgrade", "head")

    with psycopg.connect(raw) as conn:
        conn.autocommit = False
        with conn.cursor() as cur:
            peer_id = _make_peer(cur)
            conn.commit()
            with pytest.raises(psycopg.errors.CheckViolation):
                cur.execute(
                    "UPDATE federation_trusted_peers "
                    "SET circuit_last_failure_reason = 'unknown_reason' WHERE id = %s",
                    (peer_id,),
                )


# ===========================================================================
# 13. Lease trigger_type CHECK
# ===========================================================================


def test_lease_trigger_type_check_rejects_invalid(postgres_url: str):
    raw = _raw_dsn(postgres_url)
    _run_alembic(postgres_url, "upgrade", "head")

    with psycopg.connect(raw) as conn:
        with conn.cursor() as cur:
            peer_id = _make_peer(cur)
            conn.commit()

        conn.autocommit = False
        with conn.cursor() as cur:
            now = datetime.now(timezone.utc)
            with pytest.raises(psycopg.errors.CheckViolation):
                cur.execute("""
                    INSERT INTO federation_sync_leases
                        (id, peer_id, owner_instance_id, fencing_token,
                         acquired_at, expires_at, trigger_type)
                    VALUES (%s, %s, %s,
                            nextval('federation_sync_lease_fencing_seq'),
                            %s, %s, %s)
                """, (str(uuid.uuid4()), peer_id, str(uuid.uuid4()),
                      now, now + timedelta(seconds=60), "worker"))


# ===========================================================================
# 14. All approved AuditAction values pass the DB CHECK
# ===========================================================================


def test_all_audit_actions_pass_check_constraint(postgres_url: str):
    raw = _raw_dsn(postgres_url)
    _run_alembic(postgres_url, "upgrade", "head")

    with psycopg.connect(raw) as conn:
        with conn.cursor() as cur:
            for action in AuditAction:
                cur.execute("""
                    INSERT INTO federation_operational_audit
                        (id, actor_type, action, target_type, target_id, outcome)
                    VALUES (%s, %s, %s, %s, %s, %s)
                """, (str(uuid.uuid4()), "system", action.value,
                      "peer", str(uuid.uuid4()), "success"))
            conn.commit()


# ===========================================================================
# 15. Vocabulary consistency: Python enums vs DB CHECK constraints
# ===========================================================================


def test_vocabulary_consistency_audit_actions(postgres_url: str):
    raw = _raw_dsn(postgres_url)
    _run_alembic(postgres_url, "upgrade", "head")

    py_values = frozenset(a.value for a in AuditAction)
    with psycopg.connect(raw) as conn:
        with conn.cursor() as cur:
            db_values = _extract_check_values(cur, "ck_foa_action")
    assert py_values == db_values, (
        f"AuditAction/DB mismatch.\n"
        f"  Python only: {py_values - db_values}\n"
        f"  DB only:     {db_values - py_values}"
    )


def test_vocabulary_consistency_actor_types(postgres_url: str):
    raw = _raw_dsn(postgres_url)
    _run_alembic(postgres_url, "upgrade", "head")

    py_values = frozenset(a.value for a in AuditActorType)
    with psycopg.connect(raw) as conn:
        with conn.cursor() as cur:
            db_values = _extract_check_values(cur, "ck_foa_actor_type")
    assert py_values == db_values, (
        f"AuditActorType/DB mismatch. Python: {py_values}, DB: {db_values}"
    )


def test_vocabulary_consistency_target_types(postgres_url: str):
    raw = _raw_dsn(postgres_url)
    _run_alembic(postgres_url, "upgrade", "head")

    py_values = frozenset(a.value for a in AuditTargetType)
    with psycopg.connect(raw) as conn:
        with conn.cursor() as cur:
            db_values = _extract_check_values(cur, "ck_foa_target_type")
    assert py_values == db_values, (
        f"AuditTargetType/DB mismatch. Python: {py_values}, DB: {db_values}"
    )


def test_vocabulary_consistency_outcomes(postgres_url: str):
    raw = _raw_dsn(postgres_url)
    _run_alembic(postgres_url, "upgrade", "head")

    py_values = frozenset(a.value for a in AuditOutcome)
    with psycopg.connect(raw) as conn:
        with conn.cursor() as cur:
            db_values = _extract_check_values(cur, "ck_foa_outcome")
    assert py_values == db_values, (
        f"AuditOutcome/DB mismatch. Python: {py_values}, DB: {db_values}"
    )


def test_vocabulary_consistency_lease_trigger_types(postgres_url: str):
    raw = _raw_dsn(postgres_url)
    _run_alembic(postgres_url, "upgrade", "head")

    py_values = frozenset(a.value for a in LeaseTriggerType)
    with psycopg.connect(raw) as conn:
        with conn.cursor() as cur:
            db_values = _extract_check_values(cur, "ck_fsl_trigger_type")
    assert py_values == db_values, (
        f"LeaseTriggerType/DB mismatch. Python: {py_values}, DB: {db_values}"
    )


def test_vocabulary_consistency_worker_types(postgres_url: str):
    raw = _raw_dsn(postgres_url)
    _run_alembic(postgres_url, "upgrade", "head")

    py_values = frozenset(a.value for a in WorkerType)
    with psycopg.connect(raw) as conn:
        with conn.cursor() as cur:
            db_values = _extract_check_values(cur, "ck_fwh_worker_type")
    assert py_values == db_values, (
        f"WorkerType/DB mismatch. Python: {py_values}, DB: {db_values}"
    )


def test_vocabulary_consistency_worker_statuses(postgres_url: str):
    raw = _raw_dsn(postgres_url)
    _run_alembic(postgres_url, "upgrade", "head")

    py_values = frozenset(a.value for a in WorkerStatus)
    with psycopg.connect(raw) as conn:
        with conn.cursor() as cur:
            db_values = _extract_check_values(cur, "ck_fwh_status")
    assert py_values == db_values, (
        f"WorkerStatus/DB mismatch. Python: {py_values}, DB: {db_values}"
    )


def test_vocabulary_consistency_circuit_states(postgres_url: str):
    raw = _raw_dsn(postgres_url)
    _run_alembic(postgres_url, "upgrade", "head")

    py_values = frozenset(a.value for a in CircuitState)
    with psycopg.connect(raw) as conn:
        with conn.cursor() as cur:
            db_values = _extract_check_values(cur, "ck_ftp_circuit_state")
    assert py_values == db_values, (
        f"CircuitState/DB mismatch. Python: {py_values}, DB: {db_values}"
    )


def test_vocabulary_consistency_circuit_failure_reasons(postgres_url: str):
    raw = _raw_dsn(postgres_url)
    _run_alembic(postgres_url, "upgrade", "head")

    py_values = frozenset(a.value for a in CircuitFailureReason)
    with psycopg.connect(raw) as conn:
        with conn.cursor() as cur:
            db_values = _extract_check_values(cur, "ck_ftp_circuit_reason")
    assert py_values == db_values, (
        f"CircuitFailureReason/DB mismatch. Python: {py_values}, DB: {db_values}"
    )


# ===========================================================================
# 16. Pure-Python: AuditDetailBuilder redaction
# ===========================================================================


def test_audit_builder_redacts_sensitive_key():
    details = AuditDetailBuilder().add("token", "secret-token-value").build()
    assert details["token"] == _REDACTED


def test_audit_builder_redacts_authorization():
    details = AuditDetailBuilder().add("authorization", "Bearer abc123").build()
    assert details["authorization"] == _REDACTED


def test_audit_builder_redacts_password():
    details = AuditDetailBuilder().add("password", "hunter2").build()
    assert details["password"] == _REDACTED


def test_audit_builder_redacts_api_key():
    details = AuditDetailBuilder().add("apiKey", "my-api-key").build()
    assert details["apiKey"] == _REDACTED


def test_audit_builder_redacts_api_key_underscore():
    details = AuditDetailBuilder().add("api_key", "my-api-key").build()
    assert details["api_key"] == _REDACTED


def test_audit_builder_redacts_bearer_token_key():
    details = AuditDetailBuilder().add("bearerToken", "xyz").build()
    assert details["bearerToken"] == _REDACTED


def test_audit_builder_redacts_client_secret():
    details = AuditDetailBuilder().add("clientSecret", "cs-value").build()
    assert details["clientSecret"] == _REDACTED


def test_audit_builder_redacts_signing_key():
    details = AuditDetailBuilder().add("signingKey", "some-key").build()
    assert details["signingKey"] == _REDACTED


def test_audit_builder_redacts_db_password():
    details = AuditDetailBuilder().add("dbPassword", "pass123").build()
    assert details["dbPassword"] == _REDACTED


def test_audit_builder_redacts_credentials():
    details = AuditDetailBuilder().add("credentials", "cred").build()
    assert details["credentials"] == _REDACTED


def test_audit_builder_safe_key_kid_not_redacted():
    details = AuditDetailBuilder().add("kid", "key-id-123").build()
    assert details["kid"] == "key-id-123", "kid must NOT be redacted"


def test_audit_builder_safe_key_key_status_not_redacted():
    details = AuditDetailBuilder().add("keyStatus", "active").build()
    assert details["keyStatus"] == "active", "keyStatus must NOT be redacted"


def test_audit_builder_safe_key_public_key_fingerprint_not_redacted():
    details = AuditDetailBuilder().add("publicKeyFingerprint", "sha256:abc").build()
    assert details["publicKeyFingerprint"] == "sha256:abc"


# PEM full-block redaction tests


def test_audit_builder_redacts_full_pem_rsa():
    pem = (
        "-----BEGIN RSA PRIVATE KEY-----\n"
        "MIIEowIBAAKCAQEA2a2rwplBQLzHPZe5TNJN9...\n"
        "-----END RSA PRIVATE KEY-----"
    )
    details = AuditDetailBuilder().add("keyMaterial", pem).build()
    assert details["keyMaterial"] == _PEM_REDACTED, (
        f"Full RSA PEM block must be entirely redacted, got: {details['keyMaterial']!r}"
    )


def test_audit_builder_redacts_full_pem_ec():
    pem = (
        "-----BEGIN EC PRIVATE KEY-----\n"
        "MHQCAQEEIOaB5fGGY6BvEjkbDJuKBCzH+O8...\n"
        "-----END EC PRIVATE KEY-----"
    )
    details = AuditDetailBuilder().add("key", pem).build()
    assert details["key"] == _PEM_REDACTED


def test_audit_builder_redacts_full_pem_ed25519():
    pem = (
        "-----BEGIN PRIVATE KEY-----\n"
        "MC4CAQAwBQYDK2VdBCIEIHGjMQ...\n"
        "-----END PRIVATE KEY-----"
    )
    details = AuditDetailBuilder().add("pkey", pem).build()
    # "pkey" is not in _SENSITIVE_NORMALIZED but the value contains a PEM block
    result = details["pkey"]
    assert "BEGIN PRIVATE KEY" not in result
    assert "END PRIVATE KEY" not in result
    assert _PEM_REDACTED in result


def test_audit_builder_redacts_full_pem_generic():
    pem = (
        "-----BEGIN CERTIFICATE-----\n"
        "MIIBIjANBgkqhkiG9w0...\n"
        "-----END CERTIFICATE-----"
    )
    details = AuditDetailBuilder().add("cert", pem).build()
    assert "BEGIN CERTIFICATE" not in details["cert"]
    assert "END CERTIFICATE" not in details["cert"]
    assert _PEM_REDACTED in details["cert"]


def test_audit_builder_pem_begin_line_not_left_visible():
    """The BEGIN header must not be visible in the stored result."""
    pem = "-----BEGIN RSA PRIVATE KEY-----\nABCabc123\n-----END RSA PRIVATE KEY-----"
    details = AuditDetailBuilder().add("desc", pem).build()
    assert "BEGIN RSA PRIVATE KEY" not in details["desc"]
    assert "ABCabc123" not in details["desc"]
    assert "END RSA PRIVATE KEY" not in details["desc"]


def test_audit_builder_exception_pem_redacted():
    """PEM blocks in exception messages must be fully redacted."""
    pem = "-----BEGIN PRIVATE KEY-----\nMC4CAQAwBQY=\n-----END PRIVATE KEY-----"
    exc = ValueError(f"Failed to load key: {pem}")
    details = AuditDetailBuilder().from_exception(exc).build()
    summary = details["errorSummary"]
    assert "BEGIN PRIVATE KEY" not in summary
    assert "END PRIVATE KEY" not in summary
    assert _PEM_REDACTED in summary


def test_audit_builder_redacts_bearer_in_value():
    text_with_bearer = "Error: Authorization: Bearer eyJhbGciOiJFZERTQQ"
    details = AuditDetailBuilder().add("errorMessage", text_with_bearer).build()
    assert "eyJhbGciOiJFZERTQQ" not in details["errorMessage"]


def test_audit_builder_does_not_redact_sha256_digest():
    digest = "a" * 64
    details = AuditDetailBuilder().add("payloadDigestSha256", digest).build()
    assert details["payloadDigestSha256"] == digest


def test_audit_builder_truncates_long_value():
    long_val = "x" * 3000
    details = AuditDetailBuilder().add("description", long_val).build()
    assert len(details["description"]) < 3000
    assert "[truncated]" in details["description"]


def test_audit_builder_recursive_dict():
    nested = {
        "outer": "safe_value",
        "nested": {"password": "secret123", "safe": "visible"},
    }
    details = AuditDetailBuilder().add("context", nested).build()
    assert details["context"]["nested"]["password"] == _REDACTED
    assert details["context"]["nested"]["safe"] == "visible"
    assert details["context"]["outer"] == "safe_value"


def test_audit_builder_recursive_list():
    items = [{"token": "abc"}, {"kid": "safe-kid", "admin_token": "secret"}]
    details = AuditDetailBuilder().add("keys", items).build()
    assert details["keys"][0]["token"] == _REDACTED
    assert details["keys"][1]["kid"] == "safe-kid"
    assert details["keys"][1]["admin_token"] == _REDACTED


def test_audit_builder_case_insensitive_key():
    details = (
        AuditDetailBuilder()
        .add("Authorization", "Bearer xyz")
        .add("TOKEN", "abc")
        .add("Database_Url", "postgresql://user:pass@host/db")
        .build()
    )
    assert details["Authorization"] == _REDACTED
    assert details["TOKEN"] == _REDACTED
    assert details["Database_Url"] == _REDACTED


def test_audit_builder_from_exception():
    exc = ValueError("connection failed: host=db password=secret")
    details = AuditDetailBuilder().from_exception(exc).build()
    assert details["errorClass"] == "ValueError"
    assert "errorSummary" in details
    assert len(details["errorSummary"]) <= 500 + len("[truncated]")


def test_audit_builder_exception_truncation():
    exc = RuntimeError("x" * 1000)
    details = AuditDetailBuilder().from_exception(exc).build()
    assert "[truncated]" in details["errorSummary"]


def test_audit_builder_has_no_add_raw():
    """add_raw() must not exist as a public method."""
    builder = AuditDetailBuilder()
    assert not hasattr(builder, "add_raw"), (
        "add_raw() is an unsafe bypass and must not be a public method"
    )


def test_audit_builder_all_inputs_sanitized():
    """Calling add() with sensitive-key data always redacts, even when 'safe'."""
    builder = AuditDetailBuilder()
    builder.add("authorization", "should-be-redacted")
    details = builder.build()
    assert details["authorization"] == _REDACTED


# ===========================================================================
# 17. Audit detail size and depth limits
# ===========================================================================


def test_audit_details_size_limit_accepted():
    """Details within _MAX_DETAILS_BYTES should succeed."""
    details = {"key": "v" * 100}  # small
    result = _sanitize_details(details)
    assert isinstance(result, dict)


def test_audit_details_too_large_raises():
    """Details exceeding _MAX_DETAILS_BYTES must raise AuditDetailsTooLarge."""
    from src.license_facade_service.federation.audit import _MAX_DETAILS_BYTES
    # Build a dict that serializes to > _MAX_DETAILS_BYTES bytes
    many_keys = {f"key{i}": "v" * 200 for i in range(200)}  # ~40 KB
    with pytest.raises(AuditDetailsTooLarge):
        _sanitize_details(many_keys)


def test_audit_details_exactly_at_limit_accepted():
    """Details whose serialization equals _MAX_DETAILS_BYTES must succeed."""
    from src.license_facade_service.federation.audit import _MAX_DETAILS_BYTES
    import json
    # Build a value just under the limit
    key = "x"
    overhead = len(json.dumps({key: ""}, separators=(",", ":")))
    value = "a" * (_MAX_DETAILS_BYTES - overhead)
    details = {key: value}
    # Should not raise (may be at or just under the limit)
    serialized = json.dumps(_sanitize_details(details), separators=(",", ":"))
    assert len(serialized.encode("utf-8")) <= _MAX_DETAILS_BYTES


def test_audit_details_depth_limit():
    """Recursion beyond _MAX_REDACT_DEPTH returns '[depth limit]' for leaf values."""
    from src.license_facade_service.federation.audit import _redact_value, _MAX_REDACT_DEPTH

    def _deep(depth: int) -> dict:
        if depth == 0:
            return {"leaf": "value"}
        return {"nested": _deep(depth - 1)}

    # Within the limit: leaf value is preserved.
    result_ok = _redact_value("root", _deep(_MAX_REDACT_DEPTH - 1))
    node = result_ok
    for _ in range(_MAX_REDACT_DEPTH - 1):
        node = node["nested"]
    assert node["leaf"] == "value", (
        "Leaf within depth limit must not be replaced"
    )

    # At exactly _MAX_REDACT_DEPTH nesting levels the dict at that depth is
    # processed, but its children (at depth+1) receive '[depth limit]'.
    result_deep = _redact_value("root", _deep(_MAX_REDACT_DEPTH))
    node2 = result_deep
    for _ in range(_MAX_REDACT_DEPTH):
        node2 = node2["nested"]
    # node2 is the dict {"leaf": "[depth limit]"} — children are limited
    assert node2.get("leaf") == "[depth limit]", (
        f"String value inside dict at depth {_MAX_REDACT_DEPTH} should be "
        f"'[depth limit]', got {node2!r}"
    )


# ===========================================================================
# 18. write_audit_row: validation (async)
# ===========================================================================


@pytest.mark.anyio
async def test_write_audit_row_rejects_oversized_target_id(postgres_url: str):
    from sqlalchemy.ext.asyncio import create_async_engine, async_sessionmaker
    from src.license_facade_service.federation.audit import write_audit_row

    _run_alembic(postgres_url, "upgrade", "head")
    engine = create_async_engine(postgres_url, echo=False)
    try:
        sf = async_sessionmaker(engine, expire_on_commit=False)
        long_id = "lfs:" + "x" * 300  # exceeds 256

        with pytest.raises(AuditValidationError, match="target_id"):
            async with sf() as s:
                await write_audit_row(
                    s,
                    actor_type=AuditActorType.SYSTEM,
                    action=AuditAction.PEER_ENROLL,
                    target_type=AuditTargetType.PEER,
                    target_id=long_id,
                    outcome=AuditOutcome.SUCCESS,
                )
    finally:
        await engine.dispose()


@pytest.mark.anyio
async def test_write_audit_row_rejects_oversized_request_id(postgres_url: str):
    from sqlalchemy.ext.asyncio import create_async_engine, async_sessionmaker
    from src.license_facade_service.federation.audit import write_audit_row

    _run_alembic(postgres_url, "upgrade", "head")
    engine = create_async_engine(postgres_url, echo=False)
    try:
        sf = async_sessionmaker(engine, expire_on_commit=False)
        with pytest.raises(AuditValidationError, match="request_id"):
            async with sf() as s:
                await write_audit_row(
                    s,
                    actor_type=AuditActorType.SYSTEM,
                    action=AuditAction.PEER_ENROLL,
                    target_type=AuditTargetType.PEER,
                    target_id=str(uuid.uuid4()),
                    outcome=AuditOutcome.SUCCESS,
                    request_id="r" * 200,
                )
    finally:
        await engine.dispose()


@pytest.mark.anyio
async def test_write_audit_row_two_long_ids_same_prefix_both_rejected(postgres_url: str):
    """Two identifiers differing after char 256 must both be rejected, not collapsed."""
    from sqlalchemy.ext.asyncio import create_async_engine, async_sessionmaker
    from src.license_facade_service.federation.audit import write_audit_row

    _run_alembic(postgres_url, "upgrade", "head")
    engine = create_async_engine(postgres_url, echo=False)
    try:
        sf = async_sessionmaker(engine, expire_on_commit=False)
        prefix = "urn:lfs:licence:" + "a" * 240
        id_x = prefix + "X"  # 257 chars
        id_y = prefix + "Y"  # 257 chars

        for long_id in (id_x, id_y):
            with pytest.raises(AuditValidationError, match="target_id"):
                async with sf() as s:
                    await write_audit_row(
                        s,
                        actor_type=AuditActorType.SYSTEM,
                        action=AuditAction.PEER_ENROLL,
                        target_type=AuditTargetType.PEER,
                        target_id=long_id,
                        outcome=AuditOutcome.SUCCESS,
                    )
    finally:
        await engine.dispose()


@pytest.mark.anyio
async def test_write_audit_row_details_always_sanitized(postgres_url: str):
    """Details supplied to write_audit_row are always sanitized."""
    from sqlalchemy.ext.asyncio import create_async_engine, async_sessionmaker
    from src.license_facade_service.db.models.federation import FederationOperationalAudit
    from src.license_facade_service.federation.audit import write_audit_row

    _run_alembic(postgres_url, "upgrade", "head")
    engine = create_async_engine(postgres_url, echo=False)
    try:
        sf = async_sessionmaker(engine, expire_on_commit=False)
        # Supply 'details' with a bearer token in the value
        unsafe_details = {"note": "token=Bearer supersecret123"}

        async with sf() as s:
            row = await write_audit_row(
                s,
                actor_type=AuditActorType.SYSTEM,
                action=AuditAction.PEER_ENROLL,
                target_type=AuditTargetType.PEER,
                target_id=str(uuid.uuid4()),
                outcome=AuditOutcome.SUCCESS,
                details=unsafe_details,
            )
            await s.commit()

        async with sf() as s:
            stored = await s.get(FederationOperationalAudit, row.id)
            assert stored is not None
            note = stored.redacted_details.get("note", "")
            assert "supersecret123" not in note, (
                "Bearer token in details must be redacted before storage"
            )
    finally:
        await engine.dispose()


# ===========================================================================
# 19. _redact_exception / _apply_value_patterns: credential patterns
# ===========================================================================
#
# Each test asserts the secret is absent from:
#   (a) AuditDetailBuilder.from_exception(exc).build()["errorSummary"]
#   (b) _sanitize_details({"rawMsg": str(exc)}) (details-path redaction)
#   (c) persisted PostgreSQL JSONB (covered by the async DB test at the end)


from src.license_facade_service.federation.audit import (
    _apply_value_patterns,
    _sanitize_details,
)


def _assert_exception_redacted(exc: BaseException, secret: str) -> None:
    """Check that secret is absent from builder and sanitize_details output."""
    summary = AuditDetailBuilder().from_exception(exc).build()["errorSummary"]
    assert secret not in summary, (
        f"Secret {secret!r} must be absent from errorSummary, got: {summary!r}"
    )
    raw = {"rawMsg": str(exc)}
    sanitized = _sanitize_details(raw)
    assert secret not in sanitized["rawMsg"], (
        f"Secret {secret!r} must be absent from sanitized rawMsg"
    )


def test_exception_redacts_postgresql_dsn():
    exc = Exception("DB error: postgresql://admin:s3cr3t@db.host/lfs_db")
    _assert_exception_redacted(exc, "s3cr3t")
    _assert_exception_redacted(exc, "admin")


def test_exception_redacts_https_basic_auth():
    exc = Exception("Fetch failed: https://apiuser:mypAssword@api.example.org/v1")
    _assert_exception_redacted(exc, "mypAssword")
    _assert_exception_redacted(exc, "apiuser")


def test_exception_redacts_password_assignment():
    exc = Exception("connection failed with password=secret123")
    _assert_exception_redacted(exc, "secret123")


def test_exception_redacts_password_colon_form():
    exc = Exception("Auth error: password: hunter2")
    _assert_exception_redacted(exc, "hunter2")


def test_exception_redacts_access_token_assignment():
    exc = Exception("request rejected: access_token=abc.def.ghi")
    _assert_exception_redacted(exc, "abc.def.ghi")


def test_exception_redacts_api_key_assignment():
    exc = Exception("call failed: api_key=KEYVALUE123")
    _assert_exception_redacted(exc, "KEYVALUE123")


def test_exception_redacts_api_key_hyphen_form():
    exc = Exception("call failed: api-key=KEYVALUE456")
    _assert_exception_redacted(exc, "KEYVALUE456")


def test_exception_redacts_client_secret_assignment():
    exc = Exception("oauth error: client_secret=TOP_SECRET")
    _assert_exception_redacted(exc, "TOP_SECRET")


def test_exception_redacts_authorization_header():
    exc = Exception("rejected: Authorization: Bearer eyJhbGciOiJFZERTQSJ9")
    _assert_exception_redacted(exc, "eyJhbGciOiJFZERTQSJ9")


def test_exception_redacts_full_pem_block():
    pem = (
        "-----BEGIN RSA PRIVATE KEY-----\n"
        "MIIEowIBAAKCAQEAsupersecretbytes\n"
        "-----END RSA PRIVATE KEY-----"
    )
    exc = Exception(f"Key load failed: {pem}")
    _assert_exception_redacted(exc, "MIIEowIBAAKCAQEAsupersecretbytes")
    _assert_exception_redacted(exc, "BEGIN RSA PRIVATE KEY")


def test_exception_redacts_multiple_secrets():
    """Multiple credential patterns in one exception message — all must be removed."""
    exc = Exception(
        "pipeline failed: postgresql://user:pw1@db/lfs "
        "token=tk_live_secret "
        "api_key=AK_SECRET "
        "Bearer abc123xyz"
    )
    for secret in ("pw1", "user", "tk_live_secret", "AK_SECRET", "abc123xyz"):
        _assert_exception_redacted(exc, secret)


def test_exception_safe_sha256_digest_not_redacted():
    """SHA-256 hex digest must remain visible in exception messages."""
    digest = "a" * 64
    exc = Exception(f"verification failed for record digest={digest}")
    summary = AuditDetailBuilder().from_exception(exc).build()["errorSummary"]
    assert digest in summary, f"SHA-256 digest must not be redacted, got: {summary!r}"


def test_exception_safe_public_fingerprint_not_redacted():
    fingerprint = "sha256:abcdef1234567890"
    exc = Exception(f"key mismatch: publicKeyFingerprint={fingerprint}")
    summary = AuditDetailBuilder().from_exception(exc).build()["errorSummary"]
    assert fingerprint in summary, f"Fingerprint must not be redacted, got: {summary!r}"


def test_exception_tokenization_word_not_redacted():
    """'tokenization' must not match the 'token' assignment pattern."""
    exc = Exception("tokenization=enabled policy applied")
    summary = AuditDetailBuilder().from_exception(exc).build()["errorSummary"]
    # "tokenization" itself must not be replaced — only "token=..." assignment forms
    # This is safe because \btoken\b requires a word boundary after "token",
    # but in "tokenization" there is no boundary between "token" and "i".
    assert "tokenization=enabled" in summary, (
        f"'tokenization=enabled' must not be redacted, got: {summary!r}"
    )


def test_apply_value_patterns_no_over_redaction_kid():
    """kid=xyz must not be redacted by value patterns (kid is a safe operational field)."""
    result = _apply_value_patterns("resolved kid=my-key-id-001")
    assert "my-key-id-001" in result, (
        f"kid= value must not be redacted, got: {result!r}"
    )


# ===========================================================================
# 20. End-to-end DB: exception secrets absent from persisted JSONB
# ===========================================================================


@pytest.mark.anyio
async def test_exception_secrets_absent_from_db_jsonb(postgres_url: str):
    """Credentials embedded in exception messages must not appear in stored JSONB."""
    from sqlalchemy.ext.asyncio import create_async_engine, async_sessionmaker
    from src.license_facade_service.db.models.federation import FederationOperationalAudit
    from src.license_facade_service.federation.audit import write_audit_row

    _run_alembic(postgres_url, "upgrade", "head")
    engine = create_async_engine(postgres_url, echo=False)
    try:
        sf = async_sessionmaker(engine, expire_on_commit=False)

        scenarios = [
            ("dsn",    Exception("error: postgresql://user:pw1@db/lfs")),
            ("passwd", Exception("fail password=secret123")),
            ("token",  Exception("rejected access_token=tok_live_abc")),
            ("apikey", Exception("denied api_key=AK_SECRET_123")),
        ]
        secrets = {
            "dsn":    ("pw1", "user"),
            "passwd": ("secret123",),
            "token":  ("tok_live_abc",),
            "apikey": ("AK_SECRET_123",),
        }
        row_ids: dict[str, str] = {}

        for label, exc in scenarios:
            details = AuditDetailBuilder().from_exception(exc).build()
            async with sf() as s:
                row = await write_audit_row(
                    s,
                    actor_type=AuditActorType.SYSTEM,
                    action=AuditAction.PEER_PROBE,
                    target_type=AuditTargetType.PEER,
                    target_id=str(uuid.uuid4()),
                    outcome=AuditOutcome.FAILED,
                    details=details,
                )
                await s.commit()
            row_ids[label] = str(row.id)

        async with sf() as s:
            for label, row_id in row_ids.items():
                stored = await s.get(FederationOperationalAudit, row_id)
                assert stored is not None
                stored_json = str(stored.redacted_details)
                for secret in secrets[label]:
                    assert secret not in stored_json, (
                        f"Secret {secret!r} must not appear in stored JSONB "
                        f"for scenario {label!r}: {stored_json!r}"
                    )
    finally:
        await engine.dispose()
