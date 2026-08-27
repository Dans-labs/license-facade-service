"""federation/lease.py — Persisted synchronization lease repository.

All timing decisions use the PostgreSQL database clock via now().  The
application Python clock is never used for lease acquisition or expiry,
eliminating clock-skew vulnerabilities.

Fencing token:
  Comes from federation_sync_lease_fencing_seq (BIGINT sequence that never
  resets, even when the lease row is deleted on release).

Atomic claim:
  INSERT ... ON CONFLICT (peer_id) DO UPDATE ...
  WHERE federation_sync_leases.expires_at <= now()

  The <= comparison means a lease expiring exactly at the current database
  timestamp is considered expired and eligible for displacement.  A
  concurrent second claimer receives 0 RETURNING rows when the existing
  lease has not yet expired.

Duration bounds:
  duration_seconds must be between LEASE_MIN_SECONDS and LEASE_MAX_SECONDS.
  Zero, negative, non-integer, or out-of-range values are rejected with
  LeaseValidationError before any SQL executes.  Silent clamping is never
  performed.

This module provides ONLY the low-level lease repository.
Integration with the synchronization workflow belongs to Increment 3.
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass
from datetime import datetime

from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession

# ---------------------------------------------------------------------------
# Duration bounds
# ---------------------------------------------------------------------------

LEASE_MIN_SECONDS: int = 10        # minimum acceptable lease duration
LEASE_MAX_SECONDS: int = 3_600     # maximum acceptable lease duration (1 hour)


# ---------------------------------------------------------------------------
# Typed exceptions
# ---------------------------------------------------------------------------


class LeaseValidationError(ValueError):
    """Raised when lease parameters fail validation before SQL execution."""


class LeaseConflictError(RuntimeError):
    """Raised when verify_still_owned detects a stale fencing token or
    an expired lease; the caller must abort its import transaction."""


# ---------------------------------------------------------------------------
# Claimed lease value object
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class ClaimedLease:
    """Returned when a lease is successfully acquired."""
    peer_id: uuid.UUID
    owner_instance_id: uuid.UUID
    fencing_token: int
    expires_at: datetime      # exact value returned by PostgreSQL


# ---------------------------------------------------------------------------
# Duration validation
# ---------------------------------------------------------------------------


def _validate_duration(duration_seconds: int) -> None:
    """Validate duration_seconds is a positive integer within allowed bounds.

    Raises LeaseValidationError for invalid types, zero, negative values, or
    values outside [LEASE_MIN_SECONDS, LEASE_MAX_SECONDS].
    """
    if not isinstance(duration_seconds, int) or isinstance(duration_seconds, bool):
        raise LeaseValidationError(
            f"duration_seconds must be an integer, got {type(duration_seconds).__name__!r}"
        )
    if duration_seconds <= 0:
        raise LeaseValidationError(
            f"duration_seconds must be positive, got {duration_seconds}"
        )
    if duration_seconds < LEASE_MIN_SECONDS:
        raise LeaseValidationError(
            f"duration_seconds must be >= {LEASE_MIN_SECONDS} (got {duration_seconds})"
        )
    if duration_seconds > LEASE_MAX_SECONDS:
        raise LeaseValidationError(
            f"duration_seconds must be <= {LEASE_MAX_SECONDS} (got {duration_seconds})"
        )


# ---------------------------------------------------------------------------
# SQL statements (all time values from PostgreSQL now())
# ---------------------------------------------------------------------------
#
# acquired_at and expires_at are computed by the database; the Python
# application clock plays no role in lease timing decisions.
#
# The expiry condition uses <= now() so a lease whose expires_at exactly
# equals the current database timestamp is considered expired.
#
# nextval() is evaluated by PostgreSQL regardless of whether the DO UPDATE
# WHERE clause is satisfied.  Sequence gaps are acceptable; monotonicity
# across successful claims is guaranteed because the sequence never resets.

_CLAIM_SQL = text("""
    INSERT INTO federation_sync_leases
        (peer_id, owner_instance_id, fencing_token, acquired_at, expires_at, trigger_type)
    VALUES
        (:peer_id, :owner_instance_id,
         nextval('federation_sync_lease_fencing_seq'),
         now(),
         now() + (:duration_seconds * INTERVAL '1 second'),
         :trigger_type)
    ON CONFLICT (peer_id) DO UPDATE
        SET owner_instance_id = EXCLUDED.owner_instance_id,
            fencing_token     = EXCLUDED.fencing_token,
            acquired_at       = EXCLUDED.acquired_at,
            expires_at        = EXCLUDED.expires_at,
            heartbeat_at      = NULL,
            trigger_type      = EXCLUDED.trigger_type
        WHERE federation_sync_leases.expires_at <= now()
    RETURNING fencing_token, owner_instance_id, expires_at
""")

_RELEASE_SQL = text("""
    DELETE FROM federation_sync_leases
    WHERE peer_id           = :peer_id
      AND owner_instance_id = :owner_instance_id
      AND fencing_token     = :fencing_token
""")

# expires_at > now() is evaluated by PostgreSQL, not by the application clock.
_VERIFY_SQL = text("""
    SELECT fencing_token, owner_instance_id,
           expires_at > now() AS not_expired
    FROM federation_sync_leases
    WHERE peer_id = :peer_id
    FOR UPDATE
""")


# ---------------------------------------------------------------------------
# Repository
# ---------------------------------------------------------------------------


class SyncLeaseRepository:
    """Low-level async repository for synchronization leases.

    All methods accept an open SQLAlchemy AsyncSession.  The caller is
    responsible for transactions: claim() and release() must each run inside
    their own short, immediately-committed transaction with no network I/O.
    """

    async def claim(
        self,
        session: AsyncSession,
        *,
        peer_id: uuid.UUID,
        owner_instance_id: uuid.UUID,
        trigger_type: str,
        duration_seconds: int,
    ) -> ClaimedLease | None:
        """Attempt to claim the sync lease for peer_id.

        Validates duration_seconds before executing SQL.  Raises
        LeaseValidationError for invalid values; does NOT silently clamp.

        trigger_type must be one of: 'scheduled', 'manual', 'probe',
        'cursor_recovery'.  The DB CHECK constraint enforces this.

        Returns a ClaimedLease (with expires_at from the database clock) if
        the claim succeeded.  Returns None if an unexpired lease already
        exists for another owner.

        Call inside a short transaction that is committed immediately;
        do not hold the transaction open during subsequent network I/O.
        """
        _validate_duration(duration_seconds)
        result = await session.execute(
            _CLAIM_SQL,
            {
                "peer_id": peer_id,
                "owner_instance_id": owner_instance_id,
                "duration_seconds": duration_seconds,
                "trigger_type": trigger_type,
            },
        )
        row = result.fetchone()
        if row is None:
            return None
        if row.owner_instance_id != owner_instance_id:
            return None
        return ClaimedLease(
            peer_id=peer_id,
            owner_instance_id=owner_instance_id,
            fencing_token=row.fencing_token,
            expires_at=row.expires_at,
        )

    async def release(
        self,
        session: AsyncSession,
        *,
        peer_id: uuid.UUID,
        owner_instance_id: uuid.UUID,
        fencing_token: int,
    ) -> bool:
        """Release a previously claimed lease.

        Returns True if the lease row was deleted (this owner held it).
        Returns False if the row was already gone (another worker displaced
        it after fencing-token expiry, or it was already released).
        """
        result = await session.execute(
            _RELEASE_SQL,
            {
                "peer_id": peer_id,
                "owner_instance_id": owner_instance_id,
                "fencing_token": fencing_token,
            },
        )
        return result.rowcount > 0

    async def verify_still_owned(
        self,
        session: AsyncSession,
        *,
        peer_id: uuid.UUID,
        owner_instance_id: uuid.UUID,
        claimed_fencing_token: int,
    ) -> bool:
        """Verify lease ownership inside an import transaction (FOR UPDATE).

        Must be called inside the page-import transaction before committing
        any imported data or advancing the cursor.  Uses SELECT FOR UPDATE to
        prevent concurrent lease acquisition from racing with this check.

        Expiry is compared against PostgreSQL now(), not the application clock.

        Returns True only if:
          - A lease row exists for peer_id.
          - Its owner_instance_id matches.
          - Its fencing_token matches claimed_fencing_token.
          - expires_at > now() (DB evaluation).

        Returns False otherwise.  The caller must abort the page import and
        NOT advance the cursor.
        """
        result = await session.execute(_VERIFY_SQL, {"peer_id": peer_id})
        row = result.fetchone()
        if row is None:
            return False
        return (
            row.owner_instance_id == owner_instance_id
            and row.fencing_token == claimed_fencing_token
            and bool(row.not_expired)
        )
