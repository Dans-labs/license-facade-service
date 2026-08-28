"""federation/audit.py — Operational audit logging for Phase 5.

Provides:
  - AuditAction: bounded vocabulary of all auditable actions (kept in sync
    with the PostgreSQL CHECK constraint in the migration).
  - AuditActorType, AuditTargetType, AuditOutcome: companion enums.
  - WorkerType, WorkerStatus, LeaseTriggerType, CircuitState,
    CircuitFailureReason, PeerHealthStatus, PeerCompatStatus: further
    bounded vocabulary enums matching DB CHECK constraints.
  - AuditDetailBuilder: builds safe, recursively-redacted JSONB detail dicts.
    No public method bypasses mandatory redaction.
  - write_audit_row(): async function that writes one append-only row inside
    the caller's AsyncSession.

Design notes:
  - target_id stores stable UUIDs or key identifiers (≤ 256 chars).
    Canonical licence identifiers that exceed this limit must be supplied
    in the details mapping; the caller must use the stable internal UUID as
    target_id.  Oversized target_id is rejected with AuditValidationError.
  - All details supplied to write_audit_row() are recursively sanitized
    regardless of source.  No public API claims data is pre-sanitized.
  - PEM blocks are fully redacted (BEGIN header + body + END footer),
    leaving only the marker [PEM REDACTED].
  - Bearer tokens are redacted wherever they appear in string values.
  - SHA-256 hex digests (64-char hex strings) are NOT redacted; they are
    legitimate operational data.
  - Sanitized details exceeding _MAX_DETAILS_BYTES raise AuditDetailsTooLarge.
  - Recursion into nested mappings/lists stops at _MAX_REDACT_DEPTH.
"""

from __future__ import annotations

import json
import re
import uuid
from enum import Enum
from typing import Any

from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import Session

from src.license_facade_service.db.models.federation import FederationOperationalAudit

# ---------------------------------------------------------------------------
# Limits and constants
# ---------------------------------------------------------------------------

_REDACTED      = "[REDACTED]"
_PEM_REDACTED  = "[PEM REDACTED]"

_MAX_STR_VALUE_LEN  = 2048        # individual string values longer than this are truncated
_MAX_REASON_LEN     = 1024        # matches DB CHECK constraint
_MAX_ACTOR_ID_LEN   = 256         # matches DB VARCHAR(256)
_MAX_TARGET_ID_LEN  = 256         # matches DB VARCHAR(256)
_MAX_REQUEST_ID_LEN = 128         # matches DB VARCHAR(128)
_EXCEPTION_TRUNCATE_AT = 500      # max chars for exception summary (no stack trace)
_MAX_DETAILS_BYTES  = 16 * 1024   # 16 KiB cap for serialized JSONB details
_MAX_REDACT_DEPTH   = 10          # max recursion depth for nested structures


# ---------------------------------------------------------------------------
# Typed exceptions
# ---------------------------------------------------------------------------


class AuditValidationError(ValueError):
    """Raised when audit row arguments fail validation before any INSERT."""


class AuditDetailsTooLarge(AuditValidationError):
    """Raised when sanitized details exceed _MAX_DETAILS_BYTES."""


# ---------------------------------------------------------------------------
# Bounded vocabulary enums (MUST match the PostgreSQL CHECK constraints)
# ---------------------------------------------------------------------------


class AuditActorType(str, Enum):
    HUMAN_OPERATOR = "human_operator"
    WORKER         = "worker"
    SYSTEM         = "system"
    API_CLIENT     = "api_client"


class AuditTargetType(str, Enum):
    PEER         = "peer"
    PEER_KEY     = "peer_key"
    SIGNING_KEY  = "signing_key"
    CURSOR       = "cursor"
    CONFLICT     = "conflict"
    RDF_JOB      = "rdf_job"
    SYNC_ATTEMPT = "sync_attempt"
    RECORD       = "record"
    WORKER       = "worker"


class AuditOutcome(str, Enum):
    SUCCESS   = "success"
    REJECTED  = "rejected"
    FAILED    = "failed"
    BLOCKED   = "blocked"
    DRY_RUN   = "dry_run"
    PARTIAL   = "partial"


class AuditAction(str, Enum):
    # Peer lifecycle
    PEER_ENROLL             = "peer.enroll"
    PEER_UPDATE             = "peer.update"
    PEER_DISABLE            = "peer.disable"
    PEER_ARCHIVE            = "peer.archive"
    PEER_SUSPEND            = "peer.suspend"
    PEER_RESUME             = "peer.resume"
    PEER_CIRCUIT_RESET      = "peer.circuit_reset"
    PEER_PROBE              = "peer.probe"

    # Peer key management
    PEER_KEY_INSPECT            = "peer_key.inspect"
    PEER_KEY_APPROVE            = "peer_key.approve"
    PEER_KEY_RETIRE             = "peer_key.retire"
    PEER_KEY_REVOKE             = "peer_key.revoke"
    PEER_KEY_COLLISION_REJECTED = "peer_key.collision_rejected"

    # Local signing key rotation
    SIGNING_KEY_ROTATION_PREPARED  = "signing_key.rotation_prepared"
    SIGNING_KEY_ROTATION_ACTIVATED = "signing_key.rotation_activated"
    SIGNING_KEY_ROTATION_COMPLETED = "signing_key.rotation_completed"
    SIGNING_KEY_ROTATION_ABORTED   = "signing_key.rotation_aborted"
    LOCAL_KEY_INSPECT              = "local_key.inspect"
    LOCAL_KEY_STAGE                = "local_key.stage"
    LOCAL_KEY_SCHEDULE             = "local_key.schedule"
    LOCAL_KEY_SCHEDULE_CANCEL      = "local_key.schedule_cancel"
    LOCAL_KEY_ACTIVATE             = "local_key.activate"
    LOCAL_KEY_RETIRE               = "local_key.retire"
    LOCAL_KEY_REVOKE               = "local_key.revoke"
    LOCAL_KEY_ACTIVATION_FAILED    = "local_key.activation_failed"
    LOCAL_KEY_MATERIAL_MISMATCH    = "local_key.material_mismatch"

    # Cursor recovery
    CURSOR_INSPECT               = "cursor.inspect"
    CURSOR_CHECKPOINT_REQUESTED  = "cursor.checkpoint_requested"
    CURSOR_CHECKPOINT_APPLIED    = "cursor.checkpoint_applied"
    CURSOR_FORWARD_JUMP_REJECTED = "cursor.forward_jump_rejected"

    # Synchronization
    SYNC_MANUAL_TRIGGERED    = "sync.manual_triggered"
    SYNC_CIRCUIT_OPENED      = "sync.circuit_opened"
    SYNC_CIRCUIT_HALF_OPENED = "sync.circuit_half_opened"
    SYNC_CIRCUIT_CLOSED      = "sync.circuit_closed"

    # Conflict management
    CONFLICT_DECISION_RECORDED = "conflict.decision_recorded"
    CONFLICT_REOPENED          = "conflict.reopened"
    CONFLICT_STALE_DISMISSED   = "conflict.stale_dismissed"

    # RDF outbox recovery
    RDF_REQUEUE             = "rdf.requeue"
    RDF_DEAD_LETTER_DRAINED = "rdf.dead_letter_drained"
    RDF_REBUILD_TRIGGERED   = "rdf.rebuild_triggered"
    RDF_RECONCILE_RUN       = "rdf.reconcile_run"

    # Worker lifecycle
    WORKER_STARTED = "worker.started"
    WORKER_STOPPED = "worker.stopped"
    WORKER_FAILED  = "worker.failed"


class WorkerType(str, Enum):
    """Matches migration CHECK constraint on federation_worker_heartbeats."""
    SYNC  = "sync"
    RDF   = "rdf"
    PROBE = "probe"


class WorkerStatus(str, Enum):
    """Matches migration CHECK constraint on federation_worker_heartbeats."""
    RUNNING = "running"
    IDLE    = "idle"
    ERROR   = "error"
    STOPPED = "stopped"


class LeaseTriggerType(str, Enum):
    """Matches migration CHECK constraint on federation_sync_leases."""
    SCHEDULED       = "scheduled"
    MANUAL          = "manual"
    PROBE           = "probe"
    CURSOR_RECOVERY = "cursor_recovery"


class CircuitState(str, Enum):
    """Matches migration CHECK constraint on federation_trusted_peers."""
    CLOSED    = "closed"
    OPEN      = "open"
    HALF_OPEN = "half_open"


class CircuitFailureReason(str, Enum):
    """Matches migration CHECK constraint on federation_trusted_peers."""
    NETWORK_UNREACHABLE     = "network_unreachable"
    TLS_ERROR               = "tls_error"
    REMOTE_5XX              = "remote_5xx"
    CLOCK_SKEW              = "clock_skew"
    DISCOVERY_PARSE_FAILURE = "discovery_parse_failure"
    JWKS_PARSE_FAILURE      = "jwks_parse_failure"
    SIGNATURE_INVALID       = "signature_invalid"
    IDENTITY_MISMATCH       = "identity_mismatch"
    REVOKED_KEY_DETECTED    = "revoked_key_detected"
    KEY_COLLISION           = "key_collision"
    PROTOCOL_INCOMPATIBLE   = "protocol_incompatible"


class PeerHealthStatus(str, Enum):
    """Matches migration CHECK constraint on federation_peer_health_snapshots."""
    HEALTHY     = "healthy"
    DEGRADED    = "degraded"
    UNREACHABLE = "unreachable"
    UNKNOWN     = "unknown"


class PeerCompatStatus(str, Enum):
    """Matches migration CHECK constraint on federation_peer_health_snapshots."""
    COMPATIBLE   = "compatible"
    INCOMPATIBLE = "incompatible"
    UNKNOWN      = "unknown"
    UNCHECKED    = "unchecked"


# ---------------------------------------------------------------------------
# Redaction helpers
# ---------------------------------------------------------------------------

# Normalized (lowercase, underscores/hyphens stripped) key forms that
# indicate sensitive content.  No public method bypasses this check.
_SENSITIVE_NORMALIZED: frozenset[str] = frozenset({
    "authorization",
    "authorizationheader",
    "token",
    "accesstoken",
    "admintoken",
    "bearertoken",
    "password",
    "dbpassword",
    "secret",
    "clientsecret",
    "privatekey",
    "signingkey",
    "pem",
    "credential",
    "credentials",
    "databaseurl",
    "apikey",
})

# Normalized key forms that are explicitly SAFE — never redacted even if
# they superficially resemble sensitive names.
_SAFE_NORMALIZED: frozenset[str] = frozenset({
    "kid",
    "keyid",
    "keytype",
    "keyformat",
    "keystatus",
    "publickeyfingerprint",
})


def _normalize_key(key: str) -> str:
    """Normalize a key name for sensitive-name matching."""
    return key.lower().replace("_", "").replace("-", "")


def _is_sensitive_key(key: str) -> bool:
    """Return True if the key name indicates sensitive content."""
    normalized = _normalize_key(key)
    return normalized not in _SAFE_NORMALIZED and normalized in _SENSITIVE_NORMALIZED


# ---------------------------------------------------------------------------
# Value-based redaction patterns (applied to string content regardless of key)
# ---------------------------------------------------------------------------

# Complete PEM block: BEGIN header + base64 body + END footer.
# [\s\S]*? is lazy so it does not span multiple PEM blocks.
_PEM_PATTERN = re.compile(
    r"-----BEGIN [A-Z0-9 ]+-----[\s\S]*?-----END [A-Z0-9 ]+-----",
)

# Bearer credentials: "Bearer <token>"
_BEARER_PATTERN = re.compile(r"Bearer\s+[A-Za-z0-9._\-]+", re.IGNORECASE)

# URI userinfo: scheme://user:password@host[/path]
# Bounded quantifiers prevent catastrophic backtracking.
_URI_CREDS_PATTERN = re.compile(
    r"(\w{1,30})://[^:@\s/]{1,200}:[^@\s]{0,500}@",
    re.IGNORECASE,
)

# Assignment/header forms: key=value or key: value
# Sensitive key names, case-insensitive, bounded value (no whitespace, or quoted).
# \b...\b prevents matching substrings: "tokenization=x" is NOT matched by \btoken\b.
# Keys listed most-specific first so compound names win over bare "token"/"secret".
_ASSIGNMENT_KEYS_RE = (
    r"password"
    r"|access[_-]?token"
    r"|api[_-]?key"
    r"|client[_-]?secret"
    r"|private[_-]?key"
    r"|credential"
    r"|authorization"
    r"|secret"
    r"|token"
)
# Value portion: double-quoted, single-quoted, or unquoted bounded non-whitespace.
_ASSIGNMENT_VALUE_RE = r'(?:"[^"]{0,500}"|\'[^\']{0,500}\'|[^\s"\']{0,500})'
_ASSIGNMENT_PATTERN = re.compile(
    r"\b(" + _ASSIGNMENT_KEYS_RE + r")\b(\s*[=:]\s*)" + _ASSIGNMENT_VALUE_RE,
    re.IGNORECASE,
)


def _apply_value_patterns(value: str) -> str:
    """Apply all value-based credential redaction patterns to a string.

    This is the centralized sanitization used by both dictionary-value
    redaction and exception-summary redaction.  No truncation is performed
    here so that patterns are applied to the full string before any length
    limit is enforced.

    Patterns applied (in order):
    1. Complete PEM blocks (BEGIN header + body + END footer).
    2. Bearer credentials ("Bearer <token>").
    3. URI userinfo credentials (scheme://user:password@host).
    4. Assignment/header forms (password=…, token=…, Authorization: …, etc.).

    Safe values that are NOT redacted:
    - 64-character hex strings (SHA-256 digests).
    - Ordinary words: "tokenization", "publicKeyFingerprint", "keyStatus".
    """
    # 1. Complete PEM blocks
    value = _PEM_PATTERN.sub(_PEM_REDACTED, value)
    # 2. Bearer tokens
    value = _BEARER_PATTERN.sub("Bearer " + _REDACTED, value)
    # 3. URI credentials: preserve scheme and host; redact userinfo
    value = _URI_CREDS_PATTERN.sub(lambda m: f"{m.group(1)}://{_REDACTED}@", value)
    # 4. Assignment/header forms: preserve key + separator; redact value
    value = _ASSIGNMENT_PATTERN.sub(
        lambda m: f"{m.group(1)}{m.group(2)}{_REDACTED}", value
    )
    return value


def _redact_string(key: str, value: str) -> str:
    """Redact a string value by key name and then by value content patterns."""
    if _is_sensitive_key(key):
        return _REDACTED
    # Apply all value-based patterns (PEM, Bearer, URI creds, assignments).
    value = _apply_value_patterns(value)
    # Truncate excessively long strings AFTER redaction.
    # 64-char hex strings (SHA-256 digests) are not redacted by any pattern above.
    if len(value) > _MAX_STR_VALUE_LEN:
        value = value[:_MAX_STR_VALUE_LEN] + "[truncated]"
    return value


def _redact_value(key: str, value: Any, _depth: int = 0) -> Any:
    """Recursively redact a value according to its key and content.

    Stops recursing at _MAX_REDACT_DEPTH to prevent pathological structures.
    """
    if _depth > _MAX_REDACT_DEPTH:
        return "[depth limit]"
    if isinstance(value, dict):
        return {k: _redact_value(k, v, _depth + 1) for k, v in value.items()}
    if isinstance(value, list):
        return [_redact_value(key, item, _depth + 1) for item in value]
    if isinstance(value, str):
        return _redact_string(key, value)
    # Non-string scalars (int, bool, float, None) — key-sensitivity check only.
    if _is_sensitive_key(key):
        return _REDACTED
    return value


def _redact_exception(exc: BaseException) -> str:
    """Return a bounded, redacted exception summary (no stack trace).

    Applies all value-based credential patterns to the full exception message
    BEFORE applying the length limit, ensuring no credential is truncation-safe.
    """
    msg = f"{type(exc).__name__}: {exc}"
    # Apply all value-based patterns on the full message first.
    msg = _apply_value_patterns(msg)
    # Enforce exception-specific length limit after redaction.
    if len(msg) > _EXCEPTION_TRUNCATE_AT:
        msg = msg[:_EXCEPTION_TRUNCATE_AT] + "[truncated]"
    return msg


def _sanitize_details(details: dict[str, Any]) -> dict[str, Any]:
    """Recursively sanitize a details mapping and enforce the size cap.

    All values are passed through _redact_value regardless of their source.
    Raises AuditDetailsTooLarge when the JSON serialization of the sanitized
    result exceeds _MAX_DETAILS_BYTES.
    """
    sanitized = {k: _redact_value(k, v) for k, v in details.items()}
    serialized = json.dumps(sanitized, separators=(",", ":"))
    byte_count = len(serialized.encode("utf-8"))
    if byte_count > _MAX_DETAILS_BYTES:
        raise AuditDetailsTooLarge(
            f"Sanitized audit details exceed {_MAX_DETAILS_BYTES} bytes "
            f"(got {byte_count} bytes). "
            "Include only bounded operational identifiers in audit details."
        )
    return sanitized


# ---------------------------------------------------------------------------
# AuditDetailBuilder
# ---------------------------------------------------------------------------


class AuditDetailBuilder:
    """Builds a safe, recursively-redacted detail dict for audit rows.

    All values are passed through mandatory redaction — no method bypasses this.

    Usage::

        details = (
            AuditDetailBuilder()
            .add("kidAdded", new_kid)
            .add("fingerprintSha256", fingerprint)   # NOT redacted — safe key
            .add("authorization", token)             # REDACTED
            .from_exception(exc)
            .build()
        )
    """

    def __init__(self) -> None:
        self._data: dict[str, Any] = {}

    def add(self, key: str, value: Any) -> "AuditDetailBuilder":
        """Add a value; it is always recursively sanitized."""
        self._data[key] = _redact_value(key, value)
        return self

    def from_exception(self, exc: BaseException) -> "AuditDetailBuilder":
        """Add a bounded, redacted exception summary (no stack trace)."""
        self._data["errorClass"] = type(exc).__name__
        self._data["errorSummary"] = _redact_exception(exc)
        return self

    def build(self) -> dict[str, Any]:
        return dict(self._data)


def sanitize_free_text(value: str, *, max_len: int = _MAX_REASON_LEN) -> str:
    sanitized = _apply_value_patterns(value)
    if len(sanitized) > max_len:
        sanitized = sanitized[:max_len]
    return sanitized


def build_audit_row(
    *,
    actor_type: AuditActorType,
    action: AuditAction,
    target_type: AuditTargetType,
    target_id: str,
    outcome: AuditOutcome,
    actor_id: str | None = None,
    peer_id: uuid.UUID | None = None,
    request_id: str | None = None,
    reason: str | None = None,
    details: dict[str, Any] | None = None,
) -> FederationOperationalAudit:
    if target_id and len(target_id) > _MAX_TARGET_ID_LEN:
        raise AuditValidationError(
            f"target_id exceeds {_MAX_TARGET_ID_LEN} characters "
            f"(got {len(target_id)}). Use a stable internal UUID as target_id; "
            "include the canonical identifier in the details mapping."
        )
    if request_id and len(request_id) > _MAX_REQUEST_ID_LEN:
        raise AuditValidationError(
            f"request_id exceeds {_MAX_REQUEST_ID_LEN} characters "
            f"(got {len(request_id)})."
        )
    if actor_id and len(actor_id) > _MAX_ACTOR_ID_LEN:
        raise AuditValidationError(
            f"actor_id exceeds {_MAX_ACTOR_ID_LEN} characters "
            f"(got {len(actor_id)})."
        )
    if reason and len(reason) > _MAX_REASON_LEN:
        raise AuditValidationError(
            f"reason exceeds {_MAX_REASON_LEN} characters "
            f"(got {len(reason)})."
        )

    sanitized: dict[str, Any] | None = None
    if details is not None:
        sanitized = _sanitize_details(details)

    return FederationOperationalAudit(
        actor_type=actor_type.value,
        actor_id=actor_id,
        action=action.value,
        target_type=target_type.value,
        target_id=target_id,
        peer_id=peer_id,
        outcome=outcome.value,
        reason=reason,
        request_id=request_id,
        redacted_details=sanitized,
    )


# ---------------------------------------------------------------------------
# write_audit_row
# ---------------------------------------------------------------------------


async def write_audit_row(
    session: AsyncSession,
    *,
    actor_type: AuditActorType,
    action: AuditAction,
    target_type: AuditTargetType,
    target_id: str,
    outcome: AuditOutcome,
    actor_id: str | None = None,
    peer_id: uuid.UUID | None = None,
    request_id: str | None = None,
    reason: str | None = None,
    details: dict[str, Any] | None = None,
) -> FederationOperationalAudit:
    """Insert one append-only audit row inside the caller's AsyncSession.

    The caller is responsible for committing the session.  If the caller's
    transaction rolls back, the audit row is not persisted (correct: a
    rolled-back operation should not produce a success audit).  For
    operations where the audit row must survive a rolled-back application
    transaction, the caller must commit the audit row in a separate short
    transaction first.

    Validation:
    - target_id must be ≤ _MAX_TARGET_ID_LEN characters.  Use a stable
      internal UUID as target_id; include canonical identifiers in details.
    - request_id must be ≤ _MAX_REQUEST_ID_LEN characters.
    - actor_id must be ≤ _MAX_ACTOR_ID_LEN characters.
    - reason must be ≤ _MAX_REASON_LEN characters.
    - All validation failures raise AuditValidationError before any INSERT.
    - All supplied details are recursively sanitized regardless of source.
    - Sanitized details exceeding _MAX_DETAILS_BYTES raise AuditDetailsTooLarge.
    """
    row = build_audit_row(
        actor_type=actor_type,
        action=action,
        target_type=target_type,
        target_id=target_id,
        outcome=outcome,
        actor_id=actor_id,
        peer_id=peer_id,
        request_id=request_id,
        reason=reason,
        details=details,
    )
    session.add(row)
    return row


def write_audit_row_sync(
    session: Session,
    *,
    actor_type: AuditActorType,
    action: AuditAction,
    target_type: AuditTargetType,
    target_id: str,
    outcome: AuditOutcome,
    actor_id: str | None = None,
    peer_id: uuid.UUID | None = None,
    request_id: str | None = None,
    reason: str | None = None,
    details: dict[str, Any] | None = None,
) -> FederationOperationalAudit:
    row = build_audit_row(
        actor_type=actor_type,
        action=action,
        target_type=target_type,
        target_id=target_id,
        outcome=outcome,
        actor_id=actor_id,
        peer_id=peer_id,
        request_id=request_id,
        reason=reason,
        details=details,
    )
    session.add(row)
    return row
