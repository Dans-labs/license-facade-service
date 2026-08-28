"""Pydantic response models and signed pagination cursor utilities for Phase 5 Increment 2."""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
from enum import Enum
import uuid
from datetime import datetime
from typing import Any

from pydantic import BaseModel, ConfigDict

class CursorError(ValueError):
    """Raised when a cursor is tampered, wrong kind, wrong filters, or malformed."""


_INVALID_CURSOR_DETAIL = "Pagination cursor is invalid or does not match this request."


_cursor_secret: bytes | None = None


def configure_cursor_secret(secret: str | bytes) -> None:
    """Configure the deployment-wide cursor signing secret."""
    global _cursor_secret
    secret_bytes = secret.encode("utf-8") if isinstance(secret, str) else secret
    if len(secret_bytes) < 32:
        raise ValueError("cursor secret must be at least 32 bytes")
    _cursor_secret = secret_bytes


# ---------------------------------------------------------------------------
# Cursor utilities
# ---------------------------------------------------------------------------


def _b64url_encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def _b64url_decode(data: str) -> bytes:
    padding = 4 - len(data) % 4
    if padding != 4:
        data = data + "=" * padding
    return base64.urlsafe_b64decode(data)


def _get_cursor_secret(secret: str | bytes | None = None) -> bytes:
    if secret is not None:
        if isinstance(secret, str):
            secret = secret.encode("utf-8")
        if len(secret) < 32:
            raise CursorError(_INVALID_CURSOR_DETAIL)
        return secret
    if _cursor_secret is None:
        raise CursorError(_INVALID_CURSOR_DETAIL)
    return _cursor_secret


def _canonicalize(value: Any) -> Any:
    if value is None:
        return {"t": "null"}
    if isinstance(value, uuid.UUID):
        return {"t": "uuid", "v": str(value)}
    if isinstance(value, datetime):
        if value.tzinfo is None or value.utcoffset() is None:
            raise CursorError(_INVALID_CURSOR_DETAIL)
        return {"t": "datetime", "v": value.isoformat()}
    if isinstance(value, Enum):
        return {"t": "enum", "c": value.__class__.__qualname__, "v": value.value}
    if isinstance(value, bool):
        return {"t": "bool", "v": value}
    if isinstance(value, int):
        return {"t": "int", "v": value}
    if isinstance(value, float):
        return {"t": "float", "v": repr(value)}
    if isinstance(value, str):
        return {"t": "str", "v": value}
    if isinstance(value, (list, tuple)):
        return {"t": "list", "v": [_canonicalize(item) for item in value]}
    if isinstance(value, dict):
        items = []
        for key in sorted(value.keys(), key=lambda item: str(item)):
            items.append([str(key), _canonicalize(value[key])])
        return {"t": "dict", "v": items}
    raise CursorError(_INVALID_CURSOR_DETAIL)


def filters_hash(*parts: Any) -> str:
    """Compute a full SHA-256 hash of canonicalized filter parameters."""
    canon = json.dumps(_canonicalize(list(parts)), separators=(",", ":"), sort_keys=True)
    return hashlib.sha256(canon.encode()).hexdigest()


class CursorClaims(BaseModel):
    model_config = ConfigDict(extra="forbid")

    v: int
    k: str
    fh: str
    ts: datetime
    id: uuid.UUID
    l: int
    a: str | None = None


def build_cursor(
    kind: str,
    filters_hash: str,
    last_ts: str | datetime,
    last_id: str | uuid.UUID,
    *,
    limit: int,
    audience: str | None = None,
    secret: str | bytes | None = None,
) -> str:
    """Build a signed pagination cursor."""
    if isinstance(last_ts, str):
        ts = datetime.fromisoformat(last_ts)
    else:
        ts = last_ts
    if ts.tzinfo is None or ts.utcoffset() is None:
        raise CursorError(_INVALID_CURSOR_DETAIL)
    item_id = uuid.UUID(str(last_id))
    payload = {"v": 1, "k": kind, "a": audience, "fh": filters_hash, "ts": ts.isoformat(), "id": str(item_id), "l": limit}
    encoded = _b64url_encode(json.dumps(payload, separators=(",", ":"), sort_keys=True).encode())
    secret_bytes = _get_cursor_secret(secret)
    sig = _b64url_encode(hmac.new(secret_bytes, encoded.encode(), hashlib.sha256).digest())
    return f"{encoded}.{sig}"


def parse_cursor(
    cursor_str: str,
    expected_kind: str,
    expected_filters_hash: str,
    *,
    expected_limit: int,
    expected_audience: str | None = None,
    secret: str | bytes | None = None,
) -> CursorClaims:
    """Parse and validate a signed pagination cursor. Raises CursorError on any issue."""
    try:
        if len(cursor_str) > 4096:
            raise CursorError(_INVALID_CURSOR_DETAIL)
        parts = cursor_str.rsplit(".", 1)
        if len(parts) != 2:
            raise CursorError(_INVALID_CURSOR_DETAIL)
        encoded, sig = parts
        secret_bytes = _get_cursor_secret(secret)
        expected_sig = _b64url_encode(hmac.new(secret_bytes, encoded.encode(), hashlib.sha256).digest())
        if not hmac.compare_digest(sig, expected_sig):
            raise CursorError(_INVALID_CURSOR_DETAIL)
        raw_payload = _b64url_decode(encoded)
        if len(raw_payload) > 2048:
            raise CursorError(_INVALID_CURSOR_DETAIL)
        payload = json.loads(raw_payload.decode())
        claims = CursorClaims.model_validate(payload)
        if claims.v != 1:
            raise CursorError(_INVALID_CURSOR_DETAIL)
        if claims.k != expected_kind:
            raise CursorError(_INVALID_CURSOR_DETAIL)
        if claims.fh != expected_filters_hash:
            raise CursorError(_INVALID_CURSOR_DETAIL)
        if claims.l != expected_limit:
            raise CursorError(_INVALID_CURSOR_DETAIL)
        if expected_audience is not None and claims.a != expected_audience:
            raise CursorError(_INVALID_CURSOR_DETAIL)
        if claims.ts.tzinfo is None or claims.ts.utcoffset() is None:
            raise CursorError(_INVALID_CURSOR_DETAIL)
        return claims
    except CursorError:
        raise
    except Exception as exc:
        raise CursorError(_INVALID_CURSOR_DETAIL) from exc


# ---------------------------------------------------------------------------
# Response models
# ---------------------------------------------------------------------------


class LocalSigningKeyItem(BaseModel):
    model_config = ConfigDict(extra="forbid")

    id: uuid.UUID
    kid: str
    alg: str
    kty: str
    crv: str
    x: str
    isActive: bool
    status: str
    validFrom: datetime | None = None
    validUntil: datetime | None = None
    rotationScheduledAt: datetime | None = None
    successorKid: str | None = None
    createdAt: datetime
    updatedAt: datetime


class LocalSigningKeyListResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

    items: list[LocalSigningKeyItem]
    total: int


class PeerHealthSnapshotItem(BaseModel):
    model_config = ConfigDict(extra="forbid")

    id: uuid.UUID
    peerId: uuid.UUID | None = None
    peerNodeId: str
    sampledAt: datetime
    discoveryReachable: bool | None = None
    jwksReachable: bool | None = None
    feedReachable: bool | None = None
    lastEventPosition: int | None = None
    roundTripMs: int | None = None
    healthStatus: str | None = None
    compatibilityStatus: str | None = None
    errorCode: str | None = None
    errorDetail: str | None = None


class PeerHealthHistoryResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

    items: list[PeerHealthSnapshotItem]
    nextCursor: str | None = None
    limit: int


class PeerCursorResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

    peerId: uuid.UUID
    peerNodeId: str
    cursorExists: bool
    cursor: str | None = None
    lastRemotePosition: int | None = None
    updatedAt: datetime | None = None
    lastSyncSuccessAt: datetime | None = None


class RdfOutboxJobItem(BaseModel):
    model_config = ConfigDict(extra="forbid")

    id: uuid.UUID
    recordId: uuid.UUID | None = None
    authorityNodeId: str | None = None
    jobType: str
    status: str
    attemptCount: int
    nextAttemptAt: datetime | None = None
    leasedUntil: datetime | None = None
    lastErrorCode: str | None = None
    deadLetteredAt: datetime | None = None
    createdAt: datetime
    updatedAt: datetime


class RdfOutboxListResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

    items: list[RdfOutboxJobItem]
    nextCursor: str | None = None
    limit: int


class SyncAttemptItem(BaseModel):
    model_config = ConfigDict(extra="forbid")

    id: uuid.UUID
    peerId: uuid.UUID
    startedAt: datetime
    completedAt: datetime | None = None
    status: str
    triggerType: str
    pagesProcessed: int
    eventsProcessed: int
    errorCode: str | None = None
    createdAt: datetime


class SyncAttemptListResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

    items: list[SyncAttemptItem]
    nextCursor: str | None = None
    limit: int


class PeerCompatibilityEntry(BaseModel):
    model_config = ConfigDict(extra="forbid")

    peerId: uuid.UUID
    peerNodeId: str
    peerName: str
    compatibilityStatus: str
    lastCheckedAt: datetime | None = None


class CompatibilityResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

    localProtocolVersion: str
    localCapabilities: list[str]
    supportedMajorVersions: list[str]
    peers: list[PeerCompatibilityEntry]
    note: str


class SigningKeySummaryModel(BaseModel):
    model_config = ConfigDict(extra="forbid")

    activeKid: str | None = None
    countByStatus: dict[str, int] = {}


class PeerCountSummaryModel(BaseModel):
    model_config = ConfigDict(extra="forbid")

    byTrustStatus: dict[str, int] = {}
    syncEnabled: int = 0
    syncDisabled: int = 0
    byCircuitState: dict[str, int] = {}
    administrativelySuspended: int = 0


class SyncSummaryModel(BaseModel):
    model_config = ConfigDict(extra="forbid")

    totalAttempts: int = 0
    byStatus: dict[str, int] = {}
    mostRecentAttemptAt: datetime | None = None
    mostRecentSuccessAt: datetime | None = None


class WorkerHeartbeatSummaryEntry(BaseModel):
    model_config = ConfigDict(extra="forbid")

    workerType: str
    registeredInstances: int
    freshInstances: int
    staleInstances: int
    mostRecentHeartbeatAt: datetime | None = None
    mostRecentSuccessAt: datetime | None = None


class HealthSnapshotSummaryModel(BaseModel):
    model_config = ConfigDict(extra="forbid")

    byHealthStatus: dict[str, int] = {}
    byCompatibilityStatus: dict[str, int] = {}
