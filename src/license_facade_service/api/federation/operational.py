"""api/federation/operational.py — Phase 5 Increment 2 operational status API endpoints.

All endpoints are admin-only and read-only.
"""

from __future__ import annotations

import asyncio
import uuid
from datetime import datetime

from fastapi import APIRouter, Body, Path, Query, Request, Response, Security
from fastapi.security import HTTPAuthorizationCredentials
from sqlalchemy import select

from src.license_facade_service.api.federation.admin import (
    _admin_guard,
    _problem_from_error,
    _problem_response_doc,
    bearer_scheme,
)
from src.license_facade_service.federation.audit import (
    AuditAction,
    AuditActorType,
    AuditOutcome,
    AuditTargetType,
    write_audit_row,
)
from src.license_facade_service.federation.operational_models import (
    CompatibilityResponse,
    CursorError,
    SigningKeyActivateRequest,
    SigningKeyCancelScheduleRequest,
    SigningKeyEmergencyResponse,
    SigningKeyEmergencyRevokeRequest,
    SigningKeyInspectRequest,
    SigningKeyInspectionResponse,
    SigningKeyMutationResponse,
    SigningKeyRetireRequest,
    SigningKeyScheduleActivationRequest,
    SigningKeyStageRequest,
    LocalSigningKeyItem,
    LocalSigningKeyListResponse,
    PeerCompatibilityEntry,
    PeerCursorResponse,
    PeerHealthHistoryResponse,
    PeerHealthSnapshotItem,
    RdfOutboxJobItem,
    RdfOutboxListResponse,
    SyncAttemptItem,
    SyncAttemptListResponse,
    build_cursor,
    filters_hash,
    parse_cursor,
)
from src.license_facade_service.federation.operational_queries import (
    _RDF_VALID_STATUSES,
    query_compatibility_report,
    query_health_history,
    query_peer_cursor_data,
    query_rdf_outbox,
    query_signing_keys,
    query_sync_attempts,
)
from src.license_facade_service.db.models.federation import FederationSigningKey
from src.license_facade_service.federation.keys import SigningKeyService
from src.license_facade_service.federation.local_key_lifecycle import (
    LocalKeyError,
    LocalKeyErrorCode,
    LocalKeyState,
    SigningKeyLifecycleService,
    constant_time_x_match,
    fingerprint_for_x,
)
from src.license_facade_service.federation.outbound import FederationError
from src.license_facade_service.federation.runtime import FederationRuntime
from src.license_facade_service.services.problem import problem_response

router = APIRouter()


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------


def _db_helper(request: Request):
    """Get DB and runtime from app state. Raises FederationError if unavailable."""
    runtime: FederationRuntime | None = getattr(request.app.state, "federation_runtime", None)
    state = getattr(request.app.state, "federation_state", None)
    if runtime is None or state is None or not state.enabled:
        raise FederationError("federation-disabled", "Federation is disabled.")
    if not state.ready or runtime.db is None:
        raise FederationError("federation-unavailable", "Federation runtime is unavailable.")
    session_factory = getattr(request.app.state, "federation_async_sessionmaker", None)
    if session_factory is None:
        raise FederationError("federation-unavailable", "Federation async session factory is unavailable.")
    return runtime, session_factory


async def _write_cursor_audit(
    session_factory,
    *,
    peer_id: uuid.UUID | None,
    target_id: str,
    outcome: AuditOutcome,
    actor_id: str | None,
    details: dict,
) -> None:
    async with session_factory() as session:
        await write_audit_row(
            session,
            actor_type=AuditActorType.HUMAN_OPERATOR,
            action=AuditAction.CURSOR_INSPECT,
            target_type=AuditTargetType.PEER,
            target_id=target_id,
            peer_id=peer_id,
            outcome=outcome,
            actor_id=actor_id,
            details=details,
        )
        await session.commit()


_INVALID_CURSOR_PROBLEM = _problem_response_doc(
    "Cursor is invalid, tampered, or does not match current filters.",
    {
        "type": "https://eosc-eden.eu/problems/invalid-cursor",
        "title": "Invalid Cursor",
        "status": 400,
        "detail": "Pagination cursor is invalid or does not match current query parameters.",
    },
)

_UNAUTHORIZED_DOC = _problem_response_doc(
    "Missing or invalid bearer token.",
    {"type": "https://eosc-eden.eu/problems/unauthorized", "title": "Unauthorized", "status": 401, "detail": "Missing or invalid bearer token."},
)
_FORBIDDEN_DOC = _problem_response_doc(
    "Authenticated principal lacks admin permission.",
    {"type": "https://eosc-eden.eu/problems/forbidden", "title": "Forbidden", "status": 403, "detail": "Administrator role is required."},
)
_FED_DISABLED_DOC = _problem_response_doc(
    "Federation is disabled for this deployment.",
    {"type": "https://eosc-eden.eu/problems/federation-disabled", "title": "Federation Disabled", "status": 404, "detail": "Federation is disabled."},
)
_PEER_NOT_FOUND_DOC = _problem_response_doc(
    "The requested peer was not found.",
    {"type": "https://eosc-eden.eu/problems/peer-not-found", "title": "Peer Not Found", "status": 404, "detail": "Trusted peer was not found."},
)
_AUDIT_FAILURE_DOC = _problem_response_doc(
    "Operational audit write failed.",
    {"type": "https://eosc-eden.eu/problems/audit-failed", "title": "Service Unavailable", "status": 503, "detail": "Operational audit write failed."},
)
_VALIDATION_DOC = _problem_response_doc(
    "Request validation failed.",
    {"type": "https://eosc-eden.eu/problems/validation-error", "title": "Validation Error", "status": 422, "detail": "Request validation failed."},
)
_LOCAL_KEY_BAD_REQUEST_DOC = _problem_response_doc(
    "Signing-key input validation failed.",
    {
        "type": "https://eosc-eden.eu/problems/invalid-kid",
        "title": "Invalid Signing-Key Request",
        "status": 400,
        "detail": "Signing-key request is invalid.",
    },
)
_LOCAL_KEY_NOT_FOUND_DOC = _problem_response_doc(
    "Signing key was not found.",
    {
        "type": "https://eosc-eden.eu/problems/key-not-found",
        "title": "Signing Key Not Found",
        "status": 404,
        "detail": "Signing key was not found.",
    },
)
_LOCAL_KEY_CONFLICT_DOC = _problem_response_doc(
    "Signing-key lifecycle state conflicts with current database state.",
    {
        "type": "https://eosc-eden.eu/problems/expected-state-mismatch",
        "title": "Signing Key State Conflict",
        "status": 409,
        "detail": "Current key state does not match expected state.",
    },
)
_LOCAL_KEY_UNAVAILABLE_DOC = _problem_response_doc(
    "Signing-key material or dependent runtime component is unavailable.",
    {
        "type": "https://eosc-eden.eu/problems/key-unreadable",
        "title": "Signing Key Unavailable",
        "status": 503,
        "detail": "Signing key material is unavailable.",
    },
)
_WARNING_ACK_DOC = _problem_response_doc(
    "Operation requires explicit warning acknowledgement.",
    {
        "type": "https://eosc-eden.eu/problems/warning-ack-required",
        "title": "Warning Acknowledgement Required",
        "status": 400,
        "detail": "warningAck must be true for this operation.",
    },
)

_HEALTH_STATUSES = {"healthy", "degraded", "unreachable", "unknown"}
_COMPAT_STATUSES = {"compatible", "incompatible", "unknown", "unchecked"}
_SYNC_STATUSES = {"running", "complete", "partial", "failed", "already-running"}
_LOCAL_KEY_PATH_PATTERN = r"^[a-z0-9][a-z0-9._-]{0,127}$"


def _local_key_services(request: Request) -> tuple[FederationRuntime, SigningKeyService, SigningKeyLifecycleService]:
    runtime, _session_factory = _db_helper(request)
    signing = SigningKeyService(runtime.db, runtime.settings)
    lifecycle = SigningKeyLifecycleService(runtime.db, signing.provider)
    return runtime, signing, lifecycle


def _warning_ack_problem(request: Request):
    return problem_response(
        status=400,
        title="Warning Acknowledgement Required",
        detail="warningAck must be true for this operation.",
        type_uri="https://eosc-eden.eu/problems/warning-ack-required",
        instance=str(request.url),
    )


def _dependency_failure_problem(request: Request):
    return problem_response(
        status=503,
        title="Service Unavailable",
        detail="Federation signing-key operation is unavailable.",
        type_uri="https://eosc-eden.eu/problems/federation-unavailable",
        instance=str(request.url),
    )


def _problem_from_local_key_error(request: Request, error: LocalKeyError):
    mapping: dict[LocalKeyErrorCode, tuple[int, str]] = {
        LocalKeyErrorCode.INVALID_KID: (400, "Invalid Signing Key Identifier"),
        LocalKeyErrorCode.INVALID_REASON: (400, "Invalid Operation Reason"),
        LocalKeyErrorCode.INVALID_ACTOR_ID: (400, "Invalid Actor Identifier"),
        LocalKeyErrorCode.INVALID_ACTIVATION_TIME: (400, "Invalid Activation Time"),
        LocalKeyErrorCode.KEY_NOT_FOUND: (404, "Signing Key Not Found"),
        LocalKeyErrorCode.EXPECTED_STATE_MISMATCH: (409, "Signing Key State Conflict"),
        LocalKeyErrorCode.SCHEDULE_CONFLICT: (409, "Signing Key Schedule Conflict"),
        LocalKeyErrorCode.TRANSITION_FORBIDDEN: (409, "Signing Key Transition Forbidden"),
        LocalKeyErrorCode.COLLISION: (409, "Signing Key Collision"),
        LocalKeyErrorCode.SUCCESSOR_REQUIRED: (409, "Signing Key Successor Required"),
        LocalKeyErrorCode.ACTIVE_KEY_MISSING: (409, "Active Signing Key Missing"),
        LocalKeyErrorCode.AMBIGUOUS_ACTIVE_KEY: (409, "Ambiguous Active Signing Key"),
        LocalKeyErrorCode.KEY_NOT_REGULAR_FILE: (503, "Signing Key Unavailable"),
        LocalKeyErrorCode.KEY_UNREADABLE: (503, "Signing Key Unavailable"),
        LocalKeyErrorCode.KEY_EMPTY: (503, "Signing Key Unavailable"),
        LocalKeyErrorCode.KEY_UNSAFE_PERMISSIONS: (503, "Signing Key Unavailable"),
        LocalKeyErrorCode.KEY_PATH_ESCAPE: (503, "Signing Key Unavailable"),
        LocalKeyErrorCode.KEY_MALFORMED: (503, "Signing Key Unavailable"),
        LocalKeyErrorCode.KEY_NOT_ED25519: (503, "Signing Key Unavailable"),
        LocalKeyErrorCode.MATERIAL_MISMATCH: (503, "Signing Key Material Mismatch"),
        LocalKeyErrorCode.AUDIT_FAILED: (503, "Operational Audit Failed"),
    }
    status, title = mapping.get(error.code, (503, "Signing Key Operation Failed"))
    return problem_response(
        status=status,
        title=title,
        detail=error.detail,
        type_uri=f"https://eosc-eden.eu/problems/{error.code.value}",
        instance=str(request.url),
    )


def _build_signing_key_inventory_response(runtime: FederationRuntime, signing_service: SigningKeyService) -> LocalSigningKeyListResponse:
    key_dicts = query_signing_keys(runtime.db)
    items: list[LocalSigningKeyItem] = []
    for d in key_dicts:
        material_status = "ready"
        try:
            loaded = signing_service.provider.load_private_key(d["kid"])
            if not constant_time_x_match(d["x"], loaded.public_x):
                material_status = LocalKeyErrorCode.MATERIAL_MISMATCH.value
        except LocalKeyError as error:
            material_status = error.code.value
        items.append(
            LocalSigningKeyItem(
                id=d["id"],
                kid=d["kid"],
                alg=d["alg"],
                kty=d["kty"],
                crv=d["crv"],
                x=d["x"],
                publicFingerprint=f"sha256:{fingerprint_for_x(d['x'])}",
                materialStatus=material_status,
                isActive=d["is_active"],
                status=d["status"],
                validFrom=d["valid_from"],
                validUntil=d["valid_until"],
                rotationScheduledAt=d["rotation_scheduled_at"],
                rotatedToKid=d["rotated_to_kid"],
                successorKid=d["rotated_to_kid"],
                createdAt=d["created_at"],
                updatedAt=d["updated_at"],
            )
        )
    return LocalSigningKeyListResponse(items=items, total=len(items))


def _load_signing_key_snapshot(runtime: FederationRuntime, kid: str) -> dict | None:
    with runtime.db.transaction() as session:
        row = session.execute(select(FederationSigningKey).where(FederationSigningKey.kid == kid)).scalar_one_or_none()
        if row is None:
            return None
        previous_active = session.execute(
            select(FederationSigningKey.kid)
            .where(
                FederationSigningKey.rotated_to_kid == row.kid,
                FederationSigningKey.status.in_([LocalKeyState.RETIRED.value, LocalKeyState.REVOKED.value]),
            )
            .order_by(FederationSigningKey.updated_at.desc(), FederationSigningKey.created_at.desc(), FederationSigningKey.kid.asc())
            .limit(1)
        ).scalar_one_or_none()
        row_values = {
            "kid": row.kid,
            "status": row.status,
            "rotation_scheduled_at": row.rotation_scheduled_at,
            "rotated_to_kid": row.rotated_to_kid,
            "valid_from": row.valid_from,
            "valid_until": row.valid_until,
            "updated_at": row.updated_at,
        }
    return {
        **row_values,
        "previous_active_kid": previous_active,
    }


def _lifecycle_response_from_result(runtime: FederationRuntime, result) -> SigningKeyMutationResponse:
    snapshot = _load_signing_key_snapshot(runtime, result.kid)
    if snapshot is None:
        raise LocalKeyError(LocalKeyErrorCode.KEY_NOT_FOUND, "Signing key was not found.")
    effective_at = snapshot["updated_at"]
    if snapshot["status"] == LocalKeyState.ACTIVE.value and snapshot["valid_from"] is not None:
        effective_at = snapshot["valid_from"]
    elif snapshot["status"] in {LocalKeyState.RETIRED.value, LocalKeyState.REVOKED.value} and snapshot["valid_until"] is not None:
        effective_at = snapshot["valid_until"]
    return SigningKeyMutationResponse(
        kid=snapshot["kid"],
        status=snapshot["status"],
        resultCode=result.reason_code,
        rotationScheduledAt=snapshot["rotation_scheduled_at"],
        rotatedToKid=snapshot["rotated_to_kid"],
        previousActiveKid=snapshot["previous_active_kid"],
        effectiveAt=effective_at,
    )


def _load_signing_key_snapshot_pair(runtime: FederationRuntime, revoked_kid: str, successor_kid: str) -> tuple[dict | None, dict | None]:
    with runtime.db.transaction() as session:
        rows = session.execute(
            select(FederationSigningKey).where(FederationSigningKey.kid.in_([revoked_kid, successor_kid]))
        ).scalars().all()
        mapped = {row.kid: row for row in rows}
        if revoked_kid not in mapped or successor_kid not in mapped:
            return None, None
        previous_active = session.execute(
            select(FederationSigningKey.kid)
            .where(
                FederationSigningKey.rotated_to_kid == successor_kid,
                FederationSigningKey.status.in_([LocalKeyState.RETIRED.value, LocalKeyState.REVOKED.value]),
            )
            .order_by(FederationSigningKey.updated_at.desc(), FederationSigningKey.created_at.desc(), FederationSigningKey.kid.asc())
            .limit(1)
        ).scalar_one_or_none()
        revoked = mapped[revoked_kid]
        successor = mapped[successor_kid]
        revoked_snapshot = {
            "kid": revoked.kid,
            "status": revoked.status,
            "rotation_scheduled_at": revoked.rotation_scheduled_at,
            "rotated_to_kid": revoked.rotated_to_kid,
            "valid_from": revoked.valid_from,
            "valid_until": revoked.valid_until,
            "updated_at": revoked.updated_at,
            "previous_active_kid": previous_active,
        }
        successor_snapshot = {
            "kid": successor.kid,
            "status": successor.status,
            "rotation_scheduled_at": successor.rotation_scheduled_at,
            "rotated_to_kid": successor.rotated_to_kid,
            "valid_from": successor.valid_from,
            "valid_until": successor.valid_until,
            "updated_at": successor.updated_at,
            "previous_active_kid": previous_active,
        }
        return revoked_snapshot, successor_snapshot


def _cursor_problem(request: Request):
    return problem_response(
        status=400,
        title="Invalid Cursor",
        detail="Pagination cursor is invalid or does not match this request.",
        type_uri="https://eosc-eden.eu/problems/invalid-cursor",
        instance=str(request.url),
    )


def _invalid_filter_problem(request: Request, title: str, detail: str, type_uri: str = "https://eosc-eden.eu/problems/invalid-filter"):
    return problem_response(status=400, title=title, detail=detail, type_uri=type_uri, instance=str(request.url))


def _validate_aware_datetime(name: str, value: datetime | None):
    if value is None:
        return
    if value.tzinfo is None or value.utcoffset() is None:
        raise FederationError("invalid-filter", f"{name} must be timezone-aware.")


# ---------------------------------------------------------------------------
# Endpoint 1: GET /api/v1/admin/federation/peers/{peer_id}/health
# ---------------------------------------------------------------------------


@router.get(
    "/api/v1/admin/federation/peers/{peer_id}/health",
    response_model=PeerHealthHistoryResponse,
    tags=["Federation operations"],
    summary="List peer health probe history",
    description=(
        "Returns paginated health snapshot history for a federation peer, ordered descending by sample time.\n\n"
        "Requires admin bearer token. Supports keyset pagination via cursor, and optional filtering by "
        "health status or compatibility status."
    ),
    operation_id="getPeerHealthHistory",
    response_description="Paginated health snapshot history for the peer.",
    responses={
        400: _INVALID_CURSOR_PROBLEM,
        401: _UNAUTHORIZED_DOC,
        403: _FORBIDDEN_DOC,
        404: _PEER_NOT_FOUND_DOC,
        422: _VALIDATION_DOC,
    },
)
async def get_peer_health_history(
    request: Request,
    peer_id: uuid.UUID = Path(description="Local UUID of the trusted peer."),
    limit: int = Query(default=50, ge=1, le=200, description="Maximum number of results to return (1–200)."),
    cursor: str | None = Query(default=None, description="Keyset pagination cursor from a previous response."),
    healthStatus: str | None = Query(default=None, description="Filter by health status value."),
    compatibilityStatus: str | None = Query(default=None, description="Filter by compatibility status value."),
    _token: HTTPAuthorizationCredentials | None = Security(bearer_scheme),
):
    try:
        _admin_guard(request)
        runtime, session_factory = _db_helper(request)

        if healthStatus is not None and healthStatus not in _HEALTH_STATUSES:
            return _invalid_filter_problem(
                request,
                "Invalid Health Status",
                f"healthStatus must be one of {sorted(_HEALTH_STATUSES)}.",
            )
        if compatibilityStatus is not None and compatibilityStatus not in _COMPAT_STATUSES:
            return _invalid_filter_problem(
                request,
                "Invalid Compatibility Status",
                f"compatibilityStatus must be one of {sorted(_COMPAT_STATUSES)}.",
            )

        cursor_data: dict | None = None
        if cursor:
            fh = filters_hash(peer_id, healthStatus, compatibilityStatus, limit, "desc")
            try:
                cursor_claims = parse_cursor(
                    cursor,
                    "health",
                    fh,
                    expected_limit=limit,
                    expected_audience=runtime.settings.node_id,
                    secret=runtime.settings.admin_cursor_secret.encode() if runtime.settings.admin_cursor_secret else None,
                )
                cursor_data = {"ts": cursor_claims.ts.isoformat(), "id": str(cursor_claims.id)}
            except CursorError as exc:
                return _cursor_problem(request)

        items, next_cursor = await asyncio.to_thread(
            query_health_history,
            runtime.db,
            peer_id,
            limit=limit,
            cursor_data=cursor_data,
            health_status_filter=healthStatus,
            compat_status_filter=compatibilityStatus,
            cursor_audience=runtime.settings.node_id,
            cursor_secret=runtime.settings.admin_cursor_secret.encode() if runtime.settings.admin_cursor_secret else None,
        )

        # If no results, check peer exists to distinguish 404 vs empty
        if not items and not cursor:
            cursor_info = await asyncio.to_thread(query_peer_cursor_data, runtime.db, peer_id)
            if not cursor_info.get("peer_exists"):
                raise FederationError("peer-not-found", "Trusted peer was not found.")

        response_items = [
            PeerHealthSnapshotItem(
                id=d["id"],
                peerId=d["peer_id"],
                peerNodeId=d["peer_node_id"],
                sampledAt=d["sampled_at"],
                discoveryReachable=d["discovery_reachable"],
                jwksReachable=d["jwks_reachable"],
                feedReachable=d["feed_reachable"],
                lastEventPosition=d["last_event_position"],
                roundTripMs=d["round_trip_ms"],
                healthStatus=d["health_status"],
                compatibilityStatus=d["compatibility_status"],
                errorCode=d["error_code"],
                errorDetail=d["error_detail"],
            )
            for d in items
        ]
        return PeerHealthHistoryResponse(items=response_items, nextCursor=next_cursor, limit=limit)

    except FederationError as error:
        resp = _problem_from_error(request, error)
        resp.headers["Cache-Control"] = "no-store"
        return resp


# ---------------------------------------------------------------------------
# Endpoint 2: GET /api/v1/admin/federation/peers/{peer_id}/cursor
# ---------------------------------------------------------------------------


@router.get(
    "/api/v1/admin/federation/peers/{peer_id}/cursor",
    response_model=PeerCursorResponse,
    tags=["Federation operations"],
    summary="Inspect peer synchronization cursor state",
    description=(
        "Returns the current synchronization cursor state for a federation peer.\n\n"
        "Requires admin bearer token. Writes one operational audit row per call. "
        "Response is non-cacheable (Cache-Control: no-store)."
    ),
    operation_id="getPeerCursor",
    response_description="Current synchronization cursor state for the peer.",
    responses={
        401: _UNAUTHORIZED_DOC,
        403: _FORBIDDEN_DOC,
        404: _FED_DISABLED_DOC,
        503: _AUDIT_FAILURE_DOC,
        422: _VALIDATION_DOC,
    },
)
async def get_peer_cursor(
    request: Request,
    response: Response,
    peer_id: uuid.UUID = Path(description="Local UUID of the trusted peer."),
    _token: HTTPAuthorizationCredentials | None = Security(bearer_scheme),
):
    response.headers["Cache-Control"] = "no-store"
    try:
        _admin_guard(request)
        runtime, session_factory = _db_helper(request)

        data = await asyncio.to_thread(query_peer_cursor_data, runtime.db, peer_id)
        if not data.get("peer_exists"):
            try:
                await _write_cursor_audit(
                    session_factory,
                    peer_id=None,
                    target_id=str(peer_id),
                    outcome=AuditOutcome.REJECTED,
                    actor_id=None,
                    details={"peerId": str(peer_id)},
                )
            except Exception:
                return problem_response(
                    status=503,
                    title="Service Unavailable",
                    detail="Operational audit write failed.",
                    type_uri="https://eosc-eden.eu/problems/audit-failed",
                    instance=str(request.url),
                    headers={"Cache-Control": "no-store"},
                )
            raise FederationError("peer-not-found", "Trusted peer was not found.")

        try:
            await _write_cursor_audit(
                session_factory,
                peer_id=data["peer_id"],
                target_id=str(data["peer_id"]),
                outcome=AuditOutcome.SUCCESS,
                actor_id=None,
                details={"peerId": str(data["peer_id"]), "peerNodeId": str(data["peer_node_id"])},
            )
        except Exception:
            return problem_response(
                status=503,
                title="Service Unavailable",
                detail="Operational audit write failed.",
                type_uri="https://eosc-eden.eu/problems/audit-failed",
                instance=str(request.url),
                headers={"Cache-Control": "no-store"},
            )

        return PeerCursorResponse(
            peerId=data["peer_id"],
            peerNodeId=data["peer_node_id"],
            cursorExists=data["cursor_exists"],
            cursor=data["cursor"],
            lastRemotePosition=data["last_remote_position"],
            updatedAt=data["updated_at"],
            lastSyncSuccessAt=data["last_sync_success_at"],
        )

    except FederationError as error:
        resp = _problem_from_error(request, error)
        resp.headers["Cache-Control"] = "no-store"
        return resp


# ---------------------------------------------------------------------------
# Endpoint 3: GET /api/v1/admin/federation/signing-keys
# ---------------------------------------------------------------------------


@router.get(
    "/api/v1/admin/federation/signing-keys",
    response_model=LocalSigningKeyListResponse,
    tags=["Federation operations"],
    summary="List local federation signing keys",
    description=(
        "Returns all local federation signing keys (public material only).\n\n"
        "Requires admin bearer token. Private key material (`d`), PEM blocks, and secret references are never returned."
    ),
    operation_id="listLocalSigningKeys",
    response_description="All local signing keys with public metadata.",
    responses={
        401: _UNAUTHORIZED_DOC,
        403: _FORBIDDEN_DOC,
        404: _FED_DISABLED_DOC,
        503: _LOCAL_KEY_UNAVAILABLE_DOC,
    },
)
async def list_local_signing_keys(
    request: Request,
    _token: HTTPAuthorizationCredentials | None = Security(bearer_scheme),
):
    try:
        _admin_guard(request)
        runtime, signing_service, _lifecycle = _local_key_services(request)
        return await asyncio.to_thread(_build_signing_key_inventory_response, runtime, signing_service)
    except LocalKeyError as error:
        return _problem_from_local_key_error(request, error)
    except FederationError as error:
        return _problem_from_error(request, error)
    except Exception:
        return _dependency_failure_problem(request)


# ---------------------------------------------------------------------------
# Endpoint 4: POST /api/v1/admin/federation/signing-keys/inspect
# ---------------------------------------------------------------------------


@router.post(
    "/api/v1/admin/federation/signing-keys/inspect",
    response_model=SigningKeyInspectionResponse,
    tags=["Federation administration"],
    summary="Inspect local signing-key material",
    description=(
        "Loads one configured local signing-key candidate and returns public inspection metadata.\n\n"
        "Requires admin bearer token. The response never includes private key bytes, PEM, or filesystem paths."
    ),
    operation_id="inspectLocalSigningKey",
    responses={
        400: _LOCAL_KEY_BAD_REQUEST_DOC,
        401: _UNAUTHORIZED_DOC,
        403: _FORBIDDEN_DOC,
        404: _LOCAL_KEY_NOT_FOUND_DOC,
        422: _VALIDATION_DOC,
        503: _LOCAL_KEY_UNAVAILABLE_DOC,
    },
)
async def inspect_local_signing_key(
    request: Request,
    payload: SigningKeyInspectRequest = Body(description="Signing-key inspection request."),
    _token: HTTPAuthorizationCredentials | None = Security(bearer_scheme),
):
    try:
        _admin_guard(request)
        _runtime, _signing, lifecycle = _local_key_services(request)
        result = await asyncio.to_thread(
            lifecycle.inspect_candidate,
            kid=payload.kid,
            reason=payload.reason,
            actor_id="admin",
        )
        return SigningKeyInspectionResponse(
            kid=result.kid,
            publicFingerprint=f"sha256:{result.fingerprint}",
            publicX=result.public_x,
            resultCode=result.reason_code,
        )
    except LocalKeyError as error:
        return _problem_from_local_key_error(request, error)
    except FederationError as error:
        return _problem_from_error(request, error)
    except Exception:
        return _dependency_failure_problem(request)


@router.post(
    "/api/v1/admin/federation/signing-keys/stage",
    response_model=SigningKeyMutationResponse,
    tags=["Federation administration"],
    summary="Stage a local signing-key candidate",
    description=(
        "Stages a local signing-key candidate for future activation.\n\n"
        "Requires admin bearer token and validates lifecycle transitions under row lock."
    ),
    operation_id="stageLocalSigningKey",
    responses={
        400: _LOCAL_KEY_BAD_REQUEST_DOC,
        401: _UNAUTHORIZED_DOC,
        403: _FORBIDDEN_DOC,
        409: _LOCAL_KEY_CONFLICT_DOC,
        422: _VALIDATION_DOC,
        503: _LOCAL_KEY_UNAVAILABLE_DOC,
    },
)
async def stage_local_signing_key(
    request: Request,
    payload: SigningKeyStageRequest = Body(description="Signing-key staging request."),
    _token: HTTPAuthorizationCredentials | None = Security(bearer_scheme),
):
    try:
        _admin_guard(request)
        runtime, _signing, lifecycle = _local_key_services(request)
        expected_state = LocalKeyState(payload.expectedState) if payload.expectedState else None
        result = await asyncio.to_thread(
            lifecycle.stage_candidate,
            kid=payload.kid,
            reason=payload.reason,
            expected_state=expected_state,
            actor_id="admin",
        )
        return await asyncio.to_thread(_lifecycle_response_from_result, runtime, result)
    except LocalKeyError as error:
        return _problem_from_local_key_error(request, error)
    except FederationError as error:
        return _problem_from_error(request, error)
    except Exception:
        return _dependency_failure_problem(request)


@router.post(
    "/api/v1/admin/federation/signing-keys/{kid}/schedule-activation",
    response_model=SigningKeyMutationResponse,
    tags=["Federation administration"],
    summary="Schedule local signing-key activation",
    description=(
        "Schedules activation for a staged local signing key.\n\n"
        "Requires admin bearer token and timezone-aware activation timestamp."
    ),
    operation_id="scheduleLocalSigningKeyActivation",
    responses={
        400: _LOCAL_KEY_BAD_REQUEST_DOC,
        401: _UNAUTHORIZED_DOC,
        403: _FORBIDDEN_DOC,
        404: _LOCAL_KEY_NOT_FOUND_DOC,
        409: _LOCAL_KEY_CONFLICT_DOC,
        422: _VALIDATION_DOC,
        503: _LOCAL_KEY_UNAVAILABLE_DOC,
    },
)
async def schedule_local_signing_key_activation(
    request: Request,
    kid: str = Path(
        ...,
        description="Signing key identifier.",
        min_length=1,
        max_length=128,
        pattern=_LOCAL_KEY_PATH_PATTERN,
    ),
    payload: SigningKeyScheduleActivationRequest = Body(description="Activation schedule request."),
    _token: HTTPAuthorizationCredentials | None = Security(bearer_scheme),
):
    try:
        _admin_guard(request)
        runtime, _signing, lifecycle = _local_key_services(request)
        result = await asyncio.to_thread(
            lifecycle.schedule_activation,
            kid=kid,
            activate_at=payload.activateAt,
            reason=payload.reason,
            expected_state=LocalKeyState(payload.expectedState),
            actor_id="admin",
        )
        return await asyncio.to_thread(_lifecycle_response_from_result, runtime, result)
    except LocalKeyError as error:
        return _problem_from_local_key_error(request, error)
    except FederationError as error:
        return _problem_from_error(request, error)
    except Exception:
        return _dependency_failure_problem(request)


@router.post(
    "/api/v1/admin/federation/signing-keys/{kid}/cancel-schedule",
    response_model=SigningKeyMutationResponse,
    tags=["Federation administration"],
    summary="Cancel local signing-key schedule",
    description=(
        "Cancels a scheduled activation for a staged local signing key.\n\n"
        "Requires admin bearer token and expected-state enforcement under row lock."
    ),
    operation_id="cancelLocalSigningKeySchedule",
    responses={
        400: _LOCAL_KEY_BAD_REQUEST_DOC,
        401: _UNAUTHORIZED_DOC,
        403: _FORBIDDEN_DOC,
        404: _LOCAL_KEY_NOT_FOUND_DOC,
        409: _LOCAL_KEY_CONFLICT_DOC,
        422: _VALIDATION_DOC,
        503: _LOCAL_KEY_UNAVAILABLE_DOC,
    },
)
async def cancel_local_signing_key_schedule(
    request: Request,
    kid: str = Path(
        ...,
        description="Signing key identifier.",
        min_length=1,
        max_length=128,
        pattern=_LOCAL_KEY_PATH_PATTERN,
    ),
    payload: SigningKeyCancelScheduleRequest = Body(description="Schedule cancellation request."),
    _token: HTTPAuthorizationCredentials | None = Security(bearer_scheme),
):
    try:
        _admin_guard(request)
        runtime, _signing, lifecycle = _local_key_services(request)
        result = await asyncio.to_thread(
            lifecycle.cancel_schedule,
            kid=kid,
            reason=payload.reason,
            expected_state=LocalKeyState(payload.expectedState),
            actor_id="admin",
        )
        return await asyncio.to_thread(_lifecycle_response_from_result, runtime, result)
    except LocalKeyError as error:
        return _problem_from_local_key_error(request, error)
    except FederationError as error:
        return _problem_from_error(request, error)
    except Exception:
        return _dependency_failure_problem(request)


@router.post(
    "/api/v1/admin/federation/signing-keys/{kid}/activate",
    response_model=SigningKeyMutationResponse,
    tags=["Federation administration"],
    summary="Activate staged local signing key",
    description=(
        "Immediately activates a staged local signing key.\n\n"
        "Requires admin bearer token and explicit warning acknowledgement."
    ),
    operation_id="activateLocalSigningKey",
    responses={
        400: _WARNING_ACK_DOC,
        401: _UNAUTHORIZED_DOC,
        403: _FORBIDDEN_DOC,
        404: _LOCAL_KEY_NOT_FOUND_DOC,
        409: _LOCAL_KEY_CONFLICT_DOC,
        422: _VALIDATION_DOC,
        503: _LOCAL_KEY_UNAVAILABLE_DOC,
    },
)
async def activate_local_signing_key(
    request: Request,
    kid: str = Path(
        ...,
        description="Signing key identifier.",
        min_length=1,
        max_length=128,
        pattern=_LOCAL_KEY_PATH_PATTERN,
    ),
    payload: SigningKeyActivateRequest = Body(description="Immediate activation request."),
    _token: HTTPAuthorizationCredentials | None = Security(bearer_scheme),
):
    try:
        _admin_guard(request)
        if payload.warningAck is not True:
            return _warning_ack_problem(request)
        runtime, _signing, lifecycle = _local_key_services(request)
        result = await asyncio.to_thread(
            lifecycle.activate_staged_key,
            kid=kid,
            reason=payload.reason,
            expected_state=LocalKeyState(payload.expectedState),
            actor_id="admin",
        )
        return await asyncio.to_thread(_lifecycle_response_from_result, runtime, result)
    except LocalKeyError as error:
        return _problem_from_local_key_error(request, error)
    except FederationError as error:
        return _problem_from_error(request, error)
    except Exception:
        return _dependency_failure_problem(request)


@router.post(
    "/api/v1/admin/federation/signing-keys/{kid}/retire",
    response_model=SigningKeyMutationResponse,
    tags=["Federation administration"],
    summary="Retire staged local signing key",
    description=(
        "Retires a staged local signing key and clears pending schedule state.\n\n"
        "Requires admin bearer token and expected-state revalidation under row lock."
    ),
    operation_id="retireLocalSigningKey",
    responses={
        400: _LOCAL_KEY_BAD_REQUEST_DOC,
        401: _UNAUTHORIZED_DOC,
        403: _FORBIDDEN_DOC,
        404: _LOCAL_KEY_NOT_FOUND_DOC,
        409: _LOCAL_KEY_CONFLICT_DOC,
        422: _VALIDATION_DOC,
        503: _LOCAL_KEY_UNAVAILABLE_DOC,
    },
)
async def retire_local_signing_key(
    request: Request,
    kid: str = Path(
        ...,
        description="Signing key identifier.",
        min_length=1,
        max_length=128,
        pattern=_LOCAL_KEY_PATH_PATTERN,
    ),
    payload: SigningKeyRetireRequest = Body(description="Retire request."),
    _token: HTTPAuthorizationCredentials | None = Security(bearer_scheme),
):
    try:
        _admin_guard(request)
        runtime, _signing, lifecycle = _local_key_services(request)
        expected_state = LocalKeyState(payload.expectedState)
        result = await asyncio.to_thread(
            lifecycle.retire_staged_key,
            kid=kid,
            reason=payload.reason,
            expected_state=expected_state,
            actor_id="admin",
        )
        return await asyncio.to_thread(_lifecycle_response_from_result, runtime, result)
    except LocalKeyError as error:
        return _problem_from_local_key_error(request, error)
    except FederationError as error:
        return _problem_from_error(request, error)
    except Exception:
        return _dependency_failure_problem(request)


@router.post(
    "/api/v1/admin/federation/signing-keys/{kid}/revoke-emergency",
    response_model=SigningKeyEmergencyResponse,
    tags=["Federation administration"],
    summary="Emergency revoke active signing key with staged successor",
    description=(
        "Emergency-revokes the active key and atomically activates the staged successor.\n\n"
        "Requires admin bearer token, explicit warning acknowledgement, and expected-state checks under lock."
    ),
    operation_id="emergencyRevokeLocalSigningKey",
    responses={
        400: _WARNING_ACK_DOC,
        401: _UNAUTHORIZED_DOC,
        403: _FORBIDDEN_DOC,
        404: _LOCAL_KEY_NOT_FOUND_DOC,
        409: _LOCAL_KEY_CONFLICT_DOC,
        422: _VALIDATION_DOC,
        503: _LOCAL_KEY_UNAVAILABLE_DOC,
    },
)
async def emergency_revoke_local_signing_key(
    request: Request,
    kid: str = Path(
        ...,
        description="Current active signing key identifier.",
        min_length=1,
        max_length=128,
        pattern=_LOCAL_KEY_PATH_PATTERN,
    ),
    payload: SigningKeyEmergencyRevokeRequest = Body(description="Emergency revocation request."),
    _token: HTTPAuthorizationCredentials | None = Security(bearer_scheme),
):
    try:
        _admin_guard(request)
        if payload.warningAck is not True:
            return _warning_ack_problem(request)
        runtime, _signing, lifecycle = _local_key_services(request)
        result = await asyncio.to_thread(
            lifecycle.emergency_revoke_with_successor,
            active_kid=kid,
            successor_kid=payload.successorKid,
            reason=payload.reason,
            expected_active_state=LocalKeyState(payload.expectedState),
            expected_successor_state=LocalKeyState(payload.successorExpectedState),
            actor_id="admin",
        )
        revoked_snapshot, successor_snapshot = await asyncio.to_thread(
            _load_signing_key_snapshot_pair,
            runtime,
            result.kid,
            payload.successorKid,
        )
        if revoked_snapshot is None or successor_snapshot is None:
            raise LocalKeyError(LocalKeyErrorCode.KEY_NOT_FOUND, "Signing key was not found.")
        effective_at = revoked_snapshot["valid_until"] or revoked_snapshot["updated_at"]
        return SigningKeyEmergencyResponse(
            revokedKid=result.kid,
            successorKid=successor_snapshot["kid"],
            successorStatus=successor_snapshot["status"],
            resultCode=result.reason_code,
            effectiveAt=effective_at,
        )
    except LocalKeyError as error:
        return _problem_from_local_key_error(request, error)
    except FederationError as error:
        return _problem_from_error(request, error)
    except Exception:
        return _dependency_failure_problem(request)


# ---------------------------------------------------------------------------
# Endpoint 5: GET /api/v1/admin/federation/rdf-outbox
# ---------------------------------------------------------------------------


@router.get(
    "/api/v1/admin/federation/rdf-outbox",
    response_model=RdfOutboxListResponse,
    tags=["Federation operations"],
    summary="List RDF outbox jobs",
    description=(
        "Returns paginated RDF outbox job queue, ordered descending by update time.\n\n"
        "Requires admin bearer token. Supports keyset pagination via cursor, and optional filtering by "
        "status or record ID. Sensitive fields (payload, leased_by) are never returned."
    ),
    operation_id="listRdfOutboxJobs",
    response_description="Paginated RDF outbox job list.",
    responses={
        400: _INVALID_CURSOR_PROBLEM,
        401: _UNAUTHORIZED_DOC,
        403: _FORBIDDEN_DOC,
        404: _FED_DISABLED_DOC,
        422: _VALIDATION_DOC,
    },
)
async def list_rdf_outbox_jobs(
    request: Request,
    limit: int = Query(default=50, ge=1, le=200, description="Maximum number of results to return (1–200)."),
    cursor: str | None = Query(default=None, description="Keyset pagination cursor from a previous response."),
    status: str | None = Query(default=None, description="Filter by job status."),
    recordId: uuid.UUID | None = Query(default=None, description="Filter by record UUID."),
    _token: HTTPAuthorizationCredentials | None = Security(bearer_scheme),
):
    try:
        _admin_guard(request)
        runtime, _session_factory = _db_helper(request)

        # Validate status filter
        if status and status not in _RDF_VALID_STATUSES:
            return _invalid_filter_problem(
                request,
                "Invalid Status Filter",
                f"status must be one of {sorted(_RDF_VALID_STATUSES)}.",
            )

        record_uuid = recordId

        cursor_data: dict | None = None
        if cursor:
            fh = filters_hash(status, record_uuid, limit, "desc")
            try:
                cursor_claims = parse_cursor(
                    cursor,
                    "rdf",
                    fh,
                    expected_limit=limit,
                    expected_audience=runtime.settings.node_id,
                    secret=runtime.settings.admin_cursor_secret.encode() if runtime.settings.admin_cursor_secret else None,
                )
                cursor_data = {"ts": cursor_claims.ts.isoformat(), "id": str(cursor_claims.id)}
            except CursorError:
                return _cursor_problem(request)

        items, next_cursor = await asyncio.to_thread(
            query_rdf_outbox,
            runtime.db,
            limit=limit,
            cursor_data=cursor_data,
            status_filter=status,
            record_id_filter=record_uuid,
            cursor_audience=runtime.settings.node_id,
            cursor_secret=runtime.settings.admin_cursor_secret.encode() if runtime.settings.admin_cursor_secret else None,
        )

        response_items = [
            RdfOutboxJobItem(
                id=d["id"],
                recordId=d["record_id"],
                authorityNodeId=d["authority_node_id"],
                jobType=d["job_type"],
                status=d["status"],
                attemptCount=d["attempt_count"],
                nextAttemptAt=d["next_attempt_at"],
                leasedUntil=d["leased_until"],
                lastErrorCode=d["last_error_code"],
                deadLetteredAt=d["dead_lettered_at"],
                createdAt=d["created_at"],
                updatedAt=d["updated_at"],
            )
            for d in items
        ]
        return RdfOutboxListResponse(items=response_items, nextCursor=next_cursor, limit=limit)

    except FederationError as error:
        return _problem_from_error(request, error)


# ---------------------------------------------------------------------------
# Endpoint 5: GET /api/v1/admin/federation/sync-attempts
# ---------------------------------------------------------------------------


@router.get(
    "/api/v1/admin/federation/sync-attempts",
    response_model=SyncAttemptListResponse,
    tags=["Federation operations"],
    summary="List federation synchronization attempts",
    description=(
        "Returns paginated federation synchronization attempt history, ordered descending by start time.\n\n"
        "Requires admin bearer token. Supports keyset pagination, and optional filtering by peer, status, "
        "error class, and time range. Cursor tokens are never returned in responses."
    ),
    operation_id="listSyncAttempts",
    response_description="Paginated synchronization attempt list.",
    responses={
        400: _INVALID_CURSOR_PROBLEM,
        401: _UNAUTHORIZED_DOC,
        403: _FORBIDDEN_DOC,
        404: _FED_DISABLED_DOC,
        422: _VALIDATION_DOC,
    },
)
async def list_sync_attempts(
    request: Request,
    limit: int = Query(default=50, ge=1, le=200, description="Maximum number of results to return (1–200)."),
    cursor: str | None = Query(default=None, description="Keyset pagination cursor from a previous response."),
    peerId: uuid.UUID | None = Query(default=None, description="Filter by peer UUID."),
    status: str | None = Query(default=None, description="Filter by attempt status."),
    errorClass: str | None = Query(default=None, description="Filter by error code class."),
    startedAfter: datetime | None = Query(default=None, description="Filter attempts started after this timestamp."),
    startedBefore: datetime | None = Query(default=None, description="Filter attempts started before this timestamp."),
    _token: HTTPAuthorizationCredentials | None = Security(bearer_scheme),
):
    try:
        _admin_guard(request)
        runtime, _session_factory = _db_helper(request)

        if status is not None and status not in _SYNC_STATUSES:
            return _invalid_filter_problem(
                request,
                "Invalid Sync Status",
                f"status must be one of {sorted(_SYNC_STATUSES)}.",
            )
        if errorClass is not None and len(errorClass) > 64:
            return _invalid_filter_problem(
                request,
                "Invalid Error Class",
                "errorClass must be 64 characters or fewer.",
            )
        _validate_aware_datetime("startedAfter", startedAfter)
        _validate_aware_datetime("startedBefore", startedBefore)
        if startedAfter and startedBefore and startedAfter > startedBefore:
            return _invalid_filter_problem(
                request,
                "Invalid Time Range",
                "startedAfter must be earlier than or equal to startedBefore.",
            )

        cursor_data: dict | None = None
        if cursor:
            fh = filters_hash(peerId, status, errorClass, startedAfter, startedBefore, limit, "desc")
            try:
                cursor_claims = parse_cursor(
                    cursor,
                    "sync",
                    fh,
                    expected_limit=limit,
                    expected_audience=runtime.settings.node_id,
                    secret=runtime.settings.admin_cursor_secret.encode() if runtime.settings.admin_cursor_secret else None,
                )
                cursor_data = {"ts": cursor_claims.ts.isoformat(), "id": str(cursor_claims.id)}
            except CursorError:
                return _cursor_problem(request)

        items, next_cursor = await asyncio.to_thread(
            query_sync_attempts,
            runtime.db,
            limit=limit,
            cursor_data=cursor_data,
            peer_id_filter=peerId,
            status_filter=status,
            error_class_filter=errorClass,
            started_after=startedAfter,
            started_before=startedBefore,
            cursor_audience=runtime.settings.node_id,
            cursor_secret=runtime.settings.admin_cursor_secret.encode() if runtime.settings.admin_cursor_secret else None,
        )

        response_items = [
            SyncAttemptItem(
                id=d["id"],
                peerId=d["peer_id"],
                startedAt=d["started_at"],
                completedAt=d["completed_at"],
                status=d["status"],
                triggerType=d["trigger_type"],
                pagesProcessed=d["pages_processed"],
                eventsProcessed=d["events_processed"],
                errorCode=d["error_code"],
                createdAt=d["created_at"],
            )
            for d in items
        ]
        return SyncAttemptListResponse(items=response_items, nextCursor=next_cursor, limit=limit)

    except FederationError as error:
        return _problem_from_error(request, error)


# ---------------------------------------------------------------------------
# Endpoint 6: GET /api/v1/admin/federation/compatibility
# ---------------------------------------------------------------------------


@router.get(
    "/api/v1/admin/federation/compatibility",
    response_model=CompatibilityResponse,
    tags=["Federation operations"],
    summary="Get federation compatibility report",
    description=(
        "Returns local protocol version, capabilities, and per-peer compatibility status.\n\n"
        "Requires admin bearer token. Uses only persisted data — no live network probes are made."
    ),
    operation_id="getFederationCompatibility",
    response_description="Federation compatibility report based on persisted health snapshot data.",
    responses={
        401: _UNAUTHORIZED_DOC,
        403: _FORBIDDEN_DOC,
        404: _FED_DISABLED_DOC,
        422: _VALIDATION_DOC,
    },
)
async def get_federation_compatibility(
    request: Request,
    _token: HTTPAuthorizationCredentials | None = Security(bearer_scheme),
):
    try:
        _admin_guard(request)
        runtime, _session_factory = _db_helper(request)

        data = await asyncio.to_thread(query_compatibility_report, runtime.db, runtime.settings)

        peer_entries = [
            PeerCompatibilityEntry(
                peerId=p["peer_id"],
                peerNodeId=p["peer_node_id"],
                peerName=p["peer_name"],
                compatibilityStatus=p["compatibility_status"],
                lastCheckedAt=p["last_checked_at"],
            )
            for p in data["peers"]
        ]
        return CompatibilityResponse(
            localProtocolVersion=data["local_protocol_version"],
            localCapabilities=data["local_capabilities"],
            supportedMajorVersions=data["supported_major_versions"],
            peers=peer_entries,
            note=data["note"],
        )

    except FederationError as error:
        return _problem_from_error(request, error)
