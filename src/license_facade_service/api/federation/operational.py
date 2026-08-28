"""api/federation/operational.py — Phase 5 Increment 2 operational status API endpoints.

All endpoints are admin-only and read-only.
"""

from __future__ import annotations

import asyncio
import uuid
from datetime import datetime

from fastapi import APIRouter, Path, Query, Request, Response, Security
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer

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

_HEALTH_STATUSES = {"healthy", "degraded", "unreachable", "unknown"}
_COMPAT_STATUSES = {"compatible", "incompatible", "unknown", "unchecked"}
_SYNC_STATUSES = {"running", "complete", "partial", "failed", "already-running"}


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
    },
)
async def list_local_signing_keys(
    request: Request,
    _token: HTTPAuthorizationCredentials | None = Security(bearer_scheme),
):
    try:
        _admin_guard(request)
        runtime, _session_factory = _db_helper(request)

        key_dicts = await asyncio.to_thread(query_signing_keys, runtime.db)
        items = [
            LocalSigningKeyItem(
                id=d["id"],
                kid=d["kid"],
                alg=d["alg"],
                kty=d["kty"],
                crv=d["crv"],
                x=d["x"],
                isActive=d["is_active"],
                status=d["status"],
                validFrom=d["valid_from"],
                validUntil=d["valid_until"],
                rotationScheduledAt=d["rotation_scheduled_at"],
                successorKid=d["rotated_to_kid"],
                createdAt=d["created_at"],
                updatedAt=d["updated_at"],
            )
            for d in key_dicts
        ]
        return LocalSigningKeyListResponse(items=items, total=len(items))

    except FederationError as error:
        return _problem_from_error(request, error)


# ---------------------------------------------------------------------------
# Endpoint 4: GET /api/v1/admin/federation/rdf-outbox
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
