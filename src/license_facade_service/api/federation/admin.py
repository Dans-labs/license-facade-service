from __future__ import annotations

import uuid

from fastapi import APIRouter, Query, Request

from src.license_facade_service.config.federation import FederationSettings
from src.license_facade_service.api.v1.licenses import get_auth_service
from src.license_facade_service.federation.inbound import FederationInboundSyncService, FederationPeerService
from src.license_facade_service.federation.inbound_models import (
    AdminPublishRequest,
    AdminStatusResponse,
    ImportedRecordListResponse,
    PeerCreateRequest,
    PeerListResponse,
    PeerPatchRequest,
    PeerResponse,
    SyncResultResponse,
)
from src.license_facade_service.federation.resolution import FederationResolutionService, ResolutionError
from src.license_facade_service.federation.resolution_models import ConflictDecisionRequest, ConflictDecisionResponse, ConflictResponse
from src.license_facade_service.federation.outbound import FederationError, FederationPublicationService
from src.license_facade_service.federation.runtime import FederationRuntime
from src.license_facade_service.services.auth import AuthService, AuthenticationError, AuthorizationError, Principal
from src.license_facade_service.services.problem import ProblemDetails, problem_response

router = APIRouter()


def _guard(request: Request, allowed_roles: set[str]) -> Principal:
    auth = get_auth_service()
    try:
        principal = auth.authenticate(request)
    except AuthenticationError as exc:
        raise FederationError("unauthorized", "Missing or invalid bearer token.") from exc
    try:
        auth.authorize(principal, allowed_roles)
    except AuthorizationError as exc:
        raise FederationError("forbidden", "Administrator role is required.") from exc
    return principal


def _admin_guard(request: Request) -> Principal:
    return _guard(request, {"admin"})


def _curator_guard(request: Request) -> Principal:
    return _guard(request, {"admin", "curator"})


def _services(request: Request) -> tuple[FederationPeerService, FederationInboundSyncService, FederationPublicationService]:
    runtime: FederationRuntime | None = getattr(request.app.state, "federation_runtime", None)
    state = getattr(request.app.state, "federation_state", None)
    if runtime is None or state is None or not state.enabled:
        raise FederationError("federation-disabled", "Federation is disabled.")
    if not state.ready or runtime.db is None:
        raise FederationError("federation-unavailable", "Federation runtime is unavailable.")
    return (
        FederationPeerService(runtime.db, runtime.settings),
        FederationInboundSyncService(runtime.db, runtime.settings),
        FederationPublicationService(runtime.db, runtime.settings),
    )


def _resolution_service(request: Request) -> FederationResolutionService:
    runtime: FederationRuntime | None = getattr(request.app.state, "federation_runtime", None)
    state = getattr(request.app.state, "federation_state", None)
    if runtime is None or state is None or not state.enabled:
        from src.license_facade_service.api.v1.licenses import get_license_service

        return FederationResolutionService(None, FederationSettings.from_env(), license_service=get_license_service())
    from src.license_facade_service.api.v1.licenses import get_license_service

    return FederationResolutionService(runtime.db, runtime.settings, license_service=get_license_service())


def _problem_from_error(request: Request, error: FederationError):
    mapping: dict[str, tuple[int, str]] = {
        "unauthorized": (401, "Unauthorized"),
        "forbidden": (403, "Forbidden"),
        "federation-disabled": (404, "Federation Disabled"),
        "peer-not-found": (404, "Peer Not Found"),
        "peer-disabled": (409, "Peer Disabled"),
        "invalid-limit": (400, "Invalid Limit"),
        "invalid-cursor": (400, "Invalid Cursor"),
        "peer-exists": (409, "Peer Already Exists"),
        "peer-node-mismatch": (400, "Peer Identity Mismatch"),
        "peer-key-mismatch": (400, "Peer Key Mismatch"),
        "peer-key-required": (400, "Peer Key Required"),
        "remote-unreachable": (503, "Remote Peer Unavailable"),
        "remote-http-error": (502, "Remote Peer Error"),
        "remote-content-type": (502, "Remote Peer Error"),
        "remote-payload-too-large": (502, "Remote Peer Error"),
        "remote-response-size": (502, "Remote Peer Error"),
        "remote-schema-invalid": (502, "Remote Peer Error"),
        "duplicate-json-key": (502, "Remote Peer Error"),
        "unknown-signing-key": (400, "Unknown Signing Key"),
        "revoked-signing-key": (400, "Revoked Signing Key"),
        "peer-key-missing": (409, "Peer Key Missing"),
        "authority-mismatch": (400, "Authority Mismatch"),
        "digest-mismatch": (400, "Digest Mismatch"),
        "already-running": (409, "Synchronization Already Running"),
        "sync-internal-error": (500, "Synchronization Failed"),
    }
    status, title = mapping.get(error.code, (400, "Federation Administration Error"))
    return problem_response(
        status=status,
        title=title,
        detail=error.detail,
        type_uri=f"https://eosc-eden.eu/problems/{error.code}",
        instance=str(request.url),
    )


def _resolution_problem(request: Request, error: ResolutionError):
    mapping = {
        "invalid-identifier": (400, "Invalid Identifier"),
        "resolution-not-found": (404, "Resolution Not Found"),
        "resolution-ambiguous": (409, "Ambiguous Resolution"),
        "resolution-conflicted": (409, "Conflicted Resolution"),
        "resolution-tombstoned": (410, "Tombstoned Resolution"),
        "resolution-unavailable": (503, "Resolution Unavailable"),
        "conflict-not-found": (404, "Conflict Not Found"),
        "conflict-stale": (409, "Conflict Version Changed"),
        "conflict-not-allowed": (409, "Conflict Decision Not Allowed"),
        "conflict-data-collision": (409, "Conflict Data Collision"),
    }
    status, title = mapping.get(error.code, (400, "Resolution Error"))
    return problem_response(
        status=status,
        title=title,
        detail=error.detail,
        type_uri=f"https://eosc-eden.eu/problems/{error.code}",
        instance=str(request.url),
        extra={"resolutionContext": getattr(error, "context", {})},
    )


@router.get(
    "/api/v1/admin/federation/peers",
    response_model=PeerListResponse,
    responses={401: {"model": ProblemDetails}, 403: {"model": ProblemDetails}, 404: {"model": ProblemDetails}},
)
async def list_peers(
    request: Request,
    limit: int = Query(default=20, ge=1, le=200),
    offset: int = Query(default=0, ge=0),
):
    try:
        _admin_guard(request)
        peer_service, _, _ = _services(request)
        items, total = peer_service.list_peers(limit=limit, offset=offset)
        return PeerListResponse(items=items, limit=limit, offset=offset, total=total)
    except FederationError as error:
        return _problem_from_error(request, error)


@router.post(
    "/api/v1/admin/federation/peers",
    response_model=PeerResponse,
    responses={401: {"model": ProblemDetails}, 403: {"model": ProblemDetails}, 404: {"model": ProblemDetails}},
)
async def create_peer(request: Request, payload: PeerCreateRequest):
    try:
        _admin_guard(request)
        peer_service, _, _ = _services(request)
        return peer_service.create_peer(payload=payload, actor="admin")
    except FederationError as error:
        return _problem_from_error(request, error)


@router.get(
    "/api/v1/admin/federation/peers/{peer_id}",
    response_model=PeerResponse,
    responses={401: {"model": ProblemDetails}, 403: {"model": ProblemDetails}, 404: {"model": ProblemDetails}},
)
async def get_peer(request: Request, peer_id: uuid.UUID):
    try:
        _admin_guard(request)
        peer_service, _, _ = _services(request)
        return peer_service.get_peer(peer_id)
    except FederationError as error:
        return _problem_from_error(request, error)


@router.get(
    "/api/v1/admin/federation/peers/{peer_id}/imports",
    response_model=ImportedRecordListResponse,
    responses={401: {"model": ProblemDetails}, 403: {"model": ProblemDetails}, 404: {"model": ProblemDetails}},
)
async def list_imported_records(request: Request, peer_id: uuid.UUID):
    try:
        _admin_guard(request)
        peer_service, _, _ = _services(request)
        return peer_service.list_imported_records(peer_id)
    except FederationError as error:
        return _problem_from_error(request, error)


@router.patch(
    "/api/v1/admin/federation/peers/{peer_id}",
    response_model=PeerResponse,
    responses={401: {"model": ProblemDetails}, 403: {"model": ProblemDetails}, 404: {"model": ProblemDetails}},
)
async def patch_peer(request: Request, peer_id: uuid.UUID, payload: PeerPatchRequest):
    try:
        _admin_guard(request)
        peer_service, _, _ = _services(request)
        return peer_service.patch_peer(peer_id=peer_id, payload=payload, actor="admin")
    except FederationError as error:
        return _problem_from_error(request, error)


@router.delete(
    "/api/v1/admin/federation/peers/{peer_id}",
    response_model=PeerResponse,
    responses={401: {"model": ProblemDetails}, 403: {"model": ProblemDetails}, 404: {"model": ProblemDetails}},
)
async def delete_peer(request: Request, peer_id: uuid.UUID):
    try:
        _admin_guard(request)
        peer_service, _, _ = _services(request)
        return peer_service.archive_peer(peer_id=peer_id, actor="admin")
    except FederationError as error:
        return _problem_from_error(request, error)


@router.post(
    "/api/v1/admin/federation/peers/{peer_id}/sync",
    response_model=SyncResultResponse,
    responses={
        401: {"model": ProblemDetails},
        403: {"model": ProblemDetails},
        404: {"model": ProblemDetails},
        409: {"model": ProblemDetails},
    },
)
async def sync_peer(request: Request, peer_id: uuid.UUID):
    try:
        _admin_guard(request)
        _, sync_service, _ = _services(request)
        result = sync_service.sync_peer(
            peer_id=peer_id,
            trigger_type="manual",
            max_seconds=sync_service.settings.admin_sync_timeout_seconds,
        )
        if result.status == "already-running":
            return problem_response(
                status=409,
                title="Synchronization Already Running",
                detail=result.detail or "Synchronization already in progress.",
                type_uri="https://eosc-eden.eu/problems/already-running",
                instance=str(request.url),
            )
        return result
    except FederationError as error:
        return _problem_from_error(request, error)


@router.get(
    "/api/v1/admin/federation/status",
    response_model=AdminStatusResponse,
    responses={401: {"model": ProblemDetails}, 403: {"model": ProblemDetails}, 404: {"model": ProblemDetails}},
)
async def federation_status(request: Request):
    try:
        _admin_guard(request)
        _, sync_service, _ = _services(request)
        return sync_service.status()
    except FederationError as error:
        return _problem_from_error(request, error)


@router.post(
    "/api/v1/admin/federation/publish",
    responses={401: {"model": ProblemDetails}, 403: {"model": ProblemDetails}, 404: {"model": ProblemDetails}},
)
async def publish_record(request: Request, payload: AdminPublishRequest):
    try:
        _admin_guard(request)
        _, _, publication = _services(request)
        if publication.settings.node_id is None:
            raise FederationError("federation-unavailable", "Federation node identity is unavailable.")
        canonical_id = f"lfs:{publication.settings.node_id}:{payload.localId}:{payload.version}"
        record_uuid = publication.publish_new_version(
            canonical_id=canonical_id,
            authority_node_id=publication.settings.node_id,
            local_id=payload.localId,
            version=payload.version,
            payload=payload.payload,
        )
        return {"canonicalId": canonical_id, "recordId": str(record_uuid)}
    except FederationError as error:
        return _problem_from_error(request, error)


@router.get(
    "/api/v1/admin/federation/conflicts",
    response_model=list[ConflictResponse],
    responses={401: {"model": ProblemDetails}, 403: {"model": ProblemDetails}},
)
async def list_conflicts(request: Request, limit: int = Query(default=50, ge=1, le=200), offset: int = Query(default=0, ge=0)):
    try:
        _curator_guard(request)
        service = _resolution_service(request)
        return service.list_conflicts(limit=limit, offset=offset)
    except ResolutionError as error:
        return _resolution_problem(request, error)


@router.get(
    "/api/v1/admin/federation/conflicts/{conflict_id}",
    response_model=ConflictResponse,
    responses={401: {"model": ProblemDetails}, 403: {"model": ProblemDetails}, 404: {"model": ProblemDetails}},
)
async def get_conflict(request: Request, conflict_id: uuid.UUID):
    try:
        _curator_guard(request)
        service = _resolution_service(request)
        return service.get_conflict(conflict_id)
    except ResolutionError as error:
        return _resolution_problem(request, error)


@router.post(
    "/api/v1/admin/federation/conflicts/{conflict_id}/decisions",
    response_model=ConflictDecisionResponse,
    responses={401: {"model": ProblemDetails}, 403: {"model": ProblemDetails}, 404: {"model": ProblemDetails}, 409: {"model": ProblemDetails}},
)
async def decide_conflict(request: Request, conflict_id: uuid.UUID, payload: ConflictDecisionRequest):
    try:
        principal = _curator_guard(request)
        service = _resolution_service(request)
        return service.decide_conflict(
            conflict_id=conflict_id,
            payload=payload,
            actor_role=principal.role,
            actor_identifier=principal.role,
        )
    except ResolutionError as error:
        return _resolution_problem(request, error)


@router.post(
    "/api/v1/admin/federation/conflicts/{conflict_id}/reversals",
    response_model=ConflictDecisionResponse,
    responses={401: {"model": ProblemDetails}, 403: {"model": ProblemDetails}, 404: {"model": ProblemDetails}, 409: {"model": ProblemDetails}},
)
async def reverse_conflict(request: Request, conflict_id: uuid.UUID, payload: ConflictDecisionRequest):
    try:
        principal = _curator_guard(request)
        service = _resolution_service(request)
        reversed_payload = payload.model_copy(update={"decisionType": "reverse"})
        return service.decide_conflict(
            conflict_id=conflict_id,
            payload=reversed_payload,
            actor_role=principal.role,
            actor_identifier=principal.role,
        )
    except ResolutionError as error:
        return _resolution_problem(request, error)
