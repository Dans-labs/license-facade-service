from __future__ import annotations

import asyncio
import uuid

from typing import Any

from fastapi import APIRouter, Body, Path, Query, Request, Security
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from pydantic import BaseModel, Field

from src.license_facade_service.config.federation import FederationSettings
from src.license_facade_service.api.v1.licenses import get_auth_service
from src.license_facade_service.federation.inbound import FederationInboundSyncService, FederationPeerService
from src.license_facade_service.federation.inbound_models import (
    PeerCircuitResetRequest,
    AdminPublishRequest,
    AdminStatusResponse,
    ImportedRecordListResponse,
    PeerProbeResponse,
    PeerCreateRequest,
    PeerListResponse,
    PeerPatchRequest,
    PeerResponse,
    PeerResumeRequest,
    PeerSuspendRequest,
    SyncResultResponse,
)
from src.license_facade_service.federation.operational_queries import query_operational_status_extension
from src.license_facade_service.federation.resolution import FederationResolutionService, ResolutionError
from src.license_facade_service.federation.resolution_models import ConflictDecisionRequest, ConflictDecisionResponse, ConflictResponse
from src.license_facade_service.federation.outbound import FederationError, FederationPublicationService
from src.license_facade_service.federation.runtime import FederationRuntime
from src.license_facade_service.services.auth import AuthService, AuthenticationError, AuthorizationError, Principal
from src.license_facade_service.services.problem import ProblemDetails, problem_response

router = APIRouter()
bearer_scheme = HTTPBearer(
    auto_error=False,
    description=(
        "Bearer token for protected federation administration operations. "
        "Admin is required for peer management, status inspection, manual sync, and publication. "
        "Curator or admin may review and decide conflicts."
    ),
)


class PublishRecordResponse(BaseModel):
    canonicalId: str = Field(description="Canonical ID assigned to the newly published local authoritative record.")
    recordId: str = Field(description="Local PostgreSQL UUID of the published record.")


def _problem_response_doc(description: str, example: dict[str, Any]) -> dict[str, Any]:
    return {
        "description": description,
        "content": {
            "application/problem+json": {
                "schema": ProblemDetails.model_json_schema(),
                "example": example,
            }
        },
    }


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
        "remote-tls-error": (503, "Remote Peer Unavailable"),
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
        "sync-lease-stale": (409, "Synchronization Lease Stale"),
        "peer-suspended": (409, "Peer Suspended"),
        "peer-archived": (409, "Peer Archived"),
        "circuit-open": (409, "Circuit Open"),
        "circuit-open-admin-reset": (409, "Circuit Open"),
        "invalid-suspension": (400, "Invalid Suspension"),
        "circuit-state-stale": (409, "Circuit State Conflict"),
        "circuit-reset-race": (409, "Circuit Reset Conflict"),
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
    tags=["Federation administration"],
    summary="List trusted federation peers",
    description=(
        "Lists administratively enrolled federation peers.\n\n"
        "Bearer authentication is required and the caller must have the admin role. "
        "Use this endpoint to audit explicit peer trust configuration, pagination state, and last synchronization outcomes."
    ),
    operation_id="listFederationPeers",
    response_description="Configured trusted peers.",
    responses={
        401: _problem_response_doc("Missing or invalid bearer token.", {"type": "https://eosc-eden.eu/problems/unauthorized", "title": "Unauthorized", "status": 401, "detail": "Missing or invalid bearer token."}),
        403: _problem_response_doc("Authenticated principal lacks admin permission.", {"type": "https://eosc-eden.eu/problems/forbidden", "title": "Forbidden", "status": 403, "detail": "Administrator role is required."}),
        404: _problem_response_doc("Federation is disabled for this deployment.", {"type": "https://eosc-eden.eu/problems/federation-disabled", "title": "Federation Disabled", "status": 404, "detail": "Federation is disabled."}),
    },
)
async def list_peers(
    request: Request,
    limit: int = Query(default=20, ge=1, le=200, description="Maximum number of peers to return.", examples=[20]),
    offset: int = Query(default=0, ge=0, description="Zero-based peer list offset.", examples=[0]),
    _token: HTTPAuthorizationCredentials | None = Security(bearer_scheme),
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
    tags=["Federation administration"],
    summary="Enroll a trusted federation peer",
    description=(
        "Creates an explicitly trusted federation peer configuration.\n\n"
        "Bearer authentication is required and the caller must have the admin role. "
        "Enrollment verifies discovery metadata, expected node identity, pinned public-key material, and SSRF restrictions "
        "before the peer can participate in synchronization."
    ),
    operation_id="createFederationPeer",
    response_description="Created trusted peer configuration.",
    responses={
        401: _problem_response_doc("Missing or invalid bearer token.", {"type": "https://eosc-eden.eu/problems/unauthorized", "title": "Unauthorized", "status": 401, "detail": "Missing or invalid bearer token."}),
        403: _problem_response_doc("Authenticated principal lacks admin permission.", {"type": "https://eosc-eden.eu/problems/forbidden", "title": "Forbidden", "status": 403, "detail": "Administrator role is required."}),
        404: _problem_response_doc("Federation is disabled for this deployment.", {"type": "https://eosc-eden.eu/problems/federation-disabled", "title": "Federation Disabled", "status": 404, "detail": "Federation is disabled."}),
        400: _problem_response_doc("Peer identity, pinned key, or remote response validation failed.", {"type": "https://eosc-eden.eu/problems/peer-node-mismatch", "title": "Peer Identity Mismatch", "status": 400, "detail": "Discovery nodeId does not match requested peerNodeId."}),
        409: _problem_response_doc("A peer with the same node identity already exists.", {"type": "https://eosc-eden.eu/problems/peer-exists", "title": "Peer Already Exists", "status": 409, "detail": "Trusted peer already exists."}),
        502: _problem_response_doc("The remote peer responded with invalid or unexpected data.", {"type": "https://eosc-eden.eu/problems/remote-http-error", "title": "Remote Peer Error", "status": 502, "detail": "Remote endpoint returned a server error."}),
        503: _problem_response_doc("The remote peer could not be reached under the current security policy.", {"type": "https://eosc-eden.eu/problems/remote-unreachable", "title": "Remote Peer Unavailable", "status": 503, "detail": "Remote endpoint is unreachable."}),
    },
)
async def create_peer(
    request: Request,
    payload: PeerCreateRequest = Body(description="Trusted peer enrollment request with pinned key material and SSRF allow-list controls."),
    _token: HTTPAuthorizationCredentials | None = Security(bearer_scheme),
):
    try:
        _admin_guard(request)
        peer_service, _, _ = _services(request)
        return peer_service.create_peer(payload=payload, actor="admin")
    except FederationError as error:
        return _problem_from_error(request, error)


@router.get(
    "/api/v1/admin/federation/peers/{peer_id}",
    response_model=PeerResponse,
    tags=["Federation administration"],
    summary="Get one trusted federation peer",
    description=(
        "Returns one explicitly enrolled peer by local peer UUID.\n\n"
        "Bearer authentication is required and the caller must have the admin role."
    ),
    operation_id="getFederationPeer",
    response_description="Trusted peer configuration.",
    responses={401: _problem_response_doc("Missing or invalid bearer token.", {"type": "https://eosc-eden.eu/problems/unauthorized", "title": "Unauthorized", "status": 401, "detail": "Missing or invalid bearer token."}), 403: _problem_response_doc("Authenticated principal lacks admin permission.", {"type": "https://eosc-eden.eu/problems/forbidden", "title": "Forbidden", "status": 403, "detail": "Administrator role is required."}), 404: _problem_response_doc("Peer not found or federation disabled.", {"type": "https://eosc-eden.eu/problems/peer-not-found", "title": "Peer Not Found", "status": 404, "detail": "Trusted peer was not found."})},
)
async def get_peer(
    request: Request,
    peer_id: uuid.UUID = Path(..., description="Local UUID of the trusted peer configuration.", examples=["11111111-1111-4111-8111-111111111111"]),
    _token: HTTPAuthorizationCredentials | None = Security(bearer_scheme),
):
    try:
        _admin_guard(request)
        peer_service, _, _ = _services(request)
        return peer_service.get_peer(peer_id)
    except FederationError as error:
        return _problem_from_error(request, error)


@router.get(
    "/api/v1/admin/federation/peers/{peer_id}/imports",
    response_model=ImportedRecordListResponse,
    tags=["Federation administration"],
    summary="List retained imported records for a peer",
    description=(
        "Lists imported non-authoritative records retained locally for one trusted peer.\n\n"
        "Bearer authentication is required and the caller must have the admin role. Imported records remain resolvable "
        "locally but are not re-exported through the authoritative outbound catalog or changes feed."
    ),
    operation_id="listFederationPeerImports",
    response_description="Imported records retained for the selected peer.",
    responses={401: _problem_response_doc("Missing or invalid bearer token.", {"type": "https://eosc-eden.eu/problems/unauthorized", "title": "Unauthorized", "status": 401, "detail": "Missing or invalid bearer token."}), 403: _problem_response_doc("Authenticated principal lacks admin permission.", {"type": "https://eosc-eden.eu/problems/forbidden", "title": "Forbidden", "status": 403, "detail": "Administrator role is required."}), 404: _problem_response_doc("Peer not found or federation disabled.", {"type": "https://eosc-eden.eu/problems/peer-not-found", "title": "Peer Not Found", "status": 404, "detail": "Trusted peer was not found."})},
)
async def list_imported_records(
    request: Request,
    peer_id: uuid.UUID = Path(..., description="Local UUID of the trusted peer configuration.", examples=["11111111-1111-4111-8111-111111111111"]),
    _token: HTTPAuthorizationCredentials | None = Security(bearer_scheme),
):
    try:
        _admin_guard(request)
        peer_service, _, _ = _services(request)
        return peer_service.list_imported_records(peer_id)
    except FederationError as error:
        return _problem_from_error(request, error)


@router.patch(
    "/api/v1/admin/federation/peers/{peer_id}",
    response_model=PeerResponse,
    tags=["Federation administration"],
    summary="Update a trusted federation peer",
    description=(
        "Updates mutable configuration for an explicitly enrolled peer.\n\n"
        "Bearer authentication is required and the caller must have the admin role. "
        "Use this endpoint to change operational state, allow-lists, metadata labels, or pinned key material."
    ),
    operation_id="updateFederationPeer",
    response_description="Updated trusted peer configuration.",
    responses={401: _problem_response_doc("Missing or invalid bearer token.", {"type": "https://eosc-eden.eu/problems/unauthorized", "title": "Unauthorized", "status": 401, "detail": "Missing or invalid bearer token."}), 403: _problem_response_doc("Authenticated principal lacks admin permission.", {"type": "https://eosc-eden.eu/problems/forbidden", "title": "Forbidden", "status": 403, "detail": "Administrator role is required."}), 404: _problem_response_doc("Peer not found or federation disabled.", {"type": "https://eosc-eden.eu/problems/peer-not-found", "title": "Peer Not Found", "status": 404, "detail": "Trusted peer was not found."}), 409: _problem_response_doc("The requested update conflicts with current peer state.", {"type": "https://eosc-eden.eu/problems/peer-disabled", "title": "Peer Disabled", "status": 409, "detail": "Peer is disabled."})},
)
async def patch_peer(
    request: Request,
    peer_id: uuid.UUID = Path(..., description="Local UUID of the trusted peer configuration.", examples=["11111111-1111-4111-8111-111111111111"]),
    payload: PeerPatchRequest = Body(description="Partial update for a trusted peer configuration."),
    _token: HTTPAuthorizationCredentials | None = Security(bearer_scheme),
):
    try:
        _admin_guard(request)
        peer_service, _, _ = _services(request)
        return peer_service.patch_peer(peer_id=peer_id, payload=payload, actor="admin")
    except FederationError as error:
        return _problem_from_error(request, error)


@router.delete(
    "/api/v1/admin/federation/peers/{peer_id}",
    response_model=PeerResponse,
    tags=["Federation administration"],
    summary="Archive a trusted federation peer",
    description=(
        "Archives a trusted peer configuration.\n\n"
        "Bearer authentication is required and the caller must have the admin role. Archived peers are retained for audit "
        "and provenance purposes but are excluded from normal synchronization and resolution unless policy says otherwise."
    ),
    operation_id="archiveFederationPeer",
    response_description="Archived trusted peer configuration.",
    responses={401: _problem_response_doc("Missing or invalid bearer token.", {"type": "https://eosc-eden.eu/problems/unauthorized", "title": "Unauthorized", "status": 401, "detail": "Missing or invalid bearer token."}), 403: _problem_response_doc("Authenticated principal lacks admin permission.", {"type": "https://eosc-eden.eu/problems/forbidden", "title": "Forbidden", "status": 403, "detail": "Administrator role is required."}), 404: _problem_response_doc("Peer not found or federation disabled.", {"type": "https://eosc-eden.eu/problems/peer-not-found", "title": "Peer Not Found", "status": 404, "detail": "Trusted peer was not found."})},
)
async def delete_peer(
    request: Request,
    peer_id: uuid.UUID = Path(..., description="Local UUID of the trusted peer configuration.", examples=["11111111-1111-4111-8111-111111111111"]),
    _token: HTTPAuthorizationCredentials | None = Security(bearer_scheme),
):
    try:
        _admin_guard(request)
        peer_service, _, _ = _services(request)
        return peer_service.archive_peer(peer_id=peer_id, actor="admin")
    except FederationError as error:
        return _problem_from_error(request, error)


@router.post(
    "/api/v1/admin/federation/peers/{peer_id}/sync",
    response_model=SyncResultResponse,
    tags=["Federation administration"],
    summary="Run manual inbound synchronization for one peer",
    description=(
        "Triggers a synchronous/manual inbound synchronization against one trusted peer.\n\n"
        "Bearer authentication is required and the caller must have the admin role. "
        "Synchronization pulls signed changes, verifies discovery metadata, signatures, digests, node identity, authority, "
        "and canonical identifiers before import. Imported records are stored as non-authoritative. Cursors advance only "
        "after successful commit, repeated synchronization is idempotent, and a lock conflict may return HTTP 409."
    ),
    operation_id="syncFederationPeer",
    response_description="Outcome of the manual synchronization attempt.",
    responses={
        401: _problem_response_doc("Missing or invalid bearer token.", {"type": "https://eosc-eden.eu/problems/unauthorized", "title": "Unauthorized", "status": 401, "detail": "Missing or invalid bearer token."}),
        403: _problem_response_doc("Authenticated principal lacks admin permission.", {"type": "https://eosc-eden.eu/problems/forbidden", "title": "Forbidden", "status": 403, "detail": "Administrator role is required."}),
        404: _problem_response_doc("Peer not found or federation disabled.", {"type": "https://eosc-eden.eu/problems/peer-not-found", "title": "Peer Not Found", "status": 404, "detail": "Trusted peer was not found."}),
        409: _problem_response_doc("Synchronization is already running for this peer.", {"type": "https://eosc-eden.eu/problems/already-running", "title": "Synchronization Already Running", "status": 409, "detail": "Synchronization already in progress."}),
    },
)
async def sync_peer(
    request: Request,
    peer_id: uuid.UUID = Path(..., description="Local UUID of the trusted peer configuration.", examples=["11111111-1111-4111-8111-111111111111"]),
    _token: HTTPAuthorizationCredentials | None = Security(bearer_scheme),
):
    try:
        _admin_guard(request)
        _, sync_service, _ = _services(request)
        result = await asyncio.to_thread(
            sync_service.sync_peer,
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


@router.post(
    "/api/v1/admin/federation/peers/{peer_id}/suspend",
    response_model=PeerResponse,
    tags=["Federation administration"],
    summary="Suspend inbound synchronization for one peer",
    description=(
        "Suspends synchronization for one trusted peer without archiving trust configuration.\n\n"
        "Bearer authentication is required and the caller must have the admin role."
    ),
    operation_id="suspendFederationPeer",
)
async def suspend_peer(
    request: Request,
    payload: PeerSuspendRequest = Body(description="Suspension parameters."),
    peer_id: uuid.UUID = Path(..., description="Local UUID of the trusted peer configuration."),
    _token: HTTPAuthorizationCredentials | None = Security(bearer_scheme),
):
    try:
        _admin_guard(request)
        peer_service, _, _ = _services(request)
        return await asyncio.to_thread(
            peer_service.suspend_peer,
            peer_id=peer_id,
            reason=payload.reason,
            suspended_until=payload.suspendedUntil,
            actor="admin",
        )
    except FederationError as error:
        return _problem_from_error(request, error)


@router.post(
    "/api/v1/admin/federation/peers/{peer_id}/resume",
    response_model=PeerResponse,
    tags=["Federation administration"],
    summary="Resume inbound synchronization for one peer",
    description=(
        "Clears administrative suspension for one trusted peer.\n\n"
        "Bearer authentication is required and the caller must have the admin role."
    ),
    operation_id="resumeFederationPeer",
)
async def resume_peer(
    request: Request,
    payload: PeerResumeRequest = Body(default=PeerResumeRequest(), description="Optional resume reason."),
    peer_id: uuid.UUID = Path(..., description="Local UUID of the trusted peer configuration."),
    _token: HTTPAuthorizationCredentials | None = Security(bearer_scheme),
):
    try:
        _admin_guard(request)
        peer_service, _, _ = _services(request)
        return await asyncio.to_thread(
            peer_service.resume_peer,
            peer_id=peer_id,
            reason=payload.reason,
            actor="admin",
        )
    except FederationError as error:
        return _problem_from_error(request, error)


@router.post(
    "/api/v1/admin/federation/peers/{peer_id}/circuit/reset",
    response_model=PeerResponse,
    tags=["Federation administration"],
    summary="Reset one peer circuit breaker state",
    description=(
        "Resets one peer circuit to closed without changing trust state or cursor.\n\n"
        "Bearer authentication is required and the caller must have the admin role."
    ),
    operation_id="resetFederationPeerCircuit",
)
async def reset_peer_circuit(
    request: Request,
    payload: PeerCircuitResetRequest = Body(description="Circuit reset parameters."),
    peer_id: uuid.UUID = Path(..., description="Local UUID of the trusted peer configuration."),
    _token: HTTPAuthorizationCredentials | None = Security(bearer_scheme),
):
    try:
        _admin_guard(request)
        peer_service, _, _ = _services(request)
        return await asyncio.to_thread(
            peer_service.reset_peer_circuit,
            peer_id=peer_id,
            reason=payload.reason,
            expected_state=payload.expectedState,
            actor="admin",
        )
    except FederationError as error:
        return _problem_from_error(request, error)


@router.post(
    "/api/v1/admin/federation/peers/{peer_id}/probe",
    response_model=PeerProbeResponse,
    tags=["Federation administration"],
    summary="Run read-only peer discovery/JWKS probe",
    description=(
        "Runs a lease-fenced read-only connectivity and identity probe.\n\n"
        "Bearer authentication is required and the caller must have the admin role."
    ),
    operation_id="probeFederationPeer",
)
async def probe_peer(
    request: Request,
    peer_id: uuid.UUID = Path(..., description="Local UUID of the trusted peer configuration."),
    _token: HTTPAuthorizationCredentials | None = Security(bearer_scheme),
):
    try:
        _admin_guard(request)
        peer_service, _, _ = _services(request)
        result = await asyncio.to_thread(peer_service.probe_peer, peer_id=peer_id, actor="admin")
        return PeerProbeResponse(**result)
    except FederationError as error:
        return _problem_from_error(request, error)


@router.get(
    "/api/v1/admin/federation/status",
    response_model=AdminStatusResponse,
    tags=["Federation administration"],
    summary="Inspect local federation administration status",
    description=(
        "Returns local federation runtime and synchronization counters.\n\n"
        "Bearer authentication is required and the caller must have the admin role. Use this endpoint to inspect peer counts, "
        "accepted and rejected inbound events, imported-record totals, and worker timing configuration."
    ),
    operation_id="getFederationAdminStatus",
    response_description="Current federation administration status snapshot.",
    responses={401: _problem_response_doc("Missing or invalid bearer token.", {"type": "https://eosc-eden.eu/problems/unauthorized", "title": "Unauthorized", "status": 401, "detail": "Missing or invalid bearer token."}), 403: _problem_response_doc("Authenticated principal lacks admin permission.", {"type": "https://eosc-eden.eu/problems/forbidden", "title": "Forbidden", "status": 403, "detail": "Administrator role is required."}), 404: _problem_response_doc("Federation is disabled for this deployment.", {"type": "https://eosc-eden.eu/problems/federation-disabled", "title": "Federation Disabled", "status": 404, "detail": "Federation is disabled."})},
)
async def federation_status(request: Request, _token: HTTPAuthorizationCredentials | None = Security(bearer_scheme)):
    try:
        _admin_guard(request)
        _, sync_service, _ = _services(request)
        base = sync_service.status()
        runtime = request.app.state.federation_runtime
        ext = await asyncio.to_thread(query_operational_status_extension, runtime.db, runtime.settings)
        return AdminStatusResponse(**{**base.model_dump(), **ext})
    except FederationError as error:
        return _problem_from_error(request, error)


@router.post(
    "/api/v1/admin/federation/publish",
    response_model=PublishRecordResponse,
    tags=["Federation administration"],
    summary="Publish a local authoritative federation record",
    description=(
        "Creates a new locally authoritative record for outbound federation publication.\n\n"
        "Bearer authentication is required and the caller must have the admin role. Published records become part of the "
        "authoritative outbound catalog and change feed. Imported records are never added to the authoritative outbound feed."
    ),
    operation_id="publishFederationRecord",
    response_description="Canonical ID and local record UUID of the published authoritative record.",
    responses={401: _problem_response_doc("Missing or invalid bearer token.", {"type": "https://eosc-eden.eu/problems/unauthorized", "title": "Unauthorized", "status": 401, "detail": "Missing or invalid bearer token."}), 403: _problem_response_doc("Authenticated principal lacks admin permission.", {"type": "https://eosc-eden.eu/problems/forbidden", "title": "Forbidden", "status": 403, "detail": "Administrator role is required."}), 404: _problem_response_doc("Federation is disabled for this deployment.", {"type": "https://eosc-eden.eu/problems/federation-disabled", "title": "Federation Disabled", "status": 404, "detail": "Federation is disabled."})},
)
async def publish_record(
    request: Request,
    payload: AdminPublishRequest = Body(description="Authoritative record payload to wrap and publish."),
    _token: HTTPAuthorizationCredentials | None = Security(bearer_scheme),
):
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
    tags=["Federation conflicts"],
    summary="List federation resolution conflicts",
    description=(
        "Lists current federation resolution conflicts for curator review.\n\n"
        "Bearer authentication is required. Curator or admin role is sufficient. "
        "Conflicts track ambiguous imported candidates and append-only decision history without allowing imported data "
        "to override a local authoritative record."
    ),
    operation_id="listFederationConflicts",
    response_description="Conflicts available for curator review.",
    responses={401: _problem_response_doc("Missing or invalid bearer token.", {"type": "https://eosc-eden.eu/problems/unauthorized", "title": "Unauthorized", "status": 401, "detail": "Missing or invalid bearer token."}), 403: _problem_response_doc("Authenticated principal lacks curator/admin permission.", {"type": "https://eosc-eden.eu/problems/forbidden", "title": "Forbidden", "status": 403, "detail": "Administrator role is required."})},
)
async def list_conflicts(
    request: Request,
    limit: int = Query(default=50, ge=1, le=200, description="Maximum number of conflicts to return.", examples=[50]),
    offset: int = Query(default=0, ge=0, description="Zero-based conflict list offset.", examples=[0]),
    _token: HTTPAuthorizationCredentials | None = Security(bearer_scheme),
):
    try:
        _curator_guard(request)
        service = _resolution_service(request)
        return service.list_conflicts(limit=limit, offset=offset)
    except ResolutionError as error:
        return _resolution_problem(request, error)


@router.get(
    "/api/v1/admin/federation/conflicts/{conflict_id}",
    response_model=ConflictResponse,
    tags=["Federation conflicts"],
    summary="Get one federation resolution conflict",
    description=(
        "Returns the current state of one federation resolution conflict.\n\n"
        "Bearer authentication is required. Curator or admin role is sufficient."
    ),
    operation_id="getFederationConflict",
    response_description="Conflict details including candidate summary and latest decision event.",
    responses={401: _problem_response_doc("Missing or invalid bearer token.", {"type": "https://eosc-eden.eu/problems/unauthorized", "title": "Unauthorized", "status": 401, "detail": "Missing or invalid bearer token."}), 403: _problem_response_doc("Authenticated principal lacks curator/admin permission.", {"type": "https://eosc-eden.eu/problems/forbidden", "title": "Forbidden", "status": 403, "detail": "Administrator role is required."}), 404: _problem_response_doc("The requested conflict does not exist.", {"type": "https://eosc-eden.eu/problems/conflict-not-found", "title": "Conflict Not Found", "status": 404, "detail": "Conflict not found."})},
)
async def get_conflict(
    request: Request,
    conflict_id: uuid.UUID = Path(..., description="Conflict UUID to inspect.", examples=["22222222-2222-4222-8222-222222222222"]),
    _token: HTTPAuthorizationCredentials | None = Security(bearer_scheme),
):
    try:
        _curator_guard(request)
        service = _resolution_service(request)
        return service.get_conflict(conflict_id)
    except ResolutionError as error:
        return _resolution_problem(request, error)


@router.post(
    "/api/v1/admin/federation/conflicts/{conflict_id}/decisions",
    response_model=ConflictDecisionResponse,
    tags=["Federation conflicts"],
    summary="Record a conflict decision event",
    description=(
        "Appends a curator/admin conflict decision event for the selected conflict.\n\n"
        "Bearer authentication is required. Curator or admin role is sufficient. "
        "Optimistic concurrency is enforced through the `expectedVersion` request field; stale writes return 409."
    ),
    operation_id="decideFederationConflict",
    response_description="Recorded conflict decision event.",
    responses={401: _problem_response_doc("Missing or invalid bearer token.", {"type": "https://eosc-eden.eu/problems/unauthorized", "title": "Unauthorized", "status": 401, "detail": "Missing or invalid bearer token."}), 403: _problem_response_doc("Authenticated principal lacks curator/admin permission.", {"type": "https://eosc-eden.eu/problems/forbidden", "title": "Forbidden", "status": 403, "detail": "Administrator role is required."}), 404: _problem_response_doc("The requested conflict does not exist.", {"type": "https://eosc-eden.eu/problems/conflict-not-found", "title": "Conflict Not Found", "status": 404, "detail": "Conflict not found."}), 409: _problem_response_doc("The conflict version changed or the decision is not allowed in the current state.", {"type": "https://eosc-eden.eu/problems/conflict-stale", "title": "Conflict Version Changed", "status": 409, "detail": "Conflict version changed."})},
)
async def decide_conflict(
    request: Request,
    conflict_id: uuid.UUID = Path(..., description="Conflict UUID to update.", examples=["22222222-2222-4222-8222-222222222222"]),
    payload: ConflictDecisionRequest = Body(description="Append-only conflict decision event request with optimistic-concurrency version."),
    _token: HTTPAuthorizationCredentials | None = Security(bearer_scheme),
):
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
    tags=["Federation conflicts"],
    summary="Append a conflict reversal event",
    description=(
        "Appends a reversal event for the selected conflict.\n\n"
        "Bearer authentication is required. Curator or admin role is sufficient. "
        "The request still uses optimistic concurrency through `expectedVersion`; the endpoint forces `decisionType=reverse`."
    ),
    operation_id="reverseFederationConflict",
    response_description="Recorded conflict reversal event.",
    responses={401: _problem_response_doc("Missing or invalid bearer token.", {"type": "https://eosc-eden.eu/problems/unauthorized", "title": "Unauthorized", "status": 401, "detail": "Missing or invalid bearer token."}), 403: _problem_response_doc("Authenticated principal lacks curator/admin permission.", {"type": "https://eosc-eden.eu/problems/forbidden", "title": "Forbidden", "status": 403, "detail": "Administrator role is required."}), 404: _problem_response_doc("The requested conflict does not exist.", {"type": "https://eosc-eden.eu/problems/conflict-not-found", "title": "Conflict Not Found", "status": 404, "detail": "Conflict not found."}), 409: _problem_response_doc("The conflict version changed or the reversal is not allowed in the current state.", {"type": "https://eosc-eden.eu/problems/conflict-stale", "title": "Conflict Version Changed", "status": 409, "detail": "Conflict version changed."})},
)
async def reverse_conflict(
    request: Request,
    conflict_id: uuid.UUID = Path(..., description="Conflict UUID to reverse.", examples=["22222222-2222-4222-8222-222222222222"]),
    payload: ConflictDecisionRequest = Body(description="Conflict reversal request. `decisionType` is forced to `reverse` by the server."),
    _token: HTTPAuthorizationCredentials | None = Security(bearer_scheme),
):
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
