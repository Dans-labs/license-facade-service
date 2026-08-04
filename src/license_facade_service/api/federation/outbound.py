from __future__ import annotations

from fastapi import APIRouter, Query, Request
from fastapi.responses import Response

from src.license_facade_service.federation.canonical_json import canonicalize_to_bytes
from src.license_facade_service.federation.outbound import (
    FederationError,
    FederationOutboundService,
    _etag_for_bytes,
    _parse_if_none_match,
)
from src.license_facade_service.federation.runtime import FederationRuntime
from src.license_facade_service.federation.models import (
    FederationCatalogResponse,
    FederationChangesResponse,
    FederationDiscoveryResponse,
    FederationRecordResponse,
)
from src.license_facade_service.services.problem import ProblemDetails, problem_response

router = APIRouter()


def _federation_service(request: Request) -> FederationOutboundService:
    runtime: FederationRuntime | None = getattr(request.app.state, "federation_runtime", None)
    state = getattr(request.app.state, "federation_state", None)
    if runtime is None or state is None or not state.enabled:
        raise FederationError("federation-disabled", "Federation is disabled.")
    if not state.ready or runtime.db is None:
        if state.errors:
            if any("signing" in error.lower() for error in state.errors):
                raise FederationError("signing-unavailable", "Signing configuration is unavailable.")
            if any("identity" in error.lower() or "configuration changed" in error.lower() for error in state.errors):
                raise FederationError("inconsistent-node-identity", "Node identity state is inconsistent.")
        raise FederationError("federation-unavailable", "Federation service is unavailable.")
    return FederationOutboundService(runtime.db, runtime.settings)


def _problem_from_error(request: Request, error: FederationError) -> Response:
    mapping: dict[str, tuple[int, str]] = {
        "federation-disabled": (404, "Federation Disabled"),
        "federation-unavailable": (503, "Federation Unavailable"),
        "signing-unavailable": (503, "Signing Unavailable"),
        "inconsistent-node-identity": (503, "Inconsistent Node Identity"),
        "invalid-cursor": (400, "Invalid Cursor"),
        "unsupported-cursor-version": (400, "Unsupported Cursor Version"),
        "invalid-limit": (400, "Invalid Limit"),
        "record-not-found": (404, "Record Not Found"),
        "non-authoritative-record": (404, "Non-Authoritative Record"),
        "unpublished-record": (404, "Unpublished Record"),
    }
    status, title = mapping.get(error.code, (400, "Federation Request Error"))
    return problem_response(
        status=status,
        title=title,
        detail=error.detail,
        type_uri=f"https://eosc-eden.eu/problems/{error.code}",
        instance=str(request.url),
    )


def _response_with_etag(
    *,
    request: Request,
    payload: dict,
    etag: str,
    media_type: str = "application/json",
) -> Response:
    if_none_match = request.headers.get("if-none-match")
    if if_none_match:
        normalized = _parse_if_none_match(if_none_match)
        if "*" in normalized or etag in normalized or etag.strip('"') in normalized:
            return Response(
                status_code=304,
                content=b"",
                headers={"ETag": etag, "Cache-Control": "public, max-age=60"},
            )
    body = canonicalize_to_bytes(payload)
    return Response(
        content=body,
        media_type=media_type,
        headers={"ETag": etag, "Cache-Control": "public, max-age=60"},
    )


@router.get(
    "/.well-known/lfs",
    response_model=FederationDiscoveryResponse,
    responses={304: {"description": "Not Modified"}, 404: {"model": ProblemDetails}, 503: {"model": ProblemDetails}},
)
async def federation_discovery(request: Request):
    try:
        service = _federation_service(request)
        payload = service.discovery().model_dump(mode="json")
        etag = _etag_for_bytes(canonicalize_to_bytes(payload))
        return _response_with_etag(request=request, payload=payload, etag=etag)
    except FederationError as error:
        return _problem_from_error(request, error)


@router.get(
    "/api/v1/federation/catalog",
    response_model=FederationCatalogResponse,
    responses={304: {"description": "Not Modified"}, 400: {"model": ProblemDetails}, 404: {"model": ProblemDetails}, 503: {"model": ProblemDetails}},
)
async def federation_catalog(
    request: Request,
    cursor: str | None = Query(default=None, description="Opaque keyset cursor."),
    limit: int | None = Query(default=None, description="Page size (1-200)."),
):
    try:
        service = _federation_service(request)
        payload_model = service.get_catalog(cursor=cursor, limit=limit)
        payload = payload_model.model_dump(mode="json")
        etag = payload.pop("etag")
        return _response_with_etag(request=request, payload=payload, etag=etag)
    except FederationError as error:
        return _problem_from_error(request, error)


@router.get(
    "/api/v1/federation/changes",
    response_model=FederationChangesResponse,
    responses={304: {"description": "Not Modified"}, 400: {"model": ProblemDetails}, 404: {"model": ProblemDetails}, 503: {"model": ProblemDetails}},
)
async def federation_changes(
    request: Request,
    since: str | None = Query(default=None, description="Opaque cursor; returns events strictly after cursor position."),
    limit: int | None = Query(default=None, description="Page size (1-200)."),
):
    try:
        service = _federation_service(request)
        payload_model = service.get_changes(since=since, limit=limit)
        payload = payload_model.model_dump(mode="json")
        etag = payload.pop("etag")
        return _response_with_etag(request=request, payload=payload, etag=etag)
    except FederationError as error:
        return _problem_from_error(request, error)


@router.get(
    "/api/v1/federation/records/{encoded_id}",
    response_model=FederationRecordResponse,
    responses={304: {"description": "Not Modified"}, 400: {"model": ProblemDetails}, 404: {"model": ProblemDetails}, 503: {"model": ProblemDetails}},
)
async def federation_record(request: Request, encoded_id: str):
    try:
        service = _federation_service(request)
        payload_model = service.get_record(encoded_canonical_id=encoded_id)
        payload = payload_model.model_dump(mode="json")

        etag = _etag_for_bytes(canonicalize_to_bytes(payload))
        return _response_with_etag(request=request, payload=payload, etag=etag)
    except FederationError as error:
        return _problem_from_error(request, error)
