from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Header, Path, Query, Request
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
    tags=["Federation discovery"],
    summary="Get the federation discovery document",
    description=(
        "Returns the public federation discovery document for this node.\n\n"
        "Use this endpoint during peer enrollment to learn the node identity, public base URL, active signing key ID, "
        "and advertised federation endpoints. Conditional GET with `If-None-Match` is supported and may return 304."
    ),
    operation_id="getFederationDiscoveryDocument",
    response_description="Discovery document describing this federation node and its public endpoints.",
    responses={
        304: {"description": "Discovery document unchanged for the supplied ETag."},
        404: _problem_response_doc("Federation is disabled for this deployment.", {"type": "https://eosc-eden.eu/problems/federation-disabled", "title": "Federation Disabled", "status": 404, "detail": "Federation is disabled."}),
        503: _problem_response_doc("Federation runtime is not ready to serve discovery metadata.", {"type": "https://eosc-eden.eu/problems/federation-unavailable", "title": "Federation Unavailable", "status": 503, "detail": "Federation service is unavailable."}),
    },
)
async def federation_discovery(
    request: Request,
    _if_none_match: str | None = Header(default=None, alias="If-None-Match", description="Strong ETag validator for conditional GET. Matching ETags return 304."),
):
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
    tags=["Federation outbound"],
    summary="List authoritative outbound federation records",
    description=(
        "Returns the authoritative outbound catalog for this node.\n\n"
        "Only locally authoritative published records are included. Imported records are never re-exported here. "
        "Pagination uses an opaque keyset cursor plus a stable watermark, and conditional GET with `If-None-Match` may return 304."
    ),
    operation_id="listFederationCatalog",
    response_description="Page of locally authoritative records published by this node.",
    responses={
        304: {"description": "Catalog page unchanged for the supplied ETag."},
        400: _problem_response_doc("The supplied cursor or page size was invalid.", {"type": "https://eosc-eden.eu/problems/invalid-cursor", "title": "Invalid Cursor", "status": 400, "detail": "Cursor is invalid."}),
        404: _problem_response_doc("Federation is disabled for this deployment.", {"type": "https://eosc-eden.eu/problems/federation-disabled", "title": "Federation Disabled", "status": 404, "detail": "Federation is disabled."}),
        503: _problem_response_doc("Federation runtime is not ready to serve the outbound catalog.", {"type": "https://eosc-eden.eu/problems/federation-unavailable", "title": "Federation Unavailable", "status": 503, "detail": "Federation service is unavailable."}),
    },
)
async def federation_catalog(
    request: Request,
    cursor: str | None = Query(default=None, description="Opaque keyset cursor from a previous catalog page.", examples=["v1.node-a-k1.catalog.example"]),
    limit: int | None = Query(default=None, description="Page size in the range 1-200.", examples=[100]),
    _if_none_match: str | None = Header(default=None, alias="If-None-Match", description="Strong ETag validator for conditional GET. Matching ETags return 304."),
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
    tags=["Federation outbound"],
    summary="List signed authoritative change events",
    description=(
        "Returns the signed authoritative change feed for this node.\n\n"
        "Clients should verify signatures and digests for every event and envelope before import. "
        "`since` requests events strictly after the supplied cursor, `nextCursor` advances page traversal, and "
        "`resumeCursor` is safe to persist only after the client commits the page successfully."
    ),
    operation_id="listFederationChanges",
    response_description="Page of signed authoritative change events.",
    responses={
        304: {"description": "Change-feed page unchanged for the supplied ETag."},
        400: _problem_response_doc("The supplied cursor or page size was invalid.", {"type": "https://eosc-eden.eu/problems/invalid-cursor", "title": "Invalid Cursor", "status": 400, "detail": "Cursor is invalid."}),
        404: _problem_response_doc("Federation is disabled for this deployment.", {"type": "https://eosc-eden.eu/problems/federation-disabled", "title": "Federation Disabled", "status": 404, "detail": "Federation is disabled."}),
        503: _problem_response_doc("Federation runtime is not ready to serve the outbound change feed.", {"type": "https://eosc-eden.eu/problems/federation-unavailable", "title": "Federation Unavailable", "status": 503, "detail": "Federation service is unavailable."}),
    },
)
async def federation_changes(
    request: Request,
    since: str | None = Query(default=None, description="Opaque cursor. The response starts strictly after the cursor position.", examples=["v1.node-a-k1.changes.example"]),
    limit: int | None = Query(default=None, description="Page size in the range 1-200.", examples=[100]),
    _if_none_match: str | None = Header(default=None, alias="If-None-Match", description="Strong ETag validator for conditional GET. Matching ETags return 304."),
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
    tags=["Federation outbound"],
    summary="Get one signed authoritative federation record",
    description=(
        "Returns one signed authoritative record from the local outbound federation view.\n\n"
        "The `encoded_id` parameter is the URL-safe encoded canonical identifier from the catalog. Only locally authoritative "
        "records are served. Conditional GET with `If-None-Match` may return 304."
    ),
    operation_id="getFederationRecord",
    response_description="Signed authoritative federation record and lifecycle state.",
    responses={
        304: {"description": "Record unchanged for the supplied ETag."},
        400: _problem_response_doc("The canonical identifier encoding was invalid.", {"type": "https://eosc-eden.eu/problems/invalid-cursor", "title": "Invalid Cursor", "status": 400, "detail": "Cursor is invalid."}),
        404: _problem_response_doc("No locally authoritative published record exists for the supplied canonical ID.", {"type": "https://eosc-eden.eu/problems/record-not-found", "title": "Record Not Found", "status": 404, "detail": "Record not found."}),
        503: _problem_response_doc("Federation runtime is not ready to serve outbound records.", {"type": "https://eosc-eden.eu/problems/federation-unavailable", "title": "Federation Unavailable", "status": 503, "detail": "Federation service is unavailable."}),
    },
)
async def federation_record(
    request: Request,
    encoded_id: str = Path(..., description="URL-safe encoded canonical identifier obtained from the outbound catalog.", examples=["bGZzOmFhYWFhYWFhLWFhYWEtNGFhYS04YWFhLWFhYWFhYWFhYWFhYTpNSVQ6MQ"]),
    _if_none_match: str | None = Header(default=None, alias="If-None-Match", description="Strong ETag validator for conditional GET. Matching ETags return 304."),
):
    try:
        service = _federation_service(request)
        payload_model = service.get_record(encoded_canonical_id=encoded_id)
        payload = payload_model.model_dump(mode="json")

        etag = _etag_for_bytes(canonicalize_to_bytes(payload))
        return _response_with_etag(request=request, payload=payload, etag=etag)
    except FederationError as error:
        return _problem_from_error(request, error)
