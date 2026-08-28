from __future__ import annotations

import asyncio
from typing import Any

from fastapi import APIRouter, Header, Request
from fastapi.responses import Response

from src.license_facade_service.federation.canonical_json import canonicalize_to_bytes
from src.license_facade_service.federation.models import JwksResponse
from src.license_facade_service.federation.outbound import _etag_for_bytes, _parse_if_none_match
from src.license_facade_service.federation.keys import SigningKeyService
from src.license_facade_service.federation.local_key_lifecycle import LocalKeyError
from src.license_facade_service.federation.runtime import FederationRuntime
from src.license_facade_service.services.problem import ProblemDetails
from src.license_facade_service.services.problem import problem_response

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


@router.get(
    "/.well-known/jwks.json",
    response_model=JwksResponse,
    tags=["Federation discovery"],
    summary="Get public federation verification keys",
    description=(
        "Returns the public JWKS document for this node.\n\n"
        "Use this endpoint to obtain verification keys for signed federation discovery, catalog, record, and change-feed "
        "responses. Private signing material is never returned. Conditional GET with `If-None-Match` may return 304."
    ),
    operation_id="getFederationJwks",
    response_description="Public verification keys for signed federation traffic.",
    responses={
        304: {"description": "JWKS unchanged for the supplied ETag."},
        404: _problem_response_doc("Federation or JWKS exposure is disabled.", {"type": "about:blank", "title": "Not Found", "status": 404, "detail": "JWKS endpoint is disabled."}),
        503: _problem_response_doc("Federation database or signing state is unavailable.", {"type": "about:blank", "title": "Service Unavailable", "status": 503, "detail": "Federation database is unavailable."}),
    },
)
async def get_jwks(
    request: Request,
    _if_none_match: str | None = Header(default=None, alias="If-None-Match", description="Strong ETag validator for conditional GET. Matching ETags return 304."),
):
    runtime: FederationRuntime | None = getattr(request.app.state, "federation_runtime", None)
    state = getattr(request.app.state, "federation_state", None)
    if runtime is None or state is None or not state.enabled:
        return problem_response(
            status=404,
            title="Not Found",
            detail="Federation is disabled.",
            instance=str(request.url),
        )
    if not runtime.settings.jwks_enabled:
        return problem_response(
            status=404,
            title="Not Found",
            detail="JWKS endpoint is disabled.",
            instance=str(request.url),
        )
    if runtime.db is None:
        return problem_response(
            status=503,
            title="Service Unavailable",
            detail="Federation database is unavailable.",
            instance=str(request.url),
        )

    service = SigningKeyService(runtime.db, runtime.settings)
    try:
        jwks = await asyncio.to_thread(service.jwks)
    except LocalKeyError:
        return problem_response(
            status=503,
            title="Service Unavailable",
            detail="Federation signing keys are unavailable.",
            instance=str(request.url),
        )
    except Exception:
        return problem_response(
            status=503,
            title="Service Unavailable",
            detail="Federation signing keys are unavailable.",
            instance=str(request.url),
        )
    payload = jwks.model_dump(mode="json", exclude_none=True)
    body = canonicalize_to_bytes(payload)
    etag = _etag_for_bytes(body)
    if_none_match = _parse_if_none_match(request.headers.get("if-none-match"))
    if "*" in if_none_match or etag.strip('"') in if_none_match or etag in if_none_match:
        return Response(status_code=304, content=b"", headers={"ETag": etag, "Cache-Control": "public, max-age=300"})
    return Response(
        content=body,
        media_type="application/jwk-set+json",
        headers={"ETag": etag, "Cache-Control": "public, max-age=300"},
    )
