from __future__ import annotations

from fastapi import APIRouter, Request
from fastapi.responses import Response

from src.license_facade_service.federation.canonical_json import canonicalize_to_bytes
from src.license_facade_service.federation.models import JwksResponse
from src.license_facade_service.federation.outbound import _etag_for_bytes, _parse_if_none_match
from src.license_facade_service.federation.keys import SigningKeyService
from src.license_facade_service.federation.runtime import FederationRuntime
from src.license_facade_service.services.problem import ProblemDetails
from src.license_facade_service.services.problem import problem_response

router = APIRouter()


@router.get(
    "/.well-known/jwks.json",
    response_model=JwksResponse,
    responses={304: {"description": "Not Modified"}, 404: {"model": ProblemDetails}, 503: {"model": ProblemDetails}},
)
async def get_jwks(request: Request):
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
    payload = service.jwks().model_dump(mode="json", exclude_none=True)
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
