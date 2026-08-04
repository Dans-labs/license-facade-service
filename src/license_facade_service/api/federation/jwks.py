from __future__ import annotations

from fastapi import APIRouter, Request
from fastapi.encoders import jsonable_encoder
from fastapi.responses import JSONResponse

from src.license_facade_service.federation.keys import SigningKeyService
from src.license_facade_service.federation.runtime import FederationRuntime
from src.license_facade_service.services.problem import problem_response

router = APIRouter()


@router.get("/.well-known/jwks.json")
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
    payload = service.jwks().model_dump(exclude_none=True)
    return JSONResponse(content=jsonable_encoder(payload), media_type="application/jwk-set+json")
