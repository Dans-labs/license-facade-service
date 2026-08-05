from __future__ import annotations

import os

from fastapi import APIRouter, Depends, Request
from pydantic import BaseModel, Field

from src.license_facade_service.infra.fuseki_client import FusekiClient
from src.license_facade_service.services.licenses import LicenseService
from src.license_facade_service.api.v1.licenses import get_license_service

router = APIRouter()


class HealthResponse(BaseModel):
    status: str = Field(description="Liveness state of the process.", examples=["alive"])


class PingResponse(BaseModel):
    message: str = Field(description="Simple ping response used for smoke checks.", examples=["pong"])


class ReadinessComponent(BaseModel):
    ready: bool | None = Field(description="Whether the dependency is currently ready.")


class ReadinessFusekiComponent(ReadinessComponent):
    enabled: bool = Field(description="Whether optional Fuseki integration is enabled.")


class ReadinessFederationComponent(BaseModel):
    enabled: bool = Field(description="Whether federation features are enabled.")
    ready: bool | None = Field(description="Whether federation runtime initialization completed successfully.")
    errors: list[str] = Field(default_factory=list, description="Runtime initialization or availability errors, when present.")
    nodeId: str | None = Field(default=None, description="Configured federation node identifier, when federation is enabled.")


class ReadinessResponse(BaseModel):
    status: str = Field(description="Overall readiness state for serving requests.", examples=["ready", "not_ready"])
    licenses: ReadinessComponent = Field(description="Readiness of licence resolution against the active snapshot.")
    fuseki: ReadinessFusekiComponent = Field(description="Readiness of optional Fuseki integration.")
    federation: ReadinessFederationComponent = Field(description="Readiness of optional federation runtime.")


@router.get(
    "/health",
    response_model=HealthResponse,
    tags=["Service status"],
    summary="Check process liveness",
    description=(
        "Returns a minimal liveness response for process-level monitoring.\n\n"
        "Use this endpoint to confirm that the FastAPI process is running. "
        "It does not verify cache health, federation readiness, or Fuseki availability."
    ),
    operation_id="getServiceHealth",
    response_description="Process liveness indicator.",
)
async def health_check():
    return {"status": "alive"}


@router.get(
    "/ping",
    response_model=PingResponse,
    tags=["Service status"],
    summary="Ping the service",
    description=(
        "Returns a simple pong payload.\n\n"
        "This endpoint is useful for smoke tests and basic connectivity checks where full readiness "
        "validation is unnecessary."
    ),
    operation_id="pingService",
    response_description="Simple connectivity response.",
)
async def ping():
    return {"message": "pong"}


@router.get(
    "/ready",
    response_model=ReadinessResponse,
    tags=["Service status"],
    summary="Check service readiness",
    description=(
        "Reports whether the service is ready to resolve licences from the current snapshot.\n\n"
        "Readiness combines licence snapshot availability, optional Fuseki availability when enabled, "
        "and optional federation runtime readiness. PostgreSQL remains the federation source of truth; "
        "Fuseki failures affect RDF indexing but must not invalidate already committed PostgreSQL records."
    ),
    operation_id="getServiceReadiness",
    response_description="Aggregated readiness report for public and optional federation dependencies.",
)
async def readiness(request: Request, service: LicenseService = Depends(get_license_service)):
    licenses_ready = service.health_can_resolve()
    fuseki_enabled = os.getenv("FUSEKI_ENABLE", "true").lower() == "true"
    fuseki_ready = None
    if fuseki_enabled:
        client = FusekiClient(
            fuseki_url=os.getenv("FUSEKI_URL", "http://localhost:3030"),
            dataset=os.getenv("FUSEKI_DATASET", "licenses"),
            username=os.getenv("FUSEKI_USER"),
            password=os.getenv("FUSEKI_PASSWORD"),
            timeout=5.0,
        )
        fuseki_ready = await client.check_connection()

    federation_state = getattr(request.app.state, "federation_state", None)
    federation_ready = True
    federation_payload = {"enabled": False, "ready": None, "errors": []}
    if federation_state is not None:
        federation_payload = {
            "enabled": federation_state.enabled,
            "ready": federation_state.ready if federation_state.enabled else None,
            "errors": federation_state.errors,
            "nodeId": federation_state.node_id,
        }
        federation_ready = federation_state.ready or not federation_state.enabled

    ready = licenses_ready and (fuseki_ready is True or fuseki_ready is None) and federation_ready
    return {
        "status": "ready" if ready else "not_ready",
        "licenses": {"ready": licenses_ready},
        "fuseki": {"enabled": fuseki_enabled, "ready": fuseki_ready},
        "federation": federation_payload,
    }
