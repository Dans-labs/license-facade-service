from __future__ import annotations

import os

from fastapi import APIRouter, Depends, Request

from src.license_facade_service.infra.fuseki_client import FusekiClient
from src.license_facade_service.services.licenses import LicenseService
from src.license_facade_service.api.v1.licenses import get_license_service

router = APIRouter()


@router.get("/health")
async def health_check():
    return {"status": "alive"}


@router.get("/ping")
async def ping():
    return {"message": "pong"}


@router.get("/ready")
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
