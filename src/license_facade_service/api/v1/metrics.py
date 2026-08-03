from __future__ import annotations

import os

from fastapi import APIRouter, Depends

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
async def readiness(service: LicenseService = Depends(get_license_service)):
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

    ready = licenses_ready and (fuseki_ready is True or fuseki_ready is None)
    return {
        "status": "ready" if ready else "not_ready",
        "licenses": {"ready": licenses_ready},
        "fuseki": {"enabled": fuseki_enabled, "ready": fuseki_ready},
    }

