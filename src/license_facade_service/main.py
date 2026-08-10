from __future__ import annotations

import os
from contextlib import asynccontextmanager

import uvicorn
from fastapi import FastAPI
from starlette.middleware.cors import CORSMiddleware

from src.license_facade_service.api import openrel as openrel_api
from src.license_facade_service.api.federation import admin as federation_admin
from src.license_facade_service.api.federation import jwks as federation_jwks
from src.license_facade_service.api.federation import outbound as federation_outbound
from src.license_facade_service.api.v1 import licenses, metrics
from src.license_facade_service.config.federation import FederationSettings
from src.license_facade_service.config.openrel import OpenRelSettings
from src.license_facade_service.federation.runtime import FederationRuntime, FederationRuntimeState
from src.license_facade_service.openrel.client import OpenRelClient
from src.license_facade_service.utils.commons import get_project_details

APP_NAME = os.environ.get("APP_NAME", "License Facade Service")
EXPOSE_PORT = int(os.environ.get("EXPOSE_PORT", "12104"))
OPENAPI_TAGS = [
    {
        "name": "Service status",
        "description": "Liveness, readiness, and simple service-level diagnostics for monitoring and operators.",
    },
    {
        "name": "Licences",
        "description": "Public SPDX-compatible licence inventory, cache administration, and SPDX 3 helper endpoints.",
    },
    {
        "name": "Licence representations",
        "description": "Public canonical licence lookup and explicit representation endpoints for HTML, JSON, JSON-LD, Turtle, RDF/XML, and curated links.",
    },
    {
        "name": "Federation discovery",
        "description": "Public discovery metadata and verification keys used by trusted federation peers.",
    },
    {
        "name": "Federation outbound",
        "description": "Public authoritative outbound federation feed containing locally authoritative records only.",
    },
    {
        "name": "Federation resolution",
        "description": "Public resolution and provenance APIs that combine local authority, imported records, and SPDX fallback.",
    },
    {
        "name": "Federation administration",
        "description": "Protected administrative federation endpoints for peer management, manual synchronization, publication, and status inspection.",
    },
    {
        "name": "Federation conflicts",
        "description": "Protected curator/admin workflows for reviewing imported-resolution conflicts and recording append-only decisions.",
    },
    {
        "name": "OpenREL",
        "description": (
            "Read-only access to vocabulary and knowledge-base resources supplied "
            "by the configured OpenREL provider. These resources are external "
            "provider data, not authoritative LFS licence or federation records. "
            "Provider availability affects only the OpenREL endpoints."
        ),
    },
]


def _cors_origins() -> list[str]:
    env_origins = os.getenv("CORS_ORIGINS")
    if env_origins:
        return [origin.strip() for origin in env_origins.split(",") if origin.strip()]
    return []


@asynccontextmanager
async def lifespan(app: FastAPI):
    openrel_client: OpenRelClient | None = None
    try:
        openrel_settings: OpenRelSettings = getattr(app.state, "openrel_settings")
        openrel_client = OpenRelClient(openrel_settings)
        app.state.openrel_client = openrel_client

        service = licenses.get_license_service()
        try:
            await service.ensure_cache_updated()
        except Exception:
            # Service should remain available with last valid snapshot.
            pass

        runtime: FederationRuntime | None = getattr(app.state, "federation_runtime", None)
        if runtime is not None:
            app.state.federation_state = runtime.initialize()

        yield
    finally:
        try:
            if openrel_client is not None:
                await openrel_client.aclose()
        finally:
            app.state.openrel_client = None


def create_app() -> FastAPI:
    base_dir = os.getenv("BASE_DIR", os.getcwd())
    details = get_project_details(base_dir, ["title", "version", "description"])
    app = FastAPI(
        title=details["title"],
        version=details["version"],
        description=details["description"],
        lifespan=lifespan,
        swagger_ui_parameters={"defaultModelsExpandDepth": -1},
        openapi_tags=OPENAPI_TAGS,
    )
    app.state.federation_runtime = None
    app.state.federation_state = FederationRuntimeState(enabled=False, ready=True, errors=[])

    settings = FederationSettings.from_env()
    if settings.enabled:
        app.state.federation_runtime = FederationRuntime(settings=settings)
        app.state.federation_state = FederationRuntimeState(
            enabled=True,
            ready=False,
            errors=["Federation runtime has not completed startup initialization yet."],
            node_id=settings.node_id,
        )
    app.state.openrel_settings = OpenRelSettings.from_env()
    app.state.openrel_client = None

    origins = _cors_origins()
    allow_credentials = os.getenv("CORS_ALLOW_CREDENTIALS", "false").lower() == "true"
    app.add_middleware(
        CORSMiddleware,
        allow_origins=origins,
        allow_credentials=allow_credentials,
        allow_methods=["*"],
        allow_headers=["*"],
    )

    app.include_router(metrics.router, prefix="/api/v1")
    app.include_router(licenses.router, prefix="/api/v1")
    app.include_router(openrel_api.router)
    app.include_router(federation_outbound.router)
    app.include_router(federation_jwks.router)
    app.include_router(federation_admin.router)
    return app


app = create_app()


if __name__ == "__main__":
    reload_enabled = os.getenv("RELOAD_ENABLE", "false").lower() == "true"
    uvicorn.run(
        "src.license_facade_service.main:app",
        host="0.0.0.0",
        port=EXPOSE_PORT,
        workers=1,
        reload=reload_enabled,
    )
