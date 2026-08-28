from __future__ import annotations

import os
from contextlib import asynccontextmanager

import uvicorn
from fastapi import FastAPI, Request
from fastapi.exceptions import RequestValidationError
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine
from starlette.middleware.cors import CORSMiddleware

from src.license_facade_service.api.federation import admin as federation_admin
from src.license_facade_service.api.federation import jwks as federation_jwks
from src.license_facade_service.api.federation import operational as federation_operational
from src.license_facade_service.api.federation import outbound as federation_outbound
from src.license_facade_service.api.v1 import licenses, metrics
from src.license_facade_service.config.federation import FederationSettings
from src.license_facade_service.services.problem import problem_response
from src.license_facade_service.federation.runtime import FederationRuntime, FederationRuntimeState
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
        "name": "Federation operations",
        "description": "Protected Phase 5 operational visibility: signing-key inventory, health history, cursor inspection, RDF outbox, sync attempts, and compatibility report. All endpoints are admin-only and read-only.",
    },
]


def _cors_origins() -> list[str]:
    env_origins = os.getenv("CORS_ORIGINS")
    if env_origins:
        return [origin.strip() for origin in env_origins.split(",") if origin.strip()]
    return []


def _async_db_url(sync_url: str) -> str:
    if sync_url.startswith("postgresql://"):
        return sync_url.replace("postgresql://", "postgresql+psycopg://", 1)
    if "://" in sync_url and "+psycopg" not in sync_url:
        return sync_url.replace(sync_url.split("://", 1)[0] + "://", "postgresql+psycopg://", 1)
    return sync_url


@asynccontextmanager
async def lifespan(app: FastAPI):
    service = licenses.get_license_service()
    try:
        await service.ensure_cache_updated()
    except Exception:
        # Service should remain available with last valid snapshot.
        pass
    runtime: FederationRuntime | None = getattr(app.state, "federation_runtime", None)
    async_engine = None
    if runtime is not None:
        app.state.federation_state = runtime.initialize()
        if runtime.settings.enabled and runtime.settings.admin_cursor_secret and runtime.settings.database_url:
            from src.license_facade_service.federation.operational_models import configure_cursor_secret

            configure_cursor_secret(runtime.settings.admin_cursor_secret)
            async_db_url = _async_db_url(runtime.settings.database_url)
            async_engine = create_async_engine(async_db_url, echo=False, pool_pre_ping=True)
            app.state.federation_async_engine = async_engine
            app.state.federation_async_sessionmaker = async_sessionmaker(async_engine, expire_on_commit=False)
    yield
    if async_engine is not None:
        await async_engine.dispose()


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
    app.state.federation_async_engine = None
    app.state.federation_async_sessionmaker = None
    app.state.federation_state = FederationRuntimeState(enabled=False, ready=True, errors=[])

    @app.get(
        "/",
        tags=["Service status"],
        summary="Read service metadata",
        description=(
            "Returns service metadata loaded from `pyproject.toml`.\n\n"
            "Provides the configured title, version, and description for quick runtime identification."
        ),
        operation_id="getServiceMetadata",
        response_description="Service metadata from project configuration.",
    )
    async def service_metadata():
        return {
            "title": details["title"],
            "version": details["version"],
            "description": details["description"],
        }

    settings = FederationSettings.from_env()
    if settings.enabled:
        app.state.federation_runtime = FederationRuntime(settings=settings)
        app.state.federation_state = FederationRuntimeState(
            enabled=True,
            ready=False,
            errors=["Federation runtime has not completed startup initialization yet."],
            node_id=settings.node_id,
        )

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
    app.include_router(federation_outbound.router)
    app.include_router(federation_jwks.router)
    app.include_router(federation_admin.router)
    app.include_router(federation_operational.router)

    @app.exception_handler(RequestValidationError)
    async def _validation_exception_handler(request: Request, exc: RequestValidationError):
        return problem_response(
            status=422,
            title="Validation Error",
            detail="Request validation failed.",
            type_uri="https://eosc-eden.eu/problems/validation-error",
            instance=str(request.url),
        )
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
