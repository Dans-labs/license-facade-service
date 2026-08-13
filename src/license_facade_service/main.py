from __future__ import annotations

import os
from contextlib import asynccontextmanager

import uvicorn
from fastapi import FastAPI
from fastapi.exception_handlers import request_validation_exception_handler
from fastapi.exceptions import RequestValidationError
from starlette.middleware.cors import CORSMiddleware

from src.license_facade_service.api import openrel as openrel_api
from src.license_facade_service.api.federation import admin as federation_admin
from src.license_facade_service.api.federation import jwks as federation_jwks
from src.license_facade_service.api.federation import outbound as federation_outbound
from src.license_facade_service.api.v1 import licenses, metrics
from src.license_facade_service.config.custom_licence import CustomLicenceRegistrationSettings
from src.license_facade_service.config.federation import FederationSettings
from src.license_facade_service.config.openrel import OpenRelSettings
from src.license_facade_service.federation.runtime import FederationRuntime, FederationRuntimeState
from src.license_facade_service.openrel.client import OpenRelClient
from src.license_facade_service.services.custom_licence_registration import CustomLicenceRegistrationService
from src.license_facade_service.services.problem import problem_response
from src.license_facade_service.services.spdx_custom_license import validate_http_iri
from src.license_facade_service.services.spdx3_documents import Spdx3DocumentService
from src.license_facade_service.services.spdx_validation import SpdxStructuralValidationError
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
    registration_service: CustomLicenceRegistrationService | None = None
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
        registration_service = CustomLicenceRegistrationService(
            settings=app.state.custom_licence_registration_settings,
            federation_settings=app.state.federation_runtime.settings if runtime is not None else FederationSettings.from_env(),
            federation_ready=bool(getattr(app.state.federation_state, "ready", False)),
        )
        app.state.custom_licence_registration_service = registration_service

        yield
    finally:
        cleanup_errors: list[Exception] = []
        try:
            if openrel_client is not None:
                await openrel_client.aclose()
        except Exception as exc:  # pragma: no cover - validated via lifecycle tests
            cleanup_errors.append(exc)
        finally:
            app.state.openrel_client = None
        try:
            if registration_service is not None:
                registration_service.close()
        except Exception as exc:  # pragma: no cover - validated via lifecycle tests
            cleanup_errors.append(exc)
        finally:
            app.state.custom_licence_registration_service = None
        if cleanup_errors:
            if len(cleanup_errors) == 1:
                raise cleanup_errors[0]
            raise ExceptionGroup("service shutdown cleanup failed", cleanup_errors)


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
    app.state.custom_licence_registration_settings = CustomLicenceRegistrationSettings.from_env()
    app.state.custom_licence_registration_service = None
    app.state.openrel_client = None
    app.state.spdx3_document_service = None
    try:
        base = os.getenv("URL_BASE", "https://license.example.org/api/v1/licenses").rstrip("/")
        complete_namespace = validate_http_iri(f"{base}/spdx3/documents", "complete_namespace")
        app.state.spdx3_document_service = Spdx3DocumentService(complete_namespace=complete_namespace)
    except (ValueError, SpdxStructuralValidationError):
        app.state.spdx3_document_service = None

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

    @app.exception_handler(RequestValidationError)
    async def _request_validation_handler(request, exc: RequestValidationError):
        if request.url.path == "/api/v1/licenses" and request.method.upper() == "POST":
            safe_errors: list[dict[str, object]] = []
            for item in exc.errors():
                safe_errors.append(
                    {
                        "loc": list(item.get("loc", [])),
                        "msg": str(item.get("msg", "invalid value")),
                        "type": str(item.get("type", "value_error")),
                    }
                )
            return problem_response(
                status=422,
                title="Invalid Registration Request",
                detail="The registration request payload is invalid.",
                instance=str(request.url),
                type_uri="https://eosc-eden.eu/problems/custom-licence-request-invalid",
                extra={"validationErrors": safe_errors},
            )
        if request.url.path.startswith("/api/v1/licenses/spdx3/") and request.method.upper() == "POST":
            safe_errors: list[dict[str, object]] = []
            for item in exc.errors():
                safe_errors.append(
                    {
                        "loc": list(item.get("loc", [])),
                        "msg": str(item.get("msg", "invalid value")),
                        "type": str(item.get("type", "value_error")),
                    }
                )
            return problem_response(
                status=422,
                title="Invalid SPDX 3 Request",
                detail="The SPDX document generation request payload is invalid.",
                instance=str(request.url),
                type_uri="https://eosc-eden.eu/problems/spdx3-request-invalid",
                extra={"validationErrors": safe_errors},
            )
        return await request_validation_exception_handler(request, exc)

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
