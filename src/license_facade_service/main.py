from __future__ import annotations

import os
from contextlib import asynccontextmanager

import uvicorn
from fastapi import FastAPI
from starlette.middleware.cors import CORSMiddleware

from src.license_facade_service.api.v1 import licenses, metrics
from src.license_facade_service.services.licenses import LicenseService
from src.license_facade_service.utils.commons import get_project_details

APP_NAME = os.environ.get("APP_NAME", "License Facade Service")
EXPOSE_PORT = int(os.environ.get("EXPOSE_PORT", "12104"))


def _cors_origins() -> list[str]:
    env_origins = os.getenv("CORS_ORIGINS")
    if env_origins:
        return [origin.strip() for origin in env_origins.split(",") if origin.strip()]
    return []


@asynccontextmanager
async def lifespan(_: FastAPI):
    service = licenses.get_license_service()
    try:
        await service.ensure_cache_updated()
    except Exception:
        # Service should remain available with last valid snapshot.
        pass
    yield


def create_app() -> FastAPI:
    base_dir = os.getenv("BASE_DIR", os.getcwd())
    details = get_project_details(base_dir, ["title", "version", "description"])
    app = FastAPI(
        title=details["title"],
        version=details["version"],
        description=details["description"],
        lifespan=lifespan,
        swagger_ui_parameters={"defaultModelsExpandDepth": -1},
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

    app.include_router(metrics.router, tags=["Metrics"], prefix="/api/v1")
    app.include_router(licenses.router, tags=["Licenses"], prefix="/api/v1")
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

