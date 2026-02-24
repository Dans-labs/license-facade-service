import os
from contextlib import asynccontextmanager

import uvicorn
from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse
from starlette.exceptions import HTTPException as StarletteHTTPException
from starlette.middleware.cors import CORSMiddleware

from src.license_facade_service.api.v1 import metrics, licenses
from src.license_facade_service.utils.commons import app_settings, get_project_details

APP_NAME = os.environ.get("APP_NAME", "OSTrails Clarin SKG-IF Service")
EXPOSE_PORT = os.environ.get("EXPOSE_PORT", 12104)

import logging
from logging.handlers import TimedRotatingFileHandler

build_date = os.environ.get("BUILD_DATE", "unknown")
log_file = app_settings.get("log_file", "lsf.log")
handler = TimedRotatingFileHandler(
    log_file,
    when="midnight",  # rotate every second for testing
    interval=1,
    backupCount=7,
    encoding="utf-8",
    utc=True
)
handler.suffix = "%Y-%m-%d"

logging.basicConfig(
    level=logging.DEBUG,
    format='%(asctime)s %(levelname)s %(message)s',
    handlers=[handler]
)

@asynccontextmanager
async def lifespan(application: FastAPI):
    logging.info("start up")
    yield

app = FastAPI(
    title=get_project_details(os.getenv("BASE_DIR"), ["title"])["title"],
    version=f"{get_project_details(os.getenv('BASE_DIR'), ["version"])["version"]} (Build Date: {build_date})",
    description=get_project_details(os.getenv("BASE_DIR"), ["description"])["description"],
    # openapi_url=settings.openapi_url,
    # docs_url=settings.docs_url,
    # redoc_url=settings.redoc_url,
    swagger_ui_parameters={"defaultModelsExpandDepth": -1},
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=app_settings.cors_origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(metrics.router, tags=["Metrics"], prefix="")
app.include_router(licenses.router, tags=["Licenses"], prefix="")

@app.exception_handler(StarletteHTTPException)
async def custom_404_handler(request: Request, exc: StarletteHTTPException):
    if exc.status_code == 404:
        return JSONResponse(status_code=404, content={"message": "Endpoint not found"})
    return JSONResponse(status_code=exc.status_code, content={"message": exc.detail})


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO, format='%(asctime)s %(levelname)s %(message)s')
    num_workers = max(1, os.cpu_count() or 1)
    logging.info(f"=====Starting server with {num_workers} workers on port {EXPOSE_PORT} =====")
    uvicorn.run(
        f"{__name__}:app",
        host="0.0.0.0",
        port=int(EXPOSE_PORT),
        workers=1,
        factory=False,
        reload=app_settings.RELOAD_ENABLE,
    )