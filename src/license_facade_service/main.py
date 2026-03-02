import os
from contextlib import asynccontextmanager

import uvicorn
from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse
from starlette.exceptions import HTTPException as StarletteHTTPException
from starlette.middleware.cors import CORSMiddleware

from src.license_facade_service.api.v1 import metrics, licenses, licenses_graph
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
    logging.info("Application startup")

    # Check and update license cache on startup
    try:
        from src.license_facade_service.api.v1.licenses import ensure_cache_updated
        logging.info("Checking for license data updates...")
        await ensure_cache_updated()
        logging.info("License cache check complete")
    except Exception as e:
        logging.error(f"Failed to update license cache on startup: {e}")
        logging.warning("Service will continue but may fetch licenses on-demand")

    # Initialize Fuseki with RDF license data
    fuseki_enable = app_settings.get("fuseki_enable", True)
    if fuseki_enable:
        try:
            from src.license_facade_service.utils.license_rdf_uploader import initialize_fuseki_with_licenses

            logging.info("Initializing Fuseki with license RDF data...")

            fuseki_url = app_settings.get("fuseki_url", "http://localhost:3030")
            fuseki_dataset = app_settings.get("fuseki_dataset", "licenses")
            fuseki_user = app_settings.get("fuseki_user", "admin")
            fuseki_password = app_settings.get("fuseki_password", "admin")
            fuseki_clear = app_settings.get("fuseki_clear_on_startup", False)

            result = await initialize_fuseki_with_licenses(
                fuseki_url=fuseki_url,
                dataset=fuseki_dataset,
                username=fuseki_user,
                password=fuseki_password,
                clear_existing=fuseki_clear
            )

            if result["success"]:
                logging.info("✓ Fuseki initialization completed successfully")
            elif not result["fuseki_available"]:
                logging.warning("⚠ Fuseki server not available - RDF features will be disabled")
            else:
                logging.warning(f"⚠ Fuseki initialization completed with errors: {result.get('errors', [])}")

        except Exception as e:
            logging.error(f"Failed to initialize Fuseki: {e}")
            logging.warning("Service will continue without Fuseki RDF features")
    else:
        logging.info("Fuseki integration is disabled (fuseki_enable=false)")

    yield
    logging.info("Application shutdown")

app = FastAPI(
    title=get_project_details(os.getenv("BASE_DIR"), ["title"])["title"],
    version=f"{get_project_details(os.getenv('BASE_DIR'), ["version"])["version"]} (Build Date: {build_date})",
    description=get_project_details(os.getenv("BASE_DIR"), ["description"])["description"],
    lifespan=lifespan,
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

app.include_router(metrics.router, tags=["Metrics"], prefix="/api/v1")
app.include_router(licenses.router, tags=["Licenses"], prefix="/api/v1")

app.include_router(licenses_graph.router, tags=["RDF Transformer"], prefix="/api/v1")
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