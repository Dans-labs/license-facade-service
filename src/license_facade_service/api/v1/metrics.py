import logging
from pathlib import Path

from fastapi import APIRouter, HTTPException


router = APIRouter()


# Base directory of the project (two levels up from this file: src/license_facade_service/...)
PROJECT_ROOT = Path(__file__).resolve().parents[3]
SPDX_JSONLD_DIR = PROJECT_ROOT / "spdx_downloads" / "jsonld"


def count_spdx_jsonld_files(directory: Path) -> int:
    """Count SPDX v3 JSON-LD files (*.jsonld) in the given directory.

    Raises HTTPException(503) if the directory does not exist or is not readable.
    """

    if not directory.exists() or not directory.is_dir():
        logging.warning("SPDX JSON-LD directory not found: %s", directory)
        raise HTTPException(
            status_code=503,
            detail=f"SPDX JSON-LD directory not found: {directory}",
        )

    count = 0
    for entry in directory.iterdir():
        if entry.is_file() and entry.suffix.lower() == ".jsonld":
            count += 1
    logging.debug("Counted %d SPDX JSON-LD files in %s", count, directory)
    return count


@router.get("/health")
def health_check():
    logging.debug("Health check endpoint called")
    return {"status": "ok"}


@router.get("/ping")
def ping():
    logging.debug("Ping endpoint called")
    return {"message": "pong"}


@router.get("/metrics/spdx-jsonld-count")
def spdx_jsonld_count():
    """Return the number of SPDX v3 JSON-LD license files on disk.

    Counts files under the repository's `spdx_downloads/jsonld` directory.
    """

    count = count_spdx_jsonld_files(SPDX_JSONLD_DIR)
    return {"spdx_v3_jsonld_count": count}
