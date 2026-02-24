import logging

from fastapi import APIRouter


router = APIRouter()


@router.get("/health")
def health_check():
    logging.debug("Health check endpoint called")
    return {"status": "ok"}


@router.get("/ping")
def ping():
    logging.debug("Ping endpoint called")
    return {"message": "pong"}
