import logging

from fastapi import APIRouter


router = APIRouter()


@router.get("/licenses")
def licenses():
    logging.debug("Licenses endpoint called")
    return {"status": "ok"}

@router.get("/licenses/{id}")
def get_license(id: str):
    logging.debug(f"Get license endpoint called with id: {id}")
    return {"id": id, "name": f"License {id}", "url": f"http://example.com/licenses/{id}"}

@router.get("/licenses/{id}/json")
def get_license_json(id: str):
    logging.debug(f"Get license JSON endpoint called with id: {id}")
    return {
        "id": id,
        "name": f"License {id}",
        "url": f"http://example.com/licenses/{id}",
        "description": f"This is a description for License {id}.",
        "permissions": ["use", "modify", "distribute"],
        "conditions": ["attribution", "share-alike"],
        "limitations": ["no-commercial-use"]
    }

@router.get("/licenses/{id}/original")
def get_license_original(id: str):
    logging.debug(f"Get license original endpoint called with id: {id}")
    return f"Original license text for License {id}."

@router.get("/licenses/{id}/machine")
def get_license_machine(id: str):
    logging.debug(f"Get license machine endpoint called with id: {id}")
    return {
        "id": id,
        "permissions": ["use", "modify", "distribute"],
        "conditions": ["attribution", "share-alike"],
        "limitations": ["no-commercial-use"]
    }

@router.get("/licenses/{id}/legal")
def get_license_legal(id: str):
    logging.debug(f"Get license legal endpoint called with id: {id}")
    return f"Legal text for License {id}."