from __future__ import annotations

import json
import logging
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from fastapi import APIRouter, Depends, Query, Request
from fastapi.responses import JSONResponse, RedirectResponse, Response
from pydantic import BaseModel

from src.license_facade_service.services.auth import (
    AuthService,
    AuthenticationError,
    AuthorizationError,
    Principal,
)
from src.license_facade_service.services.licenses import (
    LicenseNotFoundError,
    LicenseService,
    REPRESENTATION_HTML,
    REPRESENTATION_JSON,
    REPRESENTATION_JSON_LD,
    REPRESENTATION_ENCODING,
    REPRESENTATION_MACHINE,
    REPRESENTATION_ORIGINAL,
    REPRESENTATION_RDFXML,
    REPRESENTATION_TURTLE,
    negotiate_representation,
)
from src.license_facade_service.services.problem import problem_response

router = APIRouter()

_license_service: LicenseService | None = None
_auth_service: AuthService | None = None


def get_license_service() -> LicenseService:
    global _license_service
    if _license_service is None:
        base_dir = Path(__file__).resolve().parents[4]
        _license_service = LicenseService(base_dir=base_dir)
    return _license_service


def get_auth_service() -> AuthService:
    global _auth_service
    if _auth_service is None:
        _auth_service = AuthService()
    return _auth_service


def _problem_404(identifier: str, request: Request) -> JSONResponse:
    return problem_response(
        status=404,
        title="License Not Found",
        detail=f"No license record found for identifier '{identifier}'.",
        instance=str(request.url),
    )


def _response_headers(content_location: str, include_vary: bool = True) -> dict[str, str]:
    headers = {
        "Cache-Control": "public, max-age=3600",
        "Content-Location": content_location,
    }
    if include_vary:
        headers["Vary"] = "Accept"
    return headers


def _require_mutation_auth(request: Request, auth_service: AuthService) -> Principal:
    try:
        principal = auth_service.authenticate(request)
    except AuthenticationError:
        raise PermissionError("authn")
    try:
        auth_service.authorize(principal, {"admin", "curator"})
    except AuthorizationError:
        raise PermissionError("authz")
    return principal


def _build_optional_representation_unavailable(
    request: Request,
    representation: str,
    links: dict[str, str],
) -> JSONResponse:
    return problem_response(
        status=404,
        title="Representation Not Available",
        detail=f"Representation '{representation}' is unavailable for this license.",
        instance=str(request.url),
        extra={"availableRepresentations": links},
    )


@router.get("/licenses")
@router.get("/licences", include_in_schema=False)
async def list_licenses(service: LicenseService = Depends(get_license_service)):
    """Return the cached SPDX license inventory with LFS URI enrichment."""
    return await service.get_all_licenses()


@router.get("/licenses/taxonomy")
@router.get("/licences/taxonomy", include_in_schema=False)
async def get_license_taxonomy():
    """Return a static taxonomy overview that cannot be shadowed by dynamic routes."""
    return {
        "description": (
            "Permissive: MIT, BSD, Apache; Weak copyleft: MPL, LGPL; "
            "Strong copyleft: GPL, AGPL; Content/documentation: Creative Commons; "
            "Public domain: CC0, Unlicense; Data licenses: ODbL, ODC-BY."
        )
    }


@router.get("/licenses/cache/status")
@router.get("/licences/cache/status", include_in_schema=False)
async def cache_status(service: LicenseService = Depends(get_license_service)):
    """Return cache status without exposing the cache filesystem path."""
    return service.cache_status().model_dump()


@router.post("/licenses/cache/update")
@router.post("/licences/cache/update", include_in_schema=False)
async def update_cache(
    request: Request,
    service: LicenseService = Depends(get_license_service),
    auth: AuthService = Depends(get_auth_service),
):
    """Refresh the SPDX snapshot after bearer-token authorization."""
    try:
        _require_mutation_auth(request, auth)
    except PermissionError as exc:
        if str(exc) == "authn":
            return problem_response(
                status=401,
                title="Unauthorized",
                detail="Missing or invalid bearer token.",
                instance=str(request.url),
            )
        return problem_response(
            status=403,
            title="Forbidden",
            detail="Authenticated principal lacks required curator/admin role.",
            instance=str(request.url),
        )
    try:
        status = await service.refresh_cache()
    except Exception as exc:
        logging.error("Cache update failed: %s", exc)
        return problem_response(
            status=500,
            title="Cache Update Failed",
            detail="Failed to refresh SPDX cache snapshot.",
            instance=str(request.url),
        )
    return {"status": "success", "cache": status.model_dump()}


@router.post("/licenses/cache/refresh")
@router.post("/licences/cache/refresh", include_in_schema=False)
async def refresh_cache(
    request: Request,
    service: LicenseService = Depends(get_license_service),
    auth: AuthService = Depends(get_auth_service),
):
    """Force refresh the SPDX snapshot after bearer-token authorization."""
    return await update_cache(request=request, service=service, auth=auth)


class MinimalSpdx3Request(BaseModel):
    name: str = "Minimal SPDX 3.0 Document"
    namespace: str = "https://example.org/spdx3/minimal-doc-1"


@router.post("/licenses/spdx3/minimal")
@router.post("/licences/spdx3/minimal", include_in_schema=False)
async def create_minimal_spdx3(
    payload: MinimalSpdx3Request,
    request: Request,
    auth: AuthService = Depends(get_auth_service),
):
    """Create a minimal SPDX 3.0 JSON-LD document after bearer-token authorization."""
    try:
        _require_mutation_auth(request, auth)
    except PermissionError as exc:
        if str(exc) == "authn":
            return problem_response(
                status=401,
                title="Unauthorized",
                detail="Missing or invalid bearer token.",
                instance=str(request.url),
            )
        return problem_response(
            status=403,
            title="Forbidden",
            detail="Authenticated principal lacks required curator/admin role.",
            instance=str(request.url),
        )
    created = datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")
    creation_info_id = "_:creationInfo_0"
    document_spdx_id = f"{payload.namespace.rstrip('/')}_document"
    return {
        "@context": "https://spdx.org/rdf/3.0.1/spdx-context.jsonld",
        "@graph": [
            {
                "@id": creation_info_id,
                "type": "CreationInfo",
                "specVersion": "3.0.1",
                "createdBy": [f"{payload.namespace.rstrip('/')}/creator"],
                "created": created,
            },
            {
                "spdxId": document_spdx_id,
                "type": "SpdxDocument",
                "rootElement": [document_spdx_id],
                "name": payload.name,
                "creationInfo": creation_info_id,
            },
        ],
    }


@router.post("/licenses/spdx3/complete/{license_id}")
@router.post("/licences/spdx3/complete/{license_id}", include_in_schema=False)
async def create_complete_spdx3(
    license_id: str,
    request: Request,
    service: LicenseService = Depends(get_license_service),
    auth: AuthService = Depends(get_auth_service),
):
    """Create a complete SPDX 3.0 JSON-LD document for a specific license."""
    try:
        _require_mutation_auth(request, auth)
    except PermissionError as exc:
        if str(exc) == "authn":
            return problem_response(
                status=401,
                title="Unauthorized",
                detail="Missing or invalid bearer token.",
                instance=str(request.url),
            )
        return problem_response(
            status=403,
            title="Forbidden",
            detail="Authenticated principal lacks required curator/admin role.",
            instance=str(request.url),
        )
    try:
        resolved = await service.resolve(license_id)
    except LicenseNotFoundError:
        return _problem_404(license_id, request)
    details = resolved.details
    return {
        "@context": "https://spdx.org/rdf/3.0.1/spdx-context.jsonld",
        "@graph": [
            {
                "@id": "_:creationInfo_0",
                "type": "CreationInfo",
                "specVersion": "3.0.1",
                "createdBy": ["https://spdx.org/tools/lfs"],
                "created": datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z"),
            },
            {
                "spdxId": f"https://spdx.org/spdxdocs/{resolved.license_id}_document",
                "type": "SpdxDocument",
                "rootElement": [f"https://spdx.org/spdxdocs/{resolved.license_id}#License-{resolved.license_id}"],
                "name": f"SPDX Document for {resolved.license_id}",
                "creationInfo": "_:creationInfo_0",
            },
            {
                "spdxId": f"https://spdx.org/spdxdocs/{resolved.license_id}#License-{resolved.license_id}",
                "type": "expandedlicensing_ListedLicense",
                "name": details.get("name", resolved.record.get("name")),
                "simplelicensing_licenseText": details.get("licenseText", ""),
                "expandedlicensing_standardLicenseTemplate": details.get("standardLicenseTemplate", ""),
            },
        ],
    }


@router.get("/licenses/{id:path}/html")
@router.get("/licences/{id:path}/html", include_in_schema=False)
async def get_license_html(
    id: str,
    request: Request,
    service: LicenseService = Depends(get_license_service),
):
    """Return the HTML landing page for a license."""
    return await _render_license_response(service, id, REPRESENTATION_HTML, request, negotiated=False)


@router.get("/licenses/{id:path}/json")
@router.get("/licences/{id:path}/json", include_in_schema=False)
async def get_license_json(
    id: str,
    request: Request,
    service: LicenseService = Depends(get_license_service),
):
    """Return SPDX-compatible JSON metadata for a license."""
    return await _render_license_response(service, id, REPRESENTATION_JSON, request, negotiated=False)


@router.get("/licenses/{id:path}/json-ld")
@router.get("/licences/{id:path}/json-ld", include_in_schema=False)
async def get_license_jsonld(
    id: str,
    request: Request,
    service: LicenseService = Depends(get_license_service),
):
    """Return JSON-LD metadata for a license."""
    return await _render_license_response(service, id, REPRESENTATION_JSON_LD, request, negotiated=False)


@router.get("/licenses/{id:path}/turtle")
@router.get("/licences/{id:path}/turtle", include_in_schema=False)
async def get_license_turtle(
    id: str,
    request: Request,
    service: LicenseService = Depends(get_license_service),
):
    """Return Turtle RDF for a license."""
    return await _render_license_response(service, id, REPRESENTATION_TURTLE, request, negotiated=False)


@router.get("/licenses/{id:path}/rdfxml")
@router.get("/licences/{id:path}/rdfxml", include_in_schema=False)
async def get_license_rdfxml(
    id: str,
    request: Request,
    service: LicenseService = Depends(get_license_service),
):
    """Return RDF/XML for a license."""
    return await _render_license_response(service, id, REPRESENTATION_RDFXML, request, negotiated=False)


@router.get("/licenses/{id:path}/original")
@router.get("/licences/{id:path}/original", include_in_schema=False)
async def get_license_original(
    id: str,
    request: Request,
    service: LicenseService = Depends(get_license_service),
):
    """Redirect to the curated original source when available."""
    try:
        resolved = await service.resolve(id)
    except LicenseNotFoundError:
        return _problem_404(id, request)
    source = service.get_original_source(resolved)
    if not source:
        return _build_optional_representation_unavailable(
            request=request,
            representation=REPRESENTATION_ORIGINAL,
            links=service.representation_links(resolved),
        )
    return RedirectResponse(url=source, status_code=307)


@router.get("/licenses/{id:path}/legal")
@router.get("/licences/{id:path}/legal", include_in_schema=False)
async def get_license_legal(
    id: str,
    request: Request,
    service: LicenseService = Depends(get_license_service),
):
    """Return a curated legal representation when available."""
    try:
        resolved = await service.resolve(id)
    except LicenseNotFoundError:
        return _problem_404(id, request)
    legal = service.get_legal_representation(resolved)
    if not legal:
        return _build_optional_representation_unavailable(
            request=request,
            representation="legal",
            links=service.representation_links(resolved),
        )
    media_type = legal.get("mediaType", "text/plain; charset=utf-8")
    content = legal.get("content", "")
    headers = {"Cache-Control": "public, max-age=3600"}
    if legal.get("profile"):
        headers["Link"] = f'<{legal["profile"]}>; rel="profile"'
    return Response(content=content, media_type=media_type, headers=headers)


@router.get("/licenses/{id:path}/machine")
@router.get("/licences/{id:path}/machine", include_in_schema=False)
async def get_license_machine(
    id: str,
    request: Request,
    service: LicenseService = Depends(get_license_service),
):
    """Return an explicit machine-readable rights expression when available."""
    try:
        resolved = await service.resolve(id)
    except LicenseNotFoundError:
        return _problem_404(id, request)
    machine = service.get_machine_representation(resolved)
    if not machine:
        return _build_optional_representation_unavailable(
            request=request,
            representation=REPRESENTATION_MACHINE,
            links=service.representation_links(resolved),
        )
    headers = {"Cache-Control": "public, max-age=3600"}
    if machine.profile:
        headers["Link"] = f'<{machine.profile}>; rel="profile"'
    body = machine.content if isinstance(machine.content, str) else json.dumps(machine.content)
    return Response(content=body, media_type=machine.media_type, headers=headers)


@router.get("/licenses/{id:path}/encoding")
@router.get("/licences/{id:path}/encoding", include_in_schema=False)
async def get_license_encoding(
    id: str,
    request: Request,
    service: LicenseService = Depends(get_license_service),
):
    """Redirect to a curated rights-encoding reference when available."""
    try:
        resolved = await service.resolve(id)
    except LicenseNotFoundError:
        return _problem_404(id, request)
    encoding = service.get_encoding_representation(resolved)
    if not encoding:
        return _build_optional_representation_unavailable(
            request=request,
            representation=REPRESENTATION_ENCODING,
            links=service.representation_links(resolved),
        )
    return RedirectResponse(url=encoding["href"], status_code=307)


@router.get("/licenses/{id:path}")
@router.get("/licences/{id:path}", include_in_schema=False)
async def get_license(
    id: str,
    request: Request,
    service: LicenseService = Depends(get_license_service),
):
    """Return the negotiated canonical representation for a license."""
    negotiated = negotiate_representation(request.headers.get("accept"))
    if negotiated is None:
        return problem_response(
            status=406,
            title="Not Acceptable",
            detail="Requested representation is not supported.",
            instance=str(request.url),
            extra={
                "supportedMediaTypes": [
                    "text/html",
                    "application/json",
                    "application/ld+json",
                    "text/turtle",
                    "application/rdf+xml",
                ]
            },
        )
    return await _render_license_response(service, id, negotiated, request, negotiated=True)


async def _render_license_response(
    service: LicenseService,
    identifier: str,
    representation: str,
    request: Request,
    *,
    negotiated: bool,
) -> Response:
    try:
        resolved = await service.resolve(identifier)
    except LicenseNotFoundError:
        return _problem_404(identifier, request)
    body, media_type = service.render_representation(resolved, representation)
    links = service.representation_links(resolved)
    content_location = links[representation]
    headers = _response_headers(content_location, include_vary=negotiated)
    return Response(content=body, media_type=media_type, headers=headers)
