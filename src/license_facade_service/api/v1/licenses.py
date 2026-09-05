from __future__ import annotations

import json
import logging
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from fastapi import APIRouter, Depends, Path as ApiPath, Query, Request, Security
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse, Response
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from pydantic import BaseModel, ConfigDict, Field, field_validator

from src.license_facade_service.custom_licences.models import PublicLicenseScope
from src.license_facade_service.services.custom_licence_registration import (
    CustomLicenceRegistrationError,
    CustomLicenceRegistrationService,
    RegisterCustomLicenceInput,
)
from src.license_facade_service.services.auth import (
    AuthService,
    AuthenticationError,
    AuthorizationError,
    Principal,
)
from src.license_facade_service.services.licenses import (
    LicenseNotFoundError,
    LicenseService,
    ResolvedLicenseSource,
    REPRESENTATION_HTML,
    REPRESENTATION_JSON,
    REPRESENTATION_JSON_LD,
    REPRESENTATION_ENCODING,
    REPRESENTATION_MACHINE,
    REPRESENTATION_ORIGINAL,
    REPRESENTATION_RDFXML,
    REPRESENTATION_TURTLE,
    negotiate_representation,
    LicenseSnapshotStatus,
)
from src.license_facade_service.services.contract import LicenseDetail, LicenseInventoryItem
from src.license_facade_service.services.contract import LicenseInventoryResponse
from src.license_facade_service.services.problem import ProblemDetails
from src.license_facade_service.services.problem import problem_response
from src.license_facade_service.services.spdx_custom_license import validate_custom_license_identifier
from src.license_facade_service.services.spdx_custom_license import validate_http_iri
from src.license_facade_service.services.spdx_validation import SpdxStructuralValidationError
from src.license_facade_service.services.spdx3_documents import Spdx3DocumentGenerationError, Spdx3DocumentService
from src.license_facade_service.federation.resolution import FederationResolutionService, ResolutionError
from src.license_facade_service.federation.resolution_models import LicenseProvenanceResponse, LicenseResolutionResponse

router = APIRouter()
bearer_scheme = HTTPBearer(
    auto_error=False,
    description=(
        "Bearer token used for protected administrative operations. "
        "Curator or admin tokens can refresh cache data and generate SPDX helper documents."
    ),
)

PROBLEM_EXAMPLES = {
    "not_found": {
        "type": "https://eosc-eden.eu/problems/resolution-not-found",
        "title": "Resolution Not Found",
        "status": 404,
        "detail": "No record or candidate exists for identifier 'Example-License'.",
        "instance": "https://license.example.org/api/v1/licenses/resolution?identifier=Example-License",
    },
    "unauthorized": {
        "type": "https://eosc-eden.eu/problems/unauthorized",
        "title": "Unauthorized",
        "status": 401,
        "detail": "Missing or invalid bearer token.",
        "instance": "https://license.example.org/api/v1/licenses/cache/refresh",
    },
    "forbidden": {
        "type": "https://eosc-eden.eu/problems/forbidden",
        "title": "Forbidden",
        "status": 403,
        "detail": "Authenticated principal lacks required curator/admin role.",
        "instance": "https://license.example.org/api/v1/licenses/cache/refresh",
    },
    "not_acceptable": {
        "type": "about:blank",
        "title": "Not Acceptable",
        "status": 406,
        "detail": "Requested representation is not supported.",
        "instance": "https://license.example.org/api/v1/licenses/MIT",
    },
}


_license_service: LicenseService | None = None
_auth_service: AuthService | None = None


class TaxonomyResponse(BaseModel):
    description: str = Field(description="Human-readable taxonomy overview for common licence families.")


class CacheMutationResponse(BaseModel):
    status: str = Field(description="Mutation outcome.", examples=["success"])
    cache: LicenseSnapshotStatus = Field(description="Snapshot status after the cache mutation completed.")


class MinimalSpdx3Request(BaseModel):
    model_config = ConfigDict(extra="forbid")

    name: str = Field(
        default="Minimal SPDX 3.0 Document",
        description="Human-readable document name for the generated SPDX 3.0 JSON-LD example.",
        examples=["Minimal SPDX 3.0 Document"],
        min_length=1,
        max_length=200,
    )
    namespace: str = Field(
        default="https://example.org/spdx3/minimal-doc-1",
        description="Base namespace used when generating example identifiers in the SPDX 3.0 document.",
        examples=["https://example.example/spdx3/minimal-doc-1"],
    )

    @field_validator("name")
    @classmethod
    def _validate_name(cls, value: str) -> str:
        candidate = value.strip()
        if not candidate:
            raise ValueError("name must be non-blank.")
        if any(ord(ch) < 32 or ord(ch) == 127 for ch in candidate):
            raise ValueError("name must not contain control characters.")
        return candidate

    @field_validator("namespace")
    @classmethod
    def _validate_namespace(cls, value: str) -> str:
        return validate_http_iri(value, "namespace")


class RegisterCustomLicenceRequest(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
        json_schema_extra={
            "examples": [
                {
                    "requestedLicenseId": "DANS-Custom-1.0",
                    "version": "1.0",
                    "name": "DANS Custom License 1.0",
                    "summary": "A custom licence maintained by DANS.",
                    "description": "Local DANS terms.",
                    "licenseText": "Copyright 2026 DANS.\n\nPermission is granted...",
                    "scope": "local",
                    "aliases": ["DANS Custom License"],
                },
                {
                    "requestedLicenseId": "DANS-Proposed-1.0",
                    "version": "1.0",
                    "name": "DANS Proposed License 1.0",
                    "summary": "A proposed licence for later SPDX review.",
                    "licenseText": "Copyright 2026 DANS.\n\nPermission is granted...",
                    "scope": "spdx-submission",
                },
                {
                    "requestedLicenseId": "DANS-Federated-1.0",
                    "version": "1.0",
                    "name": "DANS Federated License 1.0",
                    "summary": "A custom licence queued for federated publication.",
                    "licenseText": "Copyright 2026 DANS.\n\nPermission is granted...",
                    "scope": "federated",
                    "aliases": ["DANS Federated License"],
                },
            ]
        },
    )

    requested_license_id: str = Field(alias="requestedLicenseId", min_length=1, max_length=256)
    version: str = Field(min_length=1, max_length=128)
    name: str = Field(min_length=1, max_length=512)
    summary: str | None = Field(default=None, max_length=4096)
    description: str | None = Field(default=None, max_length=20000)
    license_text: str = Field(alias="licenseText", min_length=1)
    scope: PublicLicenseScope = Field(
        description=(
            "Registration scope. "
            "`local` and `spdx-submission` register without federation publication. "
            "`federated` registers locally and queues asynchronous federation publication."
        )
    )
    aliases: list[str] = Field(default_factory=list, max_length=64)

    @field_validator("requested_license_id")
    @classmethod
    def _validate_requested_license_id(cls, value: str) -> str:
        candidate = value.strip()
        if not candidate:
            raise ValueError("requestedLicenseId must be non-blank.")
        validate_custom_license_identifier(candidate)
        if len(candidate) > 256:
            raise ValueError("requestedLicenseId must be <= 256 characters.")
        return candidate

    @field_validator("version")
    @classmethod
    def _validate_version(cls, value: str) -> str:
        candidate = value.strip()
        if not candidate:
            raise ValueError("version must be non-blank.")
        validate_custom_license_identifier(candidate)
        return candidate

    @field_validator("name")
    @classmethod
    def _validate_registration_name(cls, value: str) -> str:
        candidate = value.strip()
        if not candidate:
            raise ValueError("name must be non-blank.")
        if any(ord(ch) < 32 or ord(ch) == 127 for ch in candidate):
            raise ValueError("name must not contain control characters.")
        return candidate

    @field_validator("summary")
    @classmethod
    def _normalize_summary(cls, value: str | None) -> str | None:
        if value is None:
            return None
        candidate = value.strip()
        return candidate or None

    @field_validator("description")
    @classmethod
    def _normalize_description(cls, value: str | None) -> str | None:
        if value is None:
            return None
        candidate = value.strip()
        return candidate or None

    @field_validator("license_text")
    @classmethod
    def _validate_license_text(cls, value: str) -> str:
        if not isinstance(value, str) or not value.strip():
            raise ValueError("licenseText must be non-blank.")
        return value

    @field_validator("aliases")
    @classmethod
    def _validate_aliases(cls, value: list[str]) -> list[str]:
        if len(value) > 64:
            raise ValueError("aliases must contain at most 64 items.")
        validated: list[str] = []
        for alias in value:
            candidate = alias.strip()
            if not candidate:
                raise ValueError("aliases must not contain blank values.")
            if len(candidate) > 512:
                raise ValueError("alias values must be <= 512 characters.")
            if any(ord(ch) < 32 or ord(ch) == 127 for ch in candidate):
                raise ValueError("alias values must not contain control characters.")
            validated.append(candidate)
        return validated


class RegisterCustomLicenceResponse(BaseModel):
    model_config = ConfigDict(populate_by_name=True)

    id: str
    requested_license_id: str = Field(alias="requestedLicenseId")
    version: str
    canonical_id: str = Field(alias="canonicalId")
    resolving_uuid: str = Field(alias="resolvingUuid")
    resolving_uri: str = Field(alias="resolvingUri")
    name: str
    summary: str | None = None
    description: str | None = None
    scope: PublicLicenseScope
    federation_status: str = Field(alias="federationStatus")
    spdx_submission_status: str = Field(alias="spdxSubmissionStatus")
    lifecycle_status: str = Field(alias="lifecycleStatus")
    normalized_text_digest: str = Field(alias="normalizedTextDigest")
    spdx_jsonld: dict[str, Any] = Field(alias="spdxJsonld")
    created_at: datetime = Field(alias="createdAt")
    updated_at: datetime = Field(alias="updatedAt")


def _problem_response_doc(description: str, example: dict[str, Any]) -> dict[str, Any]:
    return {
        "description": description,
        "content": {
            "application/problem+json": {
                "schema": ProblemDetails.model_json_schema(),
                "example": example,
            }
        },
    }


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


def get_spdx3_document_service(request: Request) -> Spdx3DocumentService | None:
    service = getattr(request.app.state, "spdx3_document_service", None)
    return service


def get_custom_licence_registration_service(request: Request) -> CustomLicenceRegistrationService:
    service = getattr(request.app.state, "custom_licence_registration_service", None)
    if service is None:
        raise RuntimeError("custom licence registration service is not initialized")
    return service


def _problem_404(identifier: str, request: Request) -> JSONResponse:
    return problem_response(
        status=404,
        title="License Not Found",
        detail=f"No license record found for identifier '{identifier}'.",
        instance=str(request.url),
    )


def _problem_spdx3_generation_failed(request: Request) -> JSONResponse:
    return problem_response(
        status=500,
        title="SPDX 3 Document Generation Failed",
        detail="Generated SPDX 3.0.1 document failed structural validation.",
        instance=str(request.url),
        type_uri="https://eosc-eden.eu/problems/spdx3-document-generation-invalid",
    )


def _problem_spdx3_generation_unavailable(request: Request) -> JSONResponse:
    return problem_response(
        status=500,
        title="SPDX 3 Document Generation Failed",
        detail="SPDX 3 document generation is temporarily unavailable.",
        instance=str(request.url),
        type_uri="https://eosc-eden.eu/problems/spdx3-document-generation-invalid",
    )


def _response_headers(content_location: str, include_vary: bool = True) -> dict[str, str]:
    headers = {
        "Cache-Control": "public, max-age=3600",
        "Content-Location": content_location,
        "Link": f'<{content_location}>; rel="canonical"',
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
    metadata: dict[str, object] | None = None,
) -> JSONResponse:
    extra = {"availableRepresentations": links}
    if metadata:
        extra["licenseMetadata"] = metadata
    return problem_response(
        status=404,
        title="Representation Not Available",
        detail=f"Representation '{representation}' is unavailable for this license.",
        instance=str(request.url),
        extra=extra,
    )


def _resolution_service(request: Request) -> FederationResolutionService:
    runtime = getattr(request.app.state, "federation_runtime", None)
    settings = getattr(runtime, "settings", None)
    db = getattr(runtime, "db", None) if runtime is not None else None
    if settings is None:
        from src.license_facade_service.config.federation import FederationSettings

        settings = FederationSettings.from_env()
    return FederationResolutionService(db, settings, license_service=get_license_service())


def _resolution_problem(request: Request, error: ResolutionError):
    mapping = {
        "invalid-identifier": (400, "Invalid Identifier"),
        "resolution-not-found": (404, "Resolution Not Found"),
        "resolution-ambiguous": (409, "Ambiguous Resolution"),
        "resolution-conflicted": (409, "Conflicted Resolution"),
        "resolution-tombstoned": (410, "Tombstoned Resolution"),
        "resolution-unavailable": (503, "Resolution Unavailable"),
        "conflict-not-found": (404, "Conflict Not Found"),
        "conflict-stale": (409, "Conflict Version Changed"),
        "conflict-not-allowed": (409, "Conflict Decision Not Allowed"),
        "conflict-data-collision": (409, "Conflict Data Collision"),
    }
    status, title = mapping.get(error.code, (400, "Resolution Error"))
    extra = {"resolutionContext": getattr(error, "context", {})}
    return problem_response(
        status=status,
        title=title,
        detail=error.detail,
        type_uri=f"https://eosc-eden.eu/problems/{error.code}",
        instance=str(request.url),
        extra=extra,
    )


@router.get(
    "/licenses",
    response_model=LicenseInventoryResponse,
    tags=["Licences"],
    summary="List cached licences",
    description=(
        "Returns the locally cached SPDX licence inventory enriched with LFS public URIs.\n\n"
        "Use this endpoint to browse the currently cached licence list. The response reflects the active "
        "local snapshot and does not require federation to be enabled."
    ),
    operation_id="listLicences",
    response_description="Cached licence inventory from the active local snapshot.",
)
@router.get("/licences", include_in_schema=False)
@router.get("/licenses/", include_in_schema=False)
@router.get("/licences/", include_in_schema=False)
async def list_licenses(service: LicenseService = Depends(get_license_service)):
    """Return the cached SPDX license inventory with LFS URI enrichment."""
    return await service.get_all_licenses()


@router.get(
    "/licenses/taxonomy",
    response_model=TaxonomyResponse,
    tags=["Licences"],
    summary="Show licence taxonomy overview",
    description=(
        "Returns a static taxonomy summary for common licence families.\n\n"
        "Use this endpoint to present a lightweight, human-readable overview in UIs without having to "
        "derive categories from SPDX metadata client-side."
    ),
    operation_id="getLicenceTaxonomy",
    response_description="Static taxonomy summary for common licence families.",
)
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


@router.get(
    "/licenses/cache/status",
    response_model=LicenseSnapshotStatus,
    tags=["Licences"],
    summary="Inspect local cache status",
    description=(
        "Returns status information about the current SPDX cache snapshot.\n\n"
        "The response intentionally does not expose internal filesystem paths. Use it to confirm whether "
        "the service has a usable snapshot, which version is active, and when it was last updated."
    ),
    operation_id="getLicenceCacheStatus",
    response_description="Current SPDX cache snapshot status.",
)
@router.get("/licences/cache/status", include_in_schema=False)
async def cache_status(service: LicenseService = Depends(get_license_service)):
    """Return cache status without exposing the cache filesystem path."""
    return service.cache_status().model_dump()


@router.post(
    "/licenses/cache/update",
    response_model=CacheMutationResponse,
    tags=["Licences"],
    summary="Refresh the SPDX cache snapshot",
    description=(
        "Downloads and activates a newer SPDX cache snapshot when available.\n\n"
        "Bearer authentication is required. Curator or admin role is sufficient. "
        "Missing or invalid credentials return 401; insufficient permission returns 403."
    ),
    operation_id="updateLicenceCache",
    response_description="Result of the cache refresh operation.",
    responses={
        401: _problem_response_doc("Missing or invalid bearer token.", PROBLEM_EXAMPLES["unauthorized"]),
        403: _problem_response_doc("Authenticated principal lacks curator/admin permission.", PROBLEM_EXAMPLES["forbidden"]),
        500: _problem_response_doc(
            "Cache refresh failed before a new snapshot could be activated.",
            {
                "type": "about:blank",
                "title": "Cache Update Failed",
                "status": 500,
                "detail": "Failed to refresh SPDX cache snapshot.",
                "instance": "https://license.example.org/api/v1/licenses/cache/update",
            },
        ),
    },
)
@router.post("/licences/cache/update", include_in_schema=False)
async def update_cache(
    request: Request,
    service: LicenseService = Depends(get_license_service),
    auth: AuthService = Depends(get_auth_service),
    _token: HTTPAuthorizationCredentials | None = Security(bearer_scheme),
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


@router.post(
    "/licenses/cache/refresh",
    response_model=CacheMutationResponse,
    tags=["Licences"],
    summary="Force a cache refresh",
    description=(
        "Alias for the SPDX cache update operation.\n\n"
        "Bearer authentication is required. Curator or admin role is sufficient. "
        "Missing or invalid credentials return 401; insufficient permission returns 403."
    ),
    operation_id="refreshLicenceCache",
    response_description="Result of the forced cache refresh operation.",
    responses={
        401: _problem_response_doc("Missing or invalid bearer token.", PROBLEM_EXAMPLES["unauthorized"]),
        403: _problem_response_doc("Authenticated principal lacks curator/admin permission.", PROBLEM_EXAMPLES["forbidden"]),
        500: _problem_response_doc(
            "Cache refresh failed before a new snapshot could be activated.",
            {
                "type": "about:blank",
                "title": "Cache Update Failed",
                "status": 500,
                "detail": "Failed to refresh SPDX cache snapshot.",
                "instance": "https://license.example.org/api/v1/licenses/cache/refresh",
            },
        ),
    },
)
@router.post("/licences/cache/refresh", include_in_schema=False)
async def refresh_cache(
    request: Request,
    service: LicenseService = Depends(get_license_service),
    auth: AuthService = Depends(get_auth_service),
    _token: HTTPAuthorizationCredentials | None = Security(bearer_scheme),
):
    """Force refresh the SPDX snapshot after bearer-token authorization."""
    return await update_cache(request=request, service=service, auth=auth)


@router.post(
    "/licenses",
    response_model=RegisterCustomLicenceResponse,
    tags=["Licences"],
    summary="Register an authoritative custom licence",
    description=(
        "Registers one authoritative custom licence in the local LFS PostgreSQL store.\n\n"
        "Bearer authentication is required. Curator or admin role is sufficient. "
        "Supported registration scopes are `local`, `spdx-submission`, and `federated`. "
        "For `federated`, registration creates a durable publication job and returns "
        "`federationStatus=pending`; publication is asynchronous. "
        "The `spdx-submission` scope only marks a record as ready for later review; "
        "it does not create a pull request, does not contact SPDX, and does not imply acceptance. "
        "Registration does not publish directly to peers; remote peers pull from the existing "
        "signed changes feed using synchronization workers.\n\n"
        "This endpoint does not emit a `Location` header because custom-licence resolver routing is deferred.\n\n"
        "The endpoint performs offline SPDX 3.0.1 structural validation using the vendored schema only "
        "(no OWL/SHACL semantic validation)."
    ),
    operation_id="register_custom_licence",
    response_description="Registered custom licence metadata and immutable SPDX 3.0.1 snapshot.",
    responses={
        401: _problem_response_doc("Missing or invalid bearer token.", PROBLEM_EXAMPLES["unauthorized"]),
        403: _problem_response_doc("Authenticated principal lacks curator/admin permission.", PROBLEM_EXAMPLES["forbidden"]),
        409: _problem_response_doc(
            "The requested custom licence identity or alias conflicts with an existing record.",
            {
                "type": "https://eosc-eden.eu/problems/custom-licence-already-exists",
                "title": "Custom Licence Already Registered",
                "status": 409,
                "detail": "A custom licence with the same authority, requested ID, and version already exists.",
                "instance": "https://license.example.org/api/v1/licenses",
            },
        ),
        422: _problem_response_doc(
            "Request validation failed.",
            {
                "type": "https://eosc-eden.eu/problems/custom-licence-request-invalid",
                "title": "Invalid Registration Request",
                "status": 422,
                "detail": "The registration request payload is invalid.",
                "instance": "https://license.example.org/api/v1/licenses",
            },
        ),
        500: _problem_response_doc(
            "Registration failed due to an internal persistence or generation error.",
            {
                "type": "https://eosc-eden.eu/problems/custom-licence-persistence-failed",
                "title": "Custom Licence Persistence Failed",
                "status": 500,
                "detail": "Could not persist the custom licence registration.",
                "instance": "https://license.example.org/api/v1/licenses",
            },
        ),
        503: _problem_response_doc(
            "Custom licence registration or federated publication configuration is unavailable or invalid.",
            {
                "type": "https://eosc-eden.eu/problems/custom-licence-registration-config-invalid",
                "title": "Custom Licence Registration Unavailable",
                "status": 503,
                "detail": "Custom licence registration configuration is invalid.",
                "instance": "https://license.example.org/api/v1/licenses",
            },
        ),
    },
)
@router.post("/licences", include_in_schema=False)
def register_custom_licence(
    payload: RegisterCustomLicenceRequest,
    request: Request,
    auth: AuthService = Depends(get_auth_service),
    service: CustomLicenceRegistrationService = Depends(get_custom_licence_registration_service),
    _token: HTTPAuthorizationCredentials | None = Security(bearer_scheme),
):
    """Register a custom licence and optionally enqueue federated publication."""
    try:
        principal = _require_mutation_auth(request, auth)
    except PermissionError as exc:
        if str(exc) == "authn":
            return problem_response(
                status=401,
                title="Unauthorized",
                detail="Missing or invalid bearer token.",
                instance=str(request.url),
                type_uri="https://eosc-eden.eu/problems/unauthorized",
            )
        return problem_response(
            status=403,
            title="Forbidden",
            detail="Authenticated principal lacks required curator/admin role.",
            instance=str(request.url),
            type_uri="https://eosc-eden.eu/problems/forbidden",
        )

    try:
        result = service.register(
            RegisterCustomLicenceInput(
                requested_license_id=payload.requested_license_id,
                version=payload.version,
                name=payload.name,
                summary=payload.summary,
                description=payload.description,
                license_text=payload.license_text,
                scope=payload.scope,
                aliases=tuple(payload.aliases),
                creator_role=principal.role,
            )
        )
    except CustomLicenceRegistrationError as exc:
        return problem_response(
            status=exc.status,
            title=exc.title,
            detail=exc.detail,
            instance=str(request.url),
            type_uri=f"https://eosc-eden.eu/problems/{exc.type_slug}",
            extra=exc.extra,
        )

    return JSONResponse(
        status_code=201,
        content=RegisterCustomLicenceResponse(
            id=str(result.id),
            requested_license_id=result.requested_license_id,
            version=result.version,
            canonical_id=result.canonical_id,
            resolving_uuid=str(result.resolving_uuid),
            resolving_uri=result.resolving_uri,
            name=result.name,
            summary=result.summary,
            description=result.description,
            scope=result.scope,
            federation_status=result.federation_status.value,
            spdx_submission_status=result.spdx_submission_status.value,
            lifecycle_status=result.lifecycle_status.value,
            normalized_text_digest=result.normalized_text_digest,
            spdx_jsonld=result.spdx_jsonld,
            created_at=result.created_at,
            updated_at=result.updated_at,
        ).model_dump(by_alias=True, mode="json"),
    )


@router.post(
    "/licenses/spdx3/minimal",
    tags=["Licences"],
    summary="Generate a minimal SPDX 3.0 JSON-LD document",
    description=(
        "Creates a minimal SPDX 3.0.1 JSON-LD document.\n\n"
        "Generated output is structurally validated offline against the vendored official SPDX 3.0.1 JSON Schema "
        "(`vendor/spdx/3.0.1/spdx-json-schema.json`) before it is returned. "
        "No runtime schema/context network access is performed. Validation is structural only; OWL/SHACL semantic "
        "validation is not performed. These endpoints do not use `spdx-tools` validation.\n\n"
        "Bearer authentication is required. Curator or admin role is sufficient. "
        "This helper does not publish or persist any federation state."
    ),
    operation_id="createMinimalSpdx3Document",
    response_description="Generated minimal SPDX 3.0 JSON-LD document.",
    responses={
        200: {
            "description": "Structurally validated minimal SPDX 3.0.1 JSON-LD document.",
            "content": {
                "application/json": {
                    "example": {
                        "@context": "https://spdx.org/rdf/3.0.1/spdx-context.jsonld",
                        "@graph": [
                            {
                                "@id": "_:creation-info",
                                "type": "CreationInfo",
                                "specVersion": "3.0.1",
                                "created": "2026-01-01T00:00:00Z",
                                "createdBy": ["https://example.org/spdx3/minimal-doc-1/actors/lfs-operator"],
                            },
                            {
                                "type": "Organization",
                                "spdxId": "https://example.org/spdx3/minimal-doc-1/actors/lfs-operator",
                                "name": "License Facade Service",
                                "creationInfo": "_:creation-info",
                            },
                            {
                                "type": "SpdxDocument",
                                "spdxId": "https://example.org/spdx3/minimal-doc-1/documents/minimal",
                                "name": "Minimal SPDX 3.0 Document",
                                "creationInfo": "_:creation-info",
                                "rootElement": ["https://example.org/spdx3/minimal-doc-1/actors/lfs-operator"],
                            },
                        ],
                    }
                }
            },
        },
        401: _problem_response_doc("Missing or invalid bearer token.", PROBLEM_EXAMPLES["unauthorized"]),
        403: _problem_response_doc("Authenticated principal lacks curator/admin permission.", PROBLEM_EXAMPLES["forbidden"]),
        422: _problem_response_doc(
            "Invalid SPDX document generation request payload.",
            {
                "type": "https://eosc-eden.eu/problems/spdx3-request-invalid",
                "title": "Invalid SPDX 3 Request",
                "status": 422,
                "detail": "The SPDX document generation request payload is invalid.",
                "instance": "https://license.example.org/api/v1/licenses/spdx3/minimal",
            },
        ),
        500: _problem_response_doc(
            "Generated SPDX 3.0.1 document failed structural validation.",
            {
                "type": "https://eosc-eden.eu/problems/spdx3-document-generation-invalid",
                "title": "SPDX 3 Document Generation Failed",
                "status": 500,
                "detail": "Generated SPDX 3.0.1 document failed structural validation.",
                "instance": "https://license.example.org/api/v1/licenses/spdx3/minimal",
            },
        ),
    },
)
@router.post("/licences/spdx3/minimal", include_in_schema=False)
async def create_minimal_spdx3(
    payload: MinimalSpdx3Request,
    request: Request,
    auth: AuthService = Depends(get_auth_service),
    spdx3_documents: Spdx3DocumentService | None = Depends(get_spdx3_document_service),
    _token: HTTPAuthorizationCredentials | None = Security(bearer_scheme),
):
    """Create and structurally validate a minimal SPDX 3.0.1 JSON-LD document."""
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
    if spdx3_documents is None:
        return _problem_spdx3_generation_unavailable(request)
    try:
        return spdx3_documents.create_minimal_document(name=payload.name, namespace=payload.namespace)
    except SpdxStructuralValidationError:
        return _problem_spdx3_generation_failed(request)
    except Spdx3DocumentGenerationError:
        return _problem_spdx3_generation_unavailable(request)
    except RuntimeError:
        return _problem_spdx3_generation_unavailable(request)


@router.post(
    "/licenses/spdx3/complete/{license_id}",
    tags=["Licences"],
    summary="Generate a complete SPDX 3.0 JSON-LD document for one licence",
    description=(
        "Builds a complete SPDX 3.0.1 JSON-LD document for one resolved licence.\n\n"
        "Generated output is structurally validated offline against the vendored official SPDX 3.0.1 JSON Schema "
        "(`vendor/spdx/3.0.1/spdx-json-schema.json`) before it is returned. "
        "No runtime schema/context network access is performed. Validation is structural only; OWL/SHACL semantic "
        "validation is not performed. These endpoints do not use `spdx-tools` validation.\n\n"
        "Bearer authentication is required. Curator or admin role is sufficient. "
        "Use this endpoint when you need a richer SPDX 3.0.1 representation derived from the current local snapshot."
    ),
    operation_id="createCompleteSpdx3Document",
    response_description="Generated SPDX 3.0 JSON-LD document for the requested licence.",
    responses={
        200: {
            "description": "Structurally validated complete SPDX 3.0.1 JSON-LD document.",
            "content": {
                "application/json": {
                    "example": {
                        "@context": "https://spdx.org/rdf/3.0.1/spdx-context.jsonld",
                        "@graph": [
                            {
                                "@id": "_:creation-info",
                                "type": "CreationInfo",
                                "specVersion": "3.0.1",
                                "created": "2026-01-01T00:00:00Z",
                                "createdBy": ["https://example.test/api/v1/licenses/spdx3/documents/actors/lfs-operator"],
                            },
                            {
                                "type": "Organization",
                                "spdxId": "https://example.test/api/v1/licenses/spdx3/documents/actors/lfs-operator",
                                "name": "License Facade Service",
                                "creationInfo": "_:creation-info",
                            },
                            {
                                "type": "SpdxDocument",
                                "spdxId": "https://example.test/api/v1/licenses/spdx3/documents/MIT",
                                "name": "SPDX 3.0.1 Document for MIT",
                                "creationInfo": "_:creation-info",
                                "rootElement": ["https://example.test/api/v1/licenses/spdx3/documents/licenses/MIT"],
                            },
                            {
                                "type": "expandedlicensing_ListedLicense",
                                "spdxId": "https://example.test/api/v1/licenses/spdx3/documents/licenses/MIT",
                                "name": "MIT License",
                                "simplelicensing_licenseText": "Permission is hereby granted, free of charge, ...",
                                "creationInfo": "_:creation-info",
                            },
                        ],
                    }
                }
            },
        },
        401: _problem_response_doc("Missing or invalid bearer token.", PROBLEM_EXAMPLES["unauthorized"]),
        403: _problem_response_doc("Authenticated principal lacks curator/admin permission.", PROBLEM_EXAMPLES["forbidden"]),
        422: _problem_response_doc(
            "Invalid SPDX document generation request payload.",
            {
                "type": "https://eosc-eden.eu/problems/spdx3-request-invalid",
                "title": "Invalid SPDX 3 Request",
                "status": 422,
                "detail": "The SPDX document generation request payload is invalid.",
                "instance": "https://license.example.org/api/v1/licenses/spdx3/complete/MIT",
            },
        ),
        404: _problem_response_doc("No licence matched the supplied licence ID.", PROBLEM_EXAMPLES["not_found"]),
        500: _problem_response_doc(
            "Generated SPDX 3.0.1 document failed structural validation.",
            {
                "type": "https://eosc-eden.eu/problems/spdx3-document-generation-invalid",
                "title": "SPDX 3 Document Generation Failed",
                "status": 500,
                "detail": "Generated SPDX 3.0.1 document failed structural validation.",
                "instance": "https://license.example.org/api/v1/licenses/spdx3/complete/MIT",
            },
        ),
    },
)
@router.post("/licences/spdx3/complete/{license_id}", include_in_schema=False)
async def create_complete_spdx3(
    request: Request,
    license_id: str = ApiPath(
        ...,
        description="SPDX licence ID or another supported identifier resolvable by the local service.",
        examples=["MIT"],
    ),
    service: LicenseService = Depends(get_license_service),
    auth: AuthService = Depends(get_auth_service),
    spdx3_documents: Spdx3DocumentService | None = Depends(get_spdx3_document_service),
    _token: HTTPAuthorizationCredentials | None = Security(bearer_scheme),
):
    """Create and structurally validate a complete SPDX 3.0.1 JSON-LD document."""
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
    if spdx3_documents is None:
        return _problem_spdx3_generation_unavailable(request)
    try:
        resolved = await service.resolve(license_id)
    except LicenseNotFoundError:
        return _problem_404(license_id, request)
    try:
        return spdx3_documents.create_complete_license_document(resolved=resolved)
    except SpdxStructuralValidationError:
        return _problem_spdx3_generation_failed(request)
    except (Spdx3DocumentGenerationError, RuntimeError):
        return _problem_spdx3_generation_unavailable(request)


@router.get(
    "/licenses/{id:path}/html",
    response_class=HTMLResponse,
    tags=["Licence representations"],
    summary="Get the HTML landing page for a licence",
    description=(
        "Returns the human-readable HTML landing page for a licence.\n\n"
        "Use this explicit endpoint when you want a browser-friendly representation without content negotiation. "
        "The path parameter supports SPDX IDs, local UUIDs, and URL-encoded full URIs that must be decoded exactly once."
    ),
    operation_id="getLicenceHtmlRepresentation",
    response_description="HTML landing page for the selected licence.",
    responses={200: {"content": {"text/html": {"schema": {"type": "string"}}}}},
)
@router.get("/licences/{id:path}/html", include_in_schema=False)
async def get_license_html(
    request: Request,
    id: str = ApiPath(..., description="Licence identifier to resolve. Supports SPDX IDs, retained UUIDs, and URL-encoded URIs.", examples=["MIT"]),
    service: LicenseService = Depends(get_license_service),
):
    """Return the HTML landing page for a license."""
    return await _render_license_response(service, id, REPRESENTATION_HTML, request, negotiated=False)


@router.get(
    "/licenses/{id:path}/json",
    response_model=LicenseDetail,
    tags=["Licence representations"],
    summary="Get SPDX-compatible JSON metadata for a licence",
    description=(
        "Returns SPDX-compatible JSON metadata for a single licence.\n\n"
        "Use this explicit endpoint when clients want machine-readable JSON without using the `Accept` header."
    ),
    operation_id="getLicenceJsonRepresentation",
    response_description="SPDX-compatible JSON metadata for the selected licence.",
)
@router.get("/licences/{id:path}/json", include_in_schema=False)
async def get_license_json(
    request: Request,
    id: str = ApiPath(..., description="Licence identifier to resolve. Supports SPDX IDs, retained UUIDs, and URL-encoded URIs.", examples=["MIT"]),
    service: LicenseService = Depends(get_license_service),
):
    """Return SPDX-compatible JSON metadata for a license."""
    return await _render_license_response(service, id, REPRESENTATION_JSON, request, negotiated=False)


@router.get(
    "/licenses/{id:path}/json-ld",
    response_class=Response,
    tags=["Licence representations"],
    summary="Get the JSON-LD representation for a licence",
    description=(
        "Returns the JSON-LD representation for a single licence.\n\n"
        "Use this explicit endpoint when clients need linked-data JSON without negotiating through the canonical route."
    ),
    operation_id="getLicenceJsonLdRepresentation",
    response_description="JSON-LD representation for the selected licence.",
    responses={200: {"content": {"application/ld+json": {"schema": {"type": "string"}}}}},
)
@router.get("/licences/{id:path}/json-ld", include_in_schema=False)
async def get_license_jsonld(
    request: Request,
    id: str = ApiPath(..., description="Licence identifier to resolve. Supports SPDX IDs, retained UUIDs, and URL-encoded URIs.", examples=["MIT"]),
    service: LicenseService = Depends(get_license_service),
):
    """Return JSON-LD metadata for a license."""
    return await _render_license_response(service, id, REPRESENTATION_JSON_LD, request, negotiated=False)


@router.get(
    "/licenses/{id:path}/turtle",
    response_class=Response,
    tags=["Licence representations"],
    summary="Get Turtle RDF for a licence",
    description=(
        "Returns the Turtle RDF representation for a single licence.\n\n"
        "Use this explicit endpoint when RDF clients want Turtle without content negotiation."
    ),
    operation_id="getLicenceTurtleRepresentation",
    response_description="Turtle RDF representation for the selected licence.",
    responses={200: {"content": {"text/turtle": {"schema": {"type": "string"}}}}},
)
@router.get("/licences/{id:path}/turtle", include_in_schema=False)
async def get_license_turtle(
    request: Request,
    id: str = ApiPath(..., description="Licence identifier to resolve. Supports SPDX IDs, retained UUIDs, and URL-encoded URIs.", examples=["MIT"]),
    service: LicenseService = Depends(get_license_service),
):
    """Return Turtle RDF for a license."""
    return await _render_license_response(service, id, REPRESENTATION_TURTLE, request, negotiated=False)


@router.get(
    "/licenses/{id:path}/rdfxml",
    response_class=Response,
    tags=["Licence representations"],
    summary="Get RDF/XML for a licence",
    description=(
        "Returns the RDF/XML representation for a single licence.\n\n"
        "Use this explicit endpoint when RDF clients need RDF/XML without content negotiation."
    ),
    operation_id="getLicenceRdfXmlRepresentation",
    response_description="RDF/XML representation for the selected licence.",
    responses={200: {"content": {"application/rdf+xml": {"schema": {"type": "string"}}}}},
)
@router.get("/licences/{id:path}/rdfxml", include_in_schema=False)
async def get_license_rdfxml(
    request: Request,
    id: str = ApiPath(..., description="Licence identifier to resolve. Supports SPDX IDs, retained UUIDs, and URL-encoded URIs.", examples=["MIT"]),
    service: LicenseService = Depends(get_license_service),
):
    """Return RDF/XML for a license."""
    return await _render_license_response(service, id, REPRESENTATION_RDFXML, request, negotiated=False)


@router.get(
    "/licenses/{id:path}/original",
    status_code=307,
    response_class=Response,
    tags=["Licence representations"],
    summary="Follow the curated original source for a licence",
    description=(
        "Redirects to the authoritative human-readable source maintained by the curating organisation, when available.\n\n"
        "This endpoint never invents an original source from generic SPDX references. When no approved curated original "
        "source exists, the service returns an RFC 9457 problem response with links to available alternatives."
    ),
    operation_id="getLicenceOriginalRepresentation",
    response_description="Redirect to the curated original source for the selected licence.",
    responses={
        307: {"description": "Redirect to curated original source"},
        404: _problem_response_doc("No curated original source is available for this licence.", PROBLEM_EXAMPLES["not_found"]),
    },
)
@router.get("/licences/{id:path}/original", include_in_schema=False)
async def get_license_original(
    request: Request,
    id: str = ApiPath(..., description="Licence identifier to resolve. Supports SPDX IDs, retained UUIDs, and URL-encoded URIs.", examples=["Apache-2.0"]),
    service: LicenseService = Depends(get_license_service),
):
    """Redirect to the curated original source when available."""
    try:
        resolved = await service.resolve(id)
    except LicenseNotFoundError:
        return _problem_404(id, request)
    source = service.get_original_source(resolved)
    if not source:
        metadata = service.build_metadata(resolved)
        return _build_optional_representation_unavailable(
            request=request,
            representation=REPRESENTATION_ORIGINAL,
            links=service.representation_links(resolved),
            metadata=metadata,
        )
    if not source.startswith("https://"):
        metadata = service.build_metadata(resolved)
        return problem_response(
            status=404,
            title="Representation Not Available",
            detail="Original representation target is not an approved https URL.",
            instance=str(request.url),
            extra={"availableRepresentations": service.representation_links(resolved), "licenseMetadata": metadata},
        )
    return RedirectResponse(url=source, status_code=307)


@router.get(
    "/licenses/{id:path}/legal",
    response_class=Response,
    tags=["Licence representations"],
    summary="Get the curated legal representation for a licence",
    description=(
        "Returns or redirects to a separately curated legal representation when one exists.\n\n"
        "This endpoint does not silently substitute generic SPDX licence text and claim it is a jurisdictionally valid "
        "legal text. When no curated legal representation is available, the service returns an RFC 9457 problem response."
    ),
    operation_id="getLicenceLegalRepresentation",
    response_description="Curated legal representation for the selected licence.",
    responses={
        200: {
            "content": {
                "text/plain": {"schema": {"type": "string"}},
                "text/html": {"schema": {"type": "string"}},
            }
        },
        307: {"description": "Redirect to curated legal source"},
        404: _problem_response_doc("No curated legal representation is available for this licence.", PROBLEM_EXAMPLES["not_found"]),
    },
)
@router.get("/licences/{id:path}/legal", include_in_schema=False)
async def get_license_legal(
    request: Request,
    id: str = ApiPath(..., description="Licence identifier to resolve. Supports SPDX IDs, retained UUIDs, and URL-encoded URIs.", examples=["Apache-2.0"]),
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
            metadata=service.build_metadata(resolved),
        )
    if legal.href and not legal.content:
        return RedirectResponse(url=legal.href, status_code=307)
    media_type = legal.mediaType
    content = legal.content or ""
    headers = {
        "Cache-Control": "public, max-age=3600",
        "Link": f'<{legal.profile}>; rel="profile"' if legal.profile else f'<{request.base_url}api/v1/licenses/{id}>; rel="canonical"',
    }
    return Response(content=content if isinstance(content, str) else json.dumps(content), media_type=media_type, headers=headers)


@router.get(
    "/licenses/{id:path}/machine",
    response_class=Response,
    tags=["Licence representations"],
    summary="Get a machine-readable rights expression for a licence",
    description=(
        "Returns a curated machine-readable rights-expression representation when one exists.\n\n"
        "Supported media types include JSON-LD, Turtle, and RDF/XML. General SPDX JSON metadata is not treated as a "
        "machine-readable rights expression. When no curated machine representation exists, the service returns 404."
    ),
    operation_id="getLicenceMachineRepresentation",
    response_description="Curated machine-readable rights-expression representation.",
    responses={
        200: {
            "content": {
                "application/ld+json": {"schema": {"type": "string"}},
                "text/turtle": {"schema": {"type": "string"}},
                "application/rdf+xml": {"schema": {"type": "string"}},
            }
        },
        307: {"description": "Redirect to authoritative machine representation"},
        404: _problem_response_doc("No curated machine-readable rights expression is available for this licence.", PROBLEM_EXAMPLES["not_found"]),
    },
)
@router.get("/licences/{id:path}/machine", include_in_schema=False)
async def get_license_machine(
    request: Request,
    id: str = ApiPath(..., description="Licence identifier to resolve. Supports SPDX IDs, retained UUIDs, and URL-encoded URIs.", examples=["CC-BY-4.0"]),
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
            metadata=service.build_metadata(resolved),
        )
    if machine.href and not machine.content:
        return RedirectResponse(url=machine.href, status_code=307)
    headers = {"Cache-Control": "public, max-age=3600", "Link": f'<{request.base_url}api/v1/licenses/{id}>; rel="canonical"'}
    if machine.profile:
        headers["Link"] = headers["Link"] + f', <{machine.profile}>; rel="profile"'
    body = machine.content if isinstance(machine.content, str) else json.dumps(machine.content)
    return Response(content=body, media_type=machine.mediaType, headers=headers)


@router.get(
    "/licenses/{id:path}/encoding",
    status_code=307,
    response_class=Response,
    tags=["Licence representations"],
    summary="Follow a curated encoding reference for a licence",
    description=(
        "Redirects to a curated encoding reference when one exists.\n\n"
        "Use this endpoint to discover an externally hosted encoding resource while keeping the canonical licence metadata "
        "in this service. When no curated encoding reference exists, the service returns 404."
    ),
    operation_id="getLicenceEncodingRepresentation",
    response_description="Redirect to the curated encoding reference for the selected licence.",
    responses={
        307: {"description": "Redirect to curated encoding reference"},
        404: _problem_response_doc("No curated encoding reference is available for this licence.", PROBLEM_EXAMPLES["not_found"]),
    },
)
@router.get("/licences/{id:path}/encoding", include_in_schema=False)
async def get_license_encoding(
    request: Request,
    id: str = ApiPath(..., description="Licence identifier to resolve. Supports SPDX IDs, retained UUIDs, and URL-encoded URIs.", examples=["CC-BY-4.0"]),
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
            metadata=service.build_metadata(resolved),
        )
    return RedirectResponse(url=encoding.href, status_code=307)


@router.get(
    "/licenses/resolution",
    response_model=LicenseResolutionResponse,
   tags=["Federation resolution"],
   summary="Resolve an arbitrary licence identifier",
   description=(
       "Resolves an identifier through local authoritative records, retained imported records, and SPDX fallback.\n\n"
       "Send URI-like identifiers through this canonical query endpoint and URL-encode them exactly once. "
       "Local authoritative records always win. Imported records remain non-authoritative and are not re-exported "
       "through the local authoritative federation catalog or change feed."
   ),
   operation_id="resolveLicenceIdentifier",
   response_description="Resolved licence selection and provenance summary for the supplied identifier.",
   responses={
       400: _problem_response_doc("The identifier was malformed, decoded more than once, or exceeded limits.", {
           "type": "https://eosc-eden.eu/problems/invalid-identifier",
           "title": "Invalid Identifier",
           "status": 400,
           "detail": "Identifier must be decoded exactly once.",
           "instance": "https://license.example.org/api/v1/licenses/resolution?identifier=https%253A%252F%252Fexample.org%252Flicence",
       }),
       404: _problem_response_doc("No local, imported, or SPDX fallback record matched the identifier.", PROBLEM_EXAMPLES["not_found"]),
       409: _problem_response_doc("Multiple eligible imported candidates remain unresolved or the identifier is conflicted.", {
           "type": "https://eosc-eden.eu/problems/resolution-ambiguous",
           "title": "Ambiguous Resolution",
           "status": 409,
           "detail": "Multiple imported candidates remain eligible for identifier 'shared-alias'.",
           "instance": "https://license.example.org/api/v1/licenses/resolution?identifier=shared-alias",
       }),
       410: _problem_response_doc("The selected identity is tombstoned.", {
           "type": "https://eosc-eden.eu/problems/resolution-tombstoned",
           "title": "Tombstoned Resolution",
           "status": 410,
           "detail": "The selected identity has been tombstoned.",
           "instance": "https://license.example.org/api/v1/licenses/resolution?identifier=tomb-example",
       }),
       503: _problem_response_doc("Known records exist but cannot currently be served under trust or operational policy.", {
           "type": "https://eosc-eden.eu/problems/resolution-unavailable",
           "title": "Resolution Unavailable",
           "status": 503,
           "detail": "Known records exist but all candidates are excluded by trust or operational policy.",
           "instance": "https://license.example.org/api/v1/licenses/resolution?identifier=disabled-alias",
       }),
   },
)
@router.get("/licences/resolution", include_in_schema=False)
async def resolve_license(
   request: Request,
   identifier: str = Query(
       ...,
       description=(
           "Identifier to resolve. Supports SPDX licence IDs, retained resolving UUIDs, canonical IDs, approved aliases, "
           "and URL-encoded full URIs. URI-like values should be sent through this query parameter and encoded exactly once."
       ),
       examples=["MIT", "lfs:aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa:MIT:1", "https://licenses.example.org/MIT"],
   ),
):
    try:
       return await _resolution_service(request).resolve_async(identifier)
    except ResolutionError as error:
        return _resolution_problem(request, error)


@router.get(
    "/licenses/provenance",
    response_model=LicenseProvenanceResponse,
   tags=["Federation resolution"],
   summary="Get provenance for a resolved licence identifier",
   description=(
       "Returns provenance details for a resolved identifier, including source peer, authority node, signed event history, "
       "digests, and relevant timestamps.\n\n"
       "Use this endpoint to audit where imported data came from and which signed source events were retained locally."
   ),
   operation_id="getLicenceProvenance",
   response_description="Provenance and retained signed event history for the supplied identifier.",
   responses={
       400: _problem_response_doc("The identifier was malformed, decoded more than once, or exceeded limits.", {
           "type": "https://eosc-eden.eu/problems/invalid-identifier",
           "title": "Invalid Identifier",
           "status": 400,
           "detail": "Identifier must be decoded exactly once.",
           "instance": "https://license.example.org/api/v1/licenses/provenance?identifier=https%253A%252F%252Fexample.org%252Flicence",
       }),
       404: _problem_response_doc("No resolvable record exists for the supplied identifier.", PROBLEM_EXAMPLES["not_found"]),
       409: _problem_response_doc("The identifier is currently conflicted or ambiguous.", {
           "type": "https://eosc-eden.eu/problems/resolution-conflicted",
           "title": "Conflicted Resolution",
           "status": 409,
           "detail": "The identifier is linked to an unresolved imported conflict.",
           "instance": "https://license.example.org/api/v1/licenses/provenance?identifier=shared-alias",
       }),
       410: _problem_response_doc("The selected identity is tombstoned.", {
           "type": "https://eosc-eden.eu/problems/resolution-tombstoned",
           "title": "Tombstoned Resolution",
           "status": 410,
           "detail": "The selected identity has been tombstoned.",
           "instance": "https://license.example.org/api/v1/licenses/provenance?identifier=tomb-example",
       }),
       503: _problem_response_doc("Known records exist but cannot currently be served under trust or operational policy.", {
           "type": "https://eosc-eden.eu/problems/resolution-unavailable",
           "title": "Resolution Unavailable",
           "status": 503,
           "detail": "Known records exist but all candidates are excluded by trust or operational policy.",
           "instance": "https://license.example.org/api/v1/licenses/provenance?identifier=disabled-alias",
       }),
   },
)
@router.get("/licences/provenance", include_in_schema=False)
async def get_license_provenance(
   request: Request,
   identifier: str = Query(
       ...,
       description="Identifier to audit. Use the canonical query endpoint for URI-like values and URL-encode them exactly once.",
       examples=["MIT", "lfs:aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa:MIT:1"],
   ),
):
    try:
        return _resolution_service(request).provenance(identifier)
    except ResolutionError as error:
        return _resolution_problem(request, error)


@router.get(
    "/licenses/{id:path}",
    tags=["Licence representations"],
    summary="Get the canonical negotiated licence representation",
    description=(
        "Returns the canonical representation for a licence using the `Accept` header.\n\n"
        "Supported media types are `text/html`, `application/json`, `application/ld+json`, `text/turtle`, "
        "and `application/rdf+xml`. In the current implementation, missing `Accept` or `*/*` resolves to "
        "`application/json`. If the requested representation is unsupported, the service returns 406 with an "
        "RFC 9457 problem response."
    ),
    operation_id="getLicenceRepresentation",
    response_description="Canonical negotiated representation for the selected licence.",
    responses={
        200: {
            "content": {
                "application/json": {"schema": LicenseDetail.model_json_schema()},
                "text/html": {"schema": {"type": "string"}},
                "application/ld+json": {"schema": {"type": "string"}},
                "text/turtle": {"schema": {"type": "string"}},
                "application/rdf+xml": {"schema": {"type": "string"}},
            }
        },
        404: _problem_response_doc("No licence record matched the supplied identifier.", PROBLEM_EXAMPLES["not_found"]),
        406: _problem_response_doc("The requested media type is not supported for canonical negotiation.", PROBLEM_EXAMPLES["not_acceptable"]),
    },
)
@router.get("/licences/{id:path}", include_in_schema=False)
async def get_license(
    request: Request,
    id: str = ApiPath(
        ...,
        description=(
            "Licence identifier to resolve. Supports SPDX IDs, retained UUIDs, canonical IDs, and URL-encoded full URIs. "
            "For arbitrary URI-like identifiers, prefer the query-based `/api/v1/licenses/resolution` endpoint."
        ),
        examples=["MIT"],
    ),
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
    if resolved.source == ResolvedLicenseSource.LOCAL_CUSTOM:
        custom_response = RegisterCustomLicenceResponse.model_validate(resolved.record)
        headers = _response_headers(f"/api/v1/licenses/{custom_response.canonical_id}", include_vary=negotiated)
        return JSONResponse(content=custom_response.model_dump(by_alias=True, mode="json"), headers=headers)
    body, media_type = service.render_representation(resolved, representation)
    links = service.representation_links(resolved)
    content_location = links["self"] if negotiated else links[representation]
    headers = _response_headers(content_location, include_vary=negotiated)
    return Response(content=body, media_type=media_type, headers=headers)
