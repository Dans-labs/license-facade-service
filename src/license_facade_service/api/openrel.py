from __future__ import annotations

from dataclasses import dataclass
import math
from typing import Any, Literal, Protocol

from fastapi import APIRouter, Depends, Path as ApiPath, Query, Request
from fastapi.responses import Response

from src.license_facade_service.config.openrel import OpenRelSettings
from src.license_facade_service.openrel.client import OpenRelClient, OpenRelClientError, OpenRelErrorCode
from src.license_facade_service.openrel.models import OpenRELMapping, OpenRELResource
from src.license_facade_service.services.problem import ProblemDetails, problem_response

router = APIRouter(prefix="/openrel/api/v0.4")

OpenRelListFamily = Literal[
    "actions",
    "constraints",
    "leftoperands",
    "actionclasses",
    "assetclasses",
    "constraintclasses",
    "leftoperandclasses",
    "ruleclasses",
]
OpenRelDetailFamily = Literal[
    "actions",
    "constraints",
    "leftoperands",
    "actionclasses",
    "assetclasses",
    "constraintclasses",
    "leftoperandclasses",
    "ruleclasses",
]


class OpenRelClientLike(Protocol):
    async def list_resources(self, family: str, *, prefix: str | None = None) -> list[OpenRELResource]: ...
    async def list_mappings(self, *, prefix: str | None = None) -> list[OpenRELMapping]: ...
    async def get_resource(self, family: str, identifier: str, *, prefix: str | None = None) -> OpenRELResource: ...


class _UnavailableOpenRelClient:
    def _raise(self) -> None:
        raise OpenRelClientError(OpenRelErrorCode.INVALID_CONFIGURATION, "OpenREL configuration is unavailable for this deployment.")

    async def list_resources(self, family: str, *, prefix: str | None = None) -> list[OpenRELResource]:
        self._raise()

    async def list_mappings(self, *, prefix: str | None = None) -> list[OpenRELMapping]:
        self._raise()

    async def get_resource(self, family: str, identifier: str, *, prefix: str | None = None) -> OpenRELResource:
        self._raise()


_UNAVAILABLE_CLIENT = _UnavailableOpenRelClient()


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


def get_openrel_client(request: Request) -> OpenRelClientLike:
    client: OpenRelClient | None = getattr(request.app.state, "openrel_client", None)
    if client is None:
        return _UNAVAILABLE_CLIENT
    return client


@dataclass(frozen=True)
class _MappedProblem:
    status: int
    title: str
    type_slug: str
    detail: str


_PROBLEM_MAP: dict[OpenRelErrorCode, _MappedProblem] = {
    OpenRelErrorCode.DISABLED: _MappedProblem(
        503,
        "OpenREL Disabled",
        "openrel-disabled",
        "OpenREL support is disabled for this deployment.",
    ),
    OpenRelErrorCode.INVALID_CONFIGURATION: _MappedProblem(
        503,
        "OpenREL Configuration Unavailable",
        "openrel-configuration-unavailable",
        "OpenREL configuration is unavailable for this deployment.",
    ),
    OpenRelErrorCode.INVALID_ID: _MappedProblem(
        400,
        "Invalid OpenREL Identifier",
        "openrel-invalid-identifier",
        "The supplied OpenREL identifier is invalid.",
    ),
    OpenRelErrorCode.INVALID_PREFIX: _MappedProblem(
        400,
        "Invalid OpenREL Prefix",
        "openrel-invalid-prefix",
        "The supplied OpenREL prefix is invalid.",
    ),
    OpenRelErrorCode.FORBIDDEN_DESTINATION: _MappedProblem(
        502,
        "OpenREL Upstream Destination Rejected",
        "openrel-upstream-destination-rejected",
        "The OpenREL upstream destination was rejected by policy.",
    ),
    OpenRelErrorCode.DNS_FAILURE: _MappedProblem(
        503,
        "OpenREL Provider Unreachable",
        "openrel-provider-unreachable",
        "The OpenREL provider could not be resolved or reached.",
    ),
    OpenRelErrorCode.CONNECTION_FAILURE: _MappedProblem(
        503,
        "OpenREL Provider Unreachable",
        "openrel-provider-unreachable",
        "The OpenREL provider could not be resolved or reached.",
    ),
    OpenRelErrorCode.TIMEOUT: _MappedProblem(
        504,
        "OpenREL Provider Timeout",
        "openrel-provider-timeout",
        "The OpenREL provider did not respond within the allowed time budget.",
    ),
    OpenRelErrorCode.PROVIDER_NOT_FOUND: _MappedProblem(
        404,
        "OpenREL Resource Not Found",
        "openrel-resource-not-found",
        "The requested OpenREL resource was not found upstream.",
    ),
    OpenRelErrorCode.PROVIDER_BAD_REQUEST: _MappedProblem(
        502,
        "OpenREL Provider Protocol Error",
        "openrel-provider-protocol-error",
        "The OpenREL provider rejected a facade-generated upstream request.",
    ),
    OpenRelErrorCode.PROVIDER_AUTH_FAILURE: _MappedProblem(
        502,
        "OpenREL Provider Authentication Failure",
        "openrel-provider-authentication-failure",
        "The OpenREL provider rejected upstream authentication.",
    ),
    OpenRelErrorCode.PROVIDER_RATE_LIMITED: _MappedProblem(
        503,
        "OpenREL Provider Rate Limited",
        "openrel-provider-rate-limited",
        "The OpenREL provider rate-limited this request.",
    ),
    OpenRelErrorCode.PROVIDER_UNAVAILABLE: _MappedProblem(
        503,
        "OpenREL Provider Unavailable",
        "openrel-provider-unavailable",
        "The OpenREL provider is temporarily unavailable.",
    ),
    OpenRelErrorCode.PROVIDER_ERROR: _MappedProblem(
        502,
        "OpenREL Provider Error",
        "openrel-provider-error",
        "The OpenREL provider returned an unexpected error.",
    ),
    OpenRelErrorCode.REDIRECT: _MappedProblem(
        502,
        "OpenREL Redirect Not Allowed",
        "openrel-redirect-not-allowed",
        "The OpenREL provider returned a redirect, which is not allowed.",
    ),
    OpenRelErrorCode.INVALID_CONTENT_TYPE: _MappedProblem(
        502,
        "OpenREL Content Type Invalid",
        "openrel-content-type-invalid",
        "The OpenREL provider returned an unsupported content type.",
    ),
    OpenRelErrorCode.MALFORMED_JSON: _MappedProblem(
        502,
        "OpenREL JSON Invalid",
        "openrel-json-invalid",
        "The OpenREL provider returned malformed JSON.",
    ),
    OpenRelErrorCode.DUPLICATE_JSON_KEY: _MappedProblem(
        502,
        "OpenREL JSON Duplicate Key",
        "openrel-json-duplicate-key",
        "The OpenREL provider returned JSON with duplicate object keys.",
    ),
    OpenRelErrorCode.OVERSIZED_RESPONSE: _MappedProblem(
        502,
        "OpenREL Response Too Large",
        "openrel-response-too-large",
        "The OpenREL provider response exceeded configured size limits.",
    ),
    OpenRelErrorCode.INVALID_RESPONSE_SHAPE: _MappedProblem(
        502,
        "OpenREL Response Shape Invalid",
        "openrel-response-shape-invalid",
        "The OpenREL provider response shape was not as expected.",
    ),
    OpenRelErrorCode.INVALID_RESPONSE_SCHEMA: _MappedProblem(
        502,
        "OpenREL Response Schema Invalid",
        "openrel-response-schema-invalid",
        "The OpenREL provider response failed schema validation.",
    ),
    OpenRelErrorCode.INTERNAL_ERROR: _MappedProblem(
        500,
        "OpenREL Facade Internal Error",
        "openrel-facade-internal-error",
        "An internal OpenREL facade error occurred.",
    ),
}

_INTERNAL_FALLBACK = _MappedProblem(
    500,
    "OpenREL Facade Internal Error",
    "openrel-facade-internal-error",
    "An internal OpenREL facade error occurred.",
)


def _bounded_retry_after_header(request: Request, raw_value: Any) -> str | None:
    settings: OpenRelSettings | None = getattr(request.app.state, "openrel_settings", None)
    if settings is None:
        return None
    cap_seconds = min(settings.retry_max_seconds, settings.total_timeout_seconds)
    if not math.isfinite(cap_seconds):
        return None
    cap = max(0, int(cap_seconds))

    if isinstance(raw_value, bool) or raw_value is None:
        return None

    numeric_value: float
    if isinstance(raw_value, int):
        numeric_value = float(raw_value)
    elif isinstance(raw_value, float):
        numeric_value = raw_value
    elif isinstance(raw_value, str):
        text = raw_value.strip()
        if not text:
            return None
        try:
            numeric_value = float(text)
        except ValueError:
            return None
    else:
        return None

    if not math.isfinite(numeric_value):
        return None
    if numeric_value < 0:
        return None
    if not numeric_value.is_integer():
        return None
    bounded = min(int(numeric_value), cap)
    return str(bounded)


def _problem_from_openrel_error(request: Request, error: OpenRelClientError) -> Response:
    mapped = _PROBLEM_MAP.get(error.code, _INTERNAL_FALLBACK)
    response = problem_response(
        status=mapped.status,
        title=mapped.title,
        detail=mapped.detail,
        type_uri=f"https://eosc-eden.eu/problems/{mapped.type_slug}",
        instance=str(request.url),
    )
    if error.code == OpenRelErrorCode.PROVIDER_RATE_LIMITED:
        retry_after = _bounded_retry_after_header(request, error.retry_after_seconds)
        if retry_after is not None:
            response.headers["Retry-After"] = retry_after
    return response


def _internal_problem(request: Request) -> Response:
    return problem_response(
        status=_INTERNAL_FALLBACK.status,
        title=_INTERNAL_FALLBACK.title,
        detail=_INTERNAL_FALLBACK.detail,
        type_uri=f"https://eosc-eden.eu/problems/{_INTERNAL_FALLBACK.type_slug}",
        instance=str(request.url),
    )


async def _list_resource(
    request: Request,
    client: OpenRelClientLike,
    family: OpenRelListFamily,
    *,
    prefix: str | None = None,
) -> list[OpenRELResource] | Response:
    try:
        return await client.list_resources(family=family, prefix=prefix)
    except OpenRelClientError as error:
        return _problem_from_openrel_error(request, error)
    except Exception:
        return _internal_problem(request)


async def _list_mappings(
    request: Request,
    client: OpenRelClientLike,
    *,
    prefix: str | None = None,
) -> list[OpenRELMapping] | Response:
    try:
        return await client.list_mappings(prefix=prefix)
    except OpenRelClientError as error:
        return _problem_from_openrel_error(request, error)
    except Exception:
        return _internal_problem(request)


async def _get_resource(
    request: Request,
    client: OpenRelClientLike,
    family: OpenRelDetailFamily,
    identifier: str,
    *,
    prefix: str | None = None,
) -> OpenRELResource | Response:
    try:
        return await client.get_resource(family=family, identifier=identifier, prefix=prefix)
    except OpenRelClientError as error:
        return _problem_from_openrel_error(request, error)
    except Exception:
        return _internal_problem(request)


def _openrel_description(subject: str, *, supports_prefix: bool, detail: bool) -> str:
    prefix_note = (
        "When provided, `prefix` is forwarded as an optional upstream OpenREL provider filter.\n\n"
        if supports_prefix
        else ""
    )
    identifier_note = (
        "The `id` value is proxied as an upstream identifier. Reserved characters must be percent-encoded by the caller. "
        "Opaque full-IRI transport remains best-effort and can depend on reverse-proxy path handling.\n\n"
        if detail
        else ""
    )
    return (
        f"Read-only proxy for OpenREL {subject} from the configured external provider.\n\n"
        "Returned data is external provider vocabulary/knowledge-base data. It is not an authoritative LFS "
        "licence or federation record. Provider availability impacts only OpenREL endpoints.\n\n"
        f"{prefix_note}{identifier_note}"
        "Successful responses are returned unwrapped in provider order after LFS contract validation."
    )


def _openrel_responses(*, include_bad_request: bool, include_not_found: bool) -> dict[int, dict[str, Any]]:
    responses: dict[int, dict[str, Any]] = {
        500: _problem_response_doc(
            "Unexpected internal OpenREL facade failure.",
            {
                "type": "https://eosc-eden.eu/problems/openrel-facade-internal-error",
                "title": "OpenREL Facade Internal Error",
                "status": 500,
                "detail": "An internal OpenREL facade error occurred.",
            },
        ),
        502: _problem_response_doc(
            "Upstream OpenREL provider protocol/content/destination failure.",
            {
                "type": "https://eosc-eden.eu/problems/openrel-provider-error",
                "title": "OpenREL Provider Error",
                "status": 502,
                "detail": "The OpenREL provider returned an unexpected error.",
            },
        ),
        503: _problem_response_doc(
            "OpenREL unavailable, unreachable, disabled, misconfigured, or rate-limited.",
            {
                "type": "https://eosc-eden.eu/problems/openrel-provider-unavailable",
                "title": "OpenREL Provider Unavailable",
                "status": 503,
                "detail": "The OpenREL provider is temporarily unavailable.",
            },
        ),
        504: _problem_response_doc(
            "OpenREL request exceeded the total facade timeout budget.",
            {
                "type": "https://eosc-eden.eu/problems/openrel-provider-timeout",
                "title": "OpenREL Provider Timeout",
                "status": 504,
                "detail": "The OpenREL provider did not respond within the allowed time budget.",
            },
        ),
    }
    if include_bad_request:
        responses[400] = _problem_response_doc(
            "The supplied OpenREL identifier or prefix is invalid.",
            {
                "type": "https://eosc-eden.eu/problems/openrel-invalid-identifier",
                "title": "Invalid OpenREL Identifier",
                "status": 400,
                "detail": "The supplied OpenREL identifier is invalid.",
            },
        )
    if include_not_found:
        responses[404] = _problem_response_doc(
            "No OpenREL detail resource matched the supplied identifier upstream.",
            {
                "type": "https://eosc-eden.eu/problems/openrel-resource-not-found",
                "title": "OpenREL Resource Not Found",
                "status": 404,
                "detail": "The requested OpenREL resource was not found upstream.",
            },
        )
    return responses


_ID_PARAM = ApiPath(
    ...,
    description=(
        "OpenREL resource identifier passed to the upstream provider. Reserved characters must be percent-encoded. "
        "Opaque full-IRI transport can depend on proxy path handling."
    ),
    examples=["odrl:use"],
)
_PREFIX_PARAM = Query(
    default=None,
    description="Optional OpenREL provider prefix filter forwarded upstream when supplied.",
    examples=["odrl"],
)


@router.get(
    "/actions",
    response_model=list[OpenRELResource],
    tags=["OpenREL"],
    summary="List Actions",
    description=_openrel_description("actions", supports_prefix=True, detail=False),
    operation_id="openrel_list_actions",
    response_description="List of OpenREL Action resources from the configured provider.",
    responses=_openrel_responses(include_bad_request=True, include_not_found=False),
)
async def list_actions(request: Request, prefix: str | None = _PREFIX_PARAM, client: OpenRelClientLike = Depends(get_openrel_client)):
    return await _list_resource(request, client, "actions", prefix=prefix)


@router.get(
    "/actions/{id:path}",
    response_model=OpenRELResource,
    tags=["OpenREL"],
    summary="Get Action",
    description=_openrel_description("action details", supports_prefix=True, detail=True),
    operation_id="openrel_get_action",
    response_description="OpenREL Action detail resource from the configured provider.",
    responses=_openrel_responses(include_bad_request=True, include_not_found=True),
)
async def get_action(
    request: Request,
    id: str = _ID_PARAM,
    prefix: str | None = _PREFIX_PARAM,
    client: OpenRelClientLike = Depends(get_openrel_client),
):
    return await _get_resource(request, client, "actions", id, prefix=prefix)


@router.get(
    "/constraints",
    response_model=list[OpenRELResource],
    tags=["OpenREL"],
    summary="List Constraint and Named Constraint Instances",
    description=_openrel_description("constraints", supports_prefix=False, detail=False),
    operation_id="openrel_list_constraints",
    response_description="List of OpenREL Constraint resources from the configured provider.",
    responses=_openrel_responses(include_bad_request=False, include_not_found=False),
)
async def list_constraints(request: Request, client: OpenRelClientLike = Depends(get_openrel_client)):
    return await _list_resource(request, client, "constraints")


@router.get(
    "/constraints/{id:path}",
    response_model=OpenRELResource,
    tags=["OpenREL"],
    summary="Get Constraint or Named Constraint",
    description=_openrel_description("constraint details", supports_prefix=False, detail=True),
    operation_id="openrel_get_constraint",
    response_description="OpenREL Constraint detail resource from the configured provider.",
    responses=_openrel_responses(include_bad_request=True, include_not_found=True),
)
async def get_constraint(request: Request, id: str = _ID_PARAM, client: OpenRelClientLike = Depends(get_openrel_client)):
    return await _get_resource(request, client, "constraints", id)


@router.get(
    "/leftoperands",
    response_model=list[OpenRELResource],
    tags=["OpenREL"],
    summary="List Left Operand Instances",
    description=_openrel_description("left operand instances", supports_prefix=False, detail=False),
    operation_id="openrel_list_left_operands",
    response_description="List of OpenREL Left Operand resources from the configured provider.",
    responses=_openrel_responses(include_bad_request=False, include_not_found=False),
)
async def list_left_operands(request: Request, client: OpenRelClientLike = Depends(get_openrel_client)):
    return await _list_resource(request, client, "leftoperands")


@router.get(
    "/leftoperands/{id:path}",
    response_model=OpenRELResource,
    tags=["OpenREL"],
    summary="Get Left Operand Instance",
    description=_openrel_description("left operand instance details", supports_prefix=False, detail=True),
    operation_id="openrel_get_left_operand",
    response_description="OpenREL Left Operand detail resource from the configured provider.",
    responses=_openrel_responses(include_bad_request=True, include_not_found=True),
)
async def get_left_operand(request: Request, id: str = _ID_PARAM, client: OpenRelClientLike = Depends(get_openrel_client)):
    return await _get_resource(request, client, "leftoperands", id)


@router.get(
    "/mappings",
    response_model=list[OpenRELMapping],
    tags=["OpenREL"],
    summary="List Mappings",
    description=_openrel_description("mappings", supports_prefix=True, detail=False),
    operation_id="openrel_list_mappings",
    response_description="List of OpenREL Mapping resources from the configured provider.",
    responses=_openrel_responses(include_bad_request=True, include_not_found=False),
)
async def list_mappings(request: Request, prefix: str | None = _PREFIX_PARAM, client: OpenRelClientLike = Depends(get_openrel_client)):
    return await _list_mappings(request, client, prefix=prefix)


@router.get(
    "/actionclasses",
    response_model=list[OpenRELResource],
    tags=["OpenREL"],
    summary="List Action Classes",
    description=_openrel_description("action classes", supports_prefix=True, detail=False),
    operation_id="openrel_list_action_classes",
    response_description="List of OpenREL Action Class resources from the configured provider.",
    responses=_openrel_responses(include_bad_request=True, include_not_found=False),
)
async def list_action_classes(request: Request, prefix: str | None = _PREFIX_PARAM, client: OpenRelClientLike = Depends(get_openrel_client)):
    return await _list_resource(request, client, "actionclasses", prefix=prefix)


@router.get(
    "/actionclasses/{id:path}",
    response_model=OpenRELResource,
    tags=["OpenREL"],
    summary="Get Action Class",
    description=_openrel_description("action class details", supports_prefix=True, detail=True),
    operation_id="openrel_get_action_class",
    response_description="OpenREL Action Class detail resource from the configured provider.",
    responses=_openrel_responses(include_bad_request=True, include_not_found=True),
)
async def get_action_class(
    request: Request,
    id: str = _ID_PARAM,
    prefix: str | None = _PREFIX_PARAM,
    client: OpenRelClientLike = Depends(get_openrel_client),
):
    return await _get_resource(request, client, "actionclasses", id, prefix=prefix)


@router.get(
    "/assetclasses",
    response_model=list[OpenRELResource],
    tags=["OpenREL"],
    summary="List Asset Classes",
    description=_openrel_description("asset classes", supports_prefix=True, detail=False),
    operation_id="openrel_list_asset_classes",
    response_description="List of OpenREL Asset Class resources from the configured provider.",
    responses=_openrel_responses(include_bad_request=True, include_not_found=False),
)
async def list_asset_classes(request: Request, prefix: str | None = _PREFIX_PARAM, client: OpenRelClientLike = Depends(get_openrel_client)):
    return await _list_resource(request, client, "assetclasses", prefix=prefix)


@router.get(
    "/assetclasses/{id:path}",
    response_model=OpenRELResource,
    tags=["OpenREL"],
    summary="Get Asset Class",
    description=_openrel_description("asset class details", supports_prefix=True, detail=True),
    operation_id="openrel_get_asset_class",
    response_description="OpenREL Asset Class detail resource from the configured provider.",
    responses=_openrel_responses(include_bad_request=True, include_not_found=True),
)
async def get_asset_class(
    request: Request,
    id: str = _ID_PARAM,
    prefix: str | None = _PREFIX_PARAM,
    client: OpenRelClientLike = Depends(get_openrel_client),
):
    return await _get_resource(request, client, "assetclasses", id, prefix=prefix)


@router.get(
    "/constraintclasses",
    response_model=list[OpenRELResource],
    tags=["OpenREL"],
    summary="List Constraint Classes",
    description=_openrel_description("constraint classes", supports_prefix=True, detail=False),
    operation_id="openrel_list_constraint_classes",
    response_description="List of OpenREL Constraint Class resources from the configured provider.",
    responses=_openrel_responses(include_bad_request=True, include_not_found=False),
)
async def list_constraint_classes(request: Request, prefix: str | None = _PREFIX_PARAM, client: OpenRelClientLike = Depends(get_openrel_client)):
    return await _list_resource(request, client, "constraintclasses", prefix=prefix)


@router.get(
    "/constraintclasses/{id:path}",
    response_model=OpenRELResource,
    tags=["OpenREL"],
    summary="Get Constraint Class",
    description=_openrel_description("constraint class details", supports_prefix=True, detail=True),
    operation_id="openrel_get_constraint_class",
    response_description="OpenREL Constraint Class detail resource from the configured provider.",
    responses=_openrel_responses(include_bad_request=True, include_not_found=True),
)
async def get_constraint_class(
    request: Request,
    id: str = _ID_PARAM,
    prefix: str | None = _PREFIX_PARAM,
    client: OpenRelClientLike = Depends(get_openrel_client),
):
    return await _get_resource(request, client, "constraintclasses", id, prefix=prefix)


@router.get(
    "/leftoperandclasses",
    response_model=list[OpenRELResource],
    tags=["OpenREL"],
    summary="List Left Operand Classes",
    description=_openrel_description("left operand classes", supports_prefix=True, detail=False),
    operation_id="openrel_list_left_operand_classes",
    response_description="List of OpenREL Left Operand Class resources from the configured provider.",
    responses=_openrel_responses(include_bad_request=True, include_not_found=False),
)
async def list_left_operand_classes(request: Request, prefix: str | None = _PREFIX_PARAM, client: OpenRelClientLike = Depends(get_openrel_client)):
    return await _list_resource(request, client, "leftoperandclasses", prefix=prefix)


@router.get(
    "/leftoperandclasses/{id:path}",
    response_model=OpenRELResource,
    tags=["OpenREL"],
    summary="Get Left Operand Class",
    description=_openrel_description("left operand class details", supports_prefix=True, detail=True),
    operation_id="openrel_get_left_operand_class",
    response_description="OpenREL Left Operand Class detail resource from the configured provider.",
    responses=_openrel_responses(include_bad_request=True, include_not_found=True),
)
async def get_left_operand_class(
    request: Request,
    id: str = _ID_PARAM,
    prefix: str | None = _PREFIX_PARAM,
    client: OpenRelClientLike = Depends(get_openrel_client),
):
    return await _get_resource(request, client, "leftoperandclasses", id, prefix=prefix)


@router.get(
    "/ruleclasses",
    response_model=list[OpenRELResource],
    tags=["OpenREL"],
    summary="List Rule Classes",
    description=_openrel_description("rule classes", supports_prefix=True, detail=False),
    operation_id="openrel_list_rule_classes",
    response_description="List of OpenREL Rule Class resources from the configured provider.",
    responses=_openrel_responses(include_bad_request=True, include_not_found=False),
)
async def list_rule_classes(request: Request, prefix: str | None = _PREFIX_PARAM, client: OpenRelClientLike = Depends(get_openrel_client)):
    return await _list_resource(request, client, "ruleclasses", prefix=prefix)


@router.get(
    "/ruleclasses/{id:path}",
    response_model=OpenRELResource,
    tags=["OpenREL"],
    summary="Get Rule Class",
    description=_openrel_description("rule class details", supports_prefix=True, detail=True),
    operation_id="openrel_get_rule_class",
    response_description="OpenREL Rule Class detail resource from the configured provider.",
    responses=_openrel_responses(include_bad_request=True, include_not_found=True),
)
async def get_rule_class(
    request: Request,
    id: str = _ID_PARAM,
    prefix: str | None = _PREFIX_PARAM,
    client: OpenRelClientLike = Depends(get_openrel_client),
):
    return await _get_resource(request, client, "ruleclasses", id, prefix=prefix)
