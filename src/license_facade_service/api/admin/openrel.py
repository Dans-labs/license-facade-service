from __future__ import annotations

import asyncio
from datetime import date, datetime
from typing import Any
from uuid import UUID

from contextlib import contextmanager

from fastapi import APIRouter, Body, Path, Query, Request, Security
from fastapi.responses import Response
from fastapi.security import HTTPAuthorizationCredentials
from pydantic import BaseModel, ConfigDict, Field, field_validator
from sqlalchemy import select

from src.license_facade_service.api.federation.admin import bearer_scheme
from src.license_facade_service.api.v1.licenses import get_auth_service
from src.license_facade_service.db.models.openrel_policy import OpenRelPolicyEvent, OpenRelPolicyState
from src.license_facade_service.federation.operational_models import CursorError, build_cursor, filters_hash, parse_cursor
from src.license_facade_service.runtime.openrel_policy import OpenRelPolicyRuntime
from src.license_facade_service.services.auth import AuthenticationError, AuthorizationError
from src.license_facade_service.services.custom_licence_federation_publication import CustomLicenceFederationPublicationError
from src.license_facade_service.services.openrel_application import (
    OpenRelApplicationConflictError,
    OpenRelApplicationService,
    OpenRelApplicationUnavailableError,
    OpenRelApplicationValidationError,
)
from src.license_facade_service.services.openrel_evaluation import (
    OpenRelEvaluationConfigurationError,
    OpenRelEvaluationCoordinator,
    OpenRelEvaluationError,
    OpenRelEvaluationInput,
)
from src.license_facade_service.services.openrel_policy import (
    OpenRelCandidate,
    OpenRelLicenceClassification,
    OpenRelPolicyAction,
    OpenRelPolicyMode,
    OpenRelPolicySettings,
)
from src.license_facade_service.services.openrel_policy_store import (
    OpenRelPolicyStore,
    OpenRelPolicyStoreCollisionError,
    OpenRelPolicyTransitionError,
    sanitize_review_reason,
)
from src.license_facade_service.services.problem import ProblemDetails, problem_response

router = APIRouter()
_VALID_SOURCE_KINDS = {"spdx", "custom", "federation-authoritative", "federation-imported"}
_VALID_STATUSES = {"planned", "pending-review", "approved", "applied", "rejected", "rolled-back", "failed"}
_VALID_ACTIONS = {"none", "full-replacement", "historical-mapping"}
_VALID_CLASSIFICATIONS = {"new", "historical"}
_DETAIL_MAX = 512


class OpenRelCandidateDto(BaseModel):
    model_config = ConfigDict(extra="forbid")

    provider_url: str = Field(alias="providerUrl", min_length=1, max_length=2048)
    profile: str = Field(min_length=1, max_length=1024)
    vocabulary: str = Field(min_length=1, max_length=1024)
    version: str = Field(min_length=1, max_length=128)
    content: str | None = Field(default=None, max_length=50_000)
    href: str | None = Field(default=None, max_length=2048)
    provenance: str | None = Field(default=None, max_length=2048)
    mapping_profile: str | None = Field(alias="mappingProfile", default=None, max_length=1024)
    mapping_provenance: str | None = Field(alias="mappingProvenance", default=None, max_length=2048)

    def to_model(self) -> OpenRelCandidate:
        return OpenRelCandidate(
            provider_url=self.provider_url.strip(),
            profile=self.profile.strip(),
            vocabulary=self.vocabulary.strip(),
            version=self.version.strip(),
            content=self.content,
            href=self.href,
            provenance=self.provenance,
            mapping_profile=self.mapping_profile,
            mapping_provenance=self.mapping_provenance,
        )


class OpenRelEvaluationRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    canonical_license_id: str = Field(alias="canonicalLicenseId", min_length=1, max_length=512)
    source_kind: str = Field(alias="sourceKind", min_length=1, max_length=32)
    source_record_ref: str | None = Field(alias="sourceRecordRef", default=None, max_length=512)
    registration_timestamp: date | datetime | None = Field(alias="registrationTimestamp", default=None)
    candidate_payload: dict[str, Any] = Field(alias="candidatePayload")
    candidate: OpenRelCandidateDto | None = None
    original_representation: dict[str, Any] | None = Field(alias="originalRepresentation", default=None)
    original_content_digest: str | None = Field(alias="originalContentDigest", default=None, max_length=64)

    @field_validator("source_kind")
    @classmethod
    def _validate_source_kind(cls, value: str) -> str:
        candidate = value.strip()
        if candidate not in _VALID_SOURCE_KINDS:
            raise ValueError("sourceKind is invalid.")
        return candidate


class OpenRelReviewRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    reason: str | None = Field(default=None, max_length=1024)

    @field_validator("reason")
    @classmethod
    def _trim_reason(cls, value: str | None) -> str | None:
        if value is None:
            return None
        trimmed = value.strip()
        return trimmed or None


class OpenRelApplicationResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

    policyStateId: UUID
    canonicalLicenseId: str
    status: str
    action: str
    sourceKind: str
    targetCustomLicenceId: UUID | None = None
    targetDigestBefore: str | None = None
    targetDigestAfter: str | None = None
    appliedAt: datetime | None = None
    rolledBackAt: datetime | None = None
    appliedBy: str | None = None
    rolledBackBy: str | None = None


class OpenRelPlanResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

    action: str
    classification: str
    policyVersion: str | None = None
    activeProfile: str | None = None
    activeVocabulary: str | None = None
    originalProfile: str | None = None
    mappingProfile: str | None = None
    mappingProvenance: str | None = None
    sourceProviderUrl: str | None = None
    applyAllowed: bool
    reviewRequired: bool
    reason: str


class OpenRelClassificationResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

    classification: str
    effectiveDate: date | None = None
    policyMode: str
    policyVersion: str | None = None
    classificationReason: str
    registrationTimestampTrusted: bool
    mutationAllowed: bool
    reviewRequired: bool


class OpenRelEvaluationResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

    classification: OpenRelClassificationResponse
    providerAvailable: bool
    policyPlan: OpenRelPlanResponse
    policyStateId: UUID | None = None
    persistedStatus: str | None = None
    candidateDigest: str | None = None
    reusedExistingState: bool
    reviewRequired: bool
    applicationMayBeAllowedLater: bool
    reasons: list[str]


class OpenRelPolicyStateSummaryResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

    id: UUID
    canonicalLicenseId: str
    sourceKind: str
    sourceRecordRef: str | None = None
    classification: str
    policyMode: str
    policyVersion: str
    action: str
    status: str
    providerUrl: str
    activeProfile: str | None = None
    activeVocabulary: str | None = None
    originalProfile: str | None = None
    mappingProfile: str | None = None
    mappingProvenance: str | None = None
    candidateDigest: str
    originalContentDigest: str | None = None
    applyAllowed: bool
    reviewRequired: bool
    reason: str
    createdAt: datetime
    updatedAt: datetime
    reviewedAt: datetime | None = None
    reviewedBy: str | None = None
    appliedAt: datetime | None = None
    rolledBackAt: datetime | None = None
    errorCode: str | None = None


class OpenRelPolicyStateListResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

    items: list[OpenRelPolicyStateSummaryResponse]
    nextCursor: str | None = None
    limit: int


class OpenRelPolicyEventResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

    id: UUID
    policyStateId: UUID
    eventType: str
    actorType: str
    actorId: str | None = None
    beforeStatus: str | None = None
    afterStatus: str | None = None
    details: dict[str, Any]
    occurredAt: datetime
    createdAt: datetime


class OpenRelPolicyEventListResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

    items: list[OpenRelPolicyEventResponse]
    nextCursor: str | None = None
    limit: int


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


def _auth_admin(request: Request) -> None:
    auth = get_auth_service()
    try:
        principal = auth.authenticate(request)
    except AuthenticationError as exc:
        raise _ApiProblem(401, "Unauthorized", "Missing or invalid bearer token.", "unauthorized") from exc
    try:
        auth.authorize(principal, {"admin"})
    except AuthorizationError as exc:
        raise _ApiProblem(403, "Forbidden", "Administrator role is required.", "forbidden") from exc


class _ApiProblem(Exception):
    def __init__(self, status: int, title: str, detail: str, code: str) -> None:
        super().__init__(detail)
        self.status = status
        self.title = title
        self.detail = detail
        self.code = code


def _problem(request: Request, problem: _ApiProblem) -> Response:
    return problem_response(
        status=problem.status,
        title=problem.title,
        detail=problem.detail,
        type_uri=f"https://eosc-eden.eu/problems/{problem.code}",
        instance=str(request.url),
    )


def _runtime(request: Request) -> OpenRelPolicyRuntime:
    runtime = getattr(request.app.state, "openrel_policy_runtime", None)
    if not isinstance(runtime, OpenRelPolicyRuntime):
        raise _ApiProblem(503, "OpenREL Policy Runtime Unavailable", "OpenREL policy runtime is unavailable.", "openrel-policy-unavailable")
    return runtime


def _runtime_state(request: Request):
    return getattr(request.app.state, "openrel_policy_state", None)


def _require_runtime_ready(request: Request, runtime: OpenRelPolicyRuntime) -> None:
    state = _runtime_state(request)
    if runtime.settings.mode == OpenRelPolicyMode.disabled and not runtime.settings.enabled:
        return
    if state is None or not getattr(state, "ready", False) or runtime.db is None or runtime.client is None:
        raise _ApiProblem(503, "OpenREL Policy Runtime Unavailable", "OpenREL policy runtime is unavailable.", "openrel-policy-unavailable")


@contextmanager
def _read_session(runtime: OpenRelPolicyRuntime):
    assert runtime.db is not None
    session = runtime.db.session_factory()
    try:
        yield session
    except Exception:
        session.rollback()
        raise
    finally:
        session.close()


def _classification_response(result) -> OpenRelClassificationResponse:
    return OpenRelClassificationResponse(
        classification=result.classification.value,
        effectiveDate=result.effective_date,
        policyMode=result.policy_mode.value,
        policyVersion=result.policy_version,
        classificationReason=result.classification_reason,
        registrationTimestampTrusted=result.registration_timestamp_trusted,
        mutationAllowed=result.mutation_allowed,
        reviewRequired=result.review_required,
    )


def _plan_response(plan) -> OpenRelPlanResponse:
    return OpenRelPlanResponse(
        action=plan.action.value,
        classification=plan.classification.value,
        policyVersion=plan.policy_version,
        activeProfile=plan.active_profile,
        activeVocabulary=plan.active_vocabulary,
        originalProfile=plan.original_profile,
        mappingProfile=plan.mapping_profile,
        mappingProvenance=_truncate(plan.mapping_provenance),
        sourceProviderUrl=plan.source_provider_url,
        applyAllowed=plan.apply_allowed,
        reviewRequired=plan.review_required,
        reason=_truncate(plan.reason),
    )


def _state_response(state: OpenRelPolicyState) -> OpenRelPolicyStateSummaryResponse:
    return OpenRelPolicyStateSummaryResponse(
        id=state.id,
        canonicalLicenseId=state.canonical_license_id,
        sourceKind=state.source_kind,
        sourceRecordRef=state.source_record_ref,
        classification=state.classification,
        policyMode=state.policy_mode,
        policyVersion=state.policy_version,
        action=state.action,
        status=state.status,
        providerUrl=state.provider_url,
        activeProfile=state.active_profile,
        activeVocabulary=state.active_vocabulary,
        originalProfile=state.original_profile,
        mappingProfile=state.mapping_profile,
        mappingProvenance=_truncate(state.mapping_provenance),
        candidateDigest=state.candidate_digest_sha256,
        originalContentDigest=state.original_content_digest_sha256,
        applyAllowed=bool(state.apply_allowed),
        reviewRequired=bool(state.review_required),
        reason=_truncate(state.reason),
        createdAt=state.created_at,
        updatedAt=state.updated_at,
        reviewedAt=state.reviewed_at,
        reviewedBy=state.reviewed_by,
        appliedAt=state.applied_at,
        rolledBackAt=state.rolled_back_at,
        errorCode=state.error_code,
    )


def _event_response(event: OpenRelPolicyEvent) -> OpenRelPolicyEventResponse:
    return OpenRelPolicyEventResponse(
        id=event.id,
        policyStateId=event.policy_state_id,
        eventType=event.event_type,
        actorType=event.actor_type,
        actorId=event.actor_id,
        beforeStatus=event.before_status,
        afterStatus=event.after_status,
        details=_safe_event_details(event.details),
        occurredAt=event.occurred_at,
        createdAt=event.created_at,
    )


def _truncate(value: str | None) -> str | None:
    if value is None:
        return None
    return value[:_DETAIL_MAX]


def _safe_event_details(details: Any) -> dict[str, Any]:
    if not isinstance(details, dict):
        return {}
    allowed = {"policy_mode", "policy_version", "action", "requested_action", "classification", "status", "source_kind", "apply_allowed", "review_required", "active_profile", "active_vocabulary", "original_profile", "mapping_profile", "reviewer_identity", "review_reason", "error_code"}
    safe: dict[str, Any] = {}
    for key in allowed:
        if key not in details:
            continue
        value = details[key]
        if isinstance(value, (str, bool, int, float)) or value is None:
            safe[key] = _truncate(value) if isinstance(value, str) else value
    return safe


def _state_filters_hash(*, canonical_license_id: str | None, source_kind: str | None, status: str | None, action: str | None, classification: str | None, review_required: bool | None) -> str:
    return filters_hash("openrel-policy-states", canonical_license_id, source_kind, status, action, classification, review_required)


def _event_filters_hash(*, state_id: UUID) -> str:
    return filters_hash("openrel-policy-events", str(state_id))


def _cursor_secret(request: Request) -> bytes:
    runtime = _runtime(request)
    secret = runtime.settings.admin_cursor_secret
    if not secret:
        raise _ApiProblem(503, "OpenREL Policy Runtime Unavailable", "OpenREL policy runtime is unavailable.", "openrel-policy-unavailable")
    return secret.encode("utf-8")


def _admin_actor() -> tuple[str, str]:
    return "admin", "admin"


def _application_response(state: OpenRelPolicyState) -> OpenRelApplicationResponse:
    return OpenRelApplicationResponse(
        policyStateId=state.id,
        canonicalLicenseId=state.canonical_license_id,
        status=state.status,
        action=state.action,
        sourceKind=state.source_kind,
        targetCustomLicenceId=state.target_custom_licence_id,
        targetDigestBefore=state.target_digest_before,
        targetDigestAfter=state.target_digest_after,
        appliedAt=state.applied_at,
        rolledBackAt=state.rolled_back_at,
        appliedBy=state.applied_by,
        rolledBackBy=state.rolled_back_by,
    )


def _problem_from_exception(request: Request, exc: Exception) -> Response:
    if isinstance(exc, _ApiProblem):
        return _problem(request, exc)
    if isinstance(exc, (OpenRelEvaluationError, OpenRelEvaluationConfigurationError)):
        return problem_response(
            status=422,
            title="Validation Error",
            detail=str(exc),
            instance=str(request.url),
            type_uri="https://eosc-eden.eu/problems/validation-error",
        )
    if isinstance(exc, OpenRelPolicyStoreCollisionError):
        return problem_response(
            status=409,
            title="Conflict",
            detail="OpenREL policy state conflicted with an existing materially different state.",
            instance=str(request.url),
            type_uri="https://eosc-eden.eu/problems/openrel-policy-conflict",
        )
    if isinstance(exc, OpenRelPolicyTransitionError):
        detail = "OpenREL policy state was not found." if "not found" in str(exc) else str(exc)
        status = 404 if "not found" in str(exc) else 409
        code = "openrel-policy-state-not-found" if status == 404 else "openrel-policy-transition-conflict"
        title = "Not Found" if status == 404 else "Conflict"
        return problem_response(
            status=status,
            title=title,
            detail=detail,
            instance=str(request.url),
            type_uri=f"https://eosc-eden.eu/problems/{code}",
        )
    if isinstance(exc, OpenRelApplicationValidationError):
        return problem_response(
            status=409,
            title="Conflict",
            detail="OpenREL application request conflicted with persisted policy state.",
            instance=str(request.url),
            type_uri="https://eosc-eden.eu/problems/openrel-policy-application-conflict",
        )
    if isinstance(exc, OpenRelApplicationUnavailableError):
        return problem_response(
            status=503,
            title="Service Unavailable",
            detail="Required federated publication dependency is unavailable.",
            instance=str(request.url),
            type_uri="https://eosc-eden.eu/problems/openrel-policy-unavailable",
        )
    if isinstance(exc, OpenRelApplicationConflictError):
        detail = "OpenREL policy state or target was not found." if "not found" in str(exc).lower() else "OpenREL application request conflicted with persisted policy state."
        status = 404 if "not found" in str(exc).lower() else 409
        code = "openrel-policy-state-not-found" if status == 404 else "openrel-policy-application-conflict"
        title = "Not Found" if status == 404 else "Conflict"
        return problem_response(
            status=status,
            title=title,
            detail=detail,
            instance=str(request.url),
            type_uri=f"https://eosc-eden.eu/problems/{code}",
        )
    if isinstance(exc, CustomLicenceFederationPublicationError):
        return problem_response(
            status=503,
            title="Service Unavailable",
            detail="Federated publication runtime is unavailable.",
            instance=str(request.url),
            type_uri="https://eosc-eden.eu/problems/openrel-policy-unavailable",
        )
    return problem_response(
        status=500,
        title="Internal Server Error",
        detail="An internal OpenREL administration error occurred.",
        instance=str(request.url),
        type_uri="https://eosc-eden.eu/problems/openrel-admin-internal-error",
    )


@router.post(
    "/api/v1/admin/openrel/evaluations",
    response_model=OpenRelEvaluationResponse,
    tags=["OpenREL Admin"],
    summary="Evaluate an externally supplied OpenREL candidate",
    description=(
        "Evaluates an externally supplied OpenREL candidate against the configured policy and persists a plan.\n\n"
        "Requires an admin bearer token. This endpoint does not ask OpenREL to transform a licence and does not mutate a licence. "
        "Disabled mode is inert and may return no policy-state identifier."
    ),
    responses={
        401: _problem_response_doc("Missing or invalid bearer token.", {"type": "https://eosc-eden.eu/problems/unauthorized", "title": "Unauthorized", "status": 401, "detail": "Missing or invalid bearer token."}),
        403: _problem_response_doc("Authenticated principal lacks admin permission.", {"type": "https://eosc-eden.eu/problems/forbidden", "title": "Forbidden", "status": 403, "detail": "Administrator role is required."}),
        422: _problem_response_doc("Request validation failed.", {"type": "https://eosc-eden.eu/problems/validation-error", "title": "Validation Error", "status": 422, "detail": "Request validation failed."}),
        503: _problem_response_doc("Runtime, database, or provider is unavailable.", {"type": "https://eosc-eden.eu/problems/openrel-policy-unavailable", "title": "OpenREL Policy Runtime Unavailable", "status": 503, "detail": "OpenREL policy runtime is unavailable."}),
        409: _problem_response_doc("A conflicting materially different state already exists.", {"type": "https://eosc-eden.eu/problems/openrel-policy-conflict", "title": "Conflict", "status": 409, "detail": "OpenREL policy state conflicted with an existing materially different state."}),
    },
)
def create_evaluation(
    request: Request,
    payload: OpenRelEvaluationRequest = Body(description="Externally supplied OpenREL candidate and local evaluation context."),
    _token: HTTPAuthorizationCredentials | None = Security(bearer_scheme),
):
    try:
        _auth_admin(request)
        runtime = _runtime(request)
        if runtime.settings.mode == OpenRelPolicyMode.disabled and not runtime.settings.enabled:
            coordinator = OpenRelEvaluationCoordinator(runtime.settings, client=None, policy_store=OpenRelPolicyStore(_InertSession()))
            result = coordinator.evaluate(
                OpenRelEvaluationInput(
                    canonical_license_id=payload.canonical_license_id,
                    source_kind=payload.source_kind,
                    source_record_ref=payload.source_record_ref,
                    registration_timestamp=payload.registration_timestamp,
                    candidate_payload=payload.candidate_payload,
                    candidate=payload.candidate.to_model() if payload.candidate else None,
                    original_representation=payload.original_representation,
                    original_content_digest=payload.original_content_digest,
                    actor_type="admin",
                    actor_id="admin",
                )
            )
        else:
            _require_runtime_ready(request, runtime)
            assert runtime.db is not None
            assert runtime.client is not None
            with runtime.db.transaction() as session:
                store = OpenRelPolicyStore(session)
                coordinator = OpenRelEvaluationCoordinator(runtime.settings, client=runtime.client, policy_store=store)
                result = coordinator.evaluate(
                    OpenRelEvaluationInput(
                        canonical_license_id=payload.canonical_license_id,
                        source_kind=payload.source_kind,
                        source_record_ref=payload.source_record_ref,
                        registration_timestamp=payload.registration_timestamp,
                        candidate_payload=payload.candidate_payload,
                        candidate=payload.candidate.to_model() if payload.candidate else None,
                        original_representation=payload.original_representation,
                        original_content_digest=payload.original_content_digest,
                        actor_type="admin",
                        actor_id="admin",
                    )
                )
        return OpenRelEvaluationResponse(
            classification=_classification_response(result.classification),
            providerAvailable=result.provider_available,
            policyPlan=_plan_response(result.policy_plan),
            policyStateId=result.policy_state_id,
            persistedStatus=result.persisted_status,
            candidateDigest=result.candidate_digest,
            reusedExistingState=result.reused_existing_state,
            reviewRequired=result.review_required,
            applicationMayBeAllowedLater=result.application_may_be_allowed_later,
            reasons=[_truncate(reason) or "" for reason in result.reasons],
        )
    except Exception as exc:
        return _problem_from_exception(request, exc)


class _InertSession:
    def query(self, model):
        raise AssertionError("disabled mode must not query policy store")


@router.get(
    "/api/v1/admin/openrel/policy-states",
    response_model=OpenRelPolicyStateListResponse,
    tags=["OpenREL Admin"],
    summary="List persisted OpenREL policy states",
    description=(
        "Lists persisted OpenREL policy states for administrative review.\n\n"
        "Requires an admin bearer token and uses signed keyset pagination bound to the active filters.\n\n"
        "Responses exclude candidate payloads, original representations, and other sensitive raw persistence fields."
    ),
    responses={
        400: _problem_response_doc("Cursor is invalid, tampered, or mismatched.", {"type": "https://eosc-eden.eu/problems/invalid-cursor", "title": "Invalid Cursor", "status": 400, "detail": "Pagination cursor is invalid or does not match this request."}),
        401: _problem_response_doc("Missing or invalid bearer token.", {"type": "https://eosc-eden.eu/problems/unauthorized", "title": "Unauthorized", "status": 401, "detail": "Missing or invalid bearer token."}),
        403: _problem_response_doc("Authenticated principal lacks admin permission.", {"type": "https://eosc-eden.eu/problems/forbidden", "title": "Forbidden", "status": 403, "detail": "Administrator role is required."}),
        503: _problem_response_doc("Runtime or database is unavailable.", {"type": "https://eosc-eden.eu/problems/openrel-policy-unavailable", "title": "OpenREL Policy Runtime Unavailable", "status": 503, "detail": "OpenREL policy runtime is unavailable."}),
    },
)
def list_policy_states(
    request: Request,
    canonical_license_id: str | None = Query(default=None, alias="canonicalLicenseId", max_length=512),
    source_kind: str | None = Query(default=None, alias="sourceKind"),
    status: str | None = Query(default=None),
    action: str | None = Query(default=None),
    classification: str | None = Query(default=None),
    review_required: bool | None = Query(default=None, alias="reviewRequired"),
    limit: int = Query(default=50, ge=1, le=100),
    cursor: str | None = Query(default=None),
    _token: HTTPAuthorizationCredentials | None = Security(bearer_scheme),
):
    try:
        _auth_admin(request)
        runtime = _runtime(request)
        _require_runtime_ready(request, runtime)
        if source_kind is not None and source_kind not in _VALID_SOURCE_KINDS:
            raise OpenRelEvaluationError("sourceKind is invalid.")
        if status is not None and status not in _VALID_STATUSES:
            raise OpenRelEvaluationError("status is invalid.")
        if action is not None and action not in _VALID_ACTIONS:
            raise OpenRelEvaluationError("action is invalid.")
        if classification is not None and classification not in _VALID_CLASSIFICATIONS:
            raise OpenRelEvaluationError("classification is invalid.")
        fh = _state_filters_hash(
            canonical_license_id=canonical_license_id,
            source_kind=source_kind,
            status=status,
            action=action,
            classification=classification,
            review_required=review_required,
        )
        cursor_claims = None
        if cursor:
            try:
                cursor_claims = parse_cursor(cursor, "openrel-policy-states", fh, expected_limit=limit, secret=_cursor_secret(request))
            except CursorError as exc:
                raise _ApiProblem(400, "Invalid Cursor", "Pagination cursor is invalid or does not match this request.", "invalid-cursor") from exc
        assert runtime.db is not None
        with _read_session(runtime) as session:
            stmt = select(OpenRelPolicyState)
            if canonical_license_id is not None:
                stmt = stmt.where(OpenRelPolicyState.canonical_license_id == canonical_license_id.strip())
            if source_kind is not None:
                stmt = stmt.where(OpenRelPolicyState.source_kind == source_kind)
            if status is not None:
                stmt = stmt.where(OpenRelPolicyState.status == status)
            if action is not None:
                stmt = stmt.where(OpenRelPolicyState.action == action)
            if classification is not None:
                stmt = stmt.where(OpenRelPolicyState.classification == classification)
            if review_required is not None:
                stmt = stmt.where(OpenRelPolicyState.review_required == review_required)
            if cursor_claims is not None:
                stmt = stmt.where(
                    (OpenRelPolicyState.created_at < cursor_claims.ts)
                    | ((OpenRelPolicyState.created_at == cursor_claims.ts) & (OpenRelPolicyState.id < cursor_claims.id))
                )
            stmt = stmt.order_by(OpenRelPolicyState.created_at.desc(), OpenRelPolicyState.id.desc()).limit(limit + 1)
            rows = list(session.execute(stmt).scalars().all())
        next_cursor = None
        if len(rows) > limit:
            last = rows[limit - 1]
            next_cursor = build_cursor("openrel-policy-states", fh, last.created_at, last.id, limit=limit, secret=_cursor_secret(request))
            rows = rows[:limit]
        return OpenRelPolicyStateListResponse(items=[_state_response(row) for row in rows], nextCursor=next_cursor, limit=limit)
    except Exception as exc:
        return _problem_from_exception(request, exc)


@router.get(
    "/api/v1/admin/openrel/policy-states/{state_id}",
    response_model=OpenRelPolicyStateSummaryResponse,
    tags=["OpenREL Admin"],
    summary="Get one persisted OpenREL policy state",
    description=(
        "Returns one persisted OpenREL policy state for administrative inspection.\n\n"
        "Requires an admin bearer token.\n\n"
        "The response excludes candidate payloads, original representations, and other sensitive raw persistence fields."
    ),
    responses={
        401: _problem_response_doc("Missing or invalid bearer token.", {"type": "https://eosc-eden.eu/problems/unauthorized", "title": "Unauthorized", "status": 401, "detail": "Missing or invalid bearer token."}),
        403: _problem_response_doc("Authenticated principal lacks admin permission.", {"type": "https://eosc-eden.eu/problems/forbidden", "title": "Forbidden", "status": 403, "detail": "Administrator role is required."}),
        404: _problem_response_doc("Policy state was not found.", {"type": "https://eosc-eden.eu/problems/openrel-policy-state-not-found", "title": "Not Found", "status": 404, "detail": "OpenREL policy state was not found."}),
    },
)
def get_policy_state(
    request: Request,
    state_id: UUID = Path(...),
    _token: HTTPAuthorizationCredentials | None = Security(bearer_scheme),
):
    try:
        _auth_admin(request)
        runtime = _runtime(request)
        _require_runtime_ready(request, runtime)
        assert runtime.db is not None
        with _read_session(runtime) as session:
            state = OpenRelPolicyStore(session).get_state(state_id)
            if state is None:
                raise OpenRelPolicyTransitionError("state not found")
            return _state_response(state)
    except Exception as exc:
        return _problem_from_exception(request, exc)


@router.get(
    "/api/v1/admin/openrel/policy-states/{state_id}/events",
    response_model=OpenRelPolicyEventListResponse,
    tags=["OpenREL Admin"],
    summary="List append-only audit events for one policy state",
    description=(
        "Lists sanitized append-only audit history for one OpenREL policy state.\n\n"
        "Requires an admin bearer token and uses signed keyset pagination scoped to the selected state.\n\n"
        "Only allow-listed audit details are exposed; arbitrary JSONB event content is not returned."
    ),
    responses={
        400: _problem_response_doc("Cursor is invalid, tampered, or mismatched.", {"type": "https://eosc-eden.eu/problems/invalid-cursor", "title": "Invalid Cursor", "status": 400, "detail": "Pagination cursor is invalid or does not match this request."}),
        404: _problem_response_doc("Policy state was not found.", {"type": "https://eosc-eden.eu/problems/openrel-policy-state-not-found", "title": "Not Found", "status": 404, "detail": "OpenREL policy state was not found."}),
    },
)
def list_policy_state_events(
    request: Request,
    state_id: UUID = Path(...),
    limit: int = Query(default=50, ge=1, le=100),
    cursor: str | None = Query(default=None),
    _token: HTTPAuthorizationCredentials | None = Security(bearer_scheme),
):
    try:
        _auth_admin(request)
        runtime = _runtime(request)
        _require_runtime_ready(request, runtime)
        fh = _event_filters_hash(state_id=state_id)
        cursor_claims = None
        if cursor:
            try:
                cursor_claims = parse_cursor(cursor, "openrel-policy-events", fh, expected_limit=limit, secret=_cursor_secret(request))
            except CursorError as exc:
                raise _ApiProblem(400, "Invalid Cursor", "Pagination cursor is invalid or does not match this request.", "invalid-cursor") from exc
        assert runtime.db is not None
        with _read_session(runtime) as session:
            state = OpenRelPolicyStore(session).get_state(state_id)
            if state is None:
                raise OpenRelPolicyTransitionError("state not found")
            stmt = select(OpenRelPolicyEvent).where(OpenRelPolicyEvent.policy_state_id == state_id)
            if cursor_claims is not None:
                stmt = stmt.where(
                    (OpenRelPolicyEvent.occurred_at > cursor_claims.ts)
                    | ((OpenRelPolicyEvent.occurred_at == cursor_claims.ts) & (OpenRelPolicyEvent.id > cursor_claims.id))
                )
            stmt = stmt.order_by(OpenRelPolicyEvent.occurred_at.asc(), OpenRelPolicyEvent.id.asc()).limit(limit + 1)
            rows = list(session.execute(stmt).scalars().all())
        next_cursor = None
        if len(rows) > limit:
            last = rows[limit - 1]
            next_cursor = build_cursor("openrel-policy-events", fh, last.occurred_at, last.id, limit=limit, secret=_cursor_secret(request))
            rows = rows[:limit]
        return OpenRelPolicyEventListResponse(items=[_event_response(row) for row in rows], nextCursor=next_cursor, limit=limit)
    except Exception as exc:
        return _problem_from_exception(request, exc)


def _review_transition(request: Request, state_id: UUID, new_status: str, payload: OpenRelReviewRequest) -> OpenRelPolicyStateSummaryResponse | Response:
    try:
        _auth_admin(request)
        runtime = _runtime(request)
        _require_runtime_ready(request, runtime)
        assert runtime.db is not None
        actor_type, actor_id = _admin_actor()
        with runtime.db.transaction() as session:
            state = OpenRelPolicyStore(session).transition_status(
                state_id,
                new_status=new_status,
                actor_type=actor_type,
                actor_id=actor_id,
                reviewer_identity="admin",
                review_reason=payload.reason.strip() if payload.reason else None,
            )
            return _state_response(state)
    except Exception as exc:
        return _problem_from_exception(request, exc)


def _application_service(request: Request, session) -> OpenRelApplicationService:
    federation_runtime = getattr(request.app.state, "federation_runtime", None)
    federation_state = getattr(request.app.state, "federation_state", None)
    publisher = None
    if federation_runtime is not None and getattr(federation_state, "ready", False):
        publisher = getattr(federation_runtime, "publisher", None)
    return OpenRelApplicationService(
        session,
        federation_publisher=publisher,
        federation_custom_settings=getattr(request.app.state, "custom_licence_registration_settings", None),
    )


def _mutate_policy_state(
    request: Request,
    state_id: UUID,
    payload: OpenRelReviewRequest,
    *,
    operation: str,
) -> OpenRelApplicationResponse | Response:
    try:
        _auth_admin(request)
        runtime = _runtime(request)
        _require_runtime_ready(request, runtime)
        assert runtime.db is not None
        _actor_type, actor_id = _admin_actor()
        reason = sanitize_review_reason(payload.reason)
        with runtime.db.transaction() as session:
            service = _application_service(request, session)
            if operation == "apply":
                state = service.apply(state_id, actor_id=actor_id, reason=reason)
            else:
                state = service.rollback(state_id, actor_id=actor_id, reason=reason)
            return _application_response(state)
    except Exception as exc:
        return _problem_from_exception(request, exc)


@router.post(
    "/api/v1/admin/openrel/policy-states/{state_id}/approve",
    response_model=OpenRelPolicyStateSummaryResponse,
    tags=["OpenREL Admin"],
    summary="Approve a pending OpenREL policy state review",
    description=(
        "Approves a pending-review OpenREL policy state.\n\n"
        "Requires an admin bearer token. The authenticated admin role is recorded as the reviewer and audit actor.\n\n"
        "Approval records review state only, does not apply a licence change, and returns a sanitized state view."
    ),
    responses={
        404: _problem_response_doc("Policy state was not found.", {"type": "https://eosc-eden.eu/problems/openrel-policy-state-not-found", "title": "Not Found", "status": 404, "detail": "OpenREL policy state was not found."}),
        409: _problem_response_doc("The policy state cannot be approved in its current status.", {"type": "https://eosc-eden.eu/problems/openrel-policy-transition-conflict", "title": "Conflict", "status": 409, "detail": "unsupported transition: planned -> approved"}),
    },
)
def approve_policy_state(
    request: Request,
    state_id: UUID = Path(...),
    payload: OpenRelReviewRequest = Body(default_factory=OpenRelReviewRequest),
    _token: HTTPAuthorizationCredentials | None = Security(bearer_scheme),
):
    return _review_transition(request, state_id, "approved", payload)


@router.post(
    "/api/v1/admin/openrel/policy-states/{state_id}/reject",
    response_model=OpenRelPolicyStateSummaryResponse,
    tags=["OpenREL Admin"],
    summary="Reject a pending OpenREL policy state review",
    description=(
        "Rejects a pending-review OpenREL policy state.\n\n"
        "Requires an admin bearer token. The authenticated admin role is recorded as the reviewer and audit actor.\n\n"
        "Rejection records review state only, does not apply a licence change, and returns a sanitized state view."
    ),
    responses={
        404: _problem_response_doc("Policy state was not found.", {"type": "https://eosc-eden.eu/problems/openrel-policy-state-not-found", "title": "Not Found", "status": 404, "detail": "OpenREL policy state was not found."}),
        409: _problem_response_doc("The policy state cannot be rejected in its current status.", {"type": "https://eosc-eden.eu/problems/openrel-policy-transition-conflict", "title": "Conflict", "status": 409, "detail": "unsupported transition: planned -> rejected"}),
    },
)
def reject_policy_state(
    request: Request,
    state_id: UUID = Path(...),
    payload: OpenRelReviewRequest = Body(default_factory=OpenRelReviewRequest),
    _token: HTTPAuthorizationCredentials | None = Security(bearer_scheme),
):
    return _review_transition(request, state_id, "rejected", payload)


@router.post(
    "/api/v1/admin/openrel/policy-states/{state_id}/apply",
    response_model=OpenRelApplicationResponse,
    tags=["OpenREL Admin"],
    summary="Apply a persisted approved OpenREL policy state",
    description=(
        "Applies a persisted approved OpenREL policy state using only stored candidate and target linkage data.\n\n"
        "Requires an admin bearer token. The request body accepts only an optional reason; it does not accept candidate content, digests, mappings, target identifiers, actor identity, status, or idempotency keys.\n\n"
        "Local targets mutate only local state. Published federated targets atomically append a federation revision and enqueue asynchronous RDF work without synchronous OpenREL or Fuseki calls. Exact retries return 200 without duplicating effects."
    ),
    responses={
        401: _problem_response_doc("Missing or invalid bearer token.", {"type": "https://eosc-eden.eu/problems/unauthorized", "title": "Unauthorized", "status": 401, "detail": "Missing or invalid bearer token."}),
        403: _problem_response_doc("Authenticated principal lacks admin permission.", {"type": "https://eosc-eden.eu/problems/forbidden", "title": "Forbidden", "status": 403, "detail": "Administrator role is required."}),
        404: _problem_response_doc("Policy state or persisted target was not found.", {"type": "https://eosc-eden.eu/problems/openrel-policy-state-not-found", "title": "Not Found", "status": 404, "detail": "OpenREL policy state or target was not found."}),
        409: _problem_response_doc("The persisted state cannot be applied safely.", {"type": "https://eosc-eden.eu/problems/openrel-policy-application-conflict", "title": "Conflict", "status": 409, "detail": "OpenREL application request conflicted with persisted policy state."}),
        422: _problem_response_doc("Request validation failed.", {"type": "https://eosc-eden.eu/problems/validation-error", "title": "Validation Error", "status": 422, "detail": "Request validation failed."}),
        503: _problem_response_doc("Required runtime or federated publication dependency is unavailable.", {"type": "https://eosc-eden.eu/problems/openrel-policy-unavailable", "title": "Service Unavailable", "status": 503, "detail": "Federated publication runtime is unavailable."}),
    },
)
def apply_policy_state(
    request: Request,
    state_id: UUID = Path(...),
    payload: OpenRelReviewRequest = Body(default_factory=OpenRelReviewRequest, description="Optional sanitized admin reason only."),
    _token: HTTPAuthorizationCredentials | None = Security(bearer_scheme),
):
    return _mutate_policy_state(request, state_id, payload, operation="apply")


@router.post(
    "/api/v1/admin/openrel/policy-states/{state_id}/rollback",
    response_model=OpenRelApplicationResponse,
    tags=["OpenREL Admin"],
    summary="Rollback a persisted applied OpenREL policy state",
    description=(
        "Rolls back a persisted applied OpenREL policy state using only the stored verified pre-apply snapshot.\n\n"
        "Requires an admin bearer token. The request body accepts only an optional reason; it does not accept candidate content, digests, mappings, target identifiers, actor identity, status, or idempotency keys.\n\n"
        "Published federated targets atomically append a restoring federation revision and enqueue asynchronous RDF work without synchronous OpenREL or Fuseki calls. Exact retries return 200 without duplicating effects."
    ),
    responses={
        401: _problem_response_doc("Missing or invalid bearer token.", {"type": "https://eosc-eden.eu/problems/unauthorized", "title": "Unauthorized", "status": 401, "detail": "Missing or invalid bearer token."}),
        403: _problem_response_doc("Authenticated principal lacks admin permission.", {"type": "https://eosc-eden.eu/problems/forbidden", "title": "Forbidden", "status": 403, "detail": "Administrator role is required."}),
        404: _problem_response_doc("Policy state or persisted target was not found.", {"type": "https://eosc-eden.eu/problems/openrel-policy-state-not-found", "title": "Not Found", "status": 404, "detail": "OpenREL policy state or target was not found."}),
        409: _problem_response_doc("The persisted state cannot be rolled back safely.", {"type": "https://eosc-eden.eu/problems/openrel-policy-application-conflict", "title": "Conflict", "status": 409, "detail": "OpenREL application request conflicted with persisted policy state."}),
        422: _problem_response_doc("Request validation failed.", {"type": "https://eosc-eden.eu/problems/validation-error", "title": "Validation Error", "status": 422, "detail": "Request validation failed."}),
        503: _problem_response_doc("Required runtime or federated publication dependency is unavailable.", {"type": "https://eosc-eden.eu/problems/openrel-policy-unavailable", "title": "Service Unavailable", "status": 503, "detail": "Federated publication runtime is unavailable."}),
    },
)
def rollback_policy_state(
    request: Request,
    state_id: UUID = Path(...),
    payload: OpenRelReviewRequest = Body(default_factory=OpenRelReviewRequest, description="Optional sanitized admin reason only."),
    _token: HTTPAuthorizationCredentials | None = Security(bearer_scheme),
):
    return _mutate_policy_state(request, state_id, payload, operation="rollback")


__all__ = ["router"]
