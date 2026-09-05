from __future__ import annotations

from dataclasses import dataclass
from datetime import date, datetime
from typing import Any, Protocol
from uuid import UUID

from src.license_facade_service.services.openrel_client import OpenRelClientError
from src.license_facade_service.services.openrel_policy import (
    OpenRelCandidate,
    OpenRelLicenceClassification,
    OpenRelPolicyAction,
    OpenRelLicenceClassificationResult,
    OpenRelPolicyPlan,
    OpenRelPolicyMode,
    OpenRelPolicySettings,
    classify_licence_record,
    build_openrel_policy_plan,
)
from src.license_facade_service.services.openrel_policy_store import (
    OpenRelPolicyStore,
    compute_candidate_digest,
)
from src.license_facade_service.db.models.openrel_policy import OpenRelPolicyState


class OpenRelEvaluationError(ValueError):
    pass


class OpenRelEvaluationConfigurationError(OpenRelEvaluationError):
    pass


@dataclass(frozen=True)
class OpenRelEvaluationInput:
    canonical_license_id: str
    source_kind: str
    source_record_ref: str | None
    registration_timestamp: date | datetime | None
    candidate_payload: Any
    candidate: OpenRelCandidate | None
    original_representation: Any | None
    original_content_digest: str | None
    actor_type: str
    actor_id: str | None


@dataclass(frozen=True)
class OpenRelEvaluationResult:
    classification: OpenRelLicenceClassificationResult
    provider_available: bool
    policy_plan: OpenRelPolicyPlan
    policy_state_id: UUID | None
    persisted_status: str | None
    candidate_digest: str | None
    reused_existing_state: bool
    review_required: bool
    application_may_be_allowed_later: bool
    reasons: tuple[str, ...]


class OpenRelClientProtocol(Protocol):
    def check_availability(self) -> bool: ...


class OpenRelEvaluationCoordinator:
    def __init__(
        self,
        settings: OpenRelPolicySettings,
        *,
        client: OpenRelClientProtocol | None,
        policy_store: OpenRelPolicyStore,
    ) -> None:
        self.settings = settings
        self.client = client
        self.policy_store = policy_store

    def evaluate(self, evaluation: OpenRelEvaluationInput) -> OpenRelEvaluationResult:
        normalized = self._validate_input(evaluation)
        if self.settings.validation_errors:
            if self.settings.mode == OpenRelPolicyMode.disabled and not self.settings.enabled:
                classification = classify_licence_record(
                    self.settings,
                    registration_timestamp=normalized.registration_timestamp,
                    imported_record=normalized.source_kind == "federation-imported",
                )
                plan = OpenRelPolicyPlan(
                    action=OpenRelPolicyAction.none,
                    classification=classification.classification,
                    policy_version=None,
                    active_profile=None,
                    active_vocabulary=None,
                    original_profile=self._current_profile(normalized.original_representation),
                    mapping_profile=None,
                    mapping_provenance=None,
                    source_provider_url=None,
                    apply_allowed=False,
                    review_required=True,
                    reason="OpenREL policy is disabled; evaluation is inert and no plan was persisted.",
                )
                return OpenRelEvaluationResult(
                    classification=classification,
                    provider_available=False,
                    policy_plan=plan,
                    policy_state_id=None,
                    persisted_status=None,
                    candidate_digest=None,
                    reused_existing_state=False,
                    review_required=True,
                    application_may_be_allowed_later=False,
                    reasons=(classification.classification_reason, plan.reason),
                )
            raise OpenRelEvaluationConfigurationError("; ".join(self.settings.validation_errors))
        classification = classify_licence_record(
            self.settings,
            registration_timestamp=normalized.registration_timestamp,
            imported_record=normalized.source_kind == "federation-imported",
        )
        if self.settings.mode == OpenRelPolicyMode.disabled and not self.settings.enabled:
            plan = OpenRelPolicyPlan(
                action=OpenRelPolicyAction.none,
                classification=classification.classification,
                policy_version=None,
                active_profile=None,
                active_vocabulary=None,
                original_profile=self._current_profile(normalized.original_representation),
                mapping_profile=None,
                mapping_provenance=None,
                source_provider_url=None,
                apply_allowed=False,
                review_required=True,
                reason="OpenREL policy is disabled; evaluation is inert and no plan was persisted.",
            )
            return OpenRelEvaluationResult(
                classification=classification,
                provider_available=False,
                policy_plan=plan,
                policy_state_id=None,
                persisted_status=None,
                candidate_digest=None,
                reused_existing_state=False,
                review_required=True,
                application_may_be_allowed_later=False,
                reasons=(classification.classification_reason, plan.reason),
            )

        provider_available = False
        if self.settings.enabled and self.settings.mode.value in {"active", "dry-run"}:
            if self.client is None:
                provider_available = False
            else:
                try:
                    provider_available = self.client.check_availability()
                except OpenRelClientError:
                    provider_available = False

        candidate = normalized.candidate if provider_available else None
        plan = build_openrel_policy_plan(
            self.settings,
            classification,
            candidate,
            current_profile=self._current_profile(normalized.original_representation),
            imported_record=normalized.source_kind == "federation-imported",
        )

        if not provider_available and self.settings.enabled and self.settings.mode.value in {"active", "dry-run"}:
            plan = OpenRelPolicyPlan(
                action=plan.action.none,
                classification=plan.classification,
                policy_version=plan.policy_version,
                active_profile=plan.active_profile,
                active_vocabulary=plan.active_vocabulary,
                original_profile=plan.original_profile,
                mapping_profile=None,
                mapping_provenance=None,
                source_provider_url=plan.source_provider_url,
                apply_allowed=False,
                review_required=True,
                reason="OpenREL provider is unavailable; evaluation failed closed with no local replacement or mapping plan.",
            )

        exact_existing = self._find_existing_state(
            canonical_license_id=normalized.canonical_license_id,
            plan=plan,
            candidate_payload=normalized.candidate_payload,
            source_kind=normalized.source_kind,
        )
        state = self.policy_store.record_plan(
            canonical_license_id=normalized.canonical_license_id,
            source_kind=normalized.source_kind,
            source_record_ref=normalized.source_record_ref,
            settings=self.settings,
            plan=plan,
            candidate_payload=normalized.candidate_payload,
            original_representation=normalized.original_representation,
            original_content_digest=normalized.original_content_digest,
            actor_type=normalized.actor_type,
            actor_id=normalized.actor_id,
        )
        return OpenRelEvaluationResult(
            classification=classification,
            provider_available=provider_available,
            policy_plan=self._policy_plan_from_state(state),
            policy_state_id=state.id,
            persisted_status=state.status,
            candidate_digest=state.candidate_digest_sha256,
            reused_existing_state=exact_existing is not None and exact_existing.id == state.id,
            review_required=bool(state.review_required),
            application_may_be_allowed_later=bool(state.apply_allowed),
            reasons=(classification.classification_reason, state.reason),
        )

    @staticmethod
    def _validate_input(evaluation: OpenRelEvaluationInput) -> OpenRelEvaluationInput:
        canonical_license_id = str(evaluation.canonical_license_id).strip()
        if not canonical_license_id:
            raise OpenRelEvaluationError("canonical_license_id is required")
        source_kind = str(evaluation.source_kind).strip()
        if source_kind not in {"spdx", "custom", "federation-authoritative", "federation-imported"}:
            raise OpenRelEvaluationError("unsupported source_kind")
        actor_type = str(evaluation.actor_type).strip()
        if actor_type not in {"system", "admin", "curator", "worker"}:
            raise OpenRelEvaluationError("unsupported actor_type")
        actor_id = None if evaluation.actor_id is None else str(evaluation.actor_id).strip()
        if evaluation.actor_id is not None and not actor_id:
            raise OpenRelEvaluationError("actor_id must be nonblank when supplied")
        source_record_ref = None if evaluation.source_record_ref is None else str(evaluation.source_record_ref).strip() or None
        return OpenRelEvaluationInput(
            canonical_license_id=canonical_license_id,
            source_kind=source_kind,
            source_record_ref=source_record_ref,
            registration_timestamp=evaluation.registration_timestamp,
            candidate_payload=evaluation.candidate_payload,
            candidate=evaluation.candidate,
            original_representation=evaluation.original_representation,
            original_content_digest=evaluation.original_content_digest,
            actor_type=actor_type,
            actor_id=actor_id,
        )

    @staticmethod
    def _current_profile(original_representation: Any | None) -> str | None:
        if not isinstance(original_representation, dict):
            return None
        profile = original_representation.get("profile")
        if not isinstance(profile, str) or not profile.strip():
            return None
        return profile.strip()

    def _find_existing_state(
        self,
        *,
        canonical_license_id: str,
        plan: OpenRelPolicyPlan,
        candidate_payload: Any,
        source_kind: str,
    ) -> OpenRelPolicyState | None:
        effective_policy_version = (plan.policy_version or self.settings.approved_version or "").strip()
        if not effective_policy_version:
            return None
        projected_action = OpenRelPolicyAction.none if source_kind == "federation-imported" else plan.action
        candidate_digest = compute_candidate_digest(candidate_payload)
        return (
            self.policy_store.session.query(OpenRelPolicyState)
            .filter_by(
                canonical_license_id=canonical_license_id,
                policy_version=effective_policy_version,
                candidate_digest_sha256=candidate_digest,
                action=projected_action.value,
            )
            .order_by(OpenRelPolicyState.created_at.desc(), OpenRelPolicyState.id.desc())
            .first()
        )

    @staticmethod
    def _policy_plan_from_state(state: OpenRelPolicyState) -> OpenRelPolicyPlan:
        return OpenRelPolicyPlan(
            action=OpenRelPolicyAction(state.action),
            classification=OpenRelLicenceClassification(state.classification),
            policy_version=state.policy_version,
            active_profile=state.active_profile,
            active_vocabulary=state.active_vocabulary,
            original_profile=state.original_profile,
            mapping_profile=state.mapping_profile,
            mapping_provenance=state.mapping_provenance,
            source_provider_url=state.provider_url,
            apply_allowed=bool(state.apply_allowed),
            review_required=bool(state.review_required),
            reason=state.reason,
        )


__all__ = [
    "OpenRelEvaluationCoordinator",
    "OpenRelEvaluationConfigurationError",
    "OpenRelEvaluationError",
    "OpenRelEvaluationInput",
    "OpenRelEvaluationResult",
]
