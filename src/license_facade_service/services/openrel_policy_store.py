from __future__ import annotations

import hashlib
import json
import math
import re
import uuid
from copy import deepcopy
from datetime import date, datetime, timezone
from typing import Any

from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from src.license_facade_service.db.models.openrel_policy import OpenRelPolicyEvent, OpenRelPolicyState
from src.license_facade_service.services.openrel_policy import (
    OpenRelLicenceClassification,
    OpenRelPolicyAction,
    OpenRelPolicyMode,
    OpenRelPolicyPlan,
    OpenRelPolicySettings,
)

_SENSITIVE_KEY_RE = re.compile(r"(?:authorization|token|access_token|password|secret|private_key|api_key)", re.IGNORECASE)
_SENSITIVE_ASSIGNMENT_RE = re.compile(
    r"(?i)\b(bearer\s+|token\s*=|password\s*=|api_key\s*=|secret\s*=)([^\s,;]+)"
)
_VALID_ACTOR_TYPES = {"system", "admin", "curator", "worker"}
_PLAN_IDEMPOTENCY_CONSTRAINT = "uq_openrel_policy_states_license_policy_candidate_action"


class OpenRelPolicyStoreError(ValueError):
    pass


class OpenRelPolicyStoreCollisionError(OpenRelPolicyStoreError):
    pass


class OpenRelPolicyPlanValidationError(OpenRelPolicyStoreError):
    pass


class OpenRelPolicyTransitionError(OpenRelPolicyStoreError):
    pass


def _utc_now() -> datetime:
    return datetime.now(timezone.utc)


def _safe_text(value: Any, *, max_length: int = 1024) -> str:
    if value is None:
        return ""
    text = str(value)
    return text[:max_length]


def _normalize_json_value(value: Any) -> Any:
    if value is None:
        return None
    if isinstance(value, bool):
        return value
    if isinstance(value, int) and not isinstance(value, bool):
        return value
    if isinstance(value, float):
        if math.isnan(value) or math.isinf(value):
            raise OpenRelPolicyPlanValidationError("JSON values must be finite numbers")
        return value
    if isinstance(value, str):
        return value
    if isinstance(value, list):
        return [_normalize_json_value(item) for item in value]
    if isinstance(value, tuple):
        return [_normalize_json_value(item) for item in value]
    if isinstance(value, dict):
        normalized: dict[str, Any] = {}
        for key, item in value.items():
            if not isinstance(key, str):
                raise OpenRelPolicyPlanValidationError("JSON object keys must be strings")
            normalized[key] = _normalize_json_value(item)
        return normalized
    if isinstance(value, (bytes, bytearray, set)):
        raise OpenRelPolicyPlanValidationError("unsupported non-JSON value in payload")
    if isinstance(value, (date, datetime)):
        raise OpenRelPolicyPlanValidationError("datetime/date values are not valid JSON payloads")
    raise OpenRelPolicyPlanValidationError(f"unsupported non-JSON value: {type(value).__name__}")


def _canonical_json_bytes(value: Any) -> bytes:
    normalized = _normalize_json_value(value)
    return json.dumps(normalized, ensure_ascii=False, separators=(",", ":"), sort_keys=True, allow_nan=False).encode("utf-8")


def compute_candidate_digest(candidate_payload: Any) -> str:
    canonical = _canonical_json_bytes(candidate_payload)
    return hashlib.sha256(canonical).hexdigest()


def _is_blank(value: Any) -> bool:
    return value is None or (isinstance(value, str) and not value.strip())


def _validate_actor(actor_type: str, actor_id: str | None) -> tuple[str, str | None]:
    if actor_type not in _VALID_ACTOR_TYPES:
        raise OpenRelPolicyPlanValidationError(f"unsupported actor_type: {actor_type}")
    normalized_actor_id = None
    if actor_id is not None:
        normalized_actor_id = actor_id.strip()
        if not normalized_actor_id:
            raise OpenRelPolicyPlanValidationError("actor_id must be nonblank when supplied")
    return actor_type, normalized_actor_id


def _validate_settings_before_persistence(settings: OpenRelPolicySettings, plan: OpenRelPolicyPlan) -> tuple[str, str, date]:
    if settings.validation_errors:
        raise OpenRelPolicyPlanValidationError("; ".join(settings.validation_errors))

    effective_policy_version = ((plan.policy_version or settings.approved_version or "").strip())
    if not effective_policy_version or effective_policy_version.lower() == "unknown":
        raise OpenRelPolicyPlanValidationError("policy version is required")

    provider_url = (settings.base_url or "").strip()
    if not provider_url:
        raise OpenRelPolicyPlanValidationError("provider URL is required")

    effective_date = settings.effective_date
    if effective_date is None or not isinstance(effective_date, date):
        raise OpenRelPolicyPlanValidationError("effective date is required")

    if settings.mode == OpenRelPolicyMode.active and not settings.enabled:
        raise OpenRelPolicyPlanValidationError("active mode requires enabled=True")
    if settings.mode == OpenRelPolicyMode.dry_run and not settings.enabled:
        raise OpenRelPolicyPlanValidationError("dry-run mode requires enabled=True")
    if settings.mode == OpenRelPolicyMode.disabled and settings.enabled:
        raise OpenRelPolicyPlanValidationError("disabled mode requires enabled=False")

    return effective_policy_version, provider_url, effective_date


def _project_imported_record(*, settings: OpenRelPolicySettings, plan: OpenRelPolicyPlan) -> dict[str, Any]:
    return {
        "action": OpenRelPolicyAction.none,
        "apply_allowed": False,
        "review_required": True,
        "status": "planned",
        "mapping_profile": None,
        "mapping_provenance": None,
        "active_profile": settings.approved_profile,
        "active_vocabulary": "https://openrel.org/ns#",
        "original_profile": plan.original_profile,
        "reason": "Imported record is non-authoritative; no local replacement or mapping mutation is planned.",
        "requested_action": plan.action.value,
    }


def _sanitizer_value(value: Any, *, depth: int = 0, max_depth: int = 5, max_string_length: int = 512) -> Any:
    if depth > max_depth:
        return "[...]"
    if value is None or isinstance(value, (bool, int, float)):
        return value
    if isinstance(value, str):
        return value[:max_string_length]
    if isinstance(value, list):
        return [_sanitizer_value(item, depth=depth + 1, max_depth=max_depth, max_string_length=max_string_length) for item in value[:20]]
    if isinstance(value, tuple):
        return [_sanitizer_value(item, depth=depth + 1, max_depth=max_depth, max_string_length=max_string_length) for item in value[:20]]
    if isinstance(value, dict):
        result: dict[str, Any] = {}
        for key, item in list(value.items())[:20]:
            safe_key = "key" if key is None else str(key)
            if _SENSITIVE_KEY_RE.search(safe_key):
                result[safe_key] = "[REDACTED]"
            else:
                result[safe_key] = _sanitizer_value(item, depth=depth + 1, max_depth=max_depth, max_string_length=max_string_length)
        return result
    return _safe_text(value, max_length=max_string_length)


def sanitize_audit_details(details: Any, *, max_depth: int = 5, max_string_length: int = 512) -> Any:
    return _sanitizer_value(deepcopy(details), depth=0, max_depth=max_depth, max_string_length=max_string_length)


def _reject_duplicate_json_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise OpenRelPolicyTransitionError("review reason contains duplicate JSON keys")
        result[key] = value
    return result


def _bounded_json_string(value: Any, *, max_length: int) -> str:
    candidate = json.dumps(value, ensure_ascii=False, separators=(",", ":"), sort_keys=True)
    if len(candidate) <= max_length:
        return candidate
    redacted_marker = "[REDACTED]"
    truncated_marker = "[TRUNCATED]"

    def contains_redaction(node: Any) -> bool:
        if node == redacted_marker:
            return True
        if isinstance(node, dict):
            return any(contains_redaction(item) for item in node.values())
        if isinstance(node, list):
            return any(contains_redaction(item) for item in node)
        return False

    def contains_marker(node: Any, marker: str) -> bool:
        if node == marker:
            return True
        if isinstance(node, dict):
            return any(contains_marker(item, marker) for item in node.values())
        if isinstance(node, list):
            return any(contains_marker(item, marker) for item in node)
        return False

    def valid_bounded_result(node: Any, serialized: str) -> bool:
        if len(serialized) > max_length:
            return False
        if not contains_marker(node, truncated_marker):
            return False
        if had_redaction and not contains_redaction(node):
            return False
        return True

    had_redaction = contains_redaction(value)
    if isinstance(value, dict):
        bounded: dict[str, Any] = {}
        for key in sorted(value):
            if _SENSITIVE_KEY_RE.search(key):
                bounded[key] = redacted_marker
                continue
            replacement = value[key]
            bounded[key] = replacement
            trial = json.dumps(bounded, ensure_ascii=False, separators=(",", ":"), sort_keys=True)
            if len(trial) > max_length:
                bounded[key] = truncated_marker
                trial = json.dumps(bounded, ensure_ascii=False, separators=(",", ":"), sort_keys=True)
                if len(trial) > max_length:
                    del bounded[key]
                break
        result = json.dumps(bounded, ensure_ascii=False, separators=(",", ":"), sort_keys=True)
        fallback = {"truncation": truncated_marker}
        if had_redaction:
            fallback["redaction"] = redacted_marker
        if valid_bounded_result(bounded, result):
            return result
        return json.dumps(fallback, ensure_ascii=False, separators=(",", ":"), sort_keys=True)
    if isinstance(value, list):
        bounded_list: list[Any] = []
        for item in value:
            bounded_list.append(item)
            trial = json.dumps(bounded_list, ensure_ascii=False, separators=(",", ":"), sort_keys=True)
            if len(trial) > max_length:
                bounded_list[-1] = truncated_marker
                trial = json.dumps(bounded_list, ensure_ascii=False, separators=(",", ":"), sort_keys=True)
                if len(trial) > max_length:
                    bounded_list.pop()
                break
        result = json.dumps(bounded_list, ensure_ascii=False, separators=(",", ":"), sort_keys=True)
        if valid_bounded_result(bounded_list, result):
            return result
        fallback_list: list[str] = []
        if had_redaction:
            fallback_list.append(redacted_marker)
        fallback_list.append(truncated_marker)
        return json.dumps(fallback_list, ensure_ascii=False, separators=(",", ":"), sort_keys=True)
    return json.dumps(redacted_marker, ensure_ascii=False, separators=(",", ":"), sort_keys=True)


def sanitize_review_reason(value: Any) -> str | None:
    if value is None:
        return None
    if not isinstance(value, str):
        raise OpenRelPolicyTransitionError("review reason must be a string")
    trimmed = value.strip()
    if not trimmed:
        return None
    if trimmed.startswith("{") or trimmed.startswith("["):
        try:
            parsed = json.loads(trimmed, object_pairs_hook=_reject_duplicate_json_keys)
        except json.JSONDecodeError as exc:
            raise OpenRelPolicyTransitionError("review reason contains malformed structured JSON") from exc
        if not isinstance(parsed, (dict, list)):
            raise OpenRelPolicyTransitionError("review reason structured JSON must be an object or array")
        sanitized = sanitize_audit_details(parsed, max_string_length=512)
        return _bounded_json_string(sanitized, max_length=512)
    redacted = _SENSITIVE_ASSIGNMENT_RE.sub(lambda m: f"{m.group(1)}[REDACTED]", trimmed)
    return redacted[:512]


class OpenRelPolicyStore:
    def __init__(self, session: Session) -> None:
        self.session = session

    def get_state(self, state_id: uuid.UUID) -> OpenRelPolicyState | None:
        return self.session.get(OpenRelPolicyState, state_id)

    def get_latest_state_for_canonical(self, canonical_license_id: str) -> OpenRelPolicyState | None:
        stmt = (
            select(OpenRelPolicyState)
            .where(OpenRelPolicyState.canonical_license_id == canonical_license_id)
            .order_by(OpenRelPolicyState.created_at.desc(), OpenRelPolicyState.id.desc())
            .limit(1)
        )
        return self.session.execute(stmt).scalars().first()

    def list_audit_events_for_state(self, state_id: uuid.UUID) -> list[OpenRelPolicyEvent]:
        stmt = (
            select(OpenRelPolicyEvent)
            .where(OpenRelPolicyEvent.policy_state_id == state_id)
            .order_by(OpenRelPolicyEvent.occurred_at.asc(), OpenRelPolicyEvent.id.asc())
        )
        return list(self.session.execute(stmt).scalars().all())

    def _validate_plan(self, *, source_kind: str, plan: OpenRelPolicyPlan, settings: OpenRelPolicySettings) -> None:
        if source_kind == "federation-imported":
            return

        if plan.action == OpenRelPolicyAction.full_replacement and plan.classification != OpenRelLicenceClassification.new:
            raise OpenRelPolicyPlanValidationError("full-replacement requires a new classification")
        if plan.action == OpenRelPolicyAction.historical_mapping:
            if plan.classification != OpenRelLicenceClassification.historical:
                raise OpenRelPolicyPlanValidationError("historical-mapping requires a historical classification")
            if _is_blank(plan.original_profile):
                raise OpenRelPolicyPlanValidationError("historical mapping requires original_profile")
            if _is_blank(plan.mapping_profile):
                raise OpenRelPolicyPlanValidationError("historical mapping requires mapping_profile")
            if _is_blank(plan.mapping_provenance):
                raise OpenRelPolicyPlanValidationError("historical mapping requires mapping_provenance")
            if plan.review_required is not True:
                raise OpenRelPolicyPlanValidationError("historical mapping requires review_required=True")

    def _initial_status_for_plan(self, *, settings: OpenRelPolicySettings, plan: OpenRelPolicyPlan, source_kind: str, projected_action: OpenRelPolicyAction) -> str:
        if source_kind == "federation-imported":
            return "planned"
        if settings.mode == OpenRelPolicyMode.dry_run:
            return "planned"
        if projected_action == OpenRelPolicyAction.none:
            return "planned"
        if plan.review_required:
            return "pending-review"
        return "planned"

    def _build_state_record(
        self,
        *,
        canonical_license_id: str,
        source_kind: str,
        source_record_ref: str | None,
        settings: OpenRelPolicySettings,
        plan: OpenRelPolicyPlan,
        candidate_payload: Any,
        original_representation: Any | None,
        original_content_digest: str | None,
        actor_type: str,
        actor_id: str | None,
        effective_policy_version: str,
        provider_url: str,
        effective_date: date,
        requested_action: str | None = None,
    ) -> tuple[OpenRelPolicyState, OpenRelPolicyEvent, str]:
        if not canonical_license_id or not str(canonical_license_id).strip():
            raise OpenRelPolicyPlanValidationError("canonical_license_id is required")
        if source_kind not in {"spdx", "custom", "federation-authoritative", "federation-imported"}:
            raise OpenRelPolicyPlanValidationError("unsupported source_kind")

        actor_type, actor_id = _validate_actor(actor_type, actor_id)
        self._validate_plan(source_kind=source_kind, plan=plan, settings=settings)
        normalized_candidate_payload = _normalize_json_value(candidate_payload)
        normalized_original_representation = None if original_representation is None else _normalize_json_value(original_representation)
        if original_content_digest is not None and (not isinstance(original_content_digest, str) or not re.fullmatch(r"[0-9a-f]{64}", original_content_digest)):
            raise OpenRelPolicyPlanValidationError("original_content_digest must be a lowercase 64-character SHA-256 hex string")

        if source_kind == "federation-imported":
            projected = _project_imported_record(settings=settings, plan=plan)
            projected_action = projected["action"]
            projected_apply_allowed = bool(projected["apply_allowed"])
            projected_review_required = bool(projected["review_required"])
            active_profile = projected["active_profile"]
            active_vocabulary = projected["active_vocabulary"]
            original_profile = projected["original_profile"]
            mapping_profile = projected["mapping_profile"]
            mapping_provenance = projected["mapping_provenance"]
            reason = projected["reason"]
            projected_status = projected["status"]
            requested_action_value = requested_action if requested_action is not None else projected["requested_action"]
        else:
            projected_action = plan.action
            projected_apply_allowed = bool(plan.apply_allowed)
            projected_review_required = bool(plan.review_required)
            active_profile = plan.active_profile
            active_vocabulary = plan.active_vocabulary
            original_profile = plan.original_profile
            mapping_profile = plan.mapping_profile
            mapping_provenance = plan.mapping_provenance
            reason = plan.reason
            projected_status = self._initial_status_for_plan(settings=settings, plan=plan, source_kind=source_kind, projected_action=plan.action)
            requested_action_value = requested_action if requested_action is not None else plan.action.value

        candidate_digest = compute_candidate_digest(normalized_candidate_payload)
        state = OpenRelPolicyState(
            id=uuid.uuid4(),
            canonical_license_id=str(canonical_license_id).strip(),
            source_kind=source_kind,
            source_record_ref=source_record_ref,
            classification=plan.classification.value,
            policy_mode=settings.mode.value,
            policy_version=effective_policy_version,
            effective_date=effective_date,
            action=projected_action.value,
            status=projected_status,
            provider_url=provider_url,
            active_profile=active_profile,
            active_vocabulary=active_vocabulary,
            original_profile=original_profile,
            mapping_profile=mapping_profile,
            mapping_provenance=mapping_provenance,
            candidate_digest_sha256=candidate_digest,
            original_content_digest_sha256=original_content_digest,
            candidate_payload=normalized_candidate_payload,
            original_representation=normalized_original_representation,
            apply_allowed=projected_apply_allowed,
            review_required=projected_review_required,
            reason=reason,
            created_at=_utc_now(),
            updated_at=_utc_now(),
        )

        event_details = {
            "policy_mode": settings.mode.value,
            "policy_version": effective_policy_version,
            "action": projected_action.value,
            "requested_action": requested_action_value,
            "classification": plan.classification.value,
            "status": projected_status,
            "provider_url": provider_url,
            "source_kind": source_kind,
            "apply_allowed": projected_apply_allowed,
            "review_required": projected_review_required,
            "active_profile": active_profile,
            "active_vocabulary": active_vocabulary,
            "original_profile": original_profile,
            "mapping_profile": mapping_profile,
        }
        event = OpenRelPolicyEvent(
            id=uuid.uuid4(),
            policy_state_id=state.id,
            event_type="planned",
            actor_type=actor_type,
            actor_id=actor_id,
            before_status=None,
            after_status=projected_status,
            details=sanitize_audit_details(event_details),
            occurred_at=_utc_now(),
            created_at=_utc_now(),
        )
        return state, event, candidate_digest

    def record_plan(
        self,
        *,
        canonical_license_id: str,
        source_kind: str,
        source_record_ref: str | None,
        settings: OpenRelPolicySettings,
        plan: OpenRelPolicyPlan,
        candidate_payload: Any,
        original_representation: Any | None,
        original_content_digest: str | None,
        actor_type: str,
        actor_id: str | None,
    ) -> OpenRelPolicyState:
        if not isinstance(settings, OpenRelPolicySettings):
            raise OpenRelPolicyPlanValidationError("settings must be an OpenRelPolicySettings instance")
        effective_policy_version, provider_url, effective_date = _validate_settings_before_persistence(settings, plan)
        actor_type, actor_id = _validate_actor(actor_type, actor_id)

        normalized_candidate_payload = _normalize_json_value(candidate_payload)
        normalized_original_representation = None if original_representation is None else _normalize_json_value(original_representation)
        if original_content_digest is not None and (not isinstance(original_content_digest, str) or not re.fullmatch(r"[0-9a-f]{64}", original_content_digest)):
            raise OpenRelPolicyPlanValidationError("original_content_digest must be a lowercase 64-character SHA-256 hex string")

        projected_action = OpenRelPolicyAction.none if source_kind == "federation-imported" else plan.action
        projected_reason = None
        requested_action = plan.action.value
        if source_kind == "federation-imported":
            projected_reason = _project_imported_record(settings=settings, plan=plan)["reason"]
            projected_action = OpenRelPolicyAction.none

        self._validate_plan(source_kind=source_kind, plan=plan, settings=settings)
        if source_kind == "federation-imported":
            plan = OpenRelPolicyPlan(
                action=OpenRelPolicyAction.none,
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
                reason=projected_reason or plan.reason,
            )

        candidate_digest = compute_candidate_digest(normalized_candidate_payload)
        existing = (
            self.session.query(OpenRelPolicyState)
            .filter_by(
                canonical_license_id=str(canonical_license_id).strip(),
                policy_version=effective_policy_version,
                candidate_digest_sha256=candidate_digest,
                action=projected_action.value,
            )
            .order_by(OpenRelPolicyState.created_at.desc(), OpenRelPolicyState.id.desc())
            .first()
        )
        if existing is not None:
            self._assert_material_equivalence(
                existing=existing,
                source_kind=source_kind,
                source_record_ref=source_record_ref,
                settings=settings,
                plan=plan,
                effective_policy_version=effective_policy_version,
                effective_date=effective_date,
                provider_url=provider_url,
                normalized_candidate_payload=normalized_candidate_payload,
                candidate_digest=candidate_digest,
                normalized_original_representation=normalized_original_representation,
                original_content_digest=original_content_digest,
                projected_action=projected_action,
                projected_reason=projected_reason,
            )
            return existing

        state, event, _ = self._build_state_record(
            canonical_license_id=canonical_license_id,
            source_kind=source_kind,
            source_record_ref=source_record_ref,
            settings=settings,
            plan=plan,
            candidate_payload=normalized_candidate_payload,
            original_representation=normalized_original_representation,
            original_content_digest=original_content_digest,
            actor_type=actor_type,
            actor_id=actor_id,
            effective_policy_version=effective_policy_version,
            provider_url=provider_url,
            effective_date=effective_date,
            requested_action=requested_action,
        )
        try:
            with self.session.begin_nested():
                self.session.add(state)
                self.session.flush()
                self.session.add(event)
                self.session.flush()
        except IntegrityError as exc:
            if not self._is_plan_idempotency_integrity_error(exc):
                raise
            winner = (
                self.session.query(OpenRelPolicyState)
                .filter_by(
                    canonical_license_id=str(canonical_license_id).strip(),
                    policy_version=effective_policy_version,
                    candidate_digest_sha256=candidate_digest,
                    action=projected_action.value,
                )
                .order_by(OpenRelPolicyState.created_at.desc(), OpenRelPolicyState.id.desc())
                .first()
            )
            if winner is None:
                raise
            self._assert_material_equivalence(
                existing=winner,
                source_kind=source_kind,
                source_record_ref=source_record_ref,
                settings=settings,
                plan=plan,
                effective_policy_version=effective_policy_version,
                effective_date=effective_date,
                provider_url=provider_url,
                normalized_candidate_payload=normalized_candidate_payload,
                candidate_digest=candidate_digest,
                normalized_original_representation=normalized_original_representation,
                original_content_digest=original_content_digest,
                projected_action=projected_action,
                projected_reason=projected_reason,
            )
            return winner
        return state

    def _assert_material_equivalence(
        self,
        *,
        existing: OpenRelPolicyState,
        source_kind: str,
        source_record_ref: str | None,
        settings: OpenRelPolicySettings,
        plan: OpenRelPolicyPlan,
        effective_policy_version: str,
        effective_date: date,
        provider_url: str,
        normalized_candidate_payload: Any,
        candidate_digest: str,
        normalized_original_representation: Any | None,
        original_content_digest: str | None,
        projected_action: OpenRelPolicyAction,
        projected_reason: str | None,
    ) -> None:
        material_values = {
            "source_kind": source_kind,
            "source_record_ref": source_record_ref,
            "classification": plan.classification.value,
            "policy_mode": settings.mode.value,
            "policy_version": effective_policy_version,
            "effective_date": effective_date,
            "provider_url": provider_url,
            "active_profile": (plan.active_profile if source_kind != "federation-imported" else settings.approved_profile),
            "active_vocabulary": (plan.active_vocabulary if source_kind != "federation-imported" else "https://openrel.org/ns#"),
            "original_profile": (plan.original_profile if source_kind != "federation-imported" else plan.original_profile),
            "mapping_profile": (plan.mapping_profile if source_kind != "federation-imported" else None),
            "mapping_provenance": (plan.mapping_provenance if source_kind != "federation-imported" else None),
            "candidate_payload": normalized_candidate_payload,
            "candidate_digest_sha256": candidate_digest,
            "original_representation": normalized_original_representation,
            "original_content_digest_sha256": original_content_digest,
            "apply_allowed": bool(plan.apply_allowed) if source_kind != "federation-imported" else False,
            "review_required": bool(plan.review_required) if source_kind != "federation-imported" else True,
            "reason": (plan.reason if source_kind != "federation-imported" else projected_reason or plan.reason),
            "action": projected_action.value,
        }
        for field_name, value in material_values.items():
            if getattr(existing, field_name) != value:
                raise OpenRelPolicyStoreCollisionError(f"idempotent plan collision: {field_name} changed")

    def _is_plan_idempotency_integrity_error(self, exc: IntegrityError) -> bool:
        candidate_errors = [exc]
        orig = getattr(exc, "orig", None)
        if orig is not None:
            candidate_errors.append(orig)
        for error in candidate_errors:
            diag = getattr(error, "diag", None)
            if diag is not None and getattr(diag, "constraint_name", None) == _PLAN_IDEMPOTENCY_CONSTRAINT:
                return True
            if getattr(error, "constraint_name", None) == _PLAN_IDEMPOTENCY_CONSTRAINT:
                return True
        return False

    def record_event(self, *, policy_state_id: uuid.UUID, event_type: str, actor_type: str, actor_id: str | None, before_status: str | None, after_status: str | None, details: Any) -> OpenRelPolicyEvent:
        if event_type not in {"planned", "review-approved", "review-rejected", "applied", "failed", "rolled-back"}:
            raise OpenRelPolicyTransitionError("unsupported event type")
        actor_type, actor_id = _validate_actor(actor_type, actor_id)
        event = OpenRelPolicyEvent(
            id=uuid.uuid4(),
            policy_state_id=policy_state_id,
            event_type=event_type,
            actor_type=actor_type,
            actor_id=actor_id,
            before_status=before_status,
            after_status=after_status,
            details=sanitize_audit_details(details),
            occurred_at=_utc_now(),
            created_at=_utc_now(),
        )
        self.session.add(event)
        self.session.flush()
        return event

    def _assert_compatible_retry(self, state: OpenRelPolicyState, *, new_status: str, reviewer_identity: str | None, error_code: str | None) -> None:
        if new_status == "approved" or new_status == "rejected":
            if _is_blank(reviewer_identity):
                raise OpenRelPolicyTransitionError("reviewer identity is required for this transition")
            if str(reviewer_identity).strip() != (state.reviewed_by or ""):
                raise OpenRelPolicyTransitionError("reviewer identity does not match stored review")
        if new_status == "failed":
            if _is_blank(error_code):
                raise OpenRelPolicyTransitionError("failed transition requires a nonblank error_code")
            if str(error_code).strip() != (state.error_code or ""):
                raise OpenRelPolicyTransitionError("error code does not match stored failure")
        if new_status == "applied":
            if not state.apply_allowed:
                raise OpenRelPolicyTransitionError("can only apply when apply_allowed=true")
            if state.policy_mode != OpenRelPolicyMode.active.value:
                raise OpenRelPolicyTransitionError("can only apply in active policy mode")
            if state.source_kind == "federation-imported":
                raise OpenRelPolicyTransitionError("imported records cannot be applied")
            if state.action == OpenRelPolicyAction.none.value:
                raise OpenRelPolicyTransitionError("action='none' cannot be applied")
        if new_status == "rolled-back":
            if state.original_representation is None:
                raise OpenRelPolicyTransitionError("rollback requires original_representation")

    def transition_status(
        self,
        state_id: uuid.UUID,
        *,
        new_status: str,
        actor_type: str = "system",
        actor_id: str | None = None,
        reviewer_identity: str | None = None,
        review_reason: Any = None,
        error_code: str | None = None,
        error_detail: Any = None,
    ) -> OpenRelPolicyState:
        state = self.get_state(state_id)
        if state is None:
            raise OpenRelPolicyTransitionError("state not found")

        actor_type, actor_id = _validate_actor(actor_type, actor_id)
        current = state.status
        sanitized_review_reason = sanitize_review_reason(review_reason)
        if current == new_status:
            if new_status not in {"approved", "rejected", "applied", "failed", "rolled-back"}:
                raise OpenRelPolicyTransitionError(f"unsupported transition: {current} -> {new_status}")
            self._assert_compatible_retry(state, new_status=new_status, reviewer_identity=reviewer_identity, error_code=error_code)
            return state

        allowed = {
            ("pending-review", "approved"),
            ("pending-review", "rejected"),
            ("planned", "applied"),
            ("approved", "applied"),
            ("planned", "failed"),
            ("pending-review", "failed"),
            ("approved", "failed"),
            ("applied", "rolled-back"),
        }
        if (current, new_status) not in allowed:
            raise OpenRelPolicyTransitionError(f"unsupported transition: {current} -> {new_status}")

        if new_status in {"approved", "rejected"}:
            if _is_blank(reviewer_identity):
                raise OpenRelPolicyTransitionError("reviewer identity is required for approval or rejection")
            state.reviewed_by = str(reviewer_identity).strip()
            state.reviewed_at = _utc_now()
        if new_status == "applied":
            if not state.apply_allowed:
                raise OpenRelPolicyTransitionError("can only apply when apply_allowed=true")
            if state.policy_mode != OpenRelPolicyMode.active.value:
                raise OpenRelPolicyTransitionError("can only apply in active policy mode")
            if state.source_kind == "federation-imported":
                raise OpenRelPolicyTransitionError("imported records cannot be applied")
            if state.action == OpenRelPolicyAction.none.value:
                raise OpenRelPolicyTransitionError("action='none' cannot be applied")
            state.applied_at = _utc_now()
        if new_status == "rolled-back":
            if state.original_representation is None:
                raise OpenRelPolicyTransitionError("rollback requires original_representation")
            state.rolled_back_at = _utc_now()
        if new_status == "failed":
            if _is_blank(error_code):
                raise OpenRelPolicyTransitionError("failed transition requires a nonblank error_code")
            state.error_code = str(error_code).strip()
            state.error_detail = _safe_text(sanitize_audit_details(error_detail), max_length=2048)

        state.status = new_status
        state.updated_at = _utc_now()

        event_type = {
            "approved": "review-approved",
            "rejected": "review-rejected",
            "applied": "applied",
            "failed": "failed",
            "rolled-back": "rolled-back",
        }.get(new_status, "planned")
        event = OpenRelPolicyEvent(
            id=uuid.uuid4(),
            policy_state_id=state.id,
            event_type=event_type,
            actor_type=actor_type,
            actor_id=actor_id,
            before_status=current,
            after_status=new_status,
            details=sanitize_audit_details({
                "status": new_status,
                "error_code": state.error_code,
                "error_detail": state.error_detail,
                "reviewer_identity": state.reviewed_by,
                "review_reason": sanitized_review_reason,
            }),
            occurred_at=_utc_now(),
            created_at=_utc_now(),
        )
        self.session.add(event)
        self.session.flush()
        return state


__all__ = [
    "OpenRelPolicyPlanValidationError",
    "OpenRelPolicyStore",
    "OpenRelPolicyStoreCollisionError",
    "OpenRelPolicyStoreError",
    "OpenRelPolicyTransitionError",
    "compute_candidate_digest",
    "sanitize_audit_details",
]
