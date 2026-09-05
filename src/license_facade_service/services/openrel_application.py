from __future__ import annotations

import hashlib
import json
import re
import uuid
from copy import deepcopy
from datetime import datetime, timezone
from typing import Any, Literal
from urllib.parse import urlparse

from pydantic import BaseModel, ConfigDict, Field, ValidationError, model_validator
from sqlalchemy import select
from sqlalchemy.orm import Session

from src.license_facade_service.db.models.custom_licence import (
    CustomLicence,
    CustomLicenceAuditEvent,
    CustomLicenceFederationOutbox,
    CustomLicenceRepresentation,
)
from src.license_facade_service.db.models.federation import FederationRecord
from src.license_facade_service.db.models.federation import FederationChangeEvent
from src.license_facade_service.db.models.openrel_policy import OpenRelPolicyState
from src.license_facade_service.services.custom_licence_federation_publication import (
    OUTBOX_OPERATION_UPSERT,
    OUTBOX_STATUS_PUBLISHED,
    build_custom_licence_federation_payload,
    build_federation_local_id,
)
from src.license_facade_service.config.custom_licence import CustomLicenceRegistrationSettings
from src.license_facade_service.services.custom_licence_registration import compute_normalized_text_digest
from src.license_facade_service.services.openrel_policy import OpenRelPolicyAction, OpenRelPolicyMode
from src.license_facade_service.services.openrel_policy_store import (
    OpenRelPolicyStore,
    compute_candidate_digest,
    sanitize_audit_details,
)
from src.license_facade_service.federation.license_identity import build_canonical_license_identity
from src.license_facade_service.federation.outbound import _latest_event_for_record
from src.license_facade_service.federation.outbound import FederationError
from src.license_facade_service.federation.outbound import FederationPublicationService


OPENREL_FEDERATION_IDEMPOTENCY_NAMESPACE = uuid.UUID("7b2b1a1a-0b1d-5a45-bb58-3c91263b7bc0")


_SUPPORTED_MAPPING_MEDIA_TYPES = {"application/json", "application/ld+json"}


class OpenRelApplicationError(ValueError):
    pass


class OpenRelApplicationConflictError(OpenRelApplicationError):
    pass


class OpenRelApplicationValidationError(OpenRelApplicationError):
    pass


class OpenRelApplicationUnavailableError(OpenRelApplicationError):
    pass


def _utc_now() -> datetime:
    return datetime.now(timezone.utc)


def _normalize_timestamp(value: datetime | None) -> str | None:
    if value is None:
        return None
    normalized = value.astimezone(timezone.utc).replace(microsecond=0)
    return normalized.isoformat().replace("+00:00", "Z")


def _canonical_json_bytes(value: Any) -> bytes:
    return json.dumps(deepcopy(value), ensure_ascii=False, separators=(",", ":"), sort_keys=True, allow_nan=False).encode("utf-8")


def _sha256_hex(value: Any) -> str:
    return hashlib.sha256(_canonical_json_bytes(value)).hexdigest()


def _canonical_json_text(value: Any) -> str:
    return _canonical_json_bytes(value).decode("utf-8")


def _https_uri(value: str, *, allow_pathless: bool = True) -> str:
    if not isinstance(value, str) or not value.strip():
        raise ValueError("value must be a nonblank string")
    parsed = urlparse(value)
    if parsed.scheme != "https" or not parsed.netloc or parsed.username or parsed.password:
        raise ValueError("value must be an absolute https URI without credentials")
    if not allow_pathless and not parsed.path:
        raise ValueError("value must include a path")
    return value


class FullReplacementCandidate(BaseModel):
    model_config = ConfigDict(extra="forbid")

    name: str = Field(min_length=1, max_length=512)
    summary: str | None = None
    description: str | None = None
    licenseText: str = Field(min_length=1)
    spdxJsonld: dict[str, Any]

    @model_validator(mode="after")
    def _validate_nonblank(self) -> "FullReplacementCandidate":
        if not self.name.strip():
            raise ValueError("name must be nonblank")
        if not self.licenseText.strip():
            raise ValueError("licenseText must be nonblank")
        return self


class HistoricalMappingCandidate(BaseModel):
    model_config = ConfigDict(extra="forbid")

    mediaType: str = Field(min_length=1)
    profile: str
    vocabulary: str
    content: dict[str, Any] | None = None
    href: str | None = None
    mappingProfile: str
    mappingProvenance: dict[str, Any]

    @model_validator(mode="after")
    def _validate_mapping(self) -> "HistoricalMappingCandidate":
        if not self.mediaType.strip() or self.mediaType not in _SUPPORTED_MAPPING_MEDIA_TYPES:
            raise ValueError("unsupported mediaType")
        self.profile = _https_uri(self.profile)
        self.vocabulary = _https_uri(self.vocabulary)
        self.mappingProfile = _https_uri(self.mappingProfile)
        if self.href is not None:
            self.href = _https_uri(self.href)
        if self.content is None and self.href is None:
            raise ValueError("either content or href is required")
        if not self.mappingProvenance:
            raise ValueError("mappingProvenance must be non-empty")
        return self


def build_custom_licence_snapshot(
    custom_licence: CustomLicence,
    active_representations: list[CustomLicenceRepresentation],
) -> dict[str, Any]:
    return {
        "name": custom_licence.name,
        "summary": custom_licence.summary,
        "description": custom_licence.description,
        "license_text": custom_licence.license_text,
        "normalized_text_digest": custom_licence.normalized_text_digest,
        "spdx_jsonld": deepcopy(custom_licence.spdx_jsonld),
        "public_scope": custom_licence.public_scope,
        "federation_status": custom_licence.federation_status,
        "spdx_submission_status": custom_licence.spdx_submission_status,
        "lifecycle_status": custom_licence.lifecycle_status,
        "deprecated_at": _normalize_timestamp(custom_licence.deprecated_at),
        "withdrawn_at": _normalize_timestamp(custom_licence.withdrawn_at),
        "tombstoned_at": _normalize_timestamp(custom_licence.tombstoned_at),
        "representations": [
            {
                "representation_type": row.representation_type,
                "status": row.status,
                "media_type": row.media_type,
                "profile_uri": row.profile_uri,
                "vocabulary_uri": row.vocabulary_uri,
                "content": deepcopy(row.content),
                "href": row.href,
                "content_digest_sha256": row.content_digest_sha256,
                "mapping_profile": row.mapping_profile,
                "mapping_provenance": deepcopy(row.mapping_provenance),
                "source_policy_state_id": str(row.source_policy_state_id),
                "rolled_back_at": _normalize_timestamp(row.rolled_back_at),
            }
            for row in sorted(active_representations, key=lambda item: (item.created_at, item.id))
        ],
    }


def compute_custom_licence_snapshot_digest(snapshot: dict[str, Any]) -> str:
    return hashlib.sha256(_canonical_json_bytes(snapshot)).hexdigest()


def _safe_snapshot_summary(snapshot: dict[str, Any]) -> dict[str, Any]:
    return {
        "name": snapshot["name"],
        "public_scope": snapshot["public_scope"],
        "federation_status": snapshot["federation_status"],
        "spdx_submission_status": snapshot["spdx_submission_status"],
        "lifecycle_status": snapshot["lifecycle_status"],
        "normalized_text_digest": snapshot["normalized_text_digest"],
        "representation_count": len(snapshot["representations"]),
    }


class OpenRelApplicationService:
    def __init__(
        self,
        session: Session,
        *,
        federation_publisher: FederationPublicationService | None = None,
        federation_payload_builder: Any | None = None,
        federation_custom_settings: CustomLicenceRegistrationSettings | None = None,
    ) -> None:
        self.session = session
        self.store = OpenRelPolicyStore(session)
        self.federation_publisher = federation_publisher
        self.federation_payload_builder = federation_payload_builder or build_custom_licence_federation_payload
        self.federation_custom_settings = federation_custom_settings

    def _load_locked_state(self, state_id: uuid.UUID) -> OpenRelPolicyState:
        state = (
            self.session.execute(select(OpenRelPolicyState).where(OpenRelPolicyState.id == state_id).with_for_update())
            .scalars()
            .one_or_none()
        )
        if state is None:
            raise OpenRelApplicationConflictError("policy state not found")
        return state

    def _resolve_locked_target(self, state: OpenRelPolicyState) -> CustomLicence:
        if state.source_kind == "spdx":
            raise OpenRelApplicationConflictError("SPDX sources cannot be applied")
        if state.source_kind == "federation-imported":
            raise OpenRelApplicationConflictError("imported records cannot be applied")
        if state.source_kind != "custom":
            raise OpenRelApplicationConflictError("only local custom licences are supported")
        if not state.source_record_ref:
            raise OpenRelApplicationConflictError("state source_record_ref is required")
        try:
            target_id = uuid.UUID(str(state.source_record_ref))
        except ValueError as exc:
            raise OpenRelApplicationConflictError("state source_record_ref is not a custom licence UUID") from exc
        target = (
            self.session.execute(select(CustomLicence).where(CustomLicence.id == target_id).with_for_update())
            .scalars()
            .one_or_none()
        )
        if target is None:
            raise OpenRelApplicationConflictError("target custom licence not found")
        if target.public_scope not in {"local", "federated"}:
            raise OpenRelApplicationConflictError("only local or federated custom licences are supported")
        if state.target_custom_licence_id is not None and state.target_custom_licence_id != target.id:
            raise OpenRelApplicationConflictError("state target link does not match resolved custom licence")
        return target

    def _load_locked_federation_outbox(self, custom_licence_id: uuid.UUID) -> CustomLicenceFederationOutbox:
        rows = (
            self.session.execute(
                select(CustomLicenceFederationOutbox)
                .where(
                    CustomLicenceFederationOutbox.custom_licence_id == custom_licence_id,
                    CustomLicenceFederationOutbox.operation == OUTBOX_OPERATION_UPSERT,
                )
                .with_for_update()
            )
            .scalars()
            .all()
        )
        if len(rows) != 1:
            raise OpenRelApplicationConflictError("federation publication linkage is missing or inconsistent")
        row = rows[0]
        if (
            row.status != OUTBOX_STATUS_PUBLISHED
            or row.federation_record_id is None
            or row.federation_event_id is None
            or row.published_at is None
            or row.lease_owner is not None
            or row.lease_expires_at is not None
            or row.last_error_class is not None
            or row.last_error_at is not None
        ):
            raise OpenRelApplicationConflictError("federation publication linkage is missing or inconsistent")
        return row

    def _require_federation_dependencies(self) -> FederationPublicationService:
        if self.federation_publisher is None:
            raise OpenRelApplicationUnavailableError("required federated publication dependency is unavailable")
        return self.federation_publisher

    def _federation_idempotency_key(self, *, state_id: uuid.UUID, action: Literal["apply", "rollback"]) -> uuid.UUID:
        return uuid.uuid5(OPENREL_FEDERATION_IDEMPOTENCY_NAMESPACE, f"openrel-policy-state:{state_id}:{action}")

    def _safe_federation_provenance(self, *, state: OpenRelPolicyState, action: Literal["apply", "rollback"]) -> dict[str, Any]:
        return {
            "source": "openrel-policy",
            "policyStateId": str(state.id),
            "action": action,
            "policyVersion": state.policy_version,
            "candidateDigest": state.candidate_digest_sha256,
        }

    def _validate_federated_target_and_record(
        self,
        *,
        target: CustomLicence,
        outbox: CustomLicenceFederationOutbox,
    ) -> FederationRecord:
        publisher = self._require_federation_dependencies()
        record = (
            self.session.execute(select(FederationRecord).where(FederationRecord.id == outbox.federation_record_id).with_for_update())
            .scalars()
            .one_or_none()
        )
        if record is None:
            raise OpenRelApplicationConflictError("federation publication linkage is missing or inconsistent")
        if not record.is_authoritative or record.imported_from_peer_id is not None:
            raise OpenRelApplicationConflictError("federation publication linkage is missing or inconsistent")
        if record.authority_node_id != publisher.settings.node_id:
            raise OpenRelApplicationConflictError("federation publication linkage is missing or inconsistent")
        expected_local_id = build_federation_local_id(custom_licence_id=target.id)
        expected = build_canonical_license_identity(
            authority_node_id=record.authority_node_id,
            local_id=expected_local_id,
            version=target.version,
        )
        if (
            record.local_id != expected_local_id
            or record.version != target.version
            or record.canonical_id != expected.canonicalId
            or str(record.resolving_uuid) != expected.resolvingUuid
        ):
            raise OpenRelApplicationConflictError("federation publication linkage is missing or inconsistent")
        latest = _latest_event_for_record(
            self.session,
            record=record,
            authority_node_id=record.authority_node_id,
            for_update=False,
        )
        if latest is None and outbox.federation_event_id is not None:
            latest = (
                self.session.execute(select(FederationChangeEvent).where(FederationChangeEvent.id == outbox.federation_event_id))
                .scalars()
                .one_or_none()
            )
        if latest is None:
            raise OpenRelApplicationConflictError("federation publication linkage is missing or inconsistent")
        if getattr(latest, "operation", "upsert") in {"deprecate", "tombstone"}:
            raise OpenRelApplicationConflictError("federation publication linkage is missing or inconsistent")
        return record

    def _build_federation_payload(self, *, target: CustomLicence, rows: list[CustomLicenceRepresentation]) -> dict[str, Any]:
        publisher = self._require_federation_dependencies()
        if self.federation_custom_settings is None:
            raise OpenRelApplicationUnavailableError("required federated publication dependency is unavailable")
        aliases = []
        if hasattr(target, "aliases") and target.aliases:
            aliases = sorted({alias.alias for alias in target.aliases if getattr(alias, "alias", None)})
        return self.federation_payload_builder(
            target,
            custom_settings=self.federation_custom_settings,
            publishing_node_id=publisher.settings.node_id or "",
            aliases=aliases,
            representations=self._active_representations(rows),
        )

    def _federation_domain_error(self, exc: Exception) -> OpenRelApplicationError:
        if isinstance(exc, OpenRelApplicationError):
            return exc
        if isinstance(exc, FederationError):
            return OpenRelApplicationConflictError(exc.detail)
        return OpenRelApplicationConflictError(str(exc))

    def _load_locked_representations(self, custom_licence_id: uuid.UUID) -> list[CustomLicenceRepresentation]:
        return list(
            self.session.execute(
                select(CustomLicenceRepresentation)
                .where(CustomLicenceRepresentation.custom_licence_id == custom_licence_id)
                .order_by(CustomLicenceRepresentation.created_at.asc(), CustomLicenceRepresentation.id.asc())
                .with_for_update()
            )
            .scalars()
            .all()
        )

    def _active_representations(self, rows: list[CustomLicenceRepresentation]) -> list[CustomLicenceRepresentation]:
        return [row for row in rows if row.status == "active"]

    def _parse_replacement_candidate(self, state: OpenRelPolicyState) -> FullReplacementCandidate:
        if compute_candidate_digest(state.candidate_payload) != state.candidate_digest_sha256:
            raise OpenRelApplicationConflictError("candidate digest does not match persisted payload")
        try:
            return FullReplacementCandidate.model_validate(deepcopy(state.candidate_payload))
        except ValidationError as exc:
            raise OpenRelApplicationValidationError("persisted replacement candidate is invalid") from exc

    def _parse_mapping_candidate(self, state: OpenRelPolicyState) -> HistoricalMappingCandidate:
        if compute_candidate_digest(state.candidate_payload) != state.candidate_digest_sha256:
            raise OpenRelApplicationConflictError("candidate digest does not match persisted payload")
        try:
            candidate = HistoricalMappingCandidate.model_validate(deepcopy(state.candidate_payload))
        except ValidationError as exc:
            raise OpenRelApplicationValidationError("persisted historical mapping candidate is invalid") from exc
        if candidate.mappingProfile != state.mapping_profile:
            raise OpenRelApplicationConflictError("mappingProfile does not match persisted policy state")
        persisted_mapping_provenance = state.mapping_provenance
        if persisted_mapping_provenance is None:
            raise OpenRelApplicationConflictError("mappingProvenance does not match persisted policy state")
        if isinstance(persisted_mapping_provenance, str):
            try:
                persisted_mapping_provenance_value = json.loads(persisted_mapping_provenance)
            except json.JSONDecodeError as exc:
                raise OpenRelApplicationConflictError("mappingProvenance does not match persisted policy state") from exc
        else:
            persisted_mapping_provenance_value = deepcopy(persisted_mapping_provenance)
        if candidate.mappingProvenance != persisted_mapping_provenance_value:
            raise OpenRelApplicationConflictError("mappingProvenance does not match persisted policy state")
        return candidate

    def _record_custom_audit(
        self,
        *,
        custom_licence_id: uuid.UUID,
        event_type: str,
        actor_id: str,
        before_state: dict[str, Any] | None,
        after_state: dict[str, Any] | None,
        source: str,
    ) -> None:
        self.session.add(
            CustomLicenceAuditEvent(
                id=uuid.uuid4(),
                custom_licence_id=custom_licence_id,
                event_type=event_type,
                actor_role="admin",
                actor_identifier=actor_id,
                before_state=sanitize_audit_details(before_state),
                after_state=sanitize_audit_details(after_state),
                source=source,
                created_at=_utc_now(),
            )
        )

    def apply(self, state_id: uuid.UUID, *, actor_id: str, reason: str | None = None) -> OpenRelPolicyState:
        if not actor_id or not actor_id.strip():
            raise OpenRelApplicationValidationError("actor_id is required")
        state = self._load_locked_state(state_id)
        if state.status == "rolled-back":
            raise OpenRelApplicationConflictError("rolled-back states require re-evaluation before apply")
        if state.status == "applied":
            if state.target_custom_licence_id is None or state.target_digest_after is None:
                raise OpenRelApplicationConflictError("applied state is missing target linkage")
            target = self._resolve_locked_target(state)
            rows = self._load_locked_representations(target.id)
            live_digest = compute_custom_licence_snapshot_digest(build_custom_licence_snapshot(target, self._active_representations(rows)))
            if live_digest != state.target_digest_after:
                raise OpenRelApplicationConflictError("live target no longer matches applied snapshot")
            return state
        if state.status != "approved":
            raise OpenRelApplicationConflictError("only approved states can be applied")
        if state.policy_mode != OpenRelPolicyMode.active.value:
            raise OpenRelApplicationConflictError("only active policy mode can be applied")
        if not state.apply_allowed:
            raise OpenRelApplicationConflictError("state is not allowed to apply")

        target = self._resolve_locked_target(state)
        rows = self._load_locked_representations(target.id)
        active_rows = self._active_representations(rows)
        federation_outbox = None
        federation_record = None
        if target.public_scope == "federated":
            if target.federation_status != "published":
                raise OpenRelApplicationConflictError("federated target is not in a supported published state")
            federation_outbox = self._load_locked_federation_outbox(target.id)
            federation_record = self._validate_federated_target_and_record(target=target, outbox=federation_outbox)
        before_snapshot = build_custom_licence_snapshot(target, active_rows)
        before_digest = compute_custom_licence_snapshot_digest(before_snapshot)
        now = _utc_now()

        def _apply_mutation() -> None:
            if state.action == OpenRelPolicyAction.full_replacement.value:
                candidate = self._parse_replacement_candidate(state)
                if state.original_content_digest_sha256 is not None and state.original_content_digest_sha256 != target.normalized_text_digest:
                    raise OpenRelApplicationConflictError("original content digest does not match target")
                target.name = candidate.name.strip()
                target.summary = candidate.summary
                target.description = candidate.description
                target.license_text = candidate.licenseText
                target.normalized_text_digest = compute_normalized_text_digest(candidate.licenseText)
                target.spdx_jsonld = deepcopy(candidate.spdxJsonld)
                target.updated_at = now
            elif state.action == OpenRelPolicyAction.historical_mapping.value:
                candidate = self._parse_mapping_candidate(state)
                existing = next((row for row in rows if row.source_policy_state_id == state.id), None)
                if existing is not None:
                    raise OpenRelApplicationConflictError("historical mapping representation already exists for state")
                self.session.add(
                    CustomLicenceRepresentation(
                        id=uuid.uuid4(),
                        custom_licence_id=target.id,
                        representation_type="openrel-mapping",
                        status="active",
                        media_type=candidate.mediaType,
                        profile_uri=candidate.profile,
                        vocabulary_uri=candidate.vocabulary,
                        content=deepcopy(candidate.content),
                        href=candidate.href,
                        content_digest_sha256=_sha256_hex(candidate.content if candidate.content is not None else {"href": candidate.href}),
                        mapping_profile=candidate.mappingProfile,
                        mapping_provenance=deepcopy(candidate.mappingProvenance),
                        source_policy_state_id=state.id,
                        created_at=now,
                        updated_at=now,
                        rolled_back_at=None,
                    )
                )
            else:
                raise OpenRelApplicationConflictError("unsupported apply action")

            self.session.flush()
            rows_after = self._load_locked_representations(target.id)
            after_snapshot = build_custom_licence_snapshot(target, self._active_representations(rows_after))
            after_digest = compute_custom_licence_snapshot_digest(after_snapshot)
            state.target_custom_licence_id = target.id
            state.target_snapshot_before = before_snapshot
            state.target_digest_before = before_digest
            state.target_snapshot_after = after_snapshot
            state.target_digest_after = after_digest
            state.applied_by = actor_id.strip()
            state.applied_at = now
            state.updated_at = now
            if federation_outbox is not None:
                payload = self._build_federation_payload(target=target, rows=rows_after)
                event = self._require_federation_dependencies().append_authoritative_upsert_in_session(
                    session=self.session,
                    record_id=federation_record.id,
                    idempotency_key=self._federation_idempotency_key(state_id=state.id, action="apply"),
                    payload=payload,
                    provenance=self._safe_federation_provenance(state=state, action="apply"),
                )
                federation_outbox.status = OUTBOX_STATUS_PUBLISHED
                federation_outbox.federation_record_id = federation_record.id
                federation_outbox.federation_event_id = event.id
                federation_outbox.published_at = now
                federation_outbox.lease_owner = None
                federation_outbox.lease_expires_at = None
                federation_outbox.last_error_class = None
                federation_outbox.last_error_at = None
                federation_outbox.updated_at = now
            self.store.transition_status(
                state.id,
                new_status="applied",
                actor_type="admin",
                actor_id=actor_id.strip(),
                review_reason=reason,
            )
            self._record_custom_audit(
                custom_licence_id=target.id,
                event_type="openrel_policy_applied",
                actor_id=actor_id.strip(),
                before_state={"digest": before_digest, "snapshot": _safe_snapshot_summary(before_snapshot)},
                after_state={"digest": after_digest, "snapshot": _safe_snapshot_summary(after_snapshot), "policyStateId": str(state.id)},
                source="services.openrel_application.apply",
            )
            self.session.flush()

        if federation_outbox is not None:
            try:
                with self.session.begin_nested():
                    _apply_mutation()
            except Exception as exc:
                raise self._federation_domain_error(exc) from exc
        else:
            _apply_mutation()
        return state

    def rollback(self, state_id: uuid.UUID, *, actor_id: str, reason: str | None = None) -> OpenRelPolicyState:
        if not actor_id or not actor_id.strip():
            raise OpenRelApplicationValidationError("actor_id is required")
        state = self._load_locked_state(state_id)
        if state.status == "rolled-back":
            target = self._resolve_locked_target(state)
            rows = self._load_locked_representations(target.id)
            live_digest = compute_custom_licence_snapshot_digest(build_custom_licence_snapshot(target, self._active_representations(rows)))
            if live_digest != state.target_digest_before:
                raise OpenRelApplicationConflictError("rolled-back target no longer matches restored snapshot")
            return state
        if state.status != "applied":
            raise OpenRelApplicationConflictError("only applied states can be rolled back")
        if state.target_digest_after is None or state.target_digest_before is None or state.target_snapshot_before is None:
            raise OpenRelApplicationConflictError("applied state is missing rollback metadata")
        target = self._resolve_locked_target(state)
        rows = self._load_locked_representations(target.id)
        active_rows = self._active_representations(rows)
        federation_outbox = None
        federation_record = None
        if target.public_scope == "federated":
            if target.federation_status != "published":
                raise OpenRelApplicationConflictError("federated target is not in a supported published state")
            federation_outbox = self._load_locked_federation_outbox(target.id)
            federation_record = self._validate_federated_target_and_record(target=target, outbox=federation_outbox)
        live_digest = compute_custom_licence_snapshot_digest(build_custom_licence_snapshot(target, active_rows))
        if live_digest != state.target_digest_after:
            raise OpenRelApplicationConflictError("target was modified after apply")
        before_snapshot = build_custom_licence_snapshot(target, active_rows)
        snapshot = deepcopy(state.target_snapshot_before)
        now = _utc_now()

        def _rollback_mutation() -> None:
            target.name = snapshot["name"]
            target.summary = snapshot["summary"]
            target.description = snapshot["description"]
            target.license_text = snapshot["license_text"]
            target.normalized_text_digest = snapshot["normalized_text_digest"]
            target.spdx_jsonld = deepcopy(snapshot["spdx_jsonld"])
            target.updated_at = now

            created_representation = next((row for row in rows if row.source_policy_state_id == state.id), None)
            if created_representation is not None:
                created_representation.status = "rolled-back"
                created_representation.rolled_back_at = now
                created_representation.updated_at = now

            self.session.flush()
            rows_after = self._load_locked_representations(target.id)
            restored_digest = compute_custom_licence_snapshot_digest(build_custom_licence_snapshot(target, self._active_representations(rows_after)))
            if restored_digest != state.target_digest_before:
                raise OpenRelApplicationConflictError("restored target digest does not match stored pre-apply digest")
            state.rolled_back_by = actor_id.strip()
            state.rolled_back_at = now
            state.updated_at = now
            if federation_outbox is not None:
                payload = self._build_federation_payload(target=target, rows=rows_after)
                event = self._require_federation_dependencies().append_authoritative_upsert_in_session(
                    session=self.session,
                    record_id=federation_record.id,
                    idempotency_key=self._federation_idempotency_key(state_id=state.id, action="rollback"),
                    payload=payload,
                    provenance=self._safe_federation_provenance(state=state, action="rollback"),
                )
                federation_outbox.status = OUTBOX_STATUS_PUBLISHED
                federation_outbox.federation_record_id = federation_record.id
                federation_outbox.federation_event_id = event.id
                federation_outbox.published_at = now
                federation_outbox.lease_owner = None
                federation_outbox.lease_expires_at = None
                federation_outbox.last_error_class = None
                federation_outbox.last_error_at = None
                federation_outbox.updated_at = now
            self.store.transition_status(
                state.id,
                new_status="rolled-back",
                actor_type="admin",
                actor_id=actor_id.strip(),
                review_reason=reason,
            )
            self._record_custom_audit(
                custom_licence_id=target.id,
                event_type="openrel_policy_rolled_back",
                actor_id=actor_id.strip(),
                before_state={"digest": state.target_digest_after, "snapshot": _safe_snapshot_summary(before_snapshot)},
                after_state={"digest": restored_digest, "snapshot": _safe_snapshot_summary(state.target_snapshot_before), "policyStateId": str(state.id)},
                source="services.openrel_application.rollback",
            )
            self.session.flush()

        if federation_outbox is not None:
            try:
                with self.session.begin_nested():
                    _rollback_mutation()
            except Exception as exc:
                raise self._federation_domain_error(exc) from exc
        else:
            _rollback_mutation()
        return state


__all__ = [
    "FullReplacementCandidate",
    "HistoricalMappingCandidate",
    "OpenRelApplicationConflictError",
    "OpenRelApplicationError",
    "OpenRelApplicationService",
    "OpenRelApplicationUnavailableError",
    "OpenRelApplicationValidationError",
    "OPENREL_FEDERATION_IDEMPOTENCY_NAMESPACE",
    "build_custom_licence_snapshot",
    "compute_custom_licence_snapshot_digest",
]
