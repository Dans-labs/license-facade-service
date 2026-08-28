from __future__ import annotations

import hashlib
import json
import unicodedata
import uuid
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any
from urllib.parse import quote

from sqlalchemy import select
from sqlalchemy.exc import IntegrityError, OperationalError, SQLAlchemyError

from src.license_facade_service.config.custom_licence import CustomLicenceRegistrationSettings
from src.license_facade_service.config.federation import FederationSettings
from src.license_facade_service.custom_licences.models import (
    CustomLicenceLifecycleStatus,
    FederationStatus,
    PublicLicenseScope,
    SpdxSubmissionStatus,
)
from src.license_facade_service.db.models.custom_licence import (
    CustomLicence,
    CustomLicenceAlias,
    CustomLicenceAuditEvent,
    CustomLicenceFederationOutbox,
    normalize_alias,
)
from src.license_facade_service.db.session import Database
from src.license_facade_service.services.custom_licence_federation_publication import (
    OUTBOX_OPERATION_UPSERT,
    OUTBOX_STATUS_PENDING,
    CustomLicenceFederationPublicationError,
    CustomLicenceFederationPublicationService,
)
from src.license_facade_service.services.spdx_custom_license import (
    SpdxCustomLicenseBuilder,
    SpdxCustomLicenseBuilderInput,
    validate_custom_license_identifier,
)
from src.license_facade_service.services.spdx_validation import SpdxStructuralValidationError

_RESOLVING_UUID_NAMESPACE = uuid.UUID("6da6ff74-1026-4fc9-a5a8-dd4236688281")


class CustomLicenceRegistrationError(Exception):
    def __init__(
        self,
        *,
        status: int,
        type_slug: str,
        title: str,
        detail: str,
        extra: dict[str, Any] | None = None,
    ) -> None:
        super().__init__(detail)
        self.status = status
        self.type_slug = type_slug
        self.title = title
        self.detail = detail
        self.extra = extra or {}


@dataclass(frozen=True)
class RegisterCustomLicenceInput:
    requested_license_id: str
    version: str
    name: str
    summary: str | None
    description: str | None
    license_text: str
    scope: PublicLicenseScope
    aliases: tuple[str, ...]
    creator_role: str


@dataclass(frozen=True)
class RegisterCustomLicenceResult:
    id: uuid.UUID
    requested_license_id: str
    version: str
    canonical_id: str
    resolving_uuid: uuid.UUID
    resolving_uri: str
    name: str
    summary: str | None
    description: str | None
    scope: PublicLicenseScope
    federation_status: FederationStatus
    spdx_submission_status: SpdxSubmissionStatus
    lifecycle_status: CustomLicenceLifecycleStatus
    normalized_text_digest: str
    spdx_jsonld: dict[str, Any]
    created_at: datetime
    updated_at: datetime


def normalize_legal_text_for_digest(license_text: str) -> str:
    """Deterministic digest normalization for duplicate detection only."""
    normalized = unicodedata.normalize("NFKC", license_text)
    normalized = normalized.replace("\r\n", "\n").replace("\r", "\n")
    return normalized


def compute_normalized_text_digest(license_text: str) -> str:
    normalized = normalize_legal_text_for_digest(license_text)
    return hashlib.sha256(normalized.encode("utf-8")).hexdigest()


def _identity_seed(*, authority_id: str, requested_license_id: str, version: str) -> str:
    return json.dumps([authority_id, requested_license_id, version], ensure_ascii=False, separators=(",", ":"))


def build_canonical_id(*, authority_id: str, requested_license_id: str, version: str) -> str:
    authority = quote(authority_id, safe="")
    requested = quote(requested_license_id, safe="")
    encoded_version = quote(version, safe="")
    return f"lfs-custom:{authority}:{requested}:{encoded_version}"


def build_resolving_uuid(*, authority_id: str, requested_license_id: str, version: str) -> uuid.UUID:
    return uuid.uuid5(
        _RESOLVING_UUID_NAMESPACE,
        _identity_seed(authority_id=authority_id, requested_license_id=requested_license_id, version=version),
    )


def build_spdx_custom_license_identifier(*, resolving_uuid: uuid.UUID) -> str:
    return f"CustomLicense-{resolving_uuid}"


def build_versioned_requested_id_alias(*, requested_license_id: str, version: str) -> str:
    requested = quote(requested_license_id, safe="")
    encoded_version = quote(version, safe="")
    return f"requested-id:{requested}:version:{encoded_version}"


def build_resolving_uri(*, authority_base_iri: str, authority_id: str, requested_license_id: str, version: str) -> str:
    authority = quote(authority_id, safe="")
    requested = quote(requested_license_id, safe="")
    encoded_version = quote(version, safe="")
    return f"{authority_base_iri.rstrip('/')}/custom-licences/{authority}/{requested}/{encoded_version}"


@dataclass
class RegistrationFailureInjection:
    fail_alias_insert: bool = False
    fail_audit_insert: bool = False
    fail_before_commit: bool = False


class CustomLicenceRegistrationService:
    def __init__(
        self,
        *,
        settings: CustomLicenceRegistrationSettings,
        federation_settings: FederationSettings | None = None,
        federation_ready: bool = False,
        spdx_builder: SpdxCustomLicenseBuilder | None = None,
        failure_injection: RegistrationFailureInjection | None = None,
    ) -> None:
        self.settings = settings
        self.federation_settings = federation_settings or FederationSettings.from_env()
        self.federation_ready = federation_ready
        self.spdx_builder = spdx_builder or SpdxCustomLicenseBuilder()
        self._db: Database | None = None
        self._publication_service: CustomLicenceFederationPublicationService | None = None
        self.failure_injection = failure_injection or RegistrationFailureInjection()

    def close(self) -> None:
        if self._db is not None:
            self._db.close()
            self._db = None
        self._publication_service = None

    @property
    def db(self) -> Database:
        if self.settings.database_url is None:
            raise CustomLicenceRegistrationError(
                status=503,
                type_slug="custom-licence-registration-config-invalid",
                title="Custom Licence Registration Unavailable",
                detail="Custom licence registration is not configured for this deployment.",
            )
        if self._db is None:
            self._db = Database.from_url(self.settings.database_url)
        return self._db

    def _assert_configuration(self) -> None:
        if self.settings.validation_errors:
            raise CustomLicenceRegistrationError(
                status=503,
                type_slug="custom-licence-registration-config-invalid",
                title="Custom Licence Registration Unavailable",
                detail="Custom licence registration is unavailable for this deployment.",
            )
        if self.settings.authority_id is None or self.settings.authority_base_iri is None:
            raise CustomLicenceRegistrationError(
                status=503,
                type_slug="custom-licence-registration-config-invalid",
                title="Custom Licence Registration Unavailable",
                detail="Custom licence registration is unavailable for this deployment.",
            )

    def _assert_federated_configuration(self) -> None:
        try:
            self.publication_service.assert_federated_registration_supported()
        except CustomLicenceFederationPublicationError as exc:
            raise CustomLicenceRegistrationError(
                status=exc.status,
                type_slug=exc.code,
                title="Custom Licence Registration Unavailable",
                detail=exc.detail,
            ) from exc

    @property
    def publication_service(self) -> CustomLicenceFederationPublicationService:
        if self._publication_service is None:
            self._publication_service = CustomLicenceFederationPublicationService(
                db=self.db,
                custom_settings=self.settings,
                federation_settings=self.federation_settings,
                federation_ready=self.federation_ready,
            )
        return self._publication_service

    def _validate_generated_lengths(
        self,
        *,
        canonical_id: str,
        resolving_uri: str,
        deduplicated_aliases: list[tuple[str, str, str]],
    ) -> None:
        if len(canonical_id) > 512:
            raise CustomLicenceRegistrationError(
                status=422,
                type_slug="custom-licence-generated-identity-too-long",
                title="Generated Identity Too Long",
                detail="Generated canonical identity exceeds supported length.",
            )
        if len(resolving_uri) > 512:
            raise CustomLicenceRegistrationError(
                status=422,
                type_slug="custom-licence-generated-identity-too-long",
                title="Generated Identity Too Long",
                detail="Generated resolving URI exceeds supported length.",
            )
        for _, alias_value, normalized_alias in deduplicated_aliases:
            if len(alias_value) > 512 or len(normalized_alias) > 512:
                raise CustomLicenceRegistrationError(
                    status=422,
                    type_slug="custom-licence-generated-identity-too-long",
                    title="Generated Identity Too Long",
                    detail="One or more generated aliases exceed supported length.",
                )

    def register(self, payload: RegisterCustomLicenceInput) -> RegisterCustomLicenceResult:
        self._assert_configuration()
        assert self.settings.authority_id is not None
        assert self.settings.authority_base_iri is not None
        assert self.settings.creator_organization_name is not None

        if payload.scope == PublicLicenseScope.LOCAL:
            federation_status = FederationStatus.NOT_PUBLISHED
            spdx_submission_status = SpdxSubmissionStatus.NOT_REQUESTED
        elif payload.scope == PublicLicenseScope.FEDERATED:
            self._assert_federated_configuration()
            federation_status = FederationStatus.PENDING
            spdx_submission_status = SpdxSubmissionStatus.NOT_REQUESTED
        elif payload.scope == PublicLicenseScope.SPDX_SUBMISSION:
            federation_status = FederationStatus.NOT_PUBLISHED
            spdx_submission_status = SpdxSubmissionStatus.READY_FOR_REVIEW
        else:
            raise CustomLicenceRegistrationError(
                status=422,
                type_slug="custom-licence-scope-unsupported",
                title="Unsupported Scope",
                detail=f"Scope '{payload.scope.value}' is not supported.",
            )

        try:
            validate_custom_license_identifier(payload.requested_license_id)
            validate_custom_license_identifier(payload.version)
        except ValueError as exc:
            raise CustomLicenceRegistrationError(
                status=422,
                type_slug="custom-licence-invalid-identifier",
                title="Invalid Identifier",
                detail=str(exc),
            ) from exc

        canonical_id = build_canonical_id(
            authority_id=self.settings.authority_id,
            requested_license_id=payload.requested_license_id,
            version=payload.version,
        )
        resolving_uuid = build_resolving_uuid(
            authority_id=self.settings.authority_id,
            requested_license_id=payload.requested_license_id,
            version=payload.version,
        )
        resolving_uri = build_resolving_uri(
            authority_base_iri=self.settings.authority_base_iri,
            authority_id=self.settings.authority_id,
            requested_license_id=payload.requested_license_id,
            version=payload.version,
        )
        versioned_requested_alias = build_versioned_requested_id_alias(
            requested_license_id=payload.requested_license_id,
            version=payload.version,
        )

        aliases: list[tuple[str, str]] = [
            ("requested_id", versioned_requested_alias),
            ("canonical_id", canonical_id),
            ("resolving_uuid", str(resolving_uuid)),
            ("resolving_uri", resolving_uri),
        ]
        aliases.extend(("legacy", alias) for alias in payload.aliases)
        deduplicated_aliases: list[tuple[str, str, str]] = []
        seen_normalized: set[str] = set()
        try:
            for alias_type, alias_value in aliases:
                normalized = normalize_alias(alias_value)
                if normalized in seen_normalized:
                    continue
                seen_normalized.add(normalized)
                deduplicated_aliases.append((alias_type, alias_value, normalized))
        except ValueError as exc:
            raise CustomLicenceRegistrationError(
                status=422,
                type_slug="custom-licence-generated-identity-too-long",
                title="Generated Identity Too Long",
                detail="Generated identifiers or aliases exceed supported length.",
            ) from exc

        self._validate_generated_lengths(
            canonical_id=canonical_id,
            resolving_uri=resolving_uri,
            deduplicated_aliases=deduplicated_aliases,
        )

        normalized_text_digest = compute_normalized_text_digest(payload.license_text)
        created_at = datetime.now(timezone.utc)

        try:
            spdx_jsonld = self.spdx_builder.build(
                SpdxCustomLicenseBuilderInput(
                    authority_base_iri=self.settings.authority_base_iri,
                    creator_organization_name=self.settings.creator_organization_name,
                    creator_organization_iri=self.settings.creator_organization_iri,
                    custom_license_id=build_spdx_custom_license_identifier(resolving_uuid=resolving_uuid),
                    name=payload.name,
                    summary=payload.summary,
                    description=payload.description,
                    license_text=payload.license_text,
                    created_at=created_at,
                )
            )
        except SpdxStructuralValidationError as exc:
            raise CustomLicenceRegistrationError(
                status=422,
                type_slug="custom-licence-spdx-structural-validation-failed",
                title="SPDX Structural Validation Failed",
                detail="Generated SPDX document failed structural validation.",
            ) from exc
        except ValueError as exc:
            raise CustomLicenceRegistrationError(
                status=500,
                type_slug="custom-licence-spdx-generation-failed",
                title="SPDX Generation Failed",
                detail="Failed to generate a structurally valid SPDX document.",
            ) from exc

        record = CustomLicence(
            id=uuid.uuid4(),
            authority_id=self.settings.authority_id,
            requested_license_id=payload.requested_license_id,
            version=payload.version,
            canonical_id=canonical_id,
            resolving_uuid=resolving_uuid,
            public_scope=payload.scope.value,
            federation_status=federation_status.value,
            spdx_submission_status=spdx_submission_status.value,
            lifecycle_status=CustomLicenceLifecycleStatus.REGISTERED.value,
            name=payload.name,
            summary=payload.summary,
            description=payload.description,
            license_text=payload.license_text,
            normalized_text_digest=normalized_text_digest,
            spdx_jsonld=spdx_jsonld,
            creator_role=payload.creator_role,
            created_at=created_at,
            updated_at=created_at,
        )
        after_state = {
            "requestedLicenseId": payload.requested_license_id,
            "version": payload.version,
            "canonicalId": canonical_id,
            "resolvingUuid": str(resolving_uuid),
            "resolvingUri": resolving_uri,
            "scope": payload.scope.value,
            "federationStatus": federation_status.value,
            "spdxSubmissionStatus": spdx_submission_status.value,
            "lifecycleStatus": CustomLicenceLifecycleStatus.REGISTERED.value,
        }

        try:
            with self.db.transaction() as session:
                session.add(record)
                session.flush()
                for alias_type, alias_value, normalized_alias in deduplicated_aliases:
                    if self.failure_injection.fail_alias_insert:
                        raise RuntimeError("forced-alias-insert-failure")
                    session.add(
                        CustomLicenceAlias(
                            id=uuid.uuid4(),
                            custom_licence_id=record.id,
                            alias_type=alias_type,
                            alias=alias_value,
                            normalized_alias=normalized_alias,
                            created_at=created_at,
                        )
                    )
                if self.failure_injection.fail_audit_insert:
                    raise RuntimeError("forced-audit-insert-failure")
                session.add(
                    CustomLicenceAuditEvent(
                        id=uuid.uuid4(),
                        custom_licence_id=record.id,
                        event_type="custom_licence_registered",
                        actor_role=payload.creator_role,
                        actor_identifier=None,
                        before_state=None,
                        after_state=after_state,
                        source="api.v1.licenses.register_custom_licence",
                        created_at=created_at,
                    )
                )
                if payload.scope == PublicLicenseScope.FEDERATED:
                    session.add(
                        CustomLicenceFederationOutbox(
                            id=uuid.uuid4(),
                            custom_licence_id=record.id,
                            operation=OUTBOX_OPERATION_UPSERT,
                            status=OUTBOX_STATUS_PENDING,
                            attempt_count=0,
                            available_at=created_at,
                            lease_owner=None,
                            lease_expires_at=None,
                            last_error_class=None,
                            last_error_at=None,
                            federation_record_id=None,
                            federation_event_id=None,
                            created_at=created_at,
                            updated_at=created_at,
                            published_at=None,
                        )
                    )
                session.flush()
                if self.failure_injection.fail_before_commit:
                    raise RuntimeError("forced-pre-commit-failure")
        except OperationalError as exc:
            raise CustomLicenceRegistrationError(
                status=503,
                type_slug="custom-licence-database-unavailable",
                title="Custom Licence Registration Unavailable",
                detail="Custom licence registration database is unavailable.",
            ) from exc
        except IntegrityError as exc:
            constraint_name = getattr(getattr(exc.orig, "diag", None), "constraint_name", None)
            if constraint_name == "uq_custom_licences_authority_requested_version":
                existing = self._lookup_existing_reference(payload.requested_license_id, payload.version)
                raise CustomLicenceRegistrationError(
                    status=409,
                    type_slug="custom-licence-already-exists",
                    title="Custom Licence Already Registered",
                    detail="A custom licence with the same authority, requested ID, and version already exists.",
                    extra=existing,
                ) from exc
            if constraint_name in {"uq_custom_licences_canonical_id", "uq_custom_licences_resolving_uuid"}:
                raise CustomLicenceRegistrationError(
                    status=409,
                    type_slug="custom-licence-identity-conflict",
                    title="Custom Licence Identity Conflict",
                    detail="A conflicting custom licence identity already exists.",
                ) from exc
            if constraint_name == "uq_custom_licence_aliases_normalized_alias":
                raise CustomLicenceRegistrationError(
                    status=409,
                    type_slug="custom-licence-alias-conflict",
                    title="Custom Licence Alias Conflict",
                    detail="One or more aliases already resolve to a different custom licence.",
                ) from exc
            raise CustomLicenceRegistrationError(
                status=500,
                type_slug="custom-licence-persistence-failed",
                title="Custom Licence Persistence Failed",
                detail="Could not persist the custom licence registration.",
            ) from exc
        except CustomLicenceRegistrationError:
            raise
        except SQLAlchemyError as exc:
            raise CustomLicenceRegistrationError(
                status=500,
                type_slug="custom-licence-persistence-failed",
                title="Custom Licence Persistence Failed",
                detail="Could not persist the custom licence registration.",
            ) from exc
        except Exception as exc:
            raise CustomLicenceRegistrationError(
                status=500,
                type_slug="custom-licence-persistence-failed",
                title="Custom Licence Persistence Failed",
                detail="Could not persist the custom licence registration.",
            ) from exc

        return RegisterCustomLicenceResult(
            id=record.id,
            requested_license_id=record.requested_license_id,
            version=record.version,
            canonical_id=record.canonical_id,
            resolving_uuid=record.resolving_uuid,
            resolving_uri=resolving_uri,
            name=record.name,
            summary=record.summary,
            description=record.description,
            scope=PublicLicenseScope(record.public_scope),
            federation_status=FederationStatus(record.federation_status),
            spdx_submission_status=SpdxSubmissionStatus(record.spdx_submission_status),
            lifecycle_status=CustomLicenceLifecycleStatus(record.lifecycle_status),
            normalized_text_digest=record.normalized_text_digest,
            spdx_jsonld=record.spdx_jsonld,
            created_at=record.created_at,
            updated_at=record.updated_at,
        )

    def _lookup_existing_reference(self, requested_license_id: str, version: str) -> dict[str, Any]:
        if self.settings.authority_id is None:
            return {}
        with self.db.transaction() as session:
            statement = (
                select(CustomLicence.id, CustomLicence.canonical_id, CustomLicence.resolving_uuid)
                .where(CustomLicence.authority_id == self.settings.authority_id)
                .where(CustomLicence.requested_license_id == requested_license_id)
                .where(CustomLicence.version == version)
                .limit(1)
            )
            row = session.execute(statement).one_or_none()
            if row is None:
                return {}
            return {
                "existingRecord": {
                    "id": str(row.id),
                    "canonicalId": row.canonical_id,
                    "resolvingUuid": str(row.resolving_uuid),
                }
            }


__all__ = [
    "CustomLicenceRegistrationError",
    "CustomLicenceRegistrationService",
    "RegisterCustomLicenceInput",
    "RegisterCustomLicenceResult",
    "RegistrationFailureInjection",
    "build_canonical_id",
    "build_resolving_uri",
    "build_resolving_uuid",
    "build_spdx_custom_license_identifier",
    "build_versioned_requested_id_alias",
    "compute_normalized_text_digest",
    "normalize_legal_text_for_digest",
]
