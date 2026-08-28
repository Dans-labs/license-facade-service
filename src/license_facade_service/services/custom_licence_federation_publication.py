from __future__ import annotations

import os
import random
import uuid
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Any
from urllib.parse import quote

from sqlalchemy import func, or_, select, text
from sqlalchemy.engine import make_url
from sqlalchemy.exc import OperationalError
from sqlalchemy.orm import Session

from src.license_facade_service.config.custom_licence import CustomLicenceRegistrationSettings
from src.license_facade_service.config.federation import FederationSettings
from src.license_facade_service.custom_licences.models import FederationStatus, PublicLicenseScope
from src.license_facade_service.db.models.custom_licence import (
    CustomLicence,
    CustomLicenceAlias,
    CustomLicenceAuditEvent,
    CustomLicenceFederationOutbox,
)
from src.license_facade_service.db.models.federation import FederationChangeEvent, FederationRecord
from src.license_facade_service.db.session import Database
from src.license_facade_service.federation.canonical_json import canonicalize_to_bytes
from src.license_facade_service.federation.digests import canonical_json_sha256_hex
from src.license_facade_service.federation.local_key_lifecycle import LocalKeyError
from src.license_facade_service.federation.outbound import FederationError, FederationPublicationService

OUTBOX_OPERATION_UPSERT = "upsert"
OUTBOX_STATUS_PENDING = "pending"
OUTBOX_STATUS_PROCESSING = "processing"
OUTBOX_STATUS_PUBLISHED = "published"
OUTBOX_STATUS_RETRYABLE_FAILED = "retryable_failed"
OUTBOX_STATUS_PERMANENTLY_FAILED = "permanently_failed"


class CustomLicenceFederationPublicationError(Exception):
    def __init__(self, *, code: str, detail: str, status: int = 503) -> None:
        super().__init__(detail)
        self.code = code
        self.detail = detail
        self.status = status


@dataclass(frozen=True)
class CustomLicenceFederationStatusResult:
    custom_licence_id: uuid.UUID
    scope: str
    federation_status: str
    outbox_status: str | None
    attempt_count: int | None
    next_attempt_at: datetime | None
    published_at: datetime | None
    federation_record_id: uuid.UUID | None
    federation_event_id: uuid.UUID | None
    last_error_class: str | None


@dataclass(frozen=True)
class PostgresDatabaseIdentity:
    database_name: str
    server_address: str
    server_port: int


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


def _normalized_database_fingerprint(database_url: str) -> tuple[str, str, int, str]:
    """Return (backend, host, port, database) — username excluded intentionally.

    Different database users may connect to the same database, so including
    username in the fingerprint would produce false mismatches.  The default
    PostgreSQL port (5432) is normalised so that explicit and implicit port
    representations compare equal.
    """
    parsed = make_url(database_url)
    backend = parsed.get_backend_name()
    host = parsed.host or ""
    port = parsed.port if parsed.port is not None else 5432
    database = parsed.database or ""
    return backend, host.lower(), port, database


def databases_match(url_a: str, url_b: str) -> bool:
    """Return True when both URLs point to the same PostgreSQL database instance.

    Compares backend driver, host, port (normalised to 5432) and database name.
    Username is excluded because different permitted users may connect to the
    same database.  Hostname aliases are *not* resolved; callers that require
    hostname-alias-aware comparison must perform a connection-level check.
    """
    try:
        return _normalized_database_fingerprint(url_a) == _normalized_database_fingerprint(url_b)
    except Exception:
        return url_a.strip() == url_b.strip()


def build_federation_local_id(*, custom_licence_id: uuid.UUID) -> str:
    return f"custom-{custom_licence_id}"


def _build_custom_resolving_uri(*, authority_base_iri: str, authority_id: str, requested_license_id: str, version: str) -> str:
    authority = quote(authority_id, safe="")
    requested = quote(requested_license_id, safe="")
    encoded_version = quote(version, safe="")
    return f"{authority_base_iri.rstrip('/')}/custom-licences/{authority}/{requested}/{encoded_version}"


def build_custom_licence_federation_payload(
    custom_licence: CustomLicence,
    *,
    custom_settings: CustomLicenceRegistrationSettings,
    publishing_node_id: str,
    aliases: list[str],
) -> dict[str, Any]:
    resolving_uri = ""
    if custom_settings.authority_base_iri:
        resolving_uri = _build_custom_resolving_uri(
            authority_base_iri=custom_settings.authority_base_iri,
            authority_id=custom_licence.authority_id,
            requested_license_id=custom_licence.requested_license_id,
            version=custom_licence.version,
        )
    return {
        "schema": "lfs.custom-licence.federation.v1",
        "customLicenceId": str(custom_licence.id),
        "customCanonicalId": custom_licence.canonical_id,
        "customResolvingUuid": str(custom_licence.resolving_uuid),
        "customResolvingUri": resolving_uri,
        "requestedLicenseId": custom_licence.requested_license_id,
        "version": custom_licence.version,
        "name": custom_licence.name,
        "summary": custom_licence.summary,
        "description": custom_licence.description,
        "licenseText": custom_licence.license_text,
        "normalizedTextDigest": custom_licence.normalized_text_digest,
        "spdxJsonld": custom_licence.spdx_jsonld,
        "customAuthorityId": custom_licence.authority_id,
        "publishingFederationNodeId": publishing_node_id,
        "sourceRecordUuid": str(custom_licence.id),
        "scope": custom_licence.public_scope,
        "lifecycleStatus": custom_licence.lifecycle_status,
        "createdAt": custom_licence.created_at.astimezone(timezone.utc).isoformat(),
        "updatedAt": custom_licence.updated_at.astimezone(timezone.utc).isoformat(),
        "aliases": aliases,
    }


def classify_publication_error(exc: Exception) -> tuple[bool, str]:
    if isinstance(exc, OperationalError):
        return True, "database_unavailable"
    if isinstance(exc, FederationError):
        transient_codes = {
            "federation-unavailable",
            "signing-unavailable",
            "inconsistent-node-identity",
        }
        return exc.code in transient_codes, f"federation:{exc.code}"
    return False, exc.__class__.__name__


class CustomLicenceFederationPublicationService:
    def __init__(
        self,
        *,
        db: Database,
        custom_settings: CustomLicenceRegistrationSettings,
        federation_settings: FederationSettings,
        federation_ready: bool,
        publisher: FederationPublicationService | None = None,
    ) -> None:
        self.db = db
        self.custom_settings = custom_settings
        self.federation_settings = federation_settings
        self.federation_ready = federation_ready
        self._publisher = publisher
        self._db_identity_validated = False
        self.max_attempts = int(os.getenv("CUSTOM_LICENCE_FEDERATION_MAX_ATTEMPTS", "8"))
        self.retry_base_seconds = float(os.getenv("CUSTOM_LICENCE_FEDERATION_RETRY_BASE_SECONDS", "2"))
        self.retry_max_seconds = float(os.getenv("CUSTOM_LICENCE_FEDERATION_RETRY_MAX_SECONDS", "120"))

    @property
    def publisher(self) -> FederationPublicationService:
        if self._publisher is None:
            self._publisher = FederationPublicationService(self.db, self.federation_settings)
        return self._publisher

    @publisher.setter
    def publisher(self, value: FederationPublicationService) -> None:
        self._publisher = value

    def assert_federated_registration_supported(self) -> None:
        if self.custom_settings.database_url is None:
            raise CustomLicenceFederationPublicationError(
                code="custom-licence-registration-config-invalid",
                detail="Custom licence registration is unavailable for this deployment.",
                status=503,
            )
        if not self.federation_settings.enabled:
            raise CustomLicenceFederationPublicationError(
                code="custom-licence-federation-unavailable",
                detail="Federated custom licence registration is unavailable for this deployment.",
                status=503,
            )
        blocking_validation_errors = [
            error
            for error in self.federation_settings.validation_errors
            if not (
                error.startswith("FEDERATION_ADMIN_CURSOR_SECRET")
                or error.startswith("FEDERATION_ADMIN_CURSOR_SECRET_FILE")
            )
        ]
        if blocking_validation_errors:
            raise CustomLicenceFederationPublicationError(
                code="custom-licence-federation-unavailable",
                detail="Federated custom licence registration is unavailable for this deployment.",
                status=503,
            )
        if self.federation_settings.database_url is None or self.federation_settings.node_id is None:
            raise CustomLicenceFederationPublicationError(
                code="custom-licence-federation-unavailable",
                detail="Federated custom licence registration is unavailable for this deployment.",
                status=503,
            )
        try:
            _ = self.publisher
        except LocalKeyError as exc:
            raise CustomLicenceFederationPublicationError(
                code="custom-licence-federation-unavailable",
                detail="Federated custom licence registration is unavailable for this deployment.",
                status=503,
            ) from exc
        if not self._db_identity_validated:
            self._assert_database_identity_match()
            self._db_identity_validated = True

    @staticmethod
    def _read_postgres_identity(session: Session) -> PostgresDatabaseIdentity:
        row = session.execute(
            text(
                """
                SELECT
                    current_database()::text AS database_name,
                    COALESCE(inet_server_addr()::text, '') AS server_address,
                    COALESCE(inet_server_port(), 0)::int AS server_port
                """
            )
        ).one()
        return PostgresDatabaseIdentity(
            database_name=str(row.database_name),
            server_address=str(row.server_address or ""),
            server_port=int(row.server_port or 0),
        )

    def _read_postgres_identity_from_url(self, database_url: str) -> PostgresDatabaseIdentity:
        db = Database.from_url(database_url)
        try:
            with db.transaction() as session:
                return self._read_postgres_identity(session)
        finally:
            db.close()

    def _assert_database_identity_match(self) -> None:
        custom_url = self.custom_settings.database_url
        federation_url = self.federation_settings.database_url
        assert custom_url is not None
        assert federation_url is not None
        try:
            with self.db.transaction() as session:
                custom_identity = self._read_postgres_identity(session)
        except OperationalError as exc:
            raise CustomLicenceFederationPublicationError(
                code="custom-licence-federation-unavailable",
                detail="Federated custom licence registration is unavailable for this deployment.",
                status=503,
            ) from exc
        try:
            federation_identity = self._read_postgres_identity_from_url(federation_url)
        except OperationalError as exc:
            raise CustomLicenceFederationPublicationError(
                code="custom-licence-federation-unavailable",
                detail="Federated custom licence registration is unavailable for this deployment.",
                status=503,
            ) from exc
        except Exception as exc:
            raise CustomLicenceFederationPublicationError(
                code="custom-licence-federation-database-mismatch",
                detail="Federated custom licence registration requires a shared PostgreSQL database.",
                status=503,
            ) from exc
        if custom_identity != federation_identity:
            raise CustomLicenceFederationPublicationError(
                code="custom-licence-federation-database-mismatch",
                detail="Federated custom licence registration requires a shared PostgreSQL database.",
                status=503,
            )

    def claim_jobs(self, *, limit: int, lease_seconds: int, worker_id: str) -> list[uuid.UUID]:
        now = _utcnow()
        lease_expires = now + timedelta(seconds=lease_seconds)
        with self.db.transaction() as session:
            rows = (
                session.execute(
                    select(CustomLicenceFederationOutbox.id)
                    .where(
                        or_(
                            CustomLicenceFederationOutbox.status == OUTBOX_STATUS_PENDING,
                            CustomLicenceFederationOutbox.status == OUTBOX_STATUS_RETRYABLE_FAILED,
                            (
                                (CustomLicenceFederationOutbox.status == OUTBOX_STATUS_PROCESSING)
                                & (CustomLicenceFederationOutbox.lease_expires_at.is_not(None))
                                & (CustomLicenceFederationOutbox.lease_expires_at <= now)
                            ),
                        ),
                        CustomLicenceFederationOutbox.available_at <= now,
                    )
                    .order_by(CustomLicenceFederationOutbox.available_at.asc())
                    .with_for_update(skip_locked=True)
                    .limit(limit)
                )
                .scalars()
                .all()
            )
            claimed: list[uuid.UUID] = []
            for job_id in rows:
                job = session.execute(
                    select(CustomLicenceFederationOutbox)
                    .where(CustomLicenceFederationOutbox.id == job_id)
                    .with_for_update(skip_locked=True)
                ).scalar_one_or_none()
                if job is None:
                    continue
                job.status = OUTBOX_STATUS_PROCESSING
                job.lease_owner = worker_id
                job.lease_expires_at = lease_expires
                job.attempt_count += 1
                job.updated_at = now
                claimed.append(job.id)
            return claimed

    def _find_compatible_existing_upsert_event(
        self,
        *,
        session: Session,
        record: FederationRecord,
        canonical_id: str,
        expected_payload_digest: str,
    ) -> uuid.UUID | None:
        events = (
            session.execute(
                select(FederationChangeEvent)
                .where(
                    FederationChangeEvent.record_id == record.id,
                    FederationChangeEvent.authority_node_id == self.federation_settings.node_id,
                )
                .order_by(FederationChangeEvent.event_sequence.desc())
            )
            .scalars()
            .all()
        )
        for event in events:
            if event.operation != "upsert":
                continue
            if event.signature_alg != "EdDSA" or not event.signature_kid or not event.signature_base64url:
                continue
            signed_payload = event.signed_payload if isinstance(event.signed_payload, dict) else {}
            signed_record = signed_payload.get("record")
            if not isinstance(signed_record, dict):
                continue
            if signed_payload.get("operation") != "upsert":
                continue
            if signed_record.get("canonicalId") != canonical_id:
                continue
            if signed_record.get("authorityNodeId") != self.federation_settings.node_id:
                continue
            if str(signed_payload.get("eventId", "")) != str(event.id):
                continue
            if signed_record.get("payloadDigestSha256") != expected_payload_digest:
                continue
            try:
                signed_bytes = canonicalize_to_bytes(signed_payload)
            except Exception:
                continue
            if not self.publisher.signing.verify_bytes(
                signed_bytes,
                signature_b64url=event.signature_base64url,
                kid=event.signature_kid,
            ):
                continue
            return event.id
        return None

    def process_job(self, *, job_id: uuid.UUID, worker_id: str) -> None:
        """Process one claimed outbox job.

        The job *must* be in ``processing`` status with ``lease_owner == worker_id``
        and a non-expired lease before any publication work is attempted.  If the
        job does not meet these conditions the method returns without side-effects.
        This prevents a stale worker from publishing after another worker has
        reclaimed the lease.
        """
        self.assert_federated_registration_supported()
        now = _utcnow()
        try:
            with self.db.transaction() as session:
                job = (
                    session.execute(
                        select(CustomLicenceFederationOutbox)
                        .where(CustomLicenceFederationOutbox.id == job_id)
                        .with_for_update()
                    )
                    .scalars()
                    .one_or_none()
                )
                if job is None or job.status == OUTBOX_STATUS_PUBLISHED:
                    return
                # Ownership guard: only the worker that holds the current lease may proceed.
                if (
                    job.status != OUTBOX_STATUS_PROCESSING
                    or job.lease_owner != worker_id
                    or job.lease_expires_at is None
                    or job.lease_expires_at <= now
                ):
                    return
                custom = (
                    session.execute(
                        select(CustomLicence)
                        .where(CustomLicence.id == job.custom_licence_id)
                        .with_for_update()
                    )
                    .scalars()
                    .one_or_none()
                )
                if custom is None:
                    job.status = OUTBOX_STATUS_PERMANENTLY_FAILED
                    job.last_error_class = "custom_licence_missing"
                    job.last_error_at = now
                    job.lease_owner = None
                    job.lease_expires_at = None
                    job.updated_at = now
                    return
                if custom.public_scope != PublicLicenseScope.FEDERATED.value:
                    job.status = OUTBOX_STATUS_PERMANENTLY_FAILED
                    job.last_error_class = "invalid_scope"
                    job.last_error_at = now
                    job.lease_owner = None
                    job.lease_expires_at = None
                    job.updated_at = now
                    custom.federation_status = FederationStatus.PUBLICATION_FAILED.value
                    session.add(
                        CustomLicenceAuditEvent(
                            id=uuid.uuid4(),
                            custom_licence_id=custom.id,
                            event_type="custom_licence_federation_publication_failed",
                            actor_role="system",
                            actor_identifier=None,
                            before_state=None,
                            after_state={
                                "federationStatus": FederationStatus.PUBLICATION_FAILED.value,
                                "errorClass": "invalid_scope",
                            },
                            source="custom_licence_federation_worker",
                            created_at=now,
                        )
                    )
                    return

                local_id = build_federation_local_id(custom_licence_id=custom.id)
                assert self.federation_settings.node_id is not None
                canonical_id = f"lfs:{self.federation_settings.node_id}:{local_id}:{custom.version}"
                alias_rows = (
                    session.execute(
                        select(CustomLicenceAlias.alias).where(CustomLicenceAlias.custom_licence_id == custom.id)
                    )
                    .scalars()
                    .all()
                )
                payload = build_custom_licence_federation_payload(
                    custom,
                    custom_settings=self.custom_settings,
                    publishing_node_id=self.federation_settings.node_id,
                    aliases=sorted(set(alias_rows)),
                )
                try:
                    record_id, event_id = self.publisher.publish_new_version_in_session(
                        session=session,
                        canonical_id=canonical_id,
                        authority_node_id=self.federation_settings.node_id,
                        local_id=local_id,
                        version=custom.version,
                        payload=payload,
                        enqueue_rdf=False,
                    )
                except FederationError as exc:
                    if exc.code != "record-exists":
                        raise
                    expected_payload_digest = canonical_json_sha256_hex(payload)
                    existing = (
                        session.execute(
                            select(FederationRecord)
                            .where(FederationRecord.canonical_id == canonical_id)
                            .with_for_update()
                        )
                        .scalars()
                        .one_or_none()
                    )
                    if (
                        existing is None
                        or not existing.is_authoritative
                        or existing.authority_node_id != self.federation_settings.node_id
                        or existing.payload_digest_sha256 != expected_payload_digest
                    ):
                        raise CustomLicenceFederationPublicationError(
                            code="custom-licence-publication-identity-mismatch",
                            detail="Federated publication identity is inconsistent with stored state.",
                            status=500,
                        ) from exc
                    compatible_event_id = self._find_compatible_existing_upsert_event(
                        session=session,
                        record=existing,
                        canonical_id=canonical_id,
                        expected_payload_digest=expected_payload_digest,
                    )
                    if compatible_event_id is None:
                        raise CustomLicenceFederationPublicationError(
                            code="custom-licence-publication-compatible-event-missing",
                            detail="Federated publication history is inconsistent with stored state.",
                            status=500,
                        ) from exc
                    record_id = existing.id
                    event_id = compatible_event_id
                job.status = OUTBOX_STATUS_PUBLISHED
                job.published_at = now
                job.federation_record_id = record_id
                job.federation_event_id = event_id
                job.lease_owner = None
                job.lease_expires_at = None
                job.last_error_class = None
                job.last_error_at = None
                job.updated_at = now
                custom.federation_status = FederationStatus.PUBLISHED.value
                session.add(
                    CustomLicenceAuditEvent(
                        id=uuid.uuid4(),
                        custom_licence_id=custom.id,
                        event_type="custom_licence_federation_published",
                        actor_role="system",
                        actor_identifier=None,
                        before_state=None,
                        after_state={
                            "federationStatus": FederationStatus.PUBLISHED.value,
                            "federationRecordId": str(record_id),
                            "federationEventId": str(event_id),
                        },
                        source="custom_licence_federation_worker",
                        created_at=now,
                    )
                )
        except Exception as exc:
            retryable, error_class = classify_publication_error(exc)
            with self.db.transaction() as session:
                job = (
                    session.execute(
                        select(CustomLicenceFederationOutbox)
                        .where(CustomLicenceFederationOutbox.id == job_id)
                        .with_for_update()
                    )
                    .scalars()
                    .one_or_none()
                )
                if job is None:
                    return
                custom = (
                    session.execute(select(CustomLicence).where(CustomLicence.id == job.custom_licence_id).with_for_update())
                    .scalars()
                    .one_or_none()
                )
                job.last_error_class = error_class[:128]
                job.last_error_at = now
                job.lease_owner = None
                job.lease_expires_at = None
                if retryable and job.attempt_count < self.max_attempts:
                    delay = min(self.retry_base_seconds * (2 ** max(job.attempt_count - 1, 0)), self.retry_max_seconds)
                    job.available_at = now + timedelta(seconds=delay + random.uniform(0.0, min(delay * 0.25, 2.0)))
                    job.status = OUTBOX_STATUS_RETRYABLE_FAILED
                else:
                    job.status = OUTBOX_STATUS_PERMANENTLY_FAILED
                    if custom is not None:
                        custom.federation_status = FederationStatus.PUBLICATION_FAILED.value
                        session.add(
                            CustomLicenceAuditEvent(
                                id=uuid.uuid4(),
                                custom_licence_id=custom.id,
                                event_type="custom_licence_federation_publication_failed",
                                actor_role="system",
                                actor_identifier=None,
                                before_state=None,
                                after_state={
                                    "federationStatus": FederationStatus.PUBLICATION_FAILED.value,
                                    "errorClass": job.last_error_class,
                                },
                                source="custom_licence_federation_worker",
                                created_at=now,
                            )
                        )
                job.updated_at = now

    def status_for_custom_licence(self, *, custom_licence_id: uuid.UUID) -> CustomLicenceFederationStatusResult:
        with self.db.transaction() as session:
            custom = (
                session.execute(select(CustomLicence).where(CustomLicence.id == custom_licence_id))
                .scalars()
                .one_or_none()
            )
            if custom is None:
                raise CustomLicenceFederationPublicationError(
                    code="custom-licence-not-found",
                    detail="Custom licence was not found.",
                    status=404,
                )
            job = (
                session.execute(
                    select(CustomLicenceFederationOutbox)
                    .where(
                        CustomLicenceFederationOutbox.custom_licence_id == custom_licence_id,
                        CustomLicenceFederationOutbox.operation == OUTBOX_OPERATION_UPSERT,
                    )
                )
                .scalars()
                .one_or_none()
            )
            return CustomLicenceFederationStatusResult(
                custom_licence_id=custom.id,
                scope=custom.public_scope,
                federation_status=custom.federation_status,
                outbox_status=job.status if job else None,
                attempt_count=job.attempt_count if job else None,
                next_attempt_at=job.available_at if job else None,
                published_at=job.published_at if job else None,
                federation_record_id=job.federation_record_id if job else None,
                federation_event_id=job.federation_event_id if job else None,
                last_error_class=job.last_error_class if job else None,
            )

    def requeue_custom_licence(self, *, custom_licence_id: uuid.UUID, actor_role: str) -> CustomLicenceFederationStatusResult:
        now = _utcnow()
        with self.db.transaction() as session:
            custom = (
                session.execute(select(CustomLicence).where(CustomLicence.id == custom_licence_id).with_for_update())
                .scalars()
                .one_or_none()
            )
            if custom is None:
                raise CustomLicenceFederationPublicationError(
                    code="custom-licence-not-found",
                    detail="Custom licence was not found.",
                    status=404,
                )
            job = (
                session.execute(
                    select(CustomLicenceFederationOutbox)
                    .where(
                        CustomLicenceFederationOutbox.custom_licence_id == custom_licence_id,
                        CustomLicenceFederationOutbox.operation == OUTBOX_OPERATION_UPSERT,
                    )
                    .with_for_update()
                )
                .scalars()
                .one_or_none()
            )
            if custom.public_scope != PublicLicenseScope.FEDERATED.value or job is None:
                raise CustomLicenceFederationPublicationError(
                    code="custom-licence-federation-not-configured",
                    detail="Custom licence is not managed by federated publication.",
                    status=409,
                )
            if job.status == OUTBOX_STATUS_PUBLISHED or custom.federation_status == FederationStatus.PUBLISHED.value:
                raise CustomLicenceFederationPublicationError(
                    code="custom-licence-already-published",
                    detail="Custom licence is already published.",
                    status=409,
                )
            if job.status not in {OUTBOX_STATUS_RETRYABLE_FAILED, OUTBOX_STATUS_PERMANENTLY_FAILED} and custom.federation_status != FederationStatus.PUBLICATION_FAILED.value:
                raise CustomLicenceFederationPublicationError(
                    code="custom-licence-retry-illegal-state",
                    detail="Custom licence publication is not in a retryable state.",
                    status=409,
                )
            job.status = OUTBOX_STATUS_PENDING
            job.available_at = now
            job.lease_owner = None
            job.lease_expires_at = None
            job.last_error_class = None
            job.last_error_at = None
            job.updated_at = now
            custom.federation_status = FederationStatus.PENDING.value
            session.add(
                CustomLicenceAuditEvent(
                    id=uuid.uuid4(),
                    custom_licence_id=custom.id,
                    event_type="custom_licence_federation_retry_requeued",
                    actor_role=actor_role,
                    actor_identifier=None,
                    before_state=None,
                    after_state={"federationStatus": FederationStatus.PENDING.value},
                    source="api.v1.admin.licenses.retry_custom_licence_federation_publication",
                    created_at=now,
                )
            )
        return self.status_for_custom_licence(custom_licence_id=custom_licence_id)

    def process_batch(self, *, limit: int, lease_seconds: int, worker_id: str) -> dict[str, int]:
        claimed = self.claim_jobs(limit=limit, lease_seconds=lease_seconds, worker_id=worker_id)
        processed = 0
        for job_id in claimed:
            self.process_job(job_id=job_id, worker_id=worker_id)
            processed += 1
        with self.db.transaction() as session:
            remaining = int(
                session.execute(
                    select(func.count())
                    .select_from(CustomLicenceFederationOutbox)
                    .where(
                        CustomLicenceFederationOutbox.status.in_(
                            [OUTBOX_STATUS_PENDING, OUTBOX_STATUS_RETRYABLE_FAILED, OUTBOX_STATUS_PROCESSING]
                        )
                    )
                ).scalar_one()
            )
        return {"claimed": len(claimed), "processed": processed, "remaining": remaining}
