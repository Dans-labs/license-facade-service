from __future__ import annotations

import base64
import json
import logging
import re
import uuid
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any

from sqlalchemy import and_, func, or_, select, text
from sqlalchemy.orm import Session

from src.license_facade_service.config.federation import FederationSettings
from src.license_facade_service.db.models.federation import (
    FederationChangeEvent,
    FederationNodeIdentityState,
    FederationRecord,
    FederationResolutionAlias,
)
from src.license_facade_service.db.session import Database
from src.license_facade_service.federation.canonical_json import canonicalize_to_bytes
from src.license_facade_service.federation.digests import canonical_json_sha256_hex, sha256_hex
from src.license_facade_service.federation.identity import identity_fingerprint
from src.license_facade_service.federation.keys import SigningKeyService
from src.license_facade_service.federation.license_identity import build_canonical_license_identity
from src.license_facade_service.federation.rdf_outbox import RdfOutboxService
from src.license_facade_service.federation.models import (
    FederationCatalogItem,
    FederationCatalogResponse,
    FederationChangeEventItem,
    FederationChangesResponse,
    FederationDiscoveryResponse,
    FederationRecordResponse,
    SignedDomainObject,
    SignedFederationChangeEventPayload,
    SignedFederationRecordPayload,
)

from pydantic import ValidationError

CANONICAL_ID_PATTERN = re.compile(r"^lfs:[0-9a-fA-F-]{36}:[A-Za-z0-9._-]+:[A-Za-z0-9._-]+$")
CURSOR_VERSION = 1
DEFAULT_LIMIT = 50
MAX_LIMIT = 200
MAX_IDENTIFIER_LENGTH = 512
PROTOCOL_VERSION = "2.0.0"
LOGGER = logging.getLogger(__name__)


class FederationError(Exception):
    def __init__(self, code: str, detail: str):
        super().__init__(detail)
        self.code = code
        self.detail = detail


def encode_canonical_id(canonical_id: str) -> str:
    return base64.urlsafe_b64encode(canonical_id.encode("utf-8")).decode("ascii").rstrip("=")


def decode_canonical_id(encoded: str) -> str:
    if len(encoded) > 1024 or "/" in encoded or "\\" in encoded or ".." in encoded:
        raise FederationError("invalid-canonical-id", "Invalid canonical identifier encoding.")
    try:
        canonical = base64.urlsafe_b64decode(encoded + "=" * (-len(encoded) % 4)).decode("utf-8")
    except Exception as exc:
        raise FederationError("invalid-canonical-id", "Invalid canonical identifier encoding.") from exc
    if len(canonical) > MAX_IDENTIFIER_LENGTH or "/" in canonical or "\\" in canonical or ".." in canonical:
        raise FederationError("invalid-canonical-id", "Invalid canonical identifier value.")
    if not CANONICAL_ID_PATTERN.match(canonical):
        raise FederationError("invalid-canonical-id", "Canonical identifier is not in supported form.")
    return canonical


def _parse_limit(limit: int | None) -> int:
    value = DEFAULT_LIMIT if limit is None else limit
    if value <= 0 or value > MAX_LIMIT:
        raise FederationError("invalid-limit", f"limit must be between 1 and {MAX_LIMIT}.")
    return value


def _parse_if_none_match(raw: str | None) -> set[str]:
    if not raw:
        return set()
    values: set[str] = set()
    for part in raw.split(","):
        token = part.strip()
        if token.startswith("W/"):
            token = token[2:].strip()
        if token.startswith('"') and token.endswith('"') and len(token) >= 2:
            token = token[1:-1]
        if token:
            values.add(token)
    return values


def _etag_for_bytes(payload: bytes) -> str:
    return f"\"{sha256_hex(payload)}\""


def _iso_z(value: datetime) -> str:
    return value.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")


def _state_from_operation(operation: str | None) -> str:
    if operation == "deprecate":
        return "deprecated"
    if operation == "tombstone":
        return "tombstoned"
    return "published"


@dataclass(frozen=True)
class _CursorClaims:
    kind: str
    node_id: str
    watermark: int | None = None
    after_position: int | None = None
    last_canonical_id: str | None = None
    last_record_uuid: str | None = None


class CursorCodec:
    def __init__(self, signing: SigningKeyService, settings: FederationSettings):
        self.signing = signing
        self.settings = settings

    def encode(self, claims: _CursorClaims) -> str:
        payload = {
            "v": CURSOR_VERSION,
            "kind": claims.kind,
            "node": claims.node_id,
            "watermark": claims.watermark,
            "after": claims.after_position,
            "lastCanonicalId": claims.last_canonical_id,
            "lastRecordUuid": claims.last_record_uuid,
        }
        payload_bytes = canonicalize_to_bytes(payload)
        signature = self.signing.sign_bytes(payload_bytes)
        return (
            f"v{CURSOR_VERSION}."
            f"{signature.kid}."
            f"{base64.urlsafe_b64encode(payload_bytes).decode('ascii').rstrip('=')}."
            f"{signature.value}"
        )

    def decode(self, token: str, *, expected_kinds: set[str]) -> _CursorClaims:
        parts = token.split(".")
        if len(parts) != 4:
            raise FederationError("invalid-cursor", "Cursor is malformed.")
        version, kid, payload_b64, signature = parts
        if version != f"v{CURSOR_VERSION}":
            raise FederationError("unsupported-cursor-version", "Cursor version is not supported.")
        try:
            payload_bytes = base64.urlsafe_b64decode(payload_b64 + "=" * (-len(payload_b64) % 4))
            payload = json.loads(payload_bytes.decode("utf-8"))
        except Exception as exc:
            raise FederationError("invalid-cursor", "Cursor payload is invalid.") from exc
        if payload.get("v") != CURSOR_VERSION:
            raise FederationError("unsupported-cursor-version", "Cursor version is not supported.")
        if not self.signing.verify_bytes(payload_bytes, signature_b64url=signature, kid=kid):
            raise FederationError("invalid-cursor", "Cursor signature is invalid.")
        kind = payload.get("kind")
        if kind not in expected_kinds:
            raise FederationError("invalid-cursor", "Cursor type does not match endpoint.")
        if payload.get("node") != self.settings.node_id:
            raise FederationError("invalid-cursor", "Cursor was issued by a different node.")
        watermark = payload.get("watermark")
        after = payload.get("after")
        if watermark is not None and (not isinstance(watermark, int) or watermark < 0):
            raise FederationError("invalid-cursor", "Cursor watermark is invalid.")
        if after is not None and (not isinstance(after, int) or after < 0):
            raise FederationError("invalid-cursor", "Cursor position is invalid.")
        return _CursorClaims(
            kind=kind,
            node_id=self.settings.node_id or "",
            watermark=watermark,
            after_position=after,
            last_canonical_id=payload.get("lastCanonicalId"),
            last_record_uuid=payload.get("lastRecordUuid"),
        )


class FederationPublicationService:
    def __init__(self, db: Database, settings: FederationSettings, *, signing: SigningKeyService | None = None):
        self.db = db
        self.settings = settings
        self.signing = signing or SigningKeyService(db, settings)
        self.rdf_outbox = RdfOutboxService(db, settings)

    def publish_new_version(
        self,
        *,
        canonical_id: str,
        authority_node_id: str,
        local_id: str,
        version: str,
        payload: dict[str, Any],
        published_at: datetime | None = None,
    ) -> uuid.UUID:
        with self.db.transaction() as session:
            record_id, _event_id = self.publish_new_version_in_session(
                session=session,
                canonical_id=canonical_id,
                authority_node_id=authority_node_id,
                local_id=local_id,
                version=version,
                payload=payload,
                published_at=published_at,
            )
            return record_id

    def publish_new_version_in_session(
        self,
        *,
        session: Session,
        canonical_id: str,
        authority_node_id: str,
        local_id: str,
        version: str,
        payload: dict[str, Any],
        published_at: datetime | None = None,
        enqueue_rdf: bool = True,
    ) -> tuple[uuid.UUID, uuid.UUID]:
        if published_at is None:
            published_at = datetime.now(timezone.utc)
        self._validate_publication_input(canonical_id=canonical_id, authority_node_id=authority_node_id, local_id=local_id, version=version)
        payload_digest = canonical_json_sha256_hex(payload)
        record_uuid = uuid.uuid4()
        now = datetime.now(timezone.utc)
        self._ensure_local_identity(session)
        if authority_node_id != self.settings.node_id:
            raise FederationError("authority-mismatch", "authority_node_id must match local node identity.")
        existing = session.execute(select(FederationRecord).where(FederationRecord.canonical_id == canonical_id)).scalar_one_or_none()
        if existing is not None:
            raise FederationError("record-exists", "Published canonical identifier already exists.")

        identity = build_canonical_license_identity(
            authority_node_id=authority_node_id,
            local_id=local_id,
            version=version,
        )
        if identity.canonicalId != canonical_id:
            raise FederationError("invalid-canonical-id", "Canonical identifier does not match authority/localId/version.")

        record = FederationRecord(
            id=record_uuid,
            authority_node_id=authority_node_id,
            local_id=local_id,
            version=version,
            canonical_id=canonical_id,
            resolving_uuid=uuid.UUID(identity.resolvingUuid),
            is_authoritative=True,
            payload=payload,
            payload_digest_sha256=payload_digest,
            published_at=published_at,
            created_at=now,
            updated_at=now,
        )
        session.add(record)
        session.flush()
        self._sync_resolution_aliases(session=session, record=record)
        event_id, _sequence = self._insert_event(
            session=session,
            record=record,
            operation="upsert",
            generated_at=published_at,
            provenance_type="publication",
            backfill_created_at=None,
            enqueue_rdf=enqueue_rdf,
        )
        return record_uuid, event_id

    def append_state_event(self, *, canonical_id: str, operation: str) -> None:
        if operation not in {"deprecate", "tombstone"}:
            raise FederationError("invalid-operation", "Unsupported event operation.")
        with self.db.transaction() as session:
            self._ensure_local_identity(session)
            record = (
                session.execute(
                    select(FederationRecord)
                    .where(FederationRecord.canonical_id == canonical_id)
                    .with_for_update()
                )
                .scalars()
                .one_or_none()
            )
            if record is None:
                raise FederationError("record-not-found", "Record not found.")
            if not record.is_authoritative or record.authority_node_id != self.settings.node_id:
                raise FederationError("non-authoritative-record", "Record is not authoritative on this node.")
            if record.published_at is None:
                raise FederationError("unpublished-record", "Record is not published.")
            latest = (
                session.execute(
                    select(FederationChangeEvent)
                    .where(
                        FederationChangeEvent.record_id == record.id,
                        FederationChangeEvent.authority_node_id == self.settings.node_id,
                    )
                    .order_by(FederationChangeEvent.event_sequence.desc())
                    .limit(1)
                    .with_for_update()
                )
                .scalars()
                .first()
            )
            current_state = _state_from_operation(latest.operation if latest else "upsert")
            if current_state == "tombstoned":
                raise FederationError("invalid-state-transition", "Tombstoned records cannot transition.")
            if current_state == "deprecated" and operation == "deprecate":
                raise FederationError("invalid-state-transition", "Record is already deprecated.")
            self._sync_resolution_aliases(session=session, record=record)
            self._insert_event(
                session=session,
                record=record,
                operation=operation,
                generated_at=datetime.now(timezone.utc),
                provenance_type="publication",
                backfill_created_at=None,
            )

    def _insert_event(
        self,
        *,
        session: Session,
        record: FederationRecord,
        operation: str,
        generated_at: datetime,
        provenance_type: str,
        backfill_created_at: datetime | None,
        enqueue_rdf: bool = True,
    ) -> tuple[uuid.UUID, int]:
        self._validate_record_identity(record)
        state = _state_from_operation(operation)
        signed_record_payload = SignedFederationRecordPayload(
            nodeId=self.settings.node_id or "",
            canonicalId=record.canonical_id,
            authorityNodeId=record.authority_node_id,
            localId=record.local_id,
            version=record.version,
            publishedAt=record.published_at or generated_at,
            payload=record.payload,
            payloadDigestSha256=record.payload_digest_sha256,
        )
        event_id = str(uuid.uuid4())
        next_sequence = int(session.execute(text("SELECT nextval('federation_change_event_sequence')")).scalar_one())
        payload = {
            "nodeId": self.settings.node_id,
            "eventId": event_id,
            "eventPosition": int(next_sequence),
            "operation": operation,
            "generatedAt": _iso_z(generated_at),
            "record": signed_record_payload.model_dump(mode="json"),
            "provenance": provenance_type,
            "backfillCreatedAt": _iso_z(backfill_created_at) if backfill_created_at else None,
        }
        try:
            signed_event_payload = SignedFederationChangeEventPayload.model_validate(payload)
        except ValidationError as exc:
            raise FederationError("invalid-event-payload", "Federation event payload failed schema validation.") from exc
        payload_json = signed_event_payload.model_dump(mode="json")
        payload_bytes = canonicalize_to_bytes(payload_json)
        if isinstance(self.signing, SigningKeyService):
            self.signing.ensure_runtime_active_key()
        signature = self.signing.sign_bytes(payload_bytes)
        digest = sha256_hex(payload_bytes)
        session.add(
            FederationChangeEvent(
                id=uuid.UUID(event_id),
                event_sequence=int(next_sequence),
                event_type="record.changed",
                authority_node_id=record.authority_node_id,
                record_id=record.id,
                operation=operation,
                generated_at=generated_at,
                payload_schema_version="1",
                signed_payload=payload_json,
                signed_payload_digest_sha256=digest,
                signature_base64url=signature.value,
                signature_kid=signature.kid,
                signature_alg=signature.alg,
                provenance_type=provenance_type,
                backfill_created_at=backfill_created_at,
                event_payload=payload_json,
                event_digest_sha256=digest,
                occurred_at=generated_at,
                created_at=datetime.now(timezone.utc),
            )
        )
        record.materialized_generation = int(next_sequence)
        if enqueue_rdf:
            self.rdf_outbox.enqueue_record_jobs(session, record, operation=operation)
        # Flush event row to make same-transaction FK references deterministic.
        session.flush()
        return uuid.UUID(event_id), int(next_sequence)

    def _validate_publication_input(self, *, canonical_id: str, authority_node_id: str, local_id: str, version: str) -> None:
        if not CANONICAL_ID_PATTERN.match(canonical_id):
            raise FederationError("invalid-canonical-id", "Canonical identifier is not in supported form.")
        if not authority_node_id or not local_id or not version:
            raise FederationError("invalid-record", "Authority, local id, and version are required.")

    def _ensure_local_identity(self, session: Session) -> None:
        row = session.execute(select(FederationNodeIdentityState).where(FederationNodeIdentityState.id == 1)).scalar_one_or_none()
        if row is None:
            if not (
                self.settings.node_id
                and self.settings.public_base_url
                and self.settings.node_name
                and self.settings.operator_name
            ):
                raise FederationError("inconsistent-node-identity", "Local node identity is unavailable or inconsistent.")
            now = datetime.now(timezone.utc)
            row = FederationNodeIdentityState(
                id=1,
                node_id=self.settings.node_id,
                public_base_url=self.settings.public_base_url,
                node_name=self.settings.node_name,
                operator_name=self.settings.operator_name,
                config_fingerprint=identity_fingerprint(self.settings),
                created_at=now,
                updated_at=now,
            )
            session.add(row)
            session.flush()
            return
        if row.node_id != self.settings.node_id:
            raise FederationError("inconsistent-node-identity", "Local node identity is unavailable or inconsistent.")
        if self.settings.public_base_url and self.settings.node_name and self.settings.operator_name:
            expected_fingerprint = identity_fingerprint(self.settings)
            if row.config_fingerprint != expected_fingerprint:
                raise FederationError("inconsistent-node-identity", "Local node identity is unavailable or inconsistent.")
        row.updated_at = datetime.now(timezone.utc)
        session.flush()

    @staticmethod
    def _validate_record_identity(record: FederationRecord) -> None:
        if not CANONICAL_ID_PATTERN.match(record.canonical_id):
            raise FederationError("invalid-canonical-id", "Canonical identifier is not in supported form.")
        expected = build_canonical_license_identity(
            authority_node_id=record.authority_node_id,
            local_id=record.local_id,
            version=record.version,
        )
        if expected.canonicalId != record.canonical_id or expected.resolvingUuid != str(record.resolving_uuid):
            raise FederationError("invalid-canonical-id", "Record identity fields are inconsistent.")

    @staticmethod
    def _normalize_alias(value: str | None) -> str | None:
        if value is None:
            return None
        normalized = value.strip()
        return normalized or None

    def _sync_resolution_aliases(self, *, session: Session, record: FederationRecord) -> None:
        aliases = [("canonical", record.canonical_id)]
        if isinstance(record.payload, dict):
            uri = record.payload.get("uri")
            if isinstance(uri, str):
                aliases.append(("authority-uri", uri))
            payload_aliases = record.payload.get("aliases", [])
            if isinstance(payload_aliases, list):
                aliases.extend(("approved-alias", alias) for alias in payload_aliases if isinstance(alias, str))
        now = datetime.now(timezone.utc)
        for alias_kind, alias_value in aliases:
            normalized = self._normalize_alias(alias_value)
            if not normalized:
                continue
            existing = session.execute(
                select(FederationResolutionAlias).where(
                    FederationResolutionAlias.normalized_identifier == normalized,
                    FederationResolutionAlias.record_id == record.id,
                    FederationResolutionAlias.alias_kind == alias_kind,
                )
            ).scalar_one_or_none()
            if existing is None:
                session.add(
                    FederationResolutionAlias(
                        id=uuid.uuid4(),
                        normalized_identifier=normalized,
                        alias_value=alias_value,
                        alias_kind=alias_kind,
                        record_id=record.id,
                        authority_node_id=record.authority_node_id,
                        source_peer_id=record.imported_from_peer_id,
                        is_authoritative=record.is_authoritative and record.imported_from_peer_id is None,
                        created_at=now,
                        updated_at=now,
                    )
                )
            else:
                existing.alias_value = alias_value
                existing.authority_node_id = record.authority_node_id
                existing.source_peer_id = record.imported_from_peer_id
                existing.is_authoritative = record.is_authoritative and record.imported_from_peer_id is None
                existing.updated_at = now


class FederationBackfillService:
    def __init__(self, db: Database, settings: FederationSettings):
        self.db = db
        self.settings = settings
        self.publisher = FederationPublicationService(db, settings)

    def backfill_missing_events(self, *, apply_changes: bool = False, confirm_write: bool = False, batch_size: int = 100) -> dict[str, int]:
        if apply_changes and not confirm_write:
            raise FederationError("backfill-confirmation-required", "Use confirm_write=true to apply backfill.")
        scanned = 0
        inserted = 0
        skipped = 0
        rejected = 0
        last_id: uuid.UUID | None = None

        while True:
            with self.db.transaction() as session:
                q = (
                    select(FederationRecord)
                    .where(
                        FederationRecord.is_authoritative.is_(True),
                        FederationRecord.authority_node_id == self.settings.node_id,
                        FederationRecord.imported_from_peer_id.is_(None),
                        FederationRecord.published_at.is_not(None),
                    )
                    .order_by(FederationRecord.id)
                    .limit(batch_size)
                )
                if last_id is not None:
                    q = q.where(FederationRecord.id > last_id)
                records = session.execute(q).scalars().all()
            if not records:
                break
            scanned += len(records)

            for record in records:
                try:
                    self.publisher._validate_record_identity(record)  # noqa: SLF001
                except FederationError:
                    rejected += 1
                    continue

                with self.db.transaction() as session:
                    count = session.execute(
                        select(func.count()).select_from(FederationChangeEvent).where(FederationChangeEvent.record_id == record.id)
                    ).scalar_one()
                    if count > 0:
                        skipped += 1
                        continue
                if not apply_changes:
                    inserted += 1
                    continue
                try:
                    with self.db.transaction() as session:
                        current = session.execute(select(FederationRecord).where(FederationRecord.id == record.id)).scalar_one()
                        self.publisher._insert_event(  # noqa: SLF001
                            session=session,
                            record=current,
                            operation="upsert",
                            generated_at=current.published_at or datetime.now(timezone.utc),
                            provenance_type="backfill",
                            backfill_created_at=datetime.now(timezone.utc),
                        )
                    inserted += 1
                except Exception:
                    rejected += 1
            last_id = records[-1].id

        return {"scanned": scanned, "inserted": inserted, "skipped": skipped, "rejected": rejected}


class FederationOutboundService:
    def __init__(self, db: Database, settings: FederationSettings):
        self.db = db
        self.settings = settings
        self.signing = SigningKeyService(db, settings)
        self.cursor_codec = CursorCodec(self.signing, settings)
        self.rdf_outbox = RdfOutboxService(db, settings)

    def discovery(self) -> FederationDiscoveryResponse:
        base = (self.settings.public_base_url or "").rstrip("/")
        return FederationDiscoveryResponse(
            protocolVersion=PROTOCOL_VERSION,
            nodeId=self.settings.node_id or "",
            nodeName=self.settings.node_name or "",
            operator=self.settings.operator_name or "",
            publicBaseUrl=base,
            currentSigningKid=self.signing.get_active_kid(),
            jwksUrl=f"{base}/.well-known/jwks.json",
            catalogUrl=f"{base}/api/v1/federation/catalog",
            changesUrl=f"{base}/api/v1/federation/changes",
            recordUrlTemplate=f"{base}/api/v1/federation/records/{{encodedCanonicalId}}",
            conformance=["LFS-FED-PHASE2-OUTBOUND"],
        )

    def get_changes(self, *, since: str | None, limit: int | None) -> FederationChangesResponse:
        effective_limit = _parse_limit(limit)
        watermark, after_position = self._resolve_changes_cursor(since)
        with self.db.transaction() as session:
            rows = (
                session.execute(
                    select(FederationChangeEvent)
                    .join(FederationRecord, FederationRecord.id == FederationChangeEvent.record_id)
                    .where(
                        self._federatable_predicate(),
                        FederationChangeEvent.event_sequence > after_position,
                        FederationChangeEvent.event_sequence <= watermark,
                    )
                    .order_by(FederationChangeEvent.event_sequence)
                    .limit(effective_limit + 1)
                )
                .scalars()
                .all()
            )

        has_more = len(rows) > effective_limit
        page = rows[:effective_limit]
        last_position = page[-1].event_sequence if page else after_position
        next_cursor = (
            self.cursor_codec.encode(
                _CursorClaims(
                    kind="changes-page",
                    node_id=self.settings.node_id or "",
                    watermark=watermark,
                    after_position=last_position,
                )
            )
            if has_more
            else None
        )
        resume_cursor = self.cursor_codec.encode(
            _CursorClaims(
                kind="changes-resume",
                node_id=self.settings.node_id or "",
                after_position=last_position if page else (after_position if since else watermark),
            )
        )

        items: list[FederationChangeEventItem] = []
        for event in page:
            payload = self._validated_event_payload(event)
            items.append(
                FederationChangeEventItem(
                    payload=payload,
                    signed=SignedDomainObject(
                        digestSha256=event.signed_payload_digest_sha256,
                        signature={"kid": event.signature_kid, "alg": event.signature_alg, "value": event.signature_base64url},
                    ),
                )
            )
        response = FederationChangesResponse(
            events=items,
            limit=effective_limit,
            hasMore=has_more,
            nextCursor=next_cursor,
            resumeCursor=resume_cursor,
            snapshotWatermark=watermark,
            etag="",
        )
        response.etag = _etag_for_bytes(canonicalize_to_bytes(response.model_dump(mode="json", exclude={"etag"})))
        return response

    def get_catalog(self, *, cursor: str | None, limit: int | None) -> FederationCatalogResponse:
        effective_limit = _parse_limit(limit)
        watermark, last_canonical, last_uuid = self._resolve_catalog_cursor(cursor)
        latest = (
            select(
                FederationChangeEvent.record_id.label("record_id"),
                func.max(FederationChangeEvent.event_sequence).label("max_sequence"),
            )
            .where(
                FederationChangeEvent.authority_node_id == self.settings.node_id,
                FederationChangeEvent.event_sequence <= watermark,
            )
            .group_by(FederationChangeEvent.record_id)
            .subquery()
        )
        with self.db.transaction() as session:
            q = (
                select(FederationRecord, FederationChangeEvent)
                .join(latest, latest.c.record_id == FederationRecord.id)
                .join(
                    FederationChangeEvent,
                    and_(
                        FederationChangeEvent.record_id == latest.c.record_id,
                        FederationChangeEvent.event_sequence == latest.c.max_sequence,
                    ),
                )
                .where(
                    self._federatable_predicate(),
                    FederationRecord.canonical_id.op("~")(r"^lfs:[0-9a-fA-F-]{36}:[A-Za-z0-9._-]+:[A-Za-z0-9._-]+$"),
                    FederationRecord.canonical_id
                    == func.concat("lfs:", FederationRecord.authority_node_id, ":", FederationRecord.local_id, ":", FederationRecord.version),
                    FederationChangeEvent.operation != "tombstone",
                )
            )
            if last_canonical and last_uuid:
                q = q.where(
                    or_(
                        FederationRecord.canonical_id > last_canonical,
                        and_(FederationRecord.canonical_id == last_canonical, FederationRecord.id > uuid.UUID(last_uuid)),
                    )
                )
            rows = session.execute(q.order_by(FederationRecord.canonical_id, FederationRecord.id).limit(effective_limit + 1)).all()

        has_more = len(rows) > effective_limit
        page = rows[:effective_limit]
        next_cursor = None
        if has_more and page:
            last_record, _ = page[-1]
            next_cursor = self.cursor_codec.encode(
                _CursorClaims(
                    kind="catalog",
                    node_id=self.settings.node_id or "",
                    watermark=watermark,
                    last_canonical_id=last_record.canonical_id,
                    last_record_uuid=str(last_record.id),
                )
            )
        items = [
            FederationCatalogItem(
                canonicalId=record.canonical_id,
                encodedId=encode_canonical_id(record.canonical_id),
                authorityNodeId=record.authority_node_id,
                version=record.version,
                publicationState=_state_from_operation(event.operation),
                publishedAt=record.published_at,
                payloadDigestSha256=record.payload_digest_sha256,
                eventPosition=event.event_sequence,
            )
            for record, event in page
        ]
        for _, event in page:
            self._validated_event_payload(event)
        response = FederationCatalogResponse(
            items=items,
            limit=effective_limit,
            hasMore=has_more,
            nextCursor=next_cursor,
            snapshotWatermark=watermark,
            etag="",
        )
        response.etag = _etag_for_bytes(canonicalize_to_bytes(response.model_dump(mode="json", exclude={"etag"})))
        return response

    def get_record(self, *, encoded_canonical_id: str) -> FederationRecordResponse:
        canonical_id = decode_canonical_id(encoded_canonical_id)
        with self.db.transaction() as session:
            record = session.execute(select(FederationRecord).where(FederationRecord.canonical_id == canonical_id)).scalar_one_or_none()
            if record is None:
                raise FederationError("record-not-found", "Record was not found.")
            if not record.is_authoritative or record.imported_from_peer_id is not None or record.authority_node_id != self.settings.node_id:
                raise FederationError("non-authoritative-record", "Record is not authoritative on this node.")
            if record.published_at is None:
                raise FederationError("unpublished-record", "Record has not been published.")
            latest = (
                session.execute(
                    select(FederationChangeEvent)
                    .where(FederationChangeEvent.record_id == record.id, FederationChangeEvent.authority_node_id == self.settings.node_id)
                    .order_by(FederationChangeEvent.event_sequence.desc())
                    .limit(1)
                )
                .scalars()
                .first()
            )
        if latest is None:
            raise FederationError("unpublished-record", "Record has no published state event.")
        self._validated_event_payload(latest)
        state = _state_from_operation(latest.operation)
        if state == "tombstoned":
            raise FederationError("unpublished-record", "Record has been tombstoned.")

        domain = SignedFederationRecordPayload(
            nodeId=self.settings.node_id or "",
            canonicalId=record.canonical_id,
            authorityNodeId=record.authority_node_id,
            localId=record.local_id,
            version=record.version,
            publishedAt=record.published_at,
            payload=record.payload,
            payloadDigestSha256=record.payload_digest_sha256,
        )
        payload_bytes = canonicalize_to_bytes(domain.model_dump(mode="json"))
        signature = self.signing.sign_bytes(payload_bytes)
        return FederationRecordResponse(
            record=domain,
            signed=SignedDomainObject(digestSha256=sha256_hex(payload_bytes), signature=signature),
            currentState=state,
            latestEventPosition=latest.event_sequence,
            latestEventDigestSha256=latest.signed_payload_digest_sha256,
        )

    def _validated_event_payload(self, event: FederationChangeEvent) -> SignedFederationChangeEventPayload:
        try:
            return SignedFederationChangeEventPayload.model_validate(event.signed_payload)
        except ValidationError as exc:
            LOGGER.warning(
                "stored federation event payload invalid",
                extra={"event_id": str(event.id), "event_position": int(event.event_sequence)},
            )
            raise FederationError(
                "stored-federation-event-invalid",
                f"Stored federation event is invalid at position {int(event.event_sequence)}.",
            ) from exc

    def _resolve_changes_cursor(self, since: str | None) -> tuple[int, int]:
        current_max = self._max_event_sequence()
        if since is None:
            return current_max, 0
        claims = self.cursor_codec.decode(since, expected_kinds={"changes-page", "changes-resume"})
        after = claims.after_position or 0
        if claims.kind == "changes-page":
            if claims.watermark is None:
                raise FederationError("invalid-cursor", "Snapshot watermark is missing.")
            return claims.watermark, after
        return current_max, after

    def _resolve_catalog_cursor(self, cursor: str | None) -> tuple[int, str | None, str | None]:
        if cursor is None:
            return self._max_event_sequence(), None, None
        claims = self.cursor_codec.decode(cursor, expected_kinds={"catalog"})
        if claims.watermark is None:
            raise FederationError("invalid-cursor", "Catalog cursor watermark is missing.")
        return claims.watermark, claims.last_canonical_id, claims.last_record_uuid

    def _max_event_sequence(self) -> int:
        with self.db.transaction() as session:
            value = session.execute(
                select(func.coalesce(func.max(FederationChangeEvent.event_sequence), 0)).where(
                    FederationChangeEvent.authority_node_id == self.settings.node_id
                )
            ).scalar_one()
        return int(value or 0)

    def _federatable_predicate(self):
        return and_(
            FederationChangeEvent.authority_node_id == self.settings.node_id,
            FederationRecord.is_authoritative.is_(True),
            FederationRecord.authority_node_id == self.settings.node_id,
            FederationRecord.imported_from_peer_id.is_(None),
            FederationRecord.published_at.is_not(None),
        )
