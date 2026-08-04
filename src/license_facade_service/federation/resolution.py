from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any
from urllib.parse import unquote, urlsplit
from uuid import UUID, uuid4

from sqlalchemy import and_, func, or_, select
from sqlalchemy.orm import Session

from src.license_facade_service.config.federation import FederationSettings
from src.license_facade_service.db.models.federation import (
    FederationConflictDecisionEvent,
    FederationRecord,
    FederationRecordProvenance,
    FederationResolutionAlias,
    FederationResolutionConflict,
    FederationResolutionAuditLog,
    FederationTrustedPeer,
)
from src.license_facade_service.db.session import Database
from src.license_facade_service.federation.inbound_models import RemoteRecordResponse
from src.license_facade_service.federation.outbound import FederationError
from src.license_facade_service.federation.rdf_outbox import RdfOutboxService
from src.license_facade_service.federation.resolution_models import (
    ConflictCandidateResponse,
    ConflictContextLinkSet,
    ConflictDecisionRequest,
    ConflictDecisionResponse,
    ConflictResponse,
    ConflictState,
    FreshnessState,
    LifecycleState,
    LicenseProvenanceResponse,
    LicenseResolutionResponse,
    ProvenanceEventResponse,
    ProvenanceSummary,
    ResolutionFreshness,
    ResolutionLinkSet,
    ResolutionOutcome,
    ResolutionSourceState,
    SourceAvailability,
    SourceOperationalState,
    SourceTrustState,
)
from src.license_facade_service.services.licenses import LicenseService, LicenseNotFoundError


class ResolutionError(FederationError):
    def __init__(self, code: str, detail: str, *, context: dict[str, Any] | None = None):
        super().__init__(code, detail)
        self.context = context or {}


@dataclass(frozen=True)
class _Candidate:
    record: FederationRecord
    source_peer: FederationTrustedPeer | None
    match_kind: str
    is_local: bool
    is_eligible: bool
    trust_state: SourceTrustState
    operational_state: SourceOperationalState
    availability: SourceAvailability
    freshness_state: FreshnessState


def _normalize_identifier(identifier: str) -> str:
    decoded = unquote(identifier)
    if decoded != unquote(decoded):
        raise ResolutionError("invalid-identifier", "Identifier must be decoded exactly once.")
    normalized = decoded.strip()
    if not normalized:
        raise ResolutionError("invalid-identifier", "Identifier is required.")
    if len(normalized) > 1024:
        raise ResolutionError("invalid-identifier", "Identifier exceeds maximum length.")
    if ".." in normalized or "\\" in normalized:
        raise ResolutionError("invalid-identifier", "Identifier contains invalid path traversal content.")
    return normalized


def _lifecycle_from_state(state: str | None) -> LifecycleState:
    if state == "deprecated":
        return "deprecated"
    if state == "tombstoned":
        return "tombstoned"
    return "active"


def _peer_trust_state(peer: FederationTrustedPeer | None) -> SourceTrustState:
    if peer is None:
        return "unknown"
    if peer.trust_status == "revoked":
        return "revoked"
    if peer.trust_status in {"trusted", "archived"}:
        return "trusted"
    return "unknown"


def _peer_operational_state(peer: FederationTrustedPeer | None) -> SourceOperationalState:
    if peer is None:
        return "enabled"
    if peer.trust_status == "archived":
        return "archived"
    if peer.sync_enabled:
        return "enabled"
    return "disabled"


def _peer_availability(peer: FederationTrustedPeer | None) -> SourceAvailability:
    if peer is None:
        return "unknown"
    if peer.last_sync_success_at is not None and peer.last_sync_status in {"complete", "partial"}:
        return "online"
    if peer.last_sync_status in {"failed", "partial", "running"}:
        return "offline"
    return "unknown"


def _freshness(peer: FederationTrustedPeer | None, record: FederationRecord) -> FreshnessState:
    if peer is None:
        return "unknown"
    if record.imported_from_peer_id is not None and _peer_availability(peer) == "offline":
        return "stale"
    if peer.last_sync_success_at is None:
        return "unknown" if record.imported_from_peer_id is None else "stale"
    if record.last_verified_at is None:
        return "stale" if record.imported_from_peer_id is not None else "fresh"
    if peer.last_sync_success_at >= record.last_verified_at:
        return "fresh"
    return "stale"


class FederationResolutionService:
    def __init__(
        self,
        db: Database | None,
        settings: FederationSettings,
        *,
        license_service: LicenseService | None = None,
    ) -> None:
        self.db = db
        self.settings = settings
        self.license_service = license_service or LicenseService()
        self.rdf_outbox = RdfOutboxService(db, settings) if db is not None else None

    def resolve(self, identifier: str) -> LicenseResolutionResponse:
        normalized = _normalize_identifier(identifier)
        if self.db is None:
            return self._resolve_spdx(normalized)
        with self.db.transaction() as session:
            result = self._resolve_in_session(session, normalized)
        if result is not None:
            return result
        return self._resolve_spdx(normalized)

    def provenance(self, identifier: str) -> LicenseProvenanceResponse:
        normalized = _normalize_identifier(identifier)
        if self.db is None:
            raise ResolutionError("resolution-not-found", "No federation record found for identifier.", context={})
        with self.db.transaction() as session:
            resolution = self._resolve_in_session(session, normalized, include_spdx=False)
            if resolution is None:
                raise ResolutionError("resolution-not-found", "No federation record found for identifier.", context={})
            record = self._record_for_resolution(session, resolution)
            if record is None:
                raise ResolutionError("resolution-not-found", "No federation record found for identifier.", context={})
            peer = self._peer_for_record(session, record)
            provenance_rows = (
                session.execute(
                    select(FederationRecordProvenance)
                    .where(FederationRecordProvenance.record_id == record.id)
                    .order_by(FederationRecordProvenance.asserted_at.desc())
                )
                .scalars()
                .all()
            )
        summary = self._provenance_summary(record, peer, provenance_rows)
        return self._build_provenance_response(normalized, resolution, record, peer, summary, provenance_rows)

    def list_conflicts(self, *, limit: int = 100, offset: int = 0) -> list[ConflictResponse]:
        if self.db is None:
            return []
        with self.db.transaction() as session:
            rows = (
                session.execute(
                    select(FederationResolutionConflict).order_by(
                        FederationResolutionConflict.updated_at.desc(), FederationResolutionConflict.created_at.desc()
                    ).limit(limit).offset(offset)
                )
                .scalars()
                .all()
            )
            return [self._conflict_response(session, row) for row in rows]

    def get_conflict(self, conflict_id: UUID) -> ConflictResponse:
        if self.db is None:
            raise ResolutionError("conflict-not-found", "Conflict record was not found.")
        with self.db.transaction() as session:
            row = session.execute(select(FederationResolutionConflict).where(FederationResolutionConflict.id == conflict_id)).scalar_one_or_none()
            if row is None:
                raise ResolutionError("conflict-not-found", "Conflict record was not found.")
            return self._conflict_response(session, row)

    def decide_conflict(
        self,
        *,
        conflict_id: UUID,
        payload: ConflictDecisionRequest,
        actor_role: str,
        actor_identifier: str | None,
    ) -> ConflictDecisionResponse:
        if self.db is None:
            raise ResolutionError("conflict-not-found", "Conflict record was not found.")
        with self.db.transaction() as session:
            conflict = (
                session.execute(
                    select(FederationResolutionConflict).where(FederationResolutionConflict.id == conflict_id).with_for_update()
                )
                .scalar_one_or_none()
            )
            if conflict is None:
                raise ResolutionError("conflict-not-found", "Conflict record was not found.")
            if conflict.version != payload.expectedVersion:
                raise ResolutionError("conflict-stale", "Conflict version has changed.", context={"conflictId": str(conflict.id)})
            before = conflict.candidate_summary or {}
            decision = self._apply_conflict_decision(session, conflict=conflict, payload=payload, actor_role=actor_role, actor_identifier=actor_identifier)
            after = conflict.candidate_summary or {}
            session.add(
                FederationResolutionAuditLog(
                    id=uuid4(),
                    subject_type="conflict",
                    subject_id=str(conflict.id),
                    action=payload.decisionType,
                    actor_role=actor_role,
                    actor_identifier=actor_identifier,
                    rationale=payload.rationale,
                    before_state=before,
                    after_state=after,
                    created_at=datetime.now(timezone.utc),
                )
            )
            return decision

    def _apply_conflict_decision(
        self,
        session: Session,
        *,
        conflict: FederationResolutionConflict,
        payload: ConflictDecisionRequest,
        actor_role: str,
        actor_identifier: str | None,
    ) -> ConflictDecisionResponse:
        candidates = self._load_conflict_candidates(session, conflict)
        selected = self._select_decision_target(conflict=conflict, payload=payload, candidates=candidates)
        now = datetime.now(timezone.utc)
        decision_version = conflict.version + 1
        effectiveness = "current"
        if payload.decisionType == "reverse":
            effectiveness = "reversed"
            conflict.status = "open"
            conflict.reopened_at = now
        elif payload.decisionType == "supersede":
            effectiveness = "superseded"
            conflict.status = "superseded"
        else:
            conflict.status = "resolved" if selected is not None else "dismissed"
        if payload.decisionType == "dismiss":
            conflict.status = "dismissed"
        if payload.decisionType == "prefer-imported" and any(c.is_local for c in candidates):
            raise ResolutionError("conflict-not-allowed", "Imported records cannot override local authority.")
        conflict.version = decision_version
        conflict.decision_effectiveness = effectiveness
        conflict.resolved_record_id = selected.record.id if selected else None
        conflict.updated_at = now
        if conflict.status == "resolved":
            conflict.resolved_at = now
        decision_event = FederationConflictDecisionEvent(
            id=uuid4(),
            conflict_id=conflict.id,
            expected_version=payload.expectedVersion,
            version=decision_version,
            decision_type=payload.decisionType,
            decision_effectiveness=effectiveness,
            actor_role=actor_role,
            actor_identifier=actor_identifier,
            rationale=payload.rationale,
            before_state={"version": payload.expectedVersion, "status": conflict.status},
            after_state={"version": decision_version, "status": conflict.status},
            created_at=now,
        )
        session.add(decision_event)
        if self.rdf_outbox is not None:
            self.rdf_outbox.enqueue_conflict_job(session, conflict, decision_event)
        return ConflictDecisionResponse(
            conflictId=conflict.id,
            version=decision_version,
            status=conflict.status,
            decisionType=payload.decisionType,
            decisionEffectiveness=effectiveness,
            actorRole=actor_role,
            actorIdentifier=actor_identifier,
            rationale=payload.rationale,
            beforeState={"version": payload.expectedVersion},
            afterState={"version": decision_version},
            createdAt=now,
        )

    def _select_decision_target(
        self,
        *,
        conflict: FederationResolutionConflict,
        payload: ConflictDecisionRequest,
        candidates: list[_Candidate],
    ) -> _Candidate | None:
        if payload.decisionType in {"dismiss", "acknowledge", "alias-correct", "reverse"}:
            return None
        if payload.aliasValue:
            normalized = _normalize_identifier(payload.aliasValue)
            matched = [
                candidate
                for candidate in candidates
                if candidate.record.canonical_id == normalized
                or candidate.record.source_record_url == normalized
            ]
            if len(matched) == 1:
                if payload.decisionType == "prefer-imported" and matched[0].is_local:
                    raise ResolutionError("conflict-not-allowed", "Imported records cannot override local authority.")
                return matched[0]
        if payload.decisionType == "prefer-imported":
            imported = [candidate for candidate in candidates if not candidate.is_local and candidate.is_eligible]
            if len(imported) != 1:
                raise ResolutionError("resolution-ambiguous", "Multiple imported candidates remain unresolved.", context={"conflictId": str(conflict.id)})
            return imported[0]
        if payload.decisionType == "approve":
            eligible = [candidate for candidate in candidates if candidate.is_eligible]
            if len(eligible) != 1:
                raise ResolutionError("resolution-ambiguous", "Multiple candidates remain unresolved.", context={"conflictId": str(conflict.id)})
            return eligible[0]
        return None

    def _resolve_in_session(
        self,
        session: Session,
        normalized: str,
        *,
        include_spdx: bool = True,
    ) -> LicenseResolutionResponse | None:
        records = self._candidate_records(session, normalized)
        if not records:
            return None

        local = [candidate for candidate in records if candidate.is_local]
        imported = [candidate for candidate in records if not candidate.is_local]
        conflict: FederationResolutionConflict | None = None

        if local:
            chosen = local[0]
            if imported:
                conflict = self._persist_conflict(normalized, records)
            if chosen.record.lifecycle_state == "tombstoned":
                raise ResolutionError(
                    "resolution-tombstoned",
                    "Selected identity is tombstoned.",
                    context=self._resolution_context(conflict, chosen),
                )
            return self._build_response(normalized, chosen, conflict)

        eligible_imported = [candidate for candidate in imported if candidate.is_eligible]
        if not eligible_imported:
            if imported:
                conflict = self._persist_conflict(normalized, records)
                raise ResolutionError(
                    "resolution-unavailable",
                    "Known records are excluded by trust or operational policy.",
                    context=self._resolution_context(conflict, imported[0]),
                )
            return None
        if len(eligible_imported) > 1:
            conflict = self._persist_conflict(normalized, records)
        if conflict is not None and not self._has_current_decision(session, conflict.id):
            if conflict is None:
                conflict = self._persist_conflict(normalized, records)
            raise ResolutionError(
                "resolution-ambiguous",
                "Multiple eligible imported candidates remain unresolved.",
                context=self._resolution_context(conflict, eligible_imported[0]),
            )
        chosen = self._choose_by_decision(session, conflict, eligible_imported) or eligible_imported[0]
        if chosen.record.lifecycle_state == "tombstoned":
            raise ResolutionError("resolution-tombstoned", "Selected identity is tombstoned.", context=self._resolution_context(conflict, chosen))
        return self._build_response(normalized, chosen, conflict)

    def _choose_by_decision(
        self,
        session: Session,
        conflict: FederationResolutionConflict | None,
        candidates: list[_Candidate],
    ) -> _Candidate | None:
        if conflict is None:
            return None
        decision = (
            session.execute(
                select(FederationConflictDecisionEvent)
                .where(FederationConflictDecisionEvent.conflict_id == conflict.id)
                .order_by(FederationConflictDecisionEvent.version.desc())
                .limit(1)
            )
            .scalars()
            .first()
        )
        if decision is None:
            return None
        if decision.decision_effectiveness not in {"current"}:
            return None
        if decision.decision_type == "prefer-imported":
            return candidates[0] if len(candidates) == 1 else None
        if decision.decision_type == "approve":
            return candidates[0] if len(candidates) == 1 else None
        return None

    def _has_current_decision(self, session: Session, conflict_id: UUID) -> bool:
        decision = (
            session.execute(
                select(FederationConflictDecisionEvent)
                .where(
                    FederationConflictDecisionEvent.conflict_id == conflict_id,
                    FederationConflictDecisionEvent.decision_effectiveness == "current",
                )
                .limit(1)
            )
            .scalars()
            .first()
        )
        return decision is not None

    def _candidate_records(self, session: Session, normalized: str) -> list[_Candidate]:
        candidates: dict[UUID, _Candidate] = {}
        matched_records = (
            session.execute(
                select(FederationRecord)
                .where(
                    or_(
                        FederationRecord.canonical_id == normalized,
                        FederationRecord.source_record_url == normalized,
                    )
                )
            )
            .scalars()
            .all()
        )
        uuid_match: UUID | None = None
        try:
            uuid_match = UUID(normalized)
        except ValueError:
            uuid_match = None
        if uuid_match is not None:
            matched_records.extend(
                session.execute(select(FederationRecord).where(FederationRecord.resolving_uuid == uuid_match)).scalars().all()
            )
        alias_rows = (
            session.execute(select(FederationResolutionAlias).where(FederationResolutionAlias.normalized_identifier == normalized))
            .scalars()
            .all()
        )
        record_ids = {row.record_id for row in alias_rows}
        if record_ids:
            matched_records.extend(session.execute(select(FederationRecord).where(FederationRecord.id.in_(record_ids))).scalars().all())
        for record in matched_records:
            peer = self._peer_for_record(session, record)
            trust = _peer_trust_state(peer)
            operational = _peer_operational_state(peer)
            availability = _peer_availability(peer)
            freshness = _freshness(peer, record)
            eligible = True
            if record.is_authoritative and record.imported_from_peer_id is None:
                trust = "trusted"
                operational = "enabled"
                availability = "online"
                freshness = "fresh"
            else:
                if trust in {"revoked", "unknown"}:
                    eligible = False
                elif operational == "disabled":
                    eligible = False
            candidate = _Candidate(
                record=record,
                source_peer=peer,
                match_kind="alias",
                is_local=record.is_authoritative and record.imported_from_peer_id is None and record.authority_node_id == self.settings.node_id,
                is_eligible=eligible,
                trust_state=trust,
                operational_state=operational,
                availability=availability,
                freshness_state=freshness,
            )
            candidates[record.id] = candidate
        return list(candidates.values())

    def _peer_for_record(self, session: Session, record: FederationRecord) -> FederationTrustedPeer | None:
        if record.imported_from_peer_id is None:
            return None
        return session.execute(select(FederationTrustedPeer).where(FederationTrustedPeer.id == record.imported_from_peer_id)).scalar_one_or_none()

    def _ensure_conflict(
        self,
        session: Session,
        normalized: str,
        candidates: list[_Candidate],
    ) -> FederationResolutionConflict:
        summary = [self._candidate_to_summary(candidate) for candidate in candidates]
        conflict = session.execute(
            select(FederationResolutionConflict).where(FederationResolutionConflict.normalized_identifier == normalized)
        ).scalar_one_or_none()
        now = datetime.now(timezone.utc)
        if conflict is None:
            conflict = FederationResolutionConflict(
                id=uuid4(),
                normalized_identifier=normalized,
                conflict_type=self._conflict_type(candidates),
                status="open",
                version=1,
                decision_effectiveness="current" if len(candidates) == 1 else None,
                candidate_summary={"candidates": summary},
                created_at=now,
                updated_at=now,
            )
            session.add(conflict)
        else:
            conflict.candidate_summary = {"candidates": summary}
            conflict.updated_at = now
            conflict.conflict_type = self._conflict_type(candidates)
            if conflict.status == "resolved" and not self._decision_matches_current(session, conflict, candidates):
                conflict.status = "superseded"
                conflict.decision_effectiveness = "stale"
        return conflict

    def _persist_conflict(self, normalized: str, candidates: list[_Candidate]) -> FederationResolutionConflict:
        if self.db is None:
            raise ResolutionError("resolution-unavailable", "Conflict persistence requires federation storage.")
        with self.db.transaction() as session:
            conflict = self._ensure_conflict(session, normalized, candidates)
            session.flush()
            return conflict

    def _decision_matches_current(self, session: Session, conflict: FederationResolutionConflict, candidates: list[_Candidate]) -> bool:
        decision = (
            session.execute(
                select(FederationConflictDecisionEvent)
                .where(FederationConflictDecisionEvent.conflict_id == conflict.id)
                .order_by(FederationConflictDecisionEvent.version.desc())
                .limit(1)
            )
            .scalars()
            .first()
        )
        if decision is None:
            return False
        if not candidates:
            return False
        return decision.decision_effectiveness == "current"

    def _conflict_type(self, candidates: list[_Candidate]) -> str:
        if any(candidate.is_local for candidate in candidates) and any(not candidate.is_local for candidate in candidates):
            return "local-vs-imported"
        if len(candidates) > 1:
            return "imported-vs-imported"
        return "alias-collision"

    def _candidate_to_summary(self, candidate: _Candidate) -> dict[str, Any]:
        return {
            "recordId": str(candidate.record.id),
            "canonicalId": candidate.record.canonical_id,
            "authorityNodeId": candidate.record.authority_node_id,
            "sourcePeerId": str(candidate.record.imported_from_peer_id) if candidate.record.imported_from_peer_id else None,
            "payloadDigestSha256": candidate.record.payload_digest_sha256,
            "version": candidate.record.version,
            "lifecycleState": candidate.record.lifecycle_state,
            "isLocalAuthoritative": candidate.is_local,
        }

    def _build_response(self, normalized: str, candidate: _Candidate, conflict: FederationResolutionConflict | None) -> LicenseResolutionResponse:
        now = datetime.now(timezone.utc)
        return LicenseResolutionResponse(
            identifier=normalized,
            canonicalId=candidate.record.canonical_id,
            authoritativeCanonicalId=candidate.record.canonical_id if candidate.is_local else candidate.record.canonical_id,
            authorityNodeId=candidate.record.authority_node_id,
            sourcePeerId=candidate.record.imported_from_peer_id,
            sourcePeerNodeId=candidate.source_peer.peer_node_id if candidate.source_peer else None,
            recordId=candidate.record.id,
            version=candidate.record.version,
            resolutionOutcome="local-authoritative" if candidate.is_local else "imported",
            lifecycleState=_lifecycle_from_state(candidate.record.lifecycle_state),
            conflictState=conflict.status if conflict is not None else "none",  # type: ignore[arg-type]
            sourceTrustState=candidate.trust_state,
            sourceOperationalState=candidate.operational_state,
            sourceAvailability=candidate.availability,
            freshnessState=candidate.freshness_state,
            freshness=ResolutionFreshness(
                resolvedAt=now,
                sourceObservedAt=candidate.source_peer.last_sync_success_at if candidate.source_peer else None,
                lastSyncedAt=candidate.source_peer.last_sync_success_at if candidate.source_peer else None,
                stale=candidate.freshness_state != "fresh",
            ),
            provenance=self._provenance_summary(candidate.record, candidate.source_peer, []),
            conflictId=conflict.id if conflict is not None else None,
            conflictStatus=conflict.status if conflict is not None else None,
            conflictDecisionEffectiveness=conflict.decision_effectiveness if conflict is not None else None,
            resolutionContextId=str(conflict.id) if conflict is not None else None,
            links=ResolutionLinkSet(
                self=f"/api/v1/licenses/resolution?identifier={normalized}",
                canonical=f"/api/v1/licenses/{candidate.record.canonical_id}",
                provenance=f"/api/v1/licenses/provenance?identifier={normalized}",
                conflict=f"/api/v1/admin/federation/conflicts/{conflict.id}" if conflict is not None else None,
                resolution=f"/api/v1/licenses/resolution?identifier={normalized}",
                representation=[
                    f"/api/v1/licenses/{candidate.record.canonical_id}",
                    f"/api/v1/licenses/{candidate.record.canonical_id}/json",
                ],
            ),
        )

    def _resolve_spdx(self, normalized: str) -> LicenseResolutionResponse:
        try:
            resolved = self.license_service.resolve(normalized)
        except LicenseNotFoundError as exc:
            raise ResolutionError("resolution-not-found", "No record or candidate was found.") from exc
        metadata = self.license_service.build_metadata(resolved)
        lifecycle = "deprecated" if metadata.get("isDeprecatedLicenseId") else "active"
        now = datetime.now(timezone.utc)
        return LicenseResolutionResponse(
            identifier=normalized,
            canonicalId=None,
            authoritativeCanonicalId=None,
            authorityNodeId=None,
            sourcePeerId=None,
            sourcePeerNodeId=None,
            recordId=None,
            version=resolved.license_id,
            resolutionOutcome="spdx-fallback",
            lifecycleState=lifecycle,  # type: ignore[arg-type]
            conflictState="none",
            sourceTrustState="unknown",
            sourceOperationalState="enabled",
            sourceAvailability="unknown",
            freshnessState="unknown",
            freshness=ResolutionFreshness(resolvedAt=now, sourceObservedAt=None, lastSyncedAt=None, stale=False),
            provenance=ProvenanceSummary(
                summary="SPDX reference data",
                sourceUri=resolved.record.get("detailsUrl") or resolved.record.get("detailsURL"),
                sourceDigestSha256=None,
            ),
            conflictId=None,
            conflictStatus=None,
            conflictDecisionEffectiveness=None,
            resolutionContextId=None,
            links=ResolutionLinkSet(
                self=f"/api/v1/licenses/resolution?identifier={normalized}",
                canonical=f"/api/v1/licenses/{resolved.license_id}",
                provenance=f"/api/v1/licenses/provenance?identifier={normalized}",
                conflict=None,
                resolution=f"/api/v1/licenses/resolution?identifier={normalized}",
                representation=[metadata["detailsURL"]],
            ),
        )

    def _record_for_resolution(
        self,
        session: Session,
        resolution: LicenseResolutionResponse,
    ) -> FederationRecord | None:
        if resolution.recordId is None:
            return None
        return session.execute(select(FederationRecord).where(FederationRecord.id == resolution.recordId)).scalar_one_or_none()

    def _resolution_context(self, conflict: FederationResolutionConflict | None, candidate: _Candidate) -> dict[str, Any]:
        return {
            "conflictId": str(conflict.id) if conflict else None,
            "canonicalId": candidate.record.canonical_id,
            "lifecycleState": _lifecycle_from_state(candidate.record.lifecycle_state),
            "links": {
                "conflict": f"/api/v1/admin/federation/conflicts/{conflict.id}" if conflict else None,
                "canonical": f"/api/v1/licenses/{candidate.record.canonical_id}",
            },
        }

    def _provenance_summary(
        self,
        record: FederationRecord,
        peer: FederationTrustedPeer | None,
        provenance_rows: list[FederationRecordProvenance],
    ) -> ProvenanceSummary:
        latest = provenance_rows[0] if provenance_rows else None
        summary = "Local authoritative record" if record.is_authoritative and record.imported_from_peer_id is None else "Imported federation record"
        return ProvenanceSummary(
            summary=summary,
            sourceUri=latest.source_uri if latest else record.source_record_url,
            sourceDigestSha256=latest.source_digest_sha256 if latest else record.payload_digest_sha256,
            sourceEventId=record.source_event_id,
            sourceEventPosition=record.source_event_position,
        )

    def _build_provenance_response(
        self,
        normalized: str,
        resolution: LicenseResolutionResponse,
        record: FederationRecord,
        peer: FederationTrustedPeer | None,
        summary: ProvenanceSummary,
        provenance_rows: list[FederationRecordProvenance],
    ) -> LicenseProvenanceResponse:
        return LicenseProvenanceResponse(
            identifier=normalized,
            canonicalId=resolution.canonicalId,
            recordId=resolution.recordId,
            sourcePeerId=resolution.sourcePeerId,
            authorityNodeId=resolution.authorityNodeId,
            lifecycleState=resolution.lifecycleState,
            provenance=summary,
            events=[
                ProvenanceEventResponse(
                    eventId=row.id,
                    eventPosition=record.source_event_position or 0,
                    operation=record.lifecycle_state or "published",
                    signedPayloadDigestSha256=record.source_signed_payload_digest_sha256 or "",
                    generatedAt=row.asserted_at,
                    receivedAt=row.imported_at or row.asserted_at,
                    processingStatus=record.verification_status or "unknown",
                    sourcePeerId=record.imported_from_peer_id,
                    sourcePeerNodeId=peer.peer_node_id if peer else None,
                    authorityNodeId=record.authority_node_id,
                    canonicalId=record.canonical_id,
                    payloadDigestSha256=record.payload_digest_sha256,
                )
                for row in provenance_rows
            ],
            links=ResolutionLinkSet(
                self=f"/api/v1/licenses/provenance?identifier={normalized}",
                canonical=f"/api/v1/licenses/{record.canonical_id}",
                provenance=f"/api/v1/licenses/provenance?identifier={normalized}",
                conflict=f"/api/v1/admin/federation/conflicts/{resolution.conflictId}" if resolution.conflictId else None,
                representation=[f"/api/v1/licenses/{record.canonical_id}/json"],
            ),
        )

    def _conflict_response(self, session: Session, row: FederationResolutionConflict) -> ConflictResponse:
        candidates = self._conflict_candidates_from_summary(row.candidate_summary)
        decision = (
            session.execute(
                select(FederationConflictDecisionEvent)
                .where(FederationConflictDecisionEvent.conflict_id == row.id)
                .order_by(FederationConflictDecisionEvent.version.desc())
                .limit(1)
            )
            .scalars()
            .first()
        )
        return ConflictResponse(
            conflictId=row.id,
            normalizedIdentifier=row.normalized_identifier,
            conflictType=row.conflict_type,
            status=row.status,
            version=row.version,
            decisionEffectiveness=row.decision_effectiveness,
            candidateSummary=[self._candidate_to_conflict_candidate(session, candidate) for candidate in candidates],
            decision=(
                ConflictDecisionResponse(
                    conflictId=decision.conflict_id,
                    version=decision.version,
                    status=row.status,
                    decisionType=decision.decision_type,
                    decisionEffectiveness=decision.decision_effectiveness,
                    actorRole=decision.actor_role,
                    actorIdentifier=decision.actor_identifier,
                    rationale=decision.rationale,
                    beforeState=decision.before_state,
                    afterState=decision.after_state,
                    createdAt=decision.created_at,
                )
                if decision
                else None
            ),
            createdAt=row.created_at,
            updatedAt=row.updated_at,
            resolvedAt=row.resolved_at,
            reopenedAt=row.reopened_at,
            links=ConflictContextLinkSet(
                self=f"/api/v1/admin/federation/conflicts/{row.id}",
                canonical=None,
                provenance=f"/api/v1/licenses/provenance?identifier={row.normalized_identifier}",
                resolution=f"/api/v1/licenses/resolution?identifier={row.normalized_identifier}",
            ),
        )

    def _candidate_to_conflict_candidate(self, session: Session, candidate: dict[str, Any]) -> ConflictCandidateResponse:
        record = session.execute(select(FederationRecord).where(FederationRecord.id == UUID(candidate["recordId"]))).scalar_one()
        peer = self._peer_for_record(session, record)
        return ConflictCandidateResponse(
            recordId=record.id,
            canonicalId=record.canonical_id,
            authorityNodeId=record.authority_node_id,
            sourcePeerId=record.imported_from_peer_id,
            sourcePeerNodeId=peer.peer_node_id if peer else None,
            payloadDigestSha256=record.payload_digest_sha256,
            version=record.version,
            lifecycleState=_lifecycle_from_state(record.lifecycle_state),
            sourceTrustState=_peer_trust_state(peer),
            sourceOperationalState=_peer_operational_state(peer),
            sourceAvailability=_peer_availability(peer),
            isLocalAuthoritative=record.is_authoritative and record.imported_from_peer_id is None and record.authority_node_id == self.settings.node_id,
        )

    @staticmethod
    def _conflict_candidates_from_summary(summary: dict[str, Any]) -> list[dict[str, Any]]:
        candidates = summary.get("candidates", [])
        return [item for item in candidates if isinstance(item, dict)]

    def _load_conflict_candidates(self, session: Session, conflict: FederationResolutionConflict) -> list[_Candidate]:
        candidates: list[_Candidate] = []
        for item in self._conflict_candidates_from_summary(conflict.candidate_summary or {}):
            try:
                record = session.execute(select(FederationRecord).where(FederationRecord.id == UUID(item["recordId"]))).scalar_one()
            except Exception:
                continue
            peer = self._peer_for_record(session, record)
            candidates.append(
                _Candidate(
                    record=record,
                    source_peer=peer,
                    match_kind="conflict",
                    is_local=record.is_authoritative and record.imported_from_peer_id is None and record.authority_node_id == self.settings.node_id,
                    is_eligible=_peer_trust_state(peer) not in {"revoked", "unknown"} and _peer_operational_state(peer) != "disabled",
                    trust_state=_peer_trust_state(peer),
                    operational_state=_peer_operational_state(peer),
                    availability=_peer_availability(peer),
                    freshness_state=_freshness(peer, record),
                )
            )
        return candidates
