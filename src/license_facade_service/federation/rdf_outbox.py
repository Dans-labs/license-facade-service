from __future__ import annotations

import asyncio
import json
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any
from uuid import UUID, uuid4

from rdflib import Graph, Literal, Namespace, URIRef
from rdflib.namespace import DCTERMS, RDF, XSD
from sqlalchemy import and_, or_, select

from src.license_facade_service.config.federation import FederationSettings
from src.license_facade_service.db.models.federation import (
    FederationChangeEvent,
    FederationConflictDecisionEvent,
    FederationRecord,
    FederationResolutionConflict,
    FederationRdfGraphState,
    FederationRdfOutboxJob,
)
from src.license_facade_service.db.session import Database
from src.license_facade_service.federation.digests import canonical_json_sha256_hex
from src.license_facade_service.federation.models import SignedFederationChangeEventPayload
from src.license_facade_service.infra.fuseki_client import FusekiClient
from src.license_facade_service.utils.rdf_transformer import json_to_rdf

LFS = Namespace("https://lfs.labs.dansdemo.nl/ns/federation#")
PROV = Namespace("http://www.w3.org/ns/prov#")


@dataclass(frozen=True)
class RdfJobClaim:
    id: UUID
    dedupe_key: str
    job_type: str
    record_id: UUID | None
    graph_uri: str
    expected_generation: int
    expected_digest_sha256: str
    payload_json: dict[str, Any]
    attempt_count: int


class RdfOutboxService:
    def __init__(self, db: Database, settings: FederationSettings, fuseki: FusekiClient | None = None) -> None:
        self.db = db
        self.settings = settings
        self.fuseki = fuseki or FusekiClient(timeout=float(settings.rdf_fuseki_timeout_seconds))

    @staticmethod
    def _graph_kind_from_uri(graph_uri: str) -> str:
        if graph_uri.startswith("urn:lfs:graph:record:"):
            return "record"
        if graph_uri.startswith("urn:lfs:graph:provenance:"):
            return "provenance"
        if graph_uri.startswith("urn:lfs:graph:decision:"):
            return "decision"
        return "unknown"

    @staticmethod
    def record_graph_uri(record_id: UUID) -> str:
        return f"urn:lfs:graph:record:{record_id}"

    @staticmethod
    def provenance_graph_uri(record_id: UUID) -> str:
        return f"urn:lfs:graph:provenance:{record_id}"

    @staticmethod
    def decision_graph_uri(conflict_id: UUID) -> str:
        return f"urn:lfs:graph:decision:{conflict_id}"

    def enqueue_record_jobs(
        self,
        session,
        record: FederationRecord,
        *,
        operation: str,
        signed_record_payload: dict | Any | None = None,
        record_digest: str | None = None,
        generation: int | None = None,
        provenance: dict[str, Any] | None = None,
    ) -> None:
        session.flush()
        graph_uri = self.record_graph_uri(record.id)
        provenance_uri = self.provenance_graph_uri(record.id)
        current_generation = int(record.materialized_generation or 0) if generation is None else int(generation)
        digest = record.payload_digest_sha256 if record_digest is None else record_digest
        revision_payload = None
        if signed_record_payload is not None:
            revision_payload = signed_record_payload.model_dump(mode="json") if hasattr(signed_record_payload, "model_dump") else signed_record_payload
        payload = {
            "recordId": str(record.id),
            "canonicalId": record.canonical_id,
            "authorityNodeId": record.authority_node_id,
            "operation": operation,
            "graphUri": graph_uri,
            "provenanceGraphUri": provenance_uri,
            "recordGeneration": current_generation,
            "recordDigestSha256": digest,
            "recordPayload": revision_payload,
            "provenance": provenance,
        }
        self._upsert_job(
            session,
            dedupe_key=f"record:{record.id}:{current_generation}:{operation}:{digest}",
            job_type="rdf-index",
            record_id=record.id,
            authority_node_id=record.authority_node_id,
            graph_uri=graph_uri,
            expected_generation=current_generation,
            expected_digest_sha256=digest,
            payload_json=payload,
        )
        self._upsert_graph_state(
            session,
            graph_uri=graph_uri,
            graph_kind="record",
            record_id=record.id,
            authority_node_id=record.authority_node_id,
            source_peer_id=record.imported_from_peer_id,
            expected_generation=current_generation,
            expected_digest_sha256=digest,
            status="pending",
        )
        self._upsert_job(
            session,
            dedupe_key=f"provenance:{record.id}:{current_generation}:{operation}:{digest}",
            job_type="rdf-index",
            record_id=record.id,
            authority_node_id=record.authority_node_id,
            graph_uri=provenance_uri,
            expected_generation=current_generation,
            expected_digest_sha256=digest,
            payload_json=payload,
        )
        self._upsert_graph_state(
            session,
            graph_uri=provenance_uri,
            graph_kind="provenance",
            record_id=record.id,
            authority_node_id=record.authority_node_id,
            source_peer_id=record.imported_from_peer_id,
            expected_generation=current_generation,
            expected_digest_sha256=digest,
            status="pending",
        )

    def enqueue_conflict_job(self, session, conflict: FederationResolutionConflict, decision: FederationConflictDecisionEvent) -> None:
        payload = {
            "conflictId": str(conflict.id),
            "version": conflict.version,
            "decisionVersion": decision.version,
            "decisionType": decision.decision_type,
        }
        self._upsert_job(
            session,
            dedupe_key=f"decision:{conflict.id}:{decision.version}:{decision.decision_type}",
            job_type="rdf-index",
            record_id=conflict.resolved_record_id,
            authority_node_id=None,
            graph_uri=self.decision_graph_uri(conflict.id),
            expected_generation=decision.version,
            expected_digest_sha256=canonical_json_sha256_hex(payload),
            payload_json=payload,
        )
        self._upsert_graph_state(
            session,
            graph_uri=self.decision_graph_uri(conflict.id),
            graph_kind="decision",
            record_id=conflict.resolved_record_id,
            authority_node_id=None,
            source_peer_id=None,
            expected_generation=decision.version,
            expected_digest_sha256=canonical_json_sha256_hex(payload),
            status="pending",
        )

    def _upsert_job(
        self,
        session,
        *,
        dedupe_key: str,
        job_type: str,
        record_id: UUID | None,
        authority_node_id: str | None,
        graph_uri: str,
        expected_generation: int,
        expected_digest_sha256: str,
        payload_json: dict[str, Any],
    ) -> None:
        existing = session.execute(select(FederationRdfOutboxJob).where(FederationRdfOutboxJob.dedupe_key == dedupe_key)).scalar_one_or_none()
        now = datetime.now(timezone.utc)
        if existing is None:
            session.add(
                FederationRdfOutboxJob(
                    id=uuid4(),
                    dedupe_key=dedupe_key,
                    job_type=job_type,
                    status="pending",
                    record_id=record_id,
                    authority_node_id=authority_node_id,
                    graph_uri=graph_uri,
                    expected_generation=expected_generation,
                    expected_digest_sha256=expected_digest_sha256,
                    payload_json=payload_json,
                    attempt_count=0,
                    next_attempt_at=now,
                    created_at=now,
                    updated_at=now,
                )
            )
            return
        existing.record_id = record_id
        existing.authority_node_id = authority_node_id
        existing.graph_uri = graph_uri
        existing.expected_generation = expected_generation
        existing.expected_digest_sha256 = expected_digest_sha256
        existing.payload_json = payload_json
        existing.status = "pending" if existing.status != "dead_lettered" else existing.status
        existing.next_attempt_at = now
        existing.updated_at = now

    def _upsert_graph_state(
        self,
        session,
        *,
        graph_uri: str,
        graph_kind: str,
        record_id: UUID | None,
        authority_node_id: str | None,
        source_peer_id: UUID | None,
        expected_generation: int,
        expected_digest_sha256: str | None,
        status: str,
    ) -> None:
        now = datetime.now(timezone.utc)
        state = session.execute(select(FederationRdfGraphState).where(FederationRdfGraphState.graph_uri == graph_uri)).scalar_one_or_none()
        if state is None:
            session.add(
                FederationRdfGraphState(
                    graph_uri=graph_uri,
                    graph_kind=graph_kind,
                    record_id=record_id,
                    authority_node_id=authority_node_id,
                    source_peer_id=source_peer_id,
                    expected_generation=expected_generation,
                    expected_digest_sha256=expected_digest_sha256,
                    current_generation=0,
                    current_digest_sha256=None,
                    status=status,
                    owned_by_service=True,
                    created_at=now,
                    updated_at=now,
                )
            )
            return
        state.graph_kind = graph_kind
        state.record_id = record_id
        state.authority_node_id = authority_node_id
        state.source_peer_id = source_peer_id
        state.expected_generation = expected_generation
        state.expected_digest_sha256 = expected_digest_sha256
        state.status = status
        state.owned_by_service = True
        state.updated_at = now

    def _authoritative_event_digest_for_claim(self, session, record: FederationRecord, claim: RdfJobClaim) -> tuple[str | None, dict[str, Any] | None]:
        event = session.execute(
            select(FederationChangeEvent)
            .where(
                FederationChangeEvent.record_id == record.id,
                FederationChangeEvent.event_sequence == claim.expected_generation,
                FederationChangeEvent.authority_node_id == record.authority_node_id,
            )
        ).scalar_one_or_none()
        if event is None:
            return None, None
        payload = SignedFederationChangeEventPayload.model_validate(event.signed_payload)
        event_record_payload = payload.record.model_dump(mode="json")
        job_record_payload = claim.payload_json.get("recordPayload")
        if not isinstance(job_record_payload, dict):
            return "", None
        if event_record_payload != job_record_payload:
            return "", None
        digest = payload.record.payloadDigestSha256
        if claim.payload_json.get("recordDigestSha256") != digest:
            return "", None
        return digest, event_record_payload

    def _current_record_digest_for_claim(self, session, record: FederationRecord, claim: RdfJobClaim) -> tuple[str | None, dict[str, Any] | None]:
        if int(record.materialized_generation or 0) != claim.expected_generation:
            return None, None
        digest, payload = self._authoritative_event_digest_for_claim(session, record, claim)
        if digest is not None:
            return digest, payload
        if record.imported_from_peer_id is not None or claim.payload_json.get("recordPayload") is None:
            return record.payload_digest_sha256, None
        return None, None

    def claim_jobs(self, *, limit: int, lease_seconds: int, worker_id: str) -> list[RdfJobClaim]:
        now = datetime.now(timezone.utc)
        lease_until = now + timedelta(seconds=lease_seconds)
        with self.db.transaction() as session:
            rows = (
                session.execute(
                    select(FederationRdfOutboxJob, FederationRdfGraphState)
                    .join(FederationRdfGraphState, FederationRdfGraphState.graph_uri == FederationRdfOutboxJob.graph_uri)
                    .where(
                        FederationRdfGraphState.owned_by_service.is_(True),
                        or_(
                            FederationRdfOutboxJob.status.in_(["pending", "retryable_failed"]),
                            and_(
                                FederationRdfOutboxJob.status == "running",
                                FederationRdfOutboxJob.leased_until.is_not(None),
                                FederationRdfOutboxJob.leased_until <= now,
                            ),
                        ),
                        or_(FederationRdfOutboxJob.next_attempt_at.is_(None), FederationRdfOutboxJob.next_attempt_at <= now),
                        or_(
                            FederationRdfGraphState.active_lease_until.is_(None),
                            FederationRdfGraphState.active_lease_until <= now,
                            FederationRdfGraphState.active_lease_job_id == FederationRdfOutboxJob.id,
                        ),
                    )
                    .order_by(
                        FederationRdfOutboxJob.graph_uri.asc(),
                        FederationRdfOutboxJob.expected_generation.desc(),
                        FederationRdfOutboxJob.created_at.asc(),
                    )
                    .with_for_update(skip_locked=True)
                    .limit(limit * 4)
                )
                .all()
            )
            claims: list[RdfJobClaim] = []
            selected_by_graph: dict[str, FederationRdfOutboxJob] = {}
            for job, state in rows:
                if job.graph_uri not in selected_by_graph:
                    selected_by_graph[job.graph_uri] = job
                elif job.expected_generation < selected_by_graph[job.graph_uri].expected_generation:
                    if job.status in {"pending", "retryable_failed"}:
                        job.status = "superseded"
                        job.leased_by = None
                        job.leased_until = None
                        job.updated_at = now
            for job in list(selected_by_graph.values())[:limit]:
                state = (
                    session.execute(
                        select(FederationRdfGraphState)
                        .where(FederationRdfGraphState.graph_uri == job.graph_uri)
                        .with_for_update(skip_locked=True)
                    )
                    .scalar_one_or_none()
                )
                if state is None:
                    continue
                state.active_lease_job_id = job.id
                state.active_lease_by = worker_id
                state.active_lease_until = lease_until
                state.status = "running"
                state.last_attempt_at = now
                state.updated_at = now
                job.status = "running"
                job.leased_by = worker_id
                job.leased_until = lease_until
                job.attempt_count += 1
                job.updated_at = now
                claims.append(
                    RdfJobClaim(
                        id=job.id,
                        dedupe_key=job.dedupe_key,
                        job_type=job.job_type,
                        record_id=job.record_id,
                        graph_uri=job.graph_uri,
                        expected_generation=job.expected_generation,
                        expected_digest_sha256=job.expected_digest_sha256,
                        payload_json=job.payload_json,
                        attempt_count=job.attempt_count,
                    )
                )
            return claims

    def process_pending_jobs(self, *, limit: int = 25, worker_id: str = "rdf-worker", lease_seconds: int | None = None) -> dict[str, int]:
        lease_seconds = lease_seconds or self.settings.rdf_outbox_lease_seconds
        claims = self.claim_jobs(limit=limit, lease_seconds=lease_seconds, worker_id=worker_id)
        result = {"claimed": len(claims), "succeeded": 0, "superseded": 0, "failed": 0, "dead_lettered": 0}
        for claim in claims:
            status = asyncio.run(self._process_claim(claim, worker_id=worker_id))
            result[status] += 1
        return result

    def retry_failed_jobs(self, *, limit: int = 100) -> int:
        now = datetime.now(timezone.utc)
        with self.db.transaction() as session:
            rows = (
                session.execute(
                    select(FederationRdfOutboxJob)
                    .where(FederationRdfOutboxJob.status == "retryable_failed")
                    .order_by(FederationRdfOutboxJob.updated_at.asc())
                    .limit(limit)
                )
                .scalars()
                .all()
            )
            for row in rows:
                row.status = "pending"
                row.next_attempt_at = now
                row.leased_by = None
                row.leased_until = None
                row.updated_at = now
                state = session.execute(select(FederationRdfGraphState).where(FederationRdfGraphState.graph_uri == row.graph_uri)).scalar_one_or_none()
                if state is not None:
                    state.status = "pending"
                    state.active_lease_job_id = None
                    state.active_lease_by = None
                    state.active_lease_until = None
                    state.updated_at = now
            return len(rows)

    def requeue_dead_lettered_jobs(self, *, limit: int = 100) -> int:
        now = datetime.now(timezone.utc)
        with self.db.transaction() as session:
            rows = (
                session.execute(
                    select(FederationRdfOutboxJob)
                    .where(FederationRdfOutboxJob.status == "dead_lettered")
                    .order_by(FederationRdfOutboxJob.updated_at.asc())
                    .limit(limit)
                )
                .scalars()
                .all()
            )
            for row in rows:
                row.status = "pending"
                row.attempt_count = 0
                row.next_attempt_at = now
                row.dead_lettered_at = None
                row.leased_by = None
                row.leased_until = None
                row.updated_at = now
                state = session.execute(select(FederationRdfGraphState).where(FederationRdfGraphState.graph_uri == row.graph_uri)).scalar_one_or_none()
                if state is not None:
                    state.status = "pending"
                    state.active_lease_job_id = None
                    state.active_lease_by = None
                    state.active_lease_until = None
                    state.updated_at = now
            return len(rows)

    def rebuild_all(self, *, dry_run: bool = True, confirm: bool = False, limit: int = 1000) -> dict[str, int]:
        if not dry_run and not confirm:
            raise ValueError("confirm=True is required for destructive rebuilds")
        created = 0
        counts = {"records": 0, "provenance": 0, "decision": 0}
        with self.db.transaction() as session:
            offset = 0
            while True:
                records = (
                    session.execute(
                        select(FederationRecord)
                        .order_by(FederationRecord.id)
                        .limit(limit)
                        .offset(offset)
                    )
                    .scalars()
                    .all()
                )
                if not records:
                    break
                for record in records:
                    counts["records"] += 1
                    if record.imported_from_peer_id is not None:
                        counts["provenance"] += 1
                    if dry_run:
                        created += 1
                        continue
                    self.enqueue_record_jobs(session, record, operation="rebuild")
                    created += 2
                offset += len(records)
            decisions = (
                session.execute(
                    select(FederationResolutionConflict)
                    .where(FederationResolutionConflict.status.in_(["resolved", "superseded"]))
                    .order_by(FederationResolutionConflict.created_at.asc())
                    .limit(limit)
                )
                .scalars()
                .all()
            )
            for conflict in decisions:
                counts["decision"] += 1
                if dry_run:
                    continue
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
                if decision is not None:
                    self.enqueue_conflict_job(session, conflict, decision)
                    created += 1
        return {"scheduled": created, "dryRun": int(dry_run), **counts}

    def reconcile(self, *, dry_run: bool = True, confirm: bool = False, limit: int = 1000) -> dict[str, int]:
        if not dry_run and not confirm:
            raise ValueError("confirm=True is required for destructive reconciliation")
        summary = {"missing": 0, "stale": 0, "unexpectedOwned": 0, "current": 0, "inaccessible": 0}
        with self.db.transaction() as session:
            expected_rows = session.execute(select(FederationRecord).order_by(FederationRecord.id)).scalars().all()
            expected_graphs: dict[str, tuple[str, FederationRecord]] = {}
            for record in expected_rows:
                expected_graphs[self.record_graph_uri(record.id)] = ("record", record)
                expected_graphs[self.provenance_graph_uri(record.id)] = ("provenance", record)
            for conflict in session.execute(select(FederationResolutionConflict).where(FederationResolutionConflict.status.in_(["resolved", "superseded"]))).scalars().all():
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
                if decision is not None:
                    expected_graphs[self.decision_graph_uri(conflict.id)] = ("decision", None)  # type: ignore[assignment]
            states = {state.graph_uri: state for state in session.execute(select(FederationRdfGraphState)).scalars().all()}
            for graph_uri, (graph_kind, record) in expected_graphs.items():
                state = states.get(graph_uri)
                if state is None:
                    summary["missing"] += 1
                    if not dry_run and record is not None:
                        self.enqueue_record_jobs(session, record, operation="reconcile")
                    continue
                if not state.owned_by_service:
                    summary["unexpectedOwned"] += 1
                    continue
                if record is not None:
                    expected_generation = int(record.materialized_generation or 0)
                    expected_digest = record.payload_digest_sha256
                else:
                    expected_generation = state.expected_generation
                    expected_digest = state.expected_digest_sha256
                if state.current_generation != expected_generation or state.current_digest_sha256 != expected_digest:
                    summary["stale"] += 1
                    if not dry_run and record is not None:
                        self.enqueue_record_jobs(session, record, operation="reconcile")
                else:
                    summary["current"] += 1
                if self.fuseki is not None and not dry_run:
                    pass
            for state in states.values():
                if state.graph_uri not in expected_graphs and state.owned_by_service:
                    summary["unexpectedOwned"] += 1
                    if not dry_run and state.record_id is not None:
                        record = session.execute(select(FederationRecord).where(FederationRecord.id == state.record_id)).scalar_one_or_none()
                        if record is not None:
                            self.enqueue_record_jobs(session, record, operation="reconcile")
                elif self.fuseki is not None:
                    try:
                        graph_text = asyncio.run(self.fuseki.construct_graph(state.graph_uri))
                    except RuntimeError:
                        graph_text = None
                    if graph_text is None:
                        summary["inaccessible"] += 1
                    else:
                        marker = f"{state.expected_generation}"
                        if state.expected_digest_sha256 and state.expected_digest_sha256 not in graph_text and marker not in graph_text:
                            summary["stale"] += 1
            return {"dryRun": int(dry_run), **summary}

    async def _process_claim(self, claim: RdfJobClaim, *, worker_id: str) -> str:
        kind = self._graph_kind_from_uri(claim.graph_uri)
        with self.db.transaction() as session:
            job = session.execute(select(FederationRdfOutboxJob).where(FederationRdfOutboxJob.id == claim.id).with_for_update()).scalar_one_or_none()
            state = session.execute(select(FederationRdfGraphState).where(FederationRdfGraphState.graph_uri == claim.graph_uri).with_for_update()).scalar_one_or_none()
            if job is None or state is None:
                return "superseded"
            if job.leased_by != worker_id or job.leased_until is None or job.leased_until <= datetime.now(timezone.utc):
                job.status = "superseded"
                job.leased_by = None
                job.leased_until = None
                job.updated_at = datetime.now(timezone.utc)
                state.active_lease_job_id = None
                state.active_lease_by = None
                state.active_lease_until = None
                state.status = "superseded"
                state.updated_at = datetime.now(timezone.utc)
                return "superseded"
            record = session.execute(select(FederationRecord).where(FederationRecord.id == claim.record_id)).scalar_one_or_none() if claim.record_id else None
            if state.expected_generation != claim.expected_generation or state.expected_digest_sha256 != claim.expected_digest_sha256:
                job.status = "superseded"
                job.leased_by = None
                job.leased_until = None
                job.updated_at = datetime.now(timezone.utc)
                state.status = "pending"
                state.active_lease_job_id = None
                state.active_lease_by = None
                state.active_lease_until = None
                state.updated_at = datetime.now(timezone.utc)
                return "superseded"
            validated_digest = None
            validated_record_payload = None
            if kind != "decision" and record is not None:
                validated_digest, validated_record_payload = self._current_record_digest_for_claim(session, record, claim)
            if kind != "decision" and record is not None and validated_digest != claim.expected_digest_sha256:
                job.status = "superseded"
                job.leased_by = None
                job.leased_until = None
                job.updated_at = datetime.now(timezone.utc)
                state.status = "pending"
                state.active_lease_job_id = None
                state.active_lease_by = None
                state.active_lease_until = None
                state.updated_at = datetime.now(timezone.utc)
                return "superseded"
        rdf_data = self._build_rdf_payload(claim, record, validated_record_payload=validated_record_payload)
        if not rdf_data:
            return "superseded"
        success = await self.fuseki.replace_graph(claim.graph_uri, rdf_data, "text/turtle")
        now = datetime.now(timezone.utc)
        with self.db.transaction() as session:
            job = session.execute(select(FederationRdfOutboxJob).where(FederationRdfOutboxJob.id == claim.id).with_for_update()).scalar_one_or_none()
            state = session.execute(select(FederationRdfGraphState).where(FederationRdfGraphState.graph_uri == claim.graph_uri).with_for_update()).scalar_one_or_none()
            current_record = session.execute(select(FederationRecord).where(FederationRecord.id == claim.record_id)).scalar_one_or_none() if claim.record_id else None
            if job is None or state is None:
                return "superseded"
            if job.leased_by != worker_id or state.active_lease_job_id != job.id:
                job.status = "superseded"
                job.leased_by = None
                job.leased_until = None
                job.updated_at = now
                return "superseded"
            if state.expected_generation != claim.expected_generation or state.expected_digest_sha256 != claim.expected_digest_sha256:
                job.status = "superseded"
                job.leased_by = None
                job.leased_until = None
                job.updated_at = now
                state.status = "pending"
                state.active_lease_job_id = None
                state.active_lease_by = None
                state.active_lease_until = None
                state.updated_at = now
                return "superseded"
            current_validated_digest = None
            if kind != "decision" and current_record is not None:
                current_validated_digest, _ = self._current_record_digest_for_claim(session, current_record, claim)
            if kind != "decision" and current_record is not None and current_validated_digest != claim.expected_digest_sha256:
                job.status = "superseded"
                job.leased_by = None
                job.leased_until = None
                job.updated_at = now
                state.status = "pending"
                state.active_lease_job_id = None
                state.active_lease_by = None
                state.active_lease_until = None
                state.updated_at = now
                return "superseded"
            if success:
                job.status = "succeeded"
                job.last_error_code = None
                job.last_error_detail = None
                job.leased_until = None
                job.leased_by = None
                job.updated_at = now
                state.current_generation = claim.expected_generation
                state.current_digest_sha256 = claim.expected_digest_sha256
                state.status = "succeeded"
                state.last_success_at = now
                state.last_attempt_at = now
                state.last_error_code = None
                state.last_error_detail = None
                state.active_lease_job_id = None
                state.active_lease_by = None
                state.active_lease_until = None
                state.updated_at = now
                return "succeeded"
            job.attempt_count = max(job.attempt_count, 1)
            job.leased_by = None
            job.leased_until = None
            if job.attempt_count >= self.settings.rdf_outbox_retry_attempts:
                job.status = "dead_lettered"
                job.dead_lettered_at = now
                job.last_error_code = "fuseki-unavailable"
                job.last_error_detail = "Fuseki write failed after retries."
                state.status = "dead_lettered"
                state.active_lease_job_id = None
                state.active_lease_by = None
                state.active_lease_until = None
                state.last_error_code = job.last_error_code
                state.last_error_detail = job.last_error_detail
                state.updated_at = now
                return "dead_lettered"
            job.status = "retryable_failed"
            job.next_attempt_at = now + timedelta(
                seconds=min(self.settings.rdf_outbox_retry_max_seconds, self.settings.rdf_outbox_retry_base_seconds * (2 ** (job.attempt_count - 1)))
            )
            job.last_error_code = "fuseki-unavailable"
            job.last_error_detail = "Fuseki write failed."
            job.updated_at = now
            state.status = "retryable_failed"
            state.active_lease_job_id = None
            state.active_lease_by = None
            state.active_lease_until = None
            state.last_error_code = job.last_error_code
            state.last_error_detail = job.last_error_detail
            state.updated_at = now
            return "failed"

    def _build_rdf_payload(
        self,
        claim: RdfJobClaim,
        record: FederationRecord | None,
        *,
        validated_record_payload: dict[str, Any] | None = None,
    ) -> str:
        kind = self._graph_kind_from_uri(claim.graph_uri)
        if kind == "decision":
            return self._build_decision_graph(claim)
        if record is None:
            return ""
        if kind == "provenance":
            return self._build_provenance_graph(claim, record, validated_record_payload=validated_record_payload)
        return self._build_record_graph(claim, record, validated_record_payload=validated_record_payload)

    def _build_record_graph(
        self,
        claim: RdfJobClaim,
        record: FederationRecord,
        *,
        validated_record_payload: dict[str, Any] | None = None,
    ) -> str:
        payload = validated_record_payload or claim.payload_json.get("recordPayload")
        digest = claim.payload_json.get("recordDigestSha256") or record.payload_digest_sha256
        graph = Graph()
        graph.bind("lfs", LFS)
        graph.bind("prov", PROV)
        graph.bind("dcterms", DCTERMS)
        subject = URIRef(claim.graph_uri)
        record_uri = URIRef(f"urn:lfs:record:{record.id}")
        provenance_uri = URIRef(self.provenance_graph_uri(record.id))
        graph.add((subject, RDF.type, LFS.ManagedGraph))
        graph.add((subject, LFS.graphKind, Literal("record")))
        graph.add((subject, LFS.recordUri, record_uri))
        graph.add((record_uri, RDF.type, LFS.LicenseRecord))
        graph.add((record_uri, LFS.canonicalId, Literal(record.canonical_id)))
        graph.add((record_uri, LFS.authorityNodeId, Literal(record.authority_node_id)))
        graph.add((record_uri, LFS.materializedGeneration, Literal(int(claim.expected_generation), datatype=XSD.integer)))
        graph.add((record_uri, LFS.payloadDigestSha256, Literal(str(digest))))
        graph.add((record_uri, LFS.lifecycleState, Literal(record.lifecycle_state or "published")))
        graph.add((record_uri, PROV.wasDerivedFrom, provenance_uri))
        generated_at = payload.get("publishedAt") if isinstance(payload, dict) else None
        graph.add((record_uri, PROV.generatedAtTime, Literal(generated_at or (record.published_at.isoformat() if record.published_at else ""))))
        if isinstance(payload, dict):
            record_payload = payload.get("payload")
            if isinstance(record_payload, dict):
                if "uri" not in record_payload:
                    record_payload = dict(record_payload)
                    record_payload["uri"] = str(record_uri)
                graph.parse(data=json_to_rdf(record_payload, format="turtle"), format="turtle")
                if record_payload.get("name"):
                    graph.add((record_uri, DCTERMS.title, Literal(str(record_payload["name"]))))
                if record_payload.get("licenseText"):
                    graph.add((record_uri, LFS.payloadLicenseText, Literal(str(record_payload["licenseText"]))))
        if record.imported_from_peer_id is not None:
            graph.add((record_uri, LFS.sourcePeerId, Literal(str(record.imported_from_peer_id))))
        return graph.serialize(format="turtle")

    def _build_provenance_graph(
        self,
        claim: RdfJobClaim,
        record: FederationRecord,
        *,
        validated_record_payload: dict[str, Any] | None = None,
    ) -> str:
        payload = validated_record_payload or claim.payload_json.get("recordPayload")
        digest = claim.payload_json.get("recordDigestSha256") or record.payload_digest_sha256
        graph = Graph()
        graph.bind("lfs", LFS)
        graph.bind("prov", PROV)
        graph.bind("dcterms", DCTERMS)
        graph.bind("xsd", XSD)
        subject = URIRef(claim.graph_uri)
        record_uri = URIRef(f"urn:lfs:record:{record.id}")
        graph.add((subject, RDF.type, LFS.ProvenanceGraph))
        graph.add((subject, LFS.graphKind, Literal("provenance")))
        graph.add((subject, PROV.wasDerivedFrom, record_uri))
        graph.add((subject, DCTERMS.identifier, Literal(record.canonical_id)))
        graph.add((record_uri, RDF.type, LFS.LicenseRecord))
        graph.add((record_uri, LFS.canonicalId, Literal(record.canonical_id)))
        graph.add((record_uri, LFS.authorityNodeId, Literal(record.authority_node_id)))
        if record.imported_from_peer_id is not None:
            graph.add((record_uri, LFS.sourcePeerId, Literal(str(record.imported_from_peer_id))))
        if record.source_event_id is not None:
            graph.add((record_uri, LFS.sourceEventId, Literal(str(record.source_event_id))))
        if record.source_event_position is not None:
            graph.add((record_uri, LFS.sourceEventPosition, Literal(int(record.source_event_position), datatype=XSD.integer)))
        graph.add((record_uri, LFS.signedRecordDigestSha256, Literal(digest if record.imported_from_peer_id is None else (record.source_signed_payload_digest_sha256 or ""))))
        graph.add((record_uri, LFS.lifecycleState, Literal(record.lifecycle_state or "published")))
        graph.add((record_uri, LFS.materializedGeneration, Literal(int(claim.expected_generation), datatype=XSD.integer)))
        graph.add((record_uri, LFS.importedAt, Literal(record.last_verified_at.isoformat() if record.last_verified_at else "")))
        graph.add((record_uri, PROV.wasAttributedTo, URIRef(f"urn:lfs:authority:{record.authority_node_id}")))
        generated_at = payload.get("publishedAt") if isinstance(payload, dict) else None
        graph.add((record_uri, PROV.generatedAtTime, Literal(generated_at or (record.last_verified_at.isoformat() if record.last_verified_at else ""))))
        graph.add((record_uri, PROV.hadPrimarySource, URIRef(self.record_graph_uri(record.id))))
        return graph.serialize(format="turtle")

    def _build_decision_graph(self, claim: RdfJobClaim) -> str:
        graph = Graph()
        graph.bind("lfs", LFS)
        graph.bind("prov", PROV)
        subject = URIRef(claim.graph_uri)
        graph.add((subject, RDF.type, LFS.ConflictDecisionGraph))
        graph.add((subject, LFS.graphKind, Literal("decision")))
        graph.add((subject, DCTERMS.identifier, Literal(claim.dedupe_key)))
        graph.add((subject, LFS.expectedGeneration, Literal(claim.expected_generation, datatype=XSD.integer)))
        graph.add((subject, LFS.expectedDigestSha256, Literal(claim.expected_digest_sha256)))
        payload = claim.payload_json
        if payload.get("conflictId"):
            graph.add((subject, LFS.conflictId, Literal(payload["conflictId"])))
        if payload.get("decisionVersion") is not None:
            graph.add((subject, LFS.decisionVersion, Literal(int(payload["decisionVersion"]), datatype=XSD.integer)))
        if payload.get("decisionType"):
            graph.add((subject, LFS.decisionType, Literal(payload["decisionType"])))
        return graph.serialize(format="turtle")
