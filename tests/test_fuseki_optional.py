from __future__ import annotations

import os
import socket
import subprocess
import time
from dataclasses import replace
from datetime import datetime, timedelta, timezone
from pathlib import Path
from uuid import UUID, uuid4

import psycopg
import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from rdflib import Graph, URIRef
from rdflib.namespace import PROV, RDF
from sqlalchemy import select

from src.license_facade_service.config.federation import FederationSettings
from src.license_facade_service.db.models.federation import (
    FederationConflictDecisionEvent,
    FederationInboundEvent,
    FederationRecord,
    FederationRecordProvenance,
    FederationResolutionAlias,
    FederationResolutionConflict,
    FederationRdfGraphState,
    FederationRdfOutboxJob,
    FederationTrustedPeer,
)
from src.license_facade_service.db.session import Database
from src.license_facade_service.federation.license_identity import build_canonical_license_identity
from src.license_facade_service.federation.outbound import FederationPublicationService
from src.license_facade_service.federation.rdf_outbox import RdfOutboxService
from src.license_facade_service.federation.resolution import FederationResolutionService
from src.license_facade_service.federation.resolution_models import ConflictDecisionRequest
from src.license_facade_service.infra.fuseki_client import FusekiClient

REPO_ROOT = Path(__file__).resolve().parents[1]
FUSEKI_IMAGE = "secoresearch/fuseki:4.10.0"


class _StaticSpdx:
    def resolve(self, license_id: str):
        return type("Resolved", (), {"license_id": license_id, "record": {"detailsUrl": f"https://spdx.example/{license_id}"}})()

    def build_metadata(self, resolved):
        return {"detailsURL": resolved.record["detailsUrl"]}


def _docker_available() -> bool:
    try:
        subprocess.run(["docker", "version"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=True)
        return True
    except Exception:
        return False


def _free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind(("127.0.0.1", 0))
        return int(sock.getsockname()[1])


def _run_alembic(database_url: str, *command: str) -> None:
    env = dict(os.environ)
    env["ALEMBIC_DATABASE_URL"] = database_url
    subprocess.run(
        ["uv", "run", "alembic", "-c", str(REPO_ROOT / "alembic.ini"), *command],
        check=True,
        cwd=REPO_ROOT,
        env=env,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )


def _start_postgres(db_name: str) -> tuple[str, str]:
    port = _free_port()
    container_name = f"lfs-pg-fuseki-{uuid4().hex[:8]}"
    subprocess.run(
        [
            "docker",
            "run",
            "-d",
            "--name",
            container_name,
            "-e",
            "POSTGRES_PASSWORD=postgres",
            "-e",
            "POSTGRES_USER=postgres",
            "-e",
            f"POSTGRES_DB={db_name}",
            "-p",
            f"{port}:5432",
            "postgres:16-alpine",
        ],
        check=True,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    dsn = f"postgresql+psycopg://postgres:postgres@127.0.0.1:{port}/{db_name}"
    try:
        deadline = time.time() + 60
        while time.time() < deadline:
            try:
                with psycopg.connect(dsn.replace("+psycopg", "")):
                    break
            except Exception:
                time.sleep(1)
        else:
            raise RuntimeError("postgres not ready")
        return dsn, container_name
    except Exception:
        subprocess.run(["docker", "rm", "-f", container_name], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=False)
        raise


def _start_fuseki() -> tuple[str, str]:
    port = _free_port()
    container_name = f"lfs-fuseki-{uuid4().hex[:8]}"
    subprocess.run(
        [
            "docker",
            "run",
            "-d",
            "--name",
            container_name,
            "-e",
            "ADMIN_PASSWORD=admin",
            "-p",
            f"{port}:3030",
            FUSEKI_IMAGE,
        ],
        check=True,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    url = f"http://127.0.0.1:{port}"
    client = FusekiClient(fuseki_url=url, dataset="licenses", username="admin", password="admin", timeout=10.0)
    try:
        deadline = time.time() + 60
        while time.time() < deadline:
            if subprocess.run(["curl", "-fsS", f"{url}/$/ping"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL).returncode == 0:
                break
            time.sleep(1)
        else:
            raise RuntimeError("fuseki not ready")
        return url, container_name
    except Exception:
        subprocess.run(["docker", "rm", "-f", container_name], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=False)
        raise


@pytest.fixture(scope="module")
def rdf_env():
    if not _docker_available():
        pytest.skip("docker not available for Fuseki integration test")
    postgres_dsn, pg_container = _start_postgres("lfs_fuseki")
    fuseki_url, fuseki_container = _start_fuseki()
    try:
        _run_alembic(postgres_dsn, "upgrade", "head")
        db = Database.from_url(postgres_dsn)
        settings = FederationSettings.from_env()
        fuseki = FusekiClient(fuseki_url=fuseki_url, dataset="licenses", username="admin", password="admin", timeout=10.0)
        asyncio = __import__("asyncio")
        asyncio.run(fuseki.create_dataset())
        asyncio.run(fuseki.clear_dataset())
        yield {
            "db": db,
            "settings": settings,
            "fuseki": fuseki,
            "postgres_container": pg_container,
            "fuseki_container": fuseki_container,
            "postgres_dsn": postgres_dsn,
            "fuseki_url": fuseki_url,
        }
    finally:
        subprocess.run(["docker", "rm", "-f", fuseki_container], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=False)
        subprocess.run(["docker", "rm", "-f", pg_container], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=False)


def _seed_imported_record(db: Database, peer_node_id: str, canonical_id: str, local_id: str, version: str, payload: dict, source_event_position: int):
    now = datetime.now(timezone.utc)
    with db.transaction() as session:
        peer = session.execute(select(FederationTrustedPeer).where(FederationTrustedPeer.peer_node_id == peer_node_id)).scalar_one_or_none()
        if peer is None:
            peer = FederationTrustedPeer(
                id=uuid4(),
                peer_node_id=peer_node_id,
                base_url=f"http://{peer_node_id}:12104",
                jwks_url=f"http://{peer_node_id}:12104/.well-known/jwks.json",
                peer_name=peer_node_id,
                operator_name=peer_node_id,
                trust_status="trusted",
                sync_enabled=True,
                allow_private_network=False,
                allowed_hostnames=peer_node_id,
                allowed_cidrs=None,
                enrollment_mode="strict",
                expected_key_fingerprint=None,
                expected_key_kid=None,
                last_sync_attempt_at=now,
                last_sync_success_at=now,
                last_sync_status="complete",
                created_at=now,
                updated_at=now,
            )
            session.add(peer)
            session.flush()
        record = FederationRecord(
            id=uuid4(),
            authority_node_id=peer_node_id,
            local_id=local_id,
            version=version,
            canonical_id=canonical_id,
            resolving_uuid=UUID(build_canonical_license_identity(authority_node_id=peer_node_id, local_id=local_id, version=version).resolvingUuid),
            is_authoritative=False,
            payload=payload,
            payload_digest_sha256=f"digest-{source_event_position}",
            published_at=now,
            materialized_generation=source_event_position,
            imported_from_peer_id=peer.id,
            lifecycle_state="published",
            source_record_url=f"{peer.base_url}/api/v1/federation/records/{canonical_id}",
            source_event_id=uuid4(),
            source_event_position=source_event_position,
            source_signature_kid="kid-1",
            source_signed_payload_digest_sha256=f"signed-{source_event_position}",
            verification_status="verified",
            last_verified_at=now,
            created_at=now,
            updated_at=now,
        )
        session.add(record)
        session.add(
            FederationRecordProvenance(
                id=uuid4(),
                record_id=record.id,
                source_node_id=peer.peer_node_id,
                source_uri=record.source_record_url,
                source_digest_sha256=record.payload_digest_sha256,
                provenance_type="imported",
                imported_at=now,
                asserted_at=now,
                metadata_json={"sourceEventPosition": source_event_position},
            )
        )
        session.add(
            FederationResolutionAlias(
                id=uuid4(),
                normalized_identifier=canonical_id,
                alias_value=canonical_id,
                alias_kind="canonical",
                record_id=record.id,
                authority_node_id=peer.peer_node_id,
                source_peer_id=peer.id,
                is_authoritative=False,
                created_at=now,
                updated_at=now,
            )
        )
        session.add(
            FederationInboundEvent(
                id=uuid4(),
                source_peer_id=peer.id,
                authority_node_id=peer.peer_node_id,
                remote_event_id=uuid4(),
                remote_event_position=source_event_position,
                remote_operation="upsert",
                signed_payload={"record": {"canonicalId": canonical_id}},
                signed_payload_digest_sha256=f"signed-{source_event_position}",
                signature_kid="kid-1",
                signature_alg="EdDSA",
                signature_base64url="sig",
                generated_at=now,
                received_at=now,
                processing_status="accepted",
                record_canonical_id=canonical_id,
                record_payload_digest_sha256=record.payload_digest_sha256,
            )
        )
        return peer, record


def _seed_local_record(db: Database, authority_node_id: str, local_id: str, version: str, payload: dict, generation: int) -> FederationRecord:
    now = datetime.now(timezone.utc)
    with db.transaction() as session:
        record = FederationRecord(
            id=uuid4(),
            authority_node_id=authority_node_id,
            local_id=local_id,
            version=version,
            canonical_id=f"lfs:{authority_node_id}:{local_id}:{version}",
            resolving_uuid=UUID(build_canonical_license_identity(authority_node_id=authority_node_id, local_id=local_id, version=version).resolvingUuid),
            is_authoritative=True,
            payload=payload,
            payload_digest_sha256=f"digest-{generation}",
            published_at=now,
            materialized_generation=generation,
            imported_from_peer_id=None,
            lifecycle_state="published",
            source_record_url=None,
            source_event_id=None,
            source_event_position=None,
            source_signature_kid=None,
            source_signed_payload_digest_sha256=None,
            verification_status="verified",
            last_verified_at=now,
            created_at=now,
            updated_at=now,
        )
        session.add(record)
        session.flush()
        return record


def _seed_conflict(db: Database, record_id: UUID) -> FederationResolutionConflict:
    now = datetime.now(timezone.utc)
    with db.transaction() as session:
        conflict = FederationResolutionConflict(
            id=uuid4(),
            normalized_identifier=f"urn:conflict:{record_id}",
            conflict_type="imported-vs-imported",
            status="resolved",
            version=1,
            decision_effectiveness="current",
            candidate_summary={"candidates": [{"recordId": str(record_id)}]},
            resolved_record_id=record_id,
            created_at=now,
            updated_at=now,
            resolved_at=now,
        )
        session.add(conflict)
        session.flush()
        decision = FederationConflictDecisionEvent(
            id=uuid4(),
            conflict_id=conflict.id,
            expected_version=1,
            version=1,
            decision_type="approve",
            decision_effectiveness="current",
            actor_role="curator",
            actor_identifier="curator@example.org",
            rationale="manual approval",
            before_state={"status": "open"},
            after_state={"status": "resolved"},
            created_at=now,
        )
        session.add(decision)
        session.flush()
        return conflict


def _graph_text(fuseki: FusekiClient, graph_uri: str) -> str:
    import asyncio

    graph = asyncio.run(fuseki.construct_graph(graph_uri))
    assert graph is not None
    return graph


def test_real_fuseki_indexing_outage_and_recovery(rdf_env):
    db: Database = rdf_env["db"]
    fuseki: FusekiClient = rdf_env["fuseki"]
    pg_container: str = rdf_env["postgres_container"]
    fuseki_container: str = rdf_env["fuseki_container"]
    settings: FederationSettings = rdf_env["settings"]
    outbox = RdfOutboxService(db, settings, fuseki=fuseki)
    resolution = FederationResolutionService(db, settings)

    local = _seed_local_record(db, settings.node_id or "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb", "LocalRDF", "1", {"licenseId": "LocalRDF"}, 1)
    peer, imported = _seed_imported_record(
        db,
        peer_node_id="aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa",
        canonical_id="lfs:aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa:ImportedRDF:1",
        local_id="ImportedRDF",
        version="1",
        payload={"licenseId": "ImportedRDF", "name": "Imported RDF"},
        source_event_position=10,
    )
    conflict = _seed_conflict(db, imported.id)

    with db.transaction() as session:
        outbox.enqueue_record_jobs(session, local, operation="upsert")
        outbox.enqueue_record_jobs(session, imported, operation="upsert")
        decision = session.execute(select(FederationConflictDecisionEvent).where(FederationConflictDecisionEvent.conflict_id == conflict.id)).scalar_one()
        outbox.enqueue_conflict_job(session, conflict, decision)

    result = outbox.process_pending_jobs(limit=10, worker_id="worker-1")
    assert result["succeeded"] >= 3
    assert result["failed"] == 0
    assert result["dead_lettered"] == 0

    record_graph = _graph_text(fuseki, outbox.record_graph_uri(imported.id))
    provenance_graph = _graph_text(fuseki, outbox.provenance_graph_uri(imported.id))
    decision_graph = _graph_text(fuseki, outbox.decision_graph_uri(conflict.id))

    assert str(imported.payload["name"]) in record_graph or str(imported.id) in record_graph
    assert str(imported.source_event_id) in provenance_graph
    assert str(imported.source_event_position) in provenance_graph
    assert "Imported RDF" not in provenance_graph
    assert str(conflict.id) in decision_graph
    assert "decisionType" not in provenance_graph

    resolution_response = resolution.resolve(imported.canonical_id)
    assert resolution_response.resolutionOutcome == "imported"
    assert resolution_response.authorityNodeId == peer.peer_node_id
    assert resolution_response.sourcePeerId == peer.id

    subprocess.run(["docker", "stop", fuseki_container], check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

    imported_next = _seed_imported_record(
        db,
        peer_node_id="aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa",
        canonical_id="lfs:aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa:ImportedRDF:2",
        local_id="ImportedRDF",
        version="2",
        payload={"licenseId": "ImportedRDF", "name": "Imported RDF v2"},
        source_event_position=11,
    )[1]
    with db.transaction() as session:
        outbox.enqueue_record_jobs(session, imported_next, operation="upsert")

    retry_result = outbox.process_pending_jobs(limit=10, worker_id="worker-2")
    assert retry_result["failed"] >= 1
    with db.transaction() as session:
        queued = session.execute(select(FederationRdfOutboxJob).where(FederationRdfOutboxJob.status == "retryable_failed")).scalars().all()
        assert queued
        state = session.execute(select(FederationRdfGraphState).where(FederationRdfGraphState.graph_uri == outbox.record_graph_uri(imported_next.id))).scalar_one()
        assert state.status == "retryable_failed"

    with db.transaction() as session:
        peer_row = session.execute(select(FederationTrustedPeer).where(FederationTrustedPeer.id == peer.id)).scalar_one()
        peer_row.last_sync_status = "failed"
        peer_row.last_sync_success_at = datetime.now(timezone.utc) - timedelta(days=1)
        peer_row.updated_at = datetime.now(timezone.utc)
    resolution_offline = resolution.resolve(imported.canonical_id)
    assert resolution_offline.freshnessState == "stale"

    requeued = outbox.retry_failed_jobs(limit=10)
    assert requeued >= 1
    subprocess.run(["docker", "start", fuseki_container], check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    time.sleep(2)
    import asyncio

    asyncio.run(fuseki.create_dataset())
    asyncio.run(fuseki.clear_dataset())
    recovered = outbox.process_pending_jobs(limit=10, worker_id="worker-3")
    assert recovered["succeeded"] >= 1

    with db.transaction() as session:
        state = session.execute(select(FederationRdfGraphState).where(FederationRdfGraphState.graph_uri == outbox.record_graph_uri(imported_next.id))).scalar_one()
        assert state.status == "succeeded"
        assert state.current_generation == imported_next.materialized_generation
        assert state.current_digest_sha256 == imported_next.payload_digest_sha256

    repeated = outbox.process_pending_jobs(limit=10, worker_id="worker-4")
    assert repeated["claimed"] == 0

    dead_outbox = RdfOutboxService(db, replace(settings, rdf_outbox_retry_attempts=1), fuseki=fuseki)
    imported_third = _seed_imported_record(
        db,
        peer_node_id="aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa",
        canonical_id="lfs:aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa:ImportedRDF:3",
        local_id="ImportedRDF",
        version="3",
        payload={"licenseId": "ImportedRDF", "name": "Imported RDF v3"},
        source_event_position=12,
    )[1]
    with db.transaction() as session:
        dead_outbox.enqueue_record_jobs(session, imported_third, operation="upsert")

    subprocess.run(["docker", "stop", fuseki_container], check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    dead = dead_outbox.process_pending_jobs(limit=10, worker_id="worker-dead")
    assert dead["dead_lettered"] >= 1

    requeued_dead = dead_outbox.requeue_dead_lettered_jobs(limit=10)
    assert requeued_dead >= 1

    subprocess.run(["docker", "start", fuseki_container], check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    time.sleep(2)
    asyncio.run(fuseki.create_dataset())
    asyncio.run(fuseki.clear_dataset())

    final = dead_outbox.process_pending_jobs(limit=10, worker_id="worker-final")
    assert final["succeeded"] >= 1

    with db.transaction() as session:
        imported_rows = session.execute(select(FederationRdfGraphState).where(FederationRdfGraphState.graph_kind == "provenance")).scalars().all()
        assert imported_rows
        record_rows = session.execute(select(FederationRdfGraphState).where(FederationRdfGraphState.graph_kind == "record")).scalars().all()
        assert record_rows
