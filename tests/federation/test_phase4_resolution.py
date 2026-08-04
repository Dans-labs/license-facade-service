from __future__ import annotations

import asyncio
import json
import os
import socket
import subprocess
import threading
import time
from datetime import datetime, timezone
from pathlib import Path
from uuid import UUID, uuid4

import psycopg
import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from fastapi.testclient import TestClient
from sqlalchemy import select

from src.license_facade_service.api.v1 import licenses as licenses_api
from src.license_facade_service.api.federation import admin as federation_admin
from src.license_facade_service.config.federation import FederationSettings
from src.license_facade_service.db.models.federation import (
    FederationConflictDecisionEvent,
    FederationRecord,
    FederationRecordProvenance,
    FederationResolutionAlias,
    FederationResolutionConflict,
    FederationRdfGraphState,
    FederationRdfOutboxJob,
    FederationTrustedPeer,
    FederationInboundEvent,
)
from src.license_facade_service.db.session import Database
from src.license_facade_service.federation.outbound import FederationPublicationService
from src.license_facade_service.federation.rdf_outbox import RdfOutboxService
from src.license_facade_service.federation.license_identity import build_canonical_license_identity
from src.license_facade_service.federation.runtime import FederationRuntime
from src.license_facade_service.main import create_app
from src.license_facade_service.services.auth import AuthService
from src.license_facade_service.services.licenses import LicenseService, SPDXClient

REPO_ROOT = Path(__file__).resolve().parents[2]


class _StaticSpdx(SPDXClient):
    async def fetch_license_list(self):
        return {
            "licenseListVersion": "1",
            "licenses": [
                {"licenseId": "MIT", "name": "MIT"},
                {"licenseId": "Apache-2.0", "name": "Apache"},
                {"licenseId": "CC-BY-4.0", "name": "CC"},
            ],
        }

    async def fetch_license_details(self, license_id: str):
        return {"licenseId": license_id, "name": license_id, "licenseText": "x", "crossRef": []}


class _FakeFuseki:
    def __init__(self, succeed: bool = True):
        self.succeed = succeed
        self.calls: list[tuple[str, str, str]] = []

    async def replace_graph(self, graph_uri: str, rdf_data: str, content_type: str = "text/turtle") -> bool:
        self.calls.append((graph_uri, rdf_data, content_type))
        return self.succeed


class _BlockingFuseki:
    def __init__(self, on_enter=None):
        self.calls: list[tuple[str, str, str]] = []
        self.entered = threading.Event()
        self.release = threading.Event()
        self.on_enter = on_enter

    async def replace_graph(self, graph_uri: str, rdf_data: str, content_type: str = "text/turtle") -> bool:
        self.calls.append((graph_uri, rdf_data, content_type))
        self.entered.set()
        if self.on_enter is not None:
            self.on_enter()
        await asyncio.to_thread(self.release.wait)
        return True


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


@pytest.fixture(scope="module")
def postgres_url():
    if not _docker_available():
        pytest.skip("docker not available for PostgreSQL phase4 tests")
    port = _free_port()
    container_name = f"lfs-pg-phase4-{uuid4().hex[:8]}"
    subprocess.run(
        [
            "docker",
            "run",
            "--rm",
            "-d",
            "--name",
            container_name,
            "-e",
            "POSTGRES_PASSWORD=postgres",
            "-e",
            "POSTGRES_USER=postgres",
            "-e",
            "POSTGRES_DB=lfs_phase4",
            "-p",
            f"{port}:5432",
            "postgres:16-alpine",
        ],
        check=True,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    dsn = f"postgresql+psycopg://postgres:postgres@127.0.0.1:{port}/lfs_phase4"
    try:
        deadline = time.time() + 45
        while time.time() < deadline:
            try:
                with psycopg.connect(dsn.replace("+psycopg", "")):
                    break
            except Exception:
                time.sleep(1)
        else:
            raise RuntimeError("postgres not ready")
        yield dsn
    finally:
        subprocess.run(["docker", "kill", container_name], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=False)


def _seed_snapshot(base_dir: Path) -> None:
    snapshot = base_dir / "resources" / "data" / "licenses" / "snapshots" / "seed"
    snapshot.mkdir(parents=True, exist_ok=True)
    licenses = {
        "licenseListVersion": "1",
        "licenses": [
            {"licenseId": "MIT", "name": "MIT", "uri": "https://example.test/licenses/MIT"},
            {"licenseId": "Apache-2.0", "name": "Apache", "uri": "https://example.test/licenses/Apache-2.0"},
            {"licenseId": "CC-BY-4.0", "name": "CC", "uri": "https://example.test/licenses/CC-BY-4.0"},
        ],
    }
    (snapshot / "licenses_list.json").write_text(json.dumps(licenses), encoding="utf-8")
    (snapshot / "version.json").write_text(json.dumps({"licenseListVersion": "1"}), encoding="utf-8")
    for lic in licenses["licenses"]:
        (snapshot / f"{lic['licenseId']}.json").write_text(
            json.dumps({"licenseId": lic["licenseId"], "name": lic["name"], "licenseText": "x", "crossRef": []}),
            encoding="utf-8",
        )
    (snapshot.parent.parent / "current_snapshot.json").write_text(json.dumps({"snapshot": "seed"}), encoding="utf-8")
    curated = {
        "MIT": {
            "original": {
                "href": "https://opensource.org/licenses/MIT",
                "relation": "original",
                "type": "original",
                "mediaType": "text/html",
                "authority": "OSI",
                "curator": "OSI",
                "provenance": "curated",
                "source": "https://opensource.org/licenses/MIT",
            }
        },
        "Apache-2.0": {
            "original": {
                "href": "https://www.apache.org/licenses/LICENSE-2.0",
                "relation": "original",
                "type": "original",
                "mediaType": "text/html",
                "authority": "ASF",
                "curator": "ASF",
                "provenance": "curated",
                "source": "https://www.apache.org/licenses/LICENSE-2.0",
            },
            "machine": {
                "content": {"@context": "https://www.w3.org/ns/odrl.jsonld", "@type": "odrl:Policy"},
                "mediaType": "application/ld+json",
                "profile": "https://www.w3.org/ns/odrl/2/",
                "vocabulary": "https://www.w3.org/ns/odrl/2/",
                "provenance": "curated",
                "source": "https://example.test/odrl",
                "version": "1.0",
                "digest": "sha256:apache",
            },
        },
        "CC-BY-4.0": {
            "original": {
                "href": "https://creativecommons.org/licenses/by/4.0/",
                "relation": "original",
                "type": "original",
                "mediaType": "text/html",
                "authority": "CC",
                "curator": "CC",
                "provenance": "curated",
                "source": "https://creativecommons.org/licenses/by/4.0/",
            },
        },
    }
    (base_dir / "resources" / "data" / "licenses" / "curated_representations.json").write_text(json.dumps(curated), encoding="utf-8")


def _peer(session, *, peer_node_id: str, trust_status: str = "trusted", sync_enabled: bool = True, last_sync_status: str | None = "complete", last_sync_success_at=None):
    now = datetime.now(timezone.utc)
    existing = session.execute(select(FederationTrustedPeer).where(FederationTrustedPeer.peer_node_id == peer_node_id)).scalar_one_or_none()
    if existing is not None:
        return existing
    peer = FederationTrustedPeer(
        id=uuid4(),
        peer_node_id=peer_node_id,
        base_url=f"http://{peer_node_id}:12104",
        jwks_url=f"http://{peer_node_id}:12104/.well-known/jwks.json",
        peer_name=peer_node_id,
        operator_name=peer_node_id,
        trust_status=trust_status,
        sync_enabled=sync_enabled,
        allow_private_network=False,
        allowed_hostnames=peer_node_id,
        allowed_cidrs=None,
        enrollment_mode="strict",
        expected_key_fingerprint=None,
        expected_key_kid=None,
        last_sync_attempt_at=now,
        last_sync_success_at=last_sync_success_at,
        last_sync_status=last_sync_status,
        created_at=now,
        updated_at=now,
    )
    session.add(peer)
    session.flush()
    return peer


def _imported_record(session, *, peer: FederationTrustedPeer, canonical_id: str, local_id: str, version: str, payload: dict, source_event_position: int, lifecycle_state: str = "published", aliases: tuple[str, ...] = ()):
    now = datetime.now(timezone.utc)
    identity = build_canonical_license_identity(authority_node_id=peer.peer_node_id, local_id=local_id, version=version)
    digest_suffix = f"{source_event_position}"
    record = FederationRecord(
        id=uuid4(),
        authority_node_id=peer.peer_node_id,
        local_id=local_id,
        version=version,
        canonical_id=canonical_id,
        resolving_uuid=UUID(identity.resolvingUuid),
        is_authoritative=False,
        payload=payload,
        payload_digest_sha256=f"digest-{digest_suffix}",
        published_at=now,
        materialized_generation=source_event_position,
        imported_from_peer_id=peer.id,
        lifecycle_state=lifecycle_state,
        source_record_url=f"{peer.base_url}/api/v1/federation/records/{canonical_id}",
        source_event_id=uuid4(),
        source_event_position=source_event_position,
        source_signature_kid="kid-1",
        source_signed_payload_digest_sha256=f"signed-{digest_suffix}",
        verification_status="verified",
        last_verified_at=now,
        created_at=now,
        updated_at=now,
    )
    session.add(record)
    session.flush()
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
    for alias in aliases:
        session.add(
            FederationResolutionAlias(
                id=uuid4(),
                normalized_identifier=alias,
                alias_value=alias,
                alias_kind="approved-alias",
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
            remote_operation="upsert" if lifecycle_state == "published" else lifecycle_state,
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
    return record


@pytest.fixture
def phase4_env(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, postgres_url: str):
    _run_alembic(postgres_url, "upgrade", "head")
    _seed_snapshot(tmp_path)
    key = Ed25519PrivateKey.generate()
    pem = key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    key_path = tmp_path / "node-b.pem"
    key_path.write_bytes(pem)

    monkeypatch.setenv("BASE_DIR", str(REPO_ROOT))
    monkeypatch.setenv("URL_BASE", "https://example.test/api/v1/licenses")
    monkeypatch.setenv("FUSEKI_ENABLE", "false")
    monkeypatch.setenv("FEDERATION_ENABLED", "true")
    monkeypatch.setenv("FEDERATION_INBOUND_ENABLED", "true")
    monkeypatch.setenv("FEDERATION_DATABASE_URL", postgres_url)
    monkeypatch.setenv("FEDERATION_NODE_ID", "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb")
    monkeypatch.setenv("FEDERATION_PUBLIC_BASE_URL", "https://node-b.example.org")
    monkeypatch.setenv("FEDERATION_NODE_NAME", "Node B")
    monkeypatch.setenv("FEDERATION_OPERATOR", "Operator B")
    monkeypatch.setenv("FEDERATION_SIGNING_KEY_PATH", str(key_path))
    monkeypatch.setenv("FEDERATION_ACTIVE_KID", "node-b-k1")
    monkeypatch.setenv("FEDERATION_JWKS_ENABLED", "true")
    monkeypatch.setenv("FEDERATION_ALLOW_HTTP_FOR_DEMO", "true")
    monkeypatch.setenv("FEDERATION_ALLOW_PRIVATE_NETWORK", "false")
    monkeypatch.setenv("FEDERATION_SYNC_ALLOWED_PORTS", "12104,443")
    monkeypatch.setenv("LFS_ADMIN_TOKEN", "admin-token")
    monkeypatch.setenv("LFS_CURATOR_TOKEN", "curator-token")
    monkeypatch.setenv("FEDERATION_RDF_OUTBOX_RETRY_ATTEMPTS", "2")

    licenses_api._license_service = LicenseService(base_dir=tmp_path, spdx_client=_StaticSpdx())
    licenses_api._auth_service = AuthService()
    runtime = FederationRuntime(FederationSettings.from_env())
    state = runtime.initialize()
    assert state.ready
    app = create_app()
    with TestClient(app) as client:
        yield {
            "client": client,
            "db": runtime.db,
            "settings": runtime.settings,
            "runtime": runtime,
        }


def test_local_authority_wins_and_imported_never_overwrites(phase4_env):
    db = phase4_env["db"]
    client = phase4_env["client"]
    settings = phase4_env["settings"]
    publication = FederationPublicationService(db, settings)
    canonical = build_canonical_license_identity(authority_node_id=settings.node_id, local_id="Local", version="1").canonicalId
    publication.publish_new_version(
        canonical_id=canonical,
        authority_node_id=settings.node_id,
        local_id="Local",
        version="1",
        payload={"licenseId": "Local", "uri": "https://example.test/licenses/Local"},
    )
    with db.transaction() as session:
        peer = _peer(session, peer_node_id="aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa")
        _imported_record(
            session,
            peer=peer,
            canonical_id="lfs:aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa:Local:1",
            local_id="Local",
            version="1",
            payload={"licenseId": "Local", "uri": "https://example.test/licenses/Local"},
            source_event_position=10,
            aliases=("https://example.test/licenses/Local",),
        )

    response = client.get("/api/v1/licenses/resolution", params={"identifier": canonical})
    assert response.status_code == 200
    body = response.json()
    assert body["resolutionOutcome"] == "local-authoritative"
    assert body["canonicalId"] == canonical
    assert body["conflictState"] in {"none", "open"}

    catalog = client.get("/api/v1/federation/catalog").json()
    assert canonical in [item["canonicalId"] for item in catalog["items"]]
    with db.transaction() as session:
        imported = session.execute(select(FederationRecord).where(FederationRecord.imported_from_peer_id.is_not(None))).scalars().all()
        assert len(imported) == 1
        conflicts = session.execute(select(FederationResolutionConflict)).scalars().all()
        assert len(conflicts) == 0


def test_imported_ambiguity_conflict_and_reversal(phase4_env):
    db = phase4_env["db"]
    client = phase4_env["client"]
    with db.transaction() as session:
        peer_a = _peer(session, peer_node_id="22222222-2222-4222-8222-222222222222", last_sync_success_at=None, last_sync_status="failed")
        peer_b = _peer(session, peer_node_id="33333333-3333-4333-8333-333333333333", last_sync_success_at=None, last_sync_status="failed")
        _imported_record(
            session,
            peer=peer_a,
            canonical_id="lfs:aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa:Shared:1",
            local_id="Shared",
            version="1",
            payload={"licenseId": "SharedA", "uri": "https://example.test/shared"},
            source_event_position=11,
            aliases=("shared-alias",),
        )
        _imported_record(
            session,
            peer=peer_b,
            canonical_id="lfs:cccccccc-cccc-4ccc-8ccc-cccccccccccc:Shared:1",
            local_id="Shared",
            version="1",
            payload={"licenseId": "SharedB", "uri": "https://example.test/shared"},
            source_event_position=12,
            aliases=("shared-alias",),
        )

    ambiguous = client.get("/api/v1/licenses/resolution", params={"identifier": "shared-alias"})
    assert ambiguous.status_code == 409
    conflict_id = ambiguous.json()["resolutionContext"]["conflictId"]

    decision = client.post(
        f"/api/v1/admin/federation/conflicts/{conflict_id}/decisions",
        headers={"Authorization": "Bearer curator-token"},
        json={"expectedVersion": 1, "decisionType": "prefer-imported", "aliasValue": "lfs:aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa:Shared:1"},
    )
    assert decision.status_code == 200
    assert decision.json()["decisionType"] == "prefer-imported"

    reversed_ = client.post(
        f"/api/v1/admin/federation/conflicts/{conflict_id}/reversals",
        headers={"Authorization": "Bearer curator-token"},
        json={"expectedVersion": 2, "decisionType": "reverse"},
    )
    assert reversed_.status_code == 200
    assert reversed_.json()["decisionEffectiveness"] == "reversed"
    with db.transaction() as session:
        conflict = session.execute(select(FederationResolutionConflict)).scalar_one()
        assert conflict.status == "open"
        decisions = session.execute(select(FederationConflictDecisionEvent).where(FederationConflictDecisionEvent.conflict_id == conflict.id)).scalars().all()
        assert len(decisions) == 2


def test_peer_policy_and_tombstones(phase4_env):
    db = phase4_env["db"]
    client = phase4_env["client"]
    with db.transaction() as session:
        trusted = _peer(session, peer_node_id="44444444-4444-4444-8444-444444444444", last_sync_success_at=None, last_sync_status="failed")
        archived = _peer(session, peer_node_id="55555555-5555-4555-8555-555555555555", trust_status="archived", sync_enabled=False, last_sync_success_at=None, last_sync_status="failed")
        disabled = _peer(session, peer_node_id="66666666-6666-4666-8666-666666666666", sync_enabled=False, last_sync_success_at=None, last_sync_status="failed")
        revoked = _peer(session, peer_node_id="77777777-7777-4777-8777-777777777777", trust_status="revoked", sync_enabled=False, last_sync_success_at=None, last_sync_status="failed")
        _imported_record(
            session,
            peer=trusted,
            canonical_id="lfs:dddddddd-dddd-4ddd-8ddd-dddddddddddd:Offline:1",
            local_id="Offline",
            version="1",
            payload={"licenseId": "Offline"},
            source_event_position=21,
            aliases=("offline-alias",),
        )
        _imported_record(
            session,
            peer=archived,
            canonical_id="lfs:eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee:Archived:1",
            local_id="Archived",
            version="1",
            payload={"licenseId": "Archived"},
            source_event_position=22,
            aliases=("archived-alias",),
        )
        _imported_record(
            session,
            peer=disabled,
            canonical_id="lfs:ffffffff-ffff-4fff-8fff-ffffffffffff:Disabled:1",
            local_id="Disabled",
            version="1",
            payload={"licenseId": "Disabled"},
            source_event_position=23,
            aliases=("disabled-alias",),
        )
        _imported_record(
            session,
            peer=revoked,
            canonical_id="lfs:11111111-1111-4111-8111-111111111111:Revoked:1",
            local_id="Revoked",
            version="1",
            payload={"licenseId": "Revoked"},
            source_event_position=24,
            aliases=("revoked-alias",),
        )
        _imported_record(
            session,
            peer=trusted,
            canonical_id="lfs:dddddddd-dddd-4ddd-8ddd-dddddddddddd:Tomb:1",
            local_id="Tomb",
            version="1",
            payload={"licenseId": "Tomb"},
            source_event_position=25,
            lifecycle_state="tombstoned",
            aliases=("tomb-alias",),
        )

    offline = client.get("/api/v1/licenses/resolution", params={"identifier": "offline-alias"})
    assert offline.status_code == 200
    assert offline.json()["freshnessState"] == "stale"

    archived = client.get("/api/v1/licenses/resolution", params={"identifier": "archived-alias"})
    assert archived.status_code == 200

    disabled = client.get("/api/v1/licenses/resolution", params={"identifier": "disabled-alias"})
    assert disabled.status_code == 503

    revoked = client.get("/api/v1/licenses/resolution", params={"identifier": "revoked-alias"})
    assert revoked.status_code == 503

    tomb = client.get("/api/v1/licenses/resolution", params={"identifier": "tomb-alias"})
    assert tomb.status_code == 410


def test_rdf_outbox_atomicity_and_out_of_order_jobs(phase4_env):
    db = phase4_env["db"]
    settings = phase4_env["settings"]
    publication = FederationPublicationService(db, settings)
    outbox = RdfOutboxService(db, settings, fuseki=_FakeFuseki(succeed=True))
    canonical = build_canonical_license_identity(authority_node_id=settings.node_id, local_id="Rdf", version="1").canonicalId
    publication.publish_new_version(
        canonical_id=canonical,
        authority_node_id=settings.node_id,
        local_id="Rdf",
        version="1",
        payload={"licenseId": "Rdf", "uri": "https://example.test/licenses/Rdf"},
    )
    with db.transaction() as session:
        jobs = session.execute(select(FederationRdfOutboxJob).order_by(FederationRdfOutboxJob.expected_generation)).scalars().all()
        assert jobs
        record = session.execute(select(FederationRecord).where(FederationRecord.canonical_id == canonical)).scalar_one()
        record.materialized_generation += 1
    result = outbox.process_pending_jobs(limit=10)
    assert result["claimed"] >= 1
    with db.transaction() as session:
        states = session.execute(select(FederationRdfGraphState)).scalars().all()
        assert states


def test_rdf_outbox_stale_generation_is_superseded_and_locked(phase4_env):
    db = phase4_env["db"]
    settings = phase4_env["settings"]
    publication = FederationPublicationService(db, settings)
    fuseki = _BlockingFuseki()
    outbox = RdfOutboxService(db, settings, fuseki=fuseki)

    canonical = build_canonical_license_identity(authority_node_id=settings.node_id, local_id="Lock", version="1").canonicalId
    publication.publish_new_version(
        canonical_id=canonical,
        authority_node_id=settings.node_id,
        local_id="Lock",
        version="1",
        payload={"licenseId": "Lock", "uri": "https://example.test/licenses/Lock"},
    )
    with db.transaction() as session:
        record = session.execute(select(FederationRecord).where(FederationRecord.canonical_id == canonical)).scalar_one()
        conflict = FederationResolutionConflict(
            id=uuid4(),
            normalized_identifier=canonical,
            conflict_type="imported-alias-collision",
            status="open",
            version=1,
            decision_effectiveness=None,
            candidate_summary={"recordId": str(record.id)},
            resolved_record_id=record.id,
            created_at=datetime.now(timezone.utc),
            updated_at=datetime.now(timezone.utc),
            resolved_at=None,
            reopened_at=None,
        )
        session.add(conflict)
        session.flush()
        decision1 = FederationConflictDecisionEvent(
            id=uuid4(),
            conflict_id=conflict.id,
            expected_version=1,
            version=1,
            decision_type="approve",
            decision_effectiveness="current",
            actor_role="curator",
            actor_identifier="tester",
            rationale="seed",
            before_state={},
            after_state={},
            created_at=datetime.now(timezone.utc),
        )
        session.add(decision1)
        outbox.enqueue_conflict_job(session, conflict, decision1)
        conflict_id = conflict.id

    first_result: dict[str, int] = {}

    def _enqueue_newer_conflict_job() -> None:
        with db.transaction() as session:
            conflict = session.execute(select(FederationResolutionConflict).where(FederationResolutionConflict.id == conflict_id)).scalar_one()
            decision2 = FederationConflictDecisionEvent(
                id=uuid4(),
                conflict_id=conflict.id,
                expected_version=2,
                version=2,
                decision_type="reverse",
                decision_effectiveness="current",
                actor_role="curator",
                actor_identifier="tester",
                rationale="advance version",
                before_state={},
                after_state={},
                created_at=datetime.now(timezone.utc),
            )
            session.add(decision2)
            outbox.enqueue_conflict_job(session, conflict, decision2)

    def _run_first_worker() -> None:
        first_result.update(outbox.process_pending_jobs(limit=1, worker_id="worker-a"))

    fuseki.on_enter = _enqueue_newer_conflict_job
    worker = threading.Thread(target=_run_first_worker, daemon=True)
    worker.start()
    assert fuseki.entered.wait(timeout=10)

    blocked = outbox.claim_jobs(limit=1, lease_seconds=settings.rdf_outbox_lease_seconds, worker_id="worker-b")
    assert all(claim.graph_uri != outbox.decision_graph_uri(conflict_id) for claim in blocked)

    fuseki.on_enter = None
    fuseki.release.set()
    worker.join(timeout=10)
    assert worker.is_alive() is False
    assert first_result["superseded"] >= 1

    follow_up = outbox.process_pending_jobs(limit=10, worker_id="worker-c")
    assert follow_up["succeeded"] >= 1

    with db.transaction() as session:
        jobs = session.execute(
            select(FederationRdfOutboxJob)
            .where(FederationRdfOutboxJob.graph_uri == outbox.decision_graph_uri(conflict_id))
            .order_by(FederationRdfOutboxJob.expected_generation, FederationRdfOutboxJob.id)
        ).scalars().all()
        assert [job.status for job in jobs].count("superseded") >= 1
        assert [job.status for job in jobs].count("succeeded") >= 1
        assert any(state.current_generation == 2 for state in session.execute(select(FederationRdfGraphState)).scalars())


def test_rdf_outbox_transaction_rollback_is_atomic(phase4_env):
    db = phase4_env["db"]
    settings = phase4_env["settings"]
    publication = FederationPublicationService(db, settings)
    outbox = RdfOutboxService(db, settings, fuseki=_FakeFuseki(succeed=True))

    canonical = build_canonical_license_identity(authority_node_id=settings.node_id, local_id="Rollback", version="1").canonicalId
    publication.publish_new_version(
        canonical_id=canonical,
        authority_node_id=settings.node_id,
        local_id="Rollback",
        version="1",
        payload={"licenseId": "Rollback", "uri": "https://example.test/licenses/Rollback"},
    )
    with db.transaction() as session:
        record_id = session.execute(select(FederationRecord.id).where(FederationRecord.canonical_id == canonical)).scalar_one()
        before_count = session.execute(select(FederationRdfOutboxJob).where(FederationRdfOutboxJob.record_id == record_id)).scalars().all()
        before_count = len(before_count)

    with pytest.raises(RuntimeError):
        with db.transaction() as session:
            record = session.execute(select(FederationRecord).where(FederationRecord.id == record_id)).scalar_one()
            outbox.enqueue_record_jobs(session, record, operation="upsert")
            raise RuntimeError("abort transaction")

    with db.transaction() as session:
        jobs = session.execute(select(FederationRdfOutboxJob).where(FederationRdfOutboxJob.record_id == record_id)).scalars().all()
        assert len(jobs) == before_count


def test_migration_repeatability_phase4(postgres_url: str):
    _run_alembic(postgres_url, "downgrade", "base")
    _run_alembic(postgres_url, "upgrade", "head")
    _run_alembic(postgres_url, "downgrade", "base")
    _run_alembic(postgres_url, "upgrade", "head")
    with psycopg.connect(postgres_url.replace("+psycopg", "")) as conn:
        with conn.cursor() as cur:
            cur.execute("SELECT to_regclass('public.federation_resolution_conflicts')")
            assert cur.fetchone()[0] is not None
