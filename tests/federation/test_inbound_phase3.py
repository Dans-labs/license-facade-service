from __future__ import annotations

import base64
import json
import os
import socket
import subprocess
import threading
import time
from dataclasses import replace
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import parse_qs, urlsplit
from uuid import uuid4

import psycopg
import pytest
import httpx
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from fastapi.testclient import TestClient
from sqlalchemy import func, select
from sqlalchemy.exc import OperationalError

from src.license_facade_service.api.v1 import licenses as licenses_api
from src.license_facade_service.config.federation import FederationSettings
from src.license_facade_service.db.models.federation import (
    FederationConflictRecord,
    FederationChangeEvent,
    FederationInboundEvent,
    FederationPeerCursor,
    FederationPeerSigningKey,
    FederationRecord,
    FederationRecordProvenance,
    FederationSyncAttempt,
    FederationTrustedPeer,
)
from src.license_facade_service.db.session import Database
from src.license_facade_service.federation.canonical_json import canonicalize_to_bytes
from src.license_facade_service.federation.digests import canonical_json_sha256_hex, sha256_hex
from src.license_facade_service.federation.inbound import (
    FederationInboundSyncService,
    FederationPeerService,
    FederationRemoteClient,
    _HttpLimits,
    ed25519_key_fingerprint_hex,
)
from src.license_facade_service.federation.inbound_models import PeerCreateRequest, PeerPatchRequest, PeerVerificationKeyRequest
from src.license_facade_service.federation.inbound_models import RemoteChangesResponse, RemoteRecordResponse
from src.license_facade_service.federation.json_strict import DuplicateJsonKeyError, loads_json_no_duplicates
from src.license_facade_service.federation.license_identity import build_canonical_license_identity
from src.license_facade_service.federation.keys import SigningKeyService
from src.license_facade_service.federation.outbound import FederationError, FederationOutboundService, FederationPublicationService
from src.license_facade_service.federation.runtime import FederationRuntime
from src.license_facade_service.federation.security import FederationUrlPolicy, UrlSecurityError
from src.license_facade_service.main import create_app
from src.license_facade_service.services.auth import AuthService
from src.license_facade_service.services.licenses import LicenseService, SPDXClient

REPO_ROOT = Path(__file__).resolve().parents[2]
NODE_B_ID = "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb"
NODE_A_ID = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"


class _StaticSpdx(SPDXClient):
    async def fetch_license_list(self):
        return {"licenseListVersion": "1", "licenses": [{"licenseId": "MIT"}]}

    async def fetch_license_details(self, license_id: str):
        return {"licenseId": license_id, "name": "MIT", "licenseText": "x", "crossRef": []}


class _RemoteScenario(FederationRemoteClient):
    def __init__(self, settings: FederationSettings, responses: dict[str, dict], offline: bool = False):
        self.settings = settings
        self.responses = responses
        self.offline = offline

    def get_json(self, url: str, *, limits, allowed_hostnames=(), allowed_cidrs=()):
        if self.offline:
            raise Exception("offline")
        parsed = urlsplit(url)
        if parsed.path.endswith("/api/v1/federation/changes"):
            since = parse_qs(parsed.query).get("since", [""])[0]
            return self.responses[f"changes:{since}"]
        if "/api/v1/federation/records/" in parsed.path:
            encoded = parsed.path.rsplit("/", 1)[1]
            return self.responses[f"record:{encoded}"]
        key = parsed.path
        if key not in self.responses:
            raise KeyError(key)
        return self.responses[key]


def _seed_snapshot(base_dir: Path) -> None:
    snapshot = base_dir / "resources" / "data" / "licenses" / "snapshots" / "seed"
    snapshot.mkdir(parents=True, exist_ok=True)
    (snapshot / "licenses_list.json").write_text(
        json.dumps({"licenseListVersion": "1", "licenses": [{"licenseId": "MIT", "name": "MIT"}]}),
        encoding="utf-8",
    )
    (snapshot / "MIT.json").write_text(
        json.dumps({"licenseId": "MIT", "name": "MIT", "licenseText": "x", "crossRef": []}),
        encoding="utf-8",
    )
    (snapshot / "version.json").write_text(json.dumps({"licenseListVersion": "1"}), encoding="utf-8")
    (snapshot.parent.parent / "current_snapshot.json").write_text(json.dumps({"snapshot": "seed"}), encoding="utf-8")


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


def _b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode("ascii").rstrip("=")


def _build_signed(payload: dict, *, kid: str, key: Ed25519PrivateKey) -> dict:
    body = canonicalize_to_bytes(payload)
    return {
        "digestSha256": sha256_hex(body),
        "canonicalization": "RFC8785-JCS",
        "encoding": "utf-8",
        "signature": {"kid": kid, "alg": "EdDSA", "encoding": "base64url", "value": _b64url(key.sign(body))},
    }


def _record_event_bundle(*, kid: str, key: Ed25519PrivateKey, local_id: str, version: str, position: int, event_id: str):
    payload = {"licenseId": local_id, "name": f"{local_id} license"}
    rec = {
        "nodeId": NODE_A_ID,
        "canonicalId": f"lfs:{NODE_A_ID}:{local_id}:{version}",
        "authorityNodeId": NODE_A_ID,
        "localId": local_id,
        "version": version,
        "publishedAt": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
        "payload": payload,
        "payloadDigestSha256": canonical_json_sha256_hex(payload),
    }
    evt = {
        "nodeId": NODE_A_ID,
        "eventId": event_id,
        "eventPosition": position,
        "operation": "upsert",
        "generatedAt": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
        "record": rec,
        "provenance": "publication",
        "backfillCreatedAt": None,
    }
    return {
        "record": rec,
        "recordSigned": _build_signed(rec, kid=kid, key=key),
        "event": evt,
        "eventSigned": _build_signed(evt, kid=kid, key=key),
    }


@pytest.fixture(scope="module")
def postgres_url():
    if not _docker_available():
        pytest.skip("docker not available for PostgreSQL inbound phase3 tests")
    port = _free_port()
    name = f"lfs-pg-phase3-{uuid4().hex[:8]}"
    subprocess.run(
        [
            "docker",
            "run",
            "--rm",
            "-d",
            "--name",
            name,
            "-e",
            "POSTGRES_PASSWORD=postgres",
            "-e",
            "POSTGRES_USER=postgres",
            "-e",
            "POSTGRES_DB=lfs_federation",
            "-p",
            f"{port}:5432",
            "postgres:16-alpine",
        ],
        check=True,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    dsn = f"postgresql+psycopg://postgres:postgres@127.0.0.1:{port}/lfs_federation"
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
        subprocess.run(["docker", "kill", name], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=False)


@pytest.fixture
def fed_env(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, postgres_url: str):
    _run_alembic(postgres_url, "downgrade", "base")
    _run_alembic(postgres_url, "upgrade", "head")
    _seed_snapshot(tmp_path)

    key_b = Ed25519PrivateKey.generate()
    pem = key_b.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    key_path = tmp_path / "node-b-signing-key.pem"
    key_path.write_bytes(pem)

    monkeypatch.setenv("BASE_DIR", str(REPO_ROOT))
    monkeypatch.setenv("URL_BASE", "https://example.test/api/v1/licenses")
    monkeypatch.setenv("FUSEKI_ENABLE", "false")
    monkeypatch.setenv("FEDERATION_ENABLED", "true")
    monkeypatch.setenv("FEDERATION_INBOUND_ENABLED", "true")
    monkeypatch.setenv("FEDERATION_DATABASE_URL", postgres_url)
    monkeypatch.setenv("FEDERATION_NODE_ID", NODE_B_ID)
    monkeypatch.setenv("FEDERATION_PUBLIC_BASE_URL", "https://node-b.example.org")
    monkeypatch.setenv("FEDERATION_NODE_NAME", "Node B")
    monkeypatch.setenv("FEDERATION_OPERATOR", "Operator B")
    monkeypatch.setenv("FEDERATION_SIGNING_KEY_PATH", str(key_path))
    monkeypatch.setenv("FEDERATION_ACTIVE_KID", "node-b-k1")
    monkeypatch.setenv("FEDERATION_JWKS_ENABLED", "true")
    monkeypatch.setenv("FEDERATION_ALLOW_HTTP_FOR_DEMO", "true")
    monkeypatch.setenv("FEDERATION_ALLOW_PRIVATE_NETWORK", "false")
    monkeypatch.setenv("FEDERATION_SYNC_ALLOWED_PORTS", "443,12104")
    monkeypatch.setenv("LFS_ADMIN_TOKEN", "admin-token")
    monkeypatch.setenv("LFS_CURATOR_TOKEN", "curator-token")

    service = LicenseService(base_dir=tmp_path, spdx_client=_StaticSpdx())
    licenses_api._license_service = service
    licenses_api._auth_service = AuthService()

    settings = FederationSettings.from_env()
    db = Database.from_url(postgres_url)
    runtime = FederationRuntime(settings)
    assert runtime.initialize().ready
    return {"db": db, "settings": settings, "dsn": postgres_url}


def _create_peer_and_sync_service(fed_env, responses: dict[str, dict], offline: bool = False):
    remote = _RemoteScenario(fed_env["settings"], responses=responses, offline=offline)
    peers = FederationPeerService(fed_env["db"], fed_env["settings"], remote_client=remote)
    sync = FederationInboundSyncService(fed_env["db"], fed_env["settings"], remote_client=remote)
    return peers, sync


def _discovery_and_jwks(*, kid: str, x: str) -> tuple[dict, dict]:
    discovery = {
        "protocolVersion": "2.0.0",
        "nodeId": NODE_A_ID,
        "nodeName": "Node A",
        "operator": "Operator A",
        "publicBaseUrl": "http://node-a:12104",
        "currentSigningKid": kid,
        "jwksUrl": "http://node-a:12104/.well-known/jwks.json",
        "catalogUrl": "http://node-a:12104/api/v1/federation/catalog",
        "changesUrl": "http://node-a:12104/api/v1/federation/changes",
        "recordUrlTemplate": "http://node-a:12104/api/v1/federation/records/{encodedCanonicalId}",
        "conformance": ["LFS-FED-PHASE2-OUTBOUND"],
    }
    jwks = {"keys": [{"kid": kid, "alg": "EdDSA", "kty": "OKP", "crv": "Ed25519", "x": x}]}
    return discovery, jwks


def test_successful_import_and_resume_cursor_and_non_authoritative_catalog_exclusion(fed_env):
    key_a = Ed25519PrivateKey.generate()
    x_a = _b64url(
        key_a.public_key().public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        )
    )
    discovery, jwks = _discovery_and_jwks(kid="a-k1", x=x_a)
    bundle = _record_event_bundle(kid="a-k1", key=key_a, local_id="DemoA", version="1", position=10, event_id=str(uuid4()))
    encoded = base64.urlsafe_b64encode(bundle["record"]["canonicalId"].encode()).decode().rstrip("=")
    responses = {
        "/.well-known/lfs": discovery,
        "/.well-known/jwks.json": jwks,
        "changes:": {
            "events": [{"payload": bundle["event"], "signed": bundle["eventSigned"]}],
            "limit": 200,
            "hasMore": False,
            "nextCursor": None,
            "resumeCursor": "resume-10",
            "snapshotWatermark": 10,
        },
        "changes:resume-10": {
            "events": [],
            "limit": 200,
            "hasMore": False,
            "nextCursor": None,
            "resumeCursor": "resume-10",
            "snapshotWatermark": 10,
        },
        f"record:{encoded}": {
            "record": bundle["record"],
            "signed": bundle["recordSigned"],
            "currentState": "published",
            "latestEventPosition": 10,
            "latestEventDigestSha256": bundle["eventSigned"]["digestSha256"],
        },
    }
    peer_service, sync = _create_peer_and_sync_service(fed_env, responses)
    peer = peer_service.create_peer(
        payload=PeerCreateRequest(
            peerNodeId=NODE_A_ID,
            baseUrl="http://node-a:12104",
            peerName="Node A",
            operatorName="Operator A",
            verificationKey=PeerVerificationKeyRequest(kid="a-k1", fingerprint=ed25519_key_fingerprint_hex(x_a)),
            allowPrivateNetwork=True,
            allowedHostnames=["node-a"],
        ),
        actor="admin",
    )
    result1 = sync.sync_peer(peer_id=peer.id, trigger_type="manual", max_seconds=10)
    assert result1.status == "complete"
    assert result1.importedRecords == 1
    assert result1.cursorAfter == "resume-10"

    result2 = sync.sync_peer(peer_id=peer.id, trigger_type="manual", max_seconds=10)
    assert result2.status == "complete"
    assert result2.importedRecords == 0

    with fed_env["db"].transaction() as session:
        imported = session.execute(
            select(FederationRecord).where(FederationRecord.canonical_id == bundle["record"]["canonicalId"])
        ).scalar_one()
        assert imported.is_authoritative is False
        assert imported.authority_node_id == NODE_A_ID
        assert imported.imported_from_peer_id == peer.id
        identity = build_canonical_license_identity(authority_node_id=NODE_A_ID, local_id="DemoA", version="1")
        assert str(imported.resolving_uuid) == identity.resolvingUuid
        cursor = session.execute(select(FederationPeerCursor).where(FederationPeerCursor.peer_id == peer.id)).scalar_one()
        assert cursor.cursor == "resume-10"
        outbound_events = session.execute(select(func.count()).select_from(FederationChangeEvent)).scalar_one()
        assert outbound_events == 0

    with TestClient(create_app()) as client:
        cat = client.get("/api/v1/federation/catalog")
        assert cat.status_code == 200
        assert all(item["canonicalId"] != bundle["record"]["canonicalId"] for item in cat.json()["items"])


def test_custom_licence_payload_sync_uses_real_outbound_and_preserves_imported_copy(fed_env, tmp_path: Path):
    source_db_name = f"lfs_source_{uuid4().hex[:8]}"
    source_dsn = fed_env["dsn"].rsplit("/", 1)[0] + f"/{source_db_name}"
    with psycopg.connect(fed_env["dsn"].replace("+psycopg", "").rsplit("/", 1)[0] + "/postgres") as conn:
        conn.autocommit = True
        with conn.cursor() as cur:
            cur.execute(f'CREATE DATABASE "{source_db_name}"')
    _run_alembic(source_dsn, "upgrade", "head")

    key_a = Ed25519PrivateKey.generate()
    key_path = tmp_path / "node-a-signing-key.pem"
    key_path.write_bytes(
        key_a.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        )
    )
    settings_a = replace(
        fed_env["settings"],
        node_id=NODE_A_ID,
        public_base_url="http://node-a:12104",
        node_name="Node A",
        operator_name="Operator A",
        database_url=source_dsn,
        signing_key_path=str(key_path),
        active_kid="node-a-k1",
        allow_http_for_demo=True,
        validation_errors=tuple(),
    )
    db_a = Database.from_url(source_dsn)
    runtime_a = FederationRuntime(settings_a)
    assert runtime_a.initialize().ready
    publication_a = FederationPublicationService(db_a, settings_a)
    outbound_a = FederationOutboundService(db_a, settings_a)

    local_id = f"custom-{uuid4()}"
    canonical_id = f"lfs:{NODE_A_ID}:{local_id}:1.0"
    licence_text = "Copyright 2026 DANS.\n\nPermission is granted..."
    payload = {
        "schema": "lfs.custom-licence.federation.v1",
        "customLicenceId": str(uuid4()),
        "customCanonicalId": "lfs-custom:lfs-local-authority:DANS-Custom-1.0:1.0",
        "customResolvingUuid": str(uuid4()),
        "customResolvingUri": "https://node-a.example/custom-licences/lfs-local-authority/DANS-Custom-1.0/1.0",
        "requestedLicenseId": "DANS-Custom-1.0",
        "version": "1.0",
        "name": "DANS Custom License 1.0",
        "summary": "Custom license for federation sync test.",
        "description": "Custom terms managed by Node A.",
        "licenseText": licence_text,
        "normalizedTextDigest": canonical_json_sha256_hex({"text": licence_text}),
        "spdxJsonld": {
            "@context": "https://spdx.org/rdf/3.0.1/spdx-context.jsonld",
            "type": "License",
            "licenseId": "DANS-Custom-1.0",
            "name": "DANS Custom License 1.0",
        },
        "customAuthorityId": "lfs-local-authority",
        "publishingFederationNodeId": NODE_A_ID,
        "sourceRecordUuid": str(uuid4()),
        "scope": "federated",
        "lifecycleStatus": "registered",
        "createdAt": datetime.now(timezone.utc).isoformat(),
        "updatedAt": datetime.now(timezone.utc).isoformat(),
        "aliases": ["DANS Custom License"],
    }
    publication_a.publish_new_version(
        canonical_id=canonical_id,
        authority_node_id=NODE_A_ID,
        local_id=local_id,
        version="1.0",
        payload=payload,
    )

    discovery = outbound_a.discovery().model_dump(mode="json")
    jwks = SigningKeyService(db_a, settings_a).jwks().model_dump(mode="json")
    changes = outbound_a.get_changes(since=None, limit=200).model_dump(mode="json")
    resume = changes["resumeCursor"]
    changes_resume = outbound_a.get_changes(since=resume, limit=200).model_dump(mode="json")
    encoded = base64.urlsafe_b64encode(canonical_id.encode()).decode().rstrip("=")
    record = outbound_a.get_record(encoded_canonical_id=encoded).model_dump(mode="json")
    RemoteChangesResponse.model_validate(changes)
    RemoteChangesResponse.model_validate(changes_resume)
    RemoteRecordResponse.model_validate(record)
    responses = {
        "/.well-known/lfs": discovery,
        "/.well-known/jwks.json": jwks,
        "changes:": changes,
        f"changes:{resume}": changes_resume,
        f"record:{encoded}": record,
    }

    peers, sync = _create_peer_and_sync_service(fed_env, responses)
    peer = peers.create_peer(
        payload=PeerCreateRequest(
            peerNodeId=NODE_A_ID,
            baseUrl="http://node-a:12104",
            peerName="Node A",
            operatorName="Operator A",
            verificationKey=PeerVerificationKeyRequest(
                kid="node-a-k1",
                fingerprint=ed25519_key_fingerprint_hex(
                    _b64url(
                        key_a.public_key().public_bytes(
                            encoding=serialization.Encoding.Raw,
                            format=serialization.PublicFormat.Raw,
                        )
                    )
                ),
            ),
            allowPrivateNetwork=True,
            allowedHostnames=["node-a"],
        ),
        actor="admin",
    )
    first = sync.sync_peer(peer_id=peer.id, trigger_type="manual", max_seconds=10)
    second = sync.sync_peer(peer_id=peer.id, trigger_type="manual", max_seconds=10)
    assert first.status == "complete", first.detail
    assert first.importedRecords == 1
    assert second.status == "complete"
    assert second.importedRecords == 0

    with fed_env["db"].transaction() as session:
        imported = session.execute(select(FederationRecord).where(FederationRecord.canonical_id == canonical_id)).scalar_one()
        assert imported.is_authoritative is False
        assert imported.imported_from_peer_id == peer.id
        assert imported.authority_node_id == NODE_A_ID
        assert imported.payload["licenseText"] == licence_text
        assert imported.payload["spdxJsonld"]["licenseId"] == "DANS-Custom-1.0"
        assert imported.payload["customAuthorityId"] == "lfs-local-authority"
        provenance_count = session.execute(
            select(func.count()).select_from(FederationRecordProvenance).where(FederationRecordProvenance.record_id == imported.id)
        ).scalar_one()
        assert provenance_count >= 1

    with TestClient(create_app()) as client:
        catalog = client.get("/api/v1/federation/catalog")
        assert catalog.status_code == 200
        assert all(item["canonicalId"] != canonical_id for item in catalog.json()["items"])
        changes_b = client.get("/api/v1/federation/changes?limit=200")
        assert changes_b.status_code == 200
        assert all(evt["payload"]["record"]["canonicalId"] != canonical_id for evt in changes_b.json()["events"])

    sync_offline = FederationInboundSyncService(
        fed_env["db"],
        fed_env["settings"],
        remote_client=_RemoteScenario(fed_env["settings"], responses=responses, offline=True),
    )
    offline_result = sync_offline.sync_peer(peer_id=peer.id, trigger_type="manual", max_seconds=10)
    assert offline_result.status in {"partial", "failed"}
    with fed_env["db"].transaction() as session:
        retained = session.execute(select(func.count()).select_from(FederationRecord).where(FederationRecord.canonical_id == canonical_id)).scalar_one()
        assert retained == 1
    db_a.close()
    if runtime_a.db is not None:
        runtime_a.db.close()


def test_multi_page_and_incremental_resume_cursor(fed_env):
    key_a = Ed25519PrivateKey.generate()
    x_a = _b64url(key_a.public_key().public_bytes(encoding=serialization.Encoding.Raw, format=serialization.PublicFormat.Raw))
    discovery, jwks = _discovery_and_jwks(kid="a-k1", x=x_a)
    b1 = _record_event_bundle(kid="a-k1", key=key_a, local_id="MP1", version="1", position=100, event_id=str(uuid4()))
    b2 = _record_event_bundle(kid="a-k1", key=key_a, local_id="MP2", version="1", position=105, event_id=str(uuid4()))
    e1 = base64.urlsafe_b64encode(b1["record"]["canonicalId"].encode()).decode().rstrip("=")
    e2 = base64.urlsafe_b64encode(b2["record"]["canonicalId"].encode()).decode().rstrip("=")
    responses = {
        "/.well-known/lfs": discovery,
        "/.well-known/jwks.json": jwks,
        "changes:": {
            "events": [{"payload": b1["event"], "signed": b1["eventSigned"]}],
            "limit": 1,
            "hasMore": True,
            "nextCursor": "next-1",
            "resumeCursor": "resume-100",
            "snapshotWatermark": 105,
        },
        "changes:next-1": {
            "events": [{"payload": b2["event"], "signed": b2["eventSigned"]}],
            "limit": 1,
            "hasMore": False,
            "nextCursor": None,
            "resumeCursor": "resume-105",
            "snapshotWatermark": 105,
        },
        "changes:resume-105": {
            "events": [],
            "limit": 1,
            "hasMore": False,
            "nextCursor": None,
            "resumeCursor": "resume-105",
            "snapshotWatermark": 105,
        },
        f"record:{e1}": {
            "record": b1["record"],
            "signed": b1["recordSigned"],
            "currentState": "published",
            "latestEventPosition": 100,
            "latestEventDigestSha256": b1["eventSigned"]["digestSha256"],
        },
        f"record:{e2}": {
            "record": b2["record"],
            "signed": b2["recordSigned"],
            "currentState": "published",
            "latestEventPosition": 105,
            "latestEventDigestSha256": b2["eventSigned"]["digestSha256"],
        },
    }
    peers, sync = _create_peer_and_sync_service(fed_env, responses)
    peer = peers.create_peer(
        payload=PeerCreateRequest(
            peerNodeId=NODE_A_ID,
            baseUrl="http://node-a:12104",
            peerName="Node A",
            operatorName="Operator A",
            verificationKey=PeerVerificationKeyRequest(kid="a-k1", fingerprint=ed25519_key_fingerprint_hex(x_a)),
            allowPrivateNetwork=True,
        ),
        actor="admin",
    )
    result = sync.sync_peer(peer_id=peer.id, trigger_type="manual", max_seconds=10)
    assert result.status == "complete"
    assert result.pagesProcessed == 2
    assert result.eventsProcessed == 2
    assert result.cursorAfter == "resume-105"
    again = sync.sync_peer(peer_id=peer.id, trigger_type="manual", max_seconds=10)
    assert again.eventsProcessed == 0


def test_tampered_event_rejected_cursor_unchanged(fed_env):
    key_a = Ed25519PrivateKey.generate()
    x_a = _b64url(key_a.public_key().public_bytes(encoding=serialization.Encoding.Raw, format=serialization.PublicFormat.Raw))
    discovery, jwks = _discovery_and_jwks(kid="a-k1", x=x_a)
    bundle = _record_event_bundle(kid="a-k1", key=key_a, local_id="TAMP", version="1", position=50, event_id=str(uuid4()))
    tampered_signed = dict(bundle["eventSigned"])
    tampered_signed["digestSha256"] = "0" * 64
    encoded = base64.urlsafe_b64encode(bundle["record"]["canonicalId"].encode()).decode().rstrip("=")
    responses = {
        "/.well-known/lfs": discovery,
        "/.well-known/jwks.json": jwks,
        "changes:": {
            "events": [{"payload": bundle["event"], "signed": tampered_signed}],
            "limit": 200,
            "hasMore": False,
            "nextCursor": None,
            "resumeCursor": "resume-50",
            "snapshotWatermark": 50,
        },
        f"record:{encoded}": {
            "record": bundle["record"],
            "signed": bundle["recordSigned"],
            "currentState": "published",
            "latestEventPosition": 50,
            "latestEventDigestSha256": bundle["eventSigned"]["digestSha256"],
        },
    }
    peers, sync = _create_peer_and_sync_service(fed_env, responses)
    peer = peers.create_peer(
        payload=PeerCreateRequest(
            peerNodeId=NODE_A_ID,
            baseUrl="http://node-a:12104",
            peerName="Node A",
            operatorName="Operator A",
            verificationKey=PeerVerificationKeyRequest(kid="a-k1", fingerprint=ed25519_key_fingerprint_hex(x_a)),
            allowPrivateNetwork=True,
        ),
        actor="admin",
    )
    result = sync.sync_peer(peer_id=peer.id, trigger_type="manual", max_seconds=10)
    assert result.status == "failed"
    with fed_env["db"].transaction() as session:
        cursor = session.execute(select(FederationPeerCursor).where(FederationPeerCursor.peer_id == peer.id)).scalar_one()
        assert cursor.cursor is None
        count = session.execute(select(func.count()).select_from(FederationRecord)).scalar_one()
        assert count == 0


def test_unknown_key_and_authority_mismatch_reject(fed_env):
    key_a = Ed25519PrivateKey.generate()
    x_a = _b64url(key_a.public_key().public_bytes(encoding=serialization.Encoding.Raw, format=serialization.PublicFormat.Raw))
    discovery, jwks = _discovery_and_jwks(kid="a-k1", x=x_a)
    bundle = _record_event_bundle(kid="a-k1", key=key_a, local_id="K1", version="1", position=1, event_id=str(uuid4()))
    bundle["event"]["record"]["authorityNodeId"] = "cccccccc-cccc-4ccc-8ccc-cccccccccccc"
    bundle["eventSigned"] = _build_signed(bundle["event"], kid="a-k1", key=key_a)
    encoded = base64.urlsafe_b64encode(bundle["record"]["canonicalId"].encode()).decode().rstrip("=")
    responses = {
        "/.well-known/lfs": discovery,
        "/.well-known/jwks.json": jwks,
        "changes:": {
            "events": [{"payload": bundle["event"], "signed": bundle["eventSigned"]}],
            "limit": 200,
            "hasMore": False,
            "nextCursor": None,
            "resumeCursor": "resume-1",
            "snapshotWatermark": 1,
        },
        f"record:{encoded}": {
            "record": bundle["record"],
            "signed": bundle["recordSigned"],
            "currentState": "published",
            "latestEventPosition": 1,
            "latestEventDigestSha256": bundle["eventSigned"]["digestSha256"],
        },
    }
    peers, sync = _create_peer_and_sync_service(fed_env, responses)
    peer = peers.create_peer(
        payload=PeerCreateRequest(
            peerNodeId=NODE_A_ID,
            baseUrl="http://node-a:12104",
            peerName="Node A",
            operatorName="Operator A",
            verificationKey=PeerVerificationKeyRequest(kid="a-k1", fingerprint=ed25519_key_fingerprint_hex(x_a)),
            allowPrivateNetwork=True,
        ),
        actor="admin",
    )
    result = sync.sync_peer(peer_id=peer.id, trigger_type="manual", max_seconds=10)
    assert result.status == "failed"

    with fed_env["db"].transaction() as session:
        key = session.execute(
            select(FederationPeerSigningKey).where(
                FederationPeerSigningKey.peer_id == peer.id,
                FederationPeerSigningKey.kid == "a-k1",
            )
        ).scalar_one()
        key.key_status = "revoked"
    result_revoked = sync.sync_peer(peer_id=peer.id, trigger_type="manual", max_seconds=10)
    assert result_revoked.status == "failed"


def test_sync_finalizes_on_remote_schema_validation_error(fed_env):
    key_a = Ed25519PrivateKey.generate()
    x_a = _b64url(key_a.public_key().public_bytes(encoding=serialization.Encoding.Raw, format=serialization.PublicFormat.Raw))
    discovery, jwks = _discovery_and_jwks(kid="a-k1", x=x_a)
    responses = {
        "/.well-known/lfs": discovery,
        "/.well-known/jwks.json": jwks,
        "changes:": {
            "events": [{"payload": {"bad": "data"}, "signed": {"bad": "data"}}],
            "limit": 200,
            "hasMore": False,
            "nextCursor": None,
            "resumeCursor": "resume-1",
            "snapshotWatermark": 1,
        },
    }
    peers, sync = _create_peer_and_sync_service(fed_env, responses)
    peer = peers.create_peer(
        payload=PeerCreateRequest(
            peerNodeId=NODE_A_ID,
            baseUrl="http://node-a:12104",
            peerName="Node A",
            operatorName="Operator A",
            verificationKey=PeerVerificationKeyRequest(kid="a-k1", fingerprint=ed25519_key_fingerprint_hex(x_a)),
            allowPrivateNetwork=True,
        ),
        actor="admin",
    )
    result = sync.sync_peer(peer_id=peer.id, trigger_type="manual", max_seconds=10)
    assert result.status == "failed"
    with fed_env["db"].transaction() as session:
        attempt = session.execute(select(FederationSyncAttempt).where(FederationSyncAttempt.peer_id == peer.id)).scalar_one()
        assert attempt.status == "failed"
        assert attempt.error_code == "remote-schema-invalid"
        peer_row = session.execute(select(FederationTrustedPeer).where(FederationTrustedPeer.id == peer.id)).scalar_one()
        assert peer_row.last_sync_status == "failed"


def test_sync_finalizes_on_db_and_unexpected_errors(fed_env):
    key_a = Ed25519PrivateKey.generate()
    x_a = _b64url(key_a.public_key().public_bytes(encoding=serialization.Encoding.Raw, format=serialization.PublicFormat.Raw))
    discovery, jwks = _discovery_and_jwks(kid="a-k1", x=x_a)
    bundle = _record_event_bundle(kid="a-k1", key=key_a, local_id="ERR", version="1", position=1, event_id=str(uuid4()))
    encoded = base64.urlsafe_b64encode(bundle["record"]["canonicalId"].encode()).decode().rstrip("=")
    responses = {
        "/.well-known/lfs": discovery,
        "/.well-known/jwks.json": jwks,
        "changes:": {
            "events": [{"payload": bundle["event"], "signed": bundle["eventSigned"]}],
            "limit": 200,
            "hasMore": False,
            "nextCursor": None,
            "resumeCursor": "resume-1",
            "snapshotWatermark": 1,
        },
        f"record:{encoded}": {
            "record": bundle["record"],
            "signed": bundle["recordSigned"],
            "currentState": "published",
            "latestEventPosition": 1,
            "latestEventDigestSha256": bundle["eventSigned"]["digestSha256"],
        },
    }
    peers, sync = _create_peer_and_sync_service(fed_env, responses)
    peer = peers.create_peer(
        payload=PeerCreateRequest(
            peerNodeId=NODE_A_ID,
            baseUrl="http://node-a:12104",
            peerName="Node A",
            operatorName="Operator A",
            verificationKey=PeerVerificationKeyRequest(kid="a-k1", fingerprint=ed25519_key_fingerprint_hex(x_a)),
            allowPrivateNetwork=True,
        ),
        actor="admin",
    )

    def raise_db_error(*_args, **_kwargs):
        raise OperationalError("select 1", {}, Exception("db down"))

    sync._process_page = raise_db_error  # type: ignore[method-assign]
    with pytest.raises(OperationalError):
        sync.sync_peer(peer_id=peer.id, trigger_type="manual", max_seconds=10)
    with fed_env["db"].transaction() as session:
        attempt = session.execute(select(FederationSyncAttempt).where(FederationSyncAttempt.peer_id == peer.id)).scalar_one()
        assert attempt.status == "failed"

    sync2 = FederationInboundSyncService(fed_env["db"], fed_env["settings"], remote_client=_RemoteScenario(fed_env["settings"], responses=responses))
    sync2._process_page = lambda *_args, **_kwargs: (_ for _ in ()).throw(RuntimeError("boom"))  # type: ignore[method-assign]
    with pytest.raises(RuntimeError):
        sync2.sync_peer(peer_id=peer.id, trigger_type="manual", max_seconds=10)
    with fed_env["db"].transaction() as session:
        attempt2 = session.execute(
            select(FederationSyncAttempt).where(FederationSyncAttempt.peer_id == peer.id).order_by(FederationSyncAttempt.started_at.desc())
        ).scalars().first()
        assert attempt2 is not None
        assert attempt2.status == "failed"


def test_durable_rejection_and_conflict_persist_after_rollback(fed_env):
    key_a = Ed25519PrivateKey.generate()
    x_a = _b64url(key_a.public_key().public_bytes(encoding=serialization.Encoding.Raw, format=serialization.PublicFormat.Raw))
    discovery, jwks = _discovery_and_jwks(kid="a-k1", x=x_a)
    bundle = _record_event_bundle(kid="a-k1", key=key_a, local_id="COLLIDE", version="1", position=1, event_id=str(uuid4()))
    encoded = base64.urlsafe_b64encode(bundle["record"]["canonicalId"].encode()).decode().rstrip("=")
    responses = {
        "/.well-known/lfs": discovery,
        "/.well-known/jwks.json": jwks,
        "changes:": {
            "events": [{"payload": bundle["event"], "signed": bundle["eventSigned"]}],
            "limit": 200,
            "hasMore": False,
            "nextCursor": None,
            "resumeCursor": "resume-1",
            "snapshotWatermark": 1,
        },
        f"record:{encoded}": {
            "record": bundle["record"],
            "signed": bundle["recordSigned"],
            "currentState": "published",
            "latestEventPosition": 1,
            "latestEventDigestSha256": bundle["eventSigned"]["digestSha256"],
        },
    }
    peers, sync = _create_peer_and_sync_service(fed_env, responses)
    peer = peers.create_peer(
        payload=PeerCreateRequest(
            peerNodeId=NODE_A_ID,
            baseUrl="http://node-a:12104",
            peerName="Node A",
            operatorName="Operator A",
            verificationKey=PeerVerificationKeyRequest(kid="a-k1", fingerprint=ed25519_key_fingerprint_hex(x_a)),
            allowPrivateNetwork=True,
        ),
        actor="admin",
    )
    with fed_env["db"].transaction() as session:
        session.add(
            FederationRecord(
                id=uuid4(),
                authority_node_id=NODE_B_ID,
                local_id="COLLIDE",
                version="1",
                canonical_id=bundle["record"]["canonicalId"],
                resolving_uuid=uuid4(),
                is_authoritative=True,
                payload={"licenseId": "COLLIDE"},
                payload_digest_sha256="deadbeef",
                published_at=datetime.now(timezone.utc),
                created_at=datetime.now(timezone.utc),
                updated_at=datetime.now(timezone.utc),
            )
        )
    result = sync.sync_peer(peer_id=peer.id, trigger_type="manual", max_seconds=10)
    assert result.status == "failed"
    with fed_env["db"].transaction() as session:
        cursor = session.execute(select(FederationPeerCursor).where(FederationPeerCursor.peer_id == peer.id)).scalar_one()
        assert cursor.cursor is None
        rejections = session.execute(
            select(func.count()).select_from(FederationInboundEvent).where(FederationInboundEvent.processing_status == "rejected")
        ).scalar_one()
        assert rejections == 1
        conflicts = session.execute(select(func.count()).select_from(FederationConflictRecord)).scalar_one()
        assert conflicts == 1


def test_offline_peer_keeps_cursor_and_data(fed_env):
    key_a = Ed25519PrivateKey.generate()
    x_a = _b64url(key_a.public_key().public_bytes(encoding=serialization.Encoding.Raw, format=serialization.PublicFormat.Raw))
    discovery, jwks = _discovery_and_jwks(kid="a-k1", x=x_a)
    bundle = _record_event_bundle(kid="a-k1", key=key_a, local_id="OFF", version="1", position=7, event_id=str(uuid4()))
    encoded = base64.urlsafe_b64encode(bundle["record"]["canonicalId"].encode()).decode().rstrip("=")
    responses = {
        "/.well-known/lfs": discovery,
        "/.well-known/jwks.json": jwks,
        "changes:": {
            "events": [{"payload": bundle["event"], "signed": bundle["eventSigned"]}],
            "limit": 200,
            "hasMore": False,
            "nextCursor": None,
            "resumeCursor": "resume-7",
            "snapshotWatermark": 7,
        },
        f"record:{encoded}": {
            "record": bundle["record"],
            "signed": bundle["recordSigned"],
            "currentState": "published",
            "latestEventPosition": 7,
            "latestEventDigestSha256": bundle["eventSigned"]["digestSha256"],
        },
    }
    peers, sync_ok = _create_peer_and_sync_service(fed_env, responses)
    peer = peers.create_peer(
        payload=PeerCreateRequest(
            peerNodeId=NODE_A_ID,
            baseUrl="http://node-a:12104",
            peerName="Node A",
            operatorName="Operator A",
            verificationKey=PeerVerificationKeyRequest(kid="a-k1", fingerprint=ed25519_key_fingerprint_hex(x_a)),
            allowPrivateNetwork=True,
        ),
        actor="admin",
    )
    assert sync_ok.sync_peer(peer_id=peer.id, trigger_type="manual", max_seconds=10).status == "complete"
    sync_offline = FederationInboundSyncService(
        fed_env["db"],
        fed_env["settings"],
        remote_client=_RemoteScenario(fed_env["settings"], responses=responses, offline=True),
    )
    result = sync_offline.sync_peer(peer_id=peer.id, trigger_type="manual", max_seconds=10)
    assert result.status in {"partial", "failed"}
    with fed_env["db"].transaction() as session:
        cursor = session.execute(select(FederationPeerCursor).where(FederationPeerCursor.peer_id == peer.id)).scalar_one()
        assert cursor.cursor == "resume-7"
        imported = session.execute(select(func.count()).select_from(FederationRecord)).scalar_one()
        assert imported == 1


def test_sequence_gaps_allowed_but_decreasing_or_reused_positions_rejected(fed_env):
    key_a = Ed25519PrivateKey.generate()
    x_a = _b64url(key_a.public_key().public_bytes(encoding=serialization.Encoding.Raw, format=serialization.PublicFormat.Raw))
    discovery, jwks = _discovery_and_jwks(kid="a-k1", x=x_a)
    e1 = _record_event_bundle(kid="a-k1", key=key_a, local_id="GAP1", version="1", position=5, event_id=str(uuid4()))
    e2 = _record_event_bundle(kid="a-k1", key=key_a, local_id="GAP2", version="1", position=9, event_id=str(uuid4()))
    enc1 = base64.urlsafe_b64encode(e1["record"]["canonicalId"].encode()).decode().rstrip("=")
    enc2 = base64.urlsafe_b64encode(e2["record"]["canonicalId"].encode()).decode().rstrip("=")
    responses_ok = {
        "/.well-known/lfs": discovery,
        "/.well-known/jwks.json": jwks,
        "changes:": {
            "events": [
                {"payload": e1["event"], "signed": e1["eventSigned"]},
                {"payload": e2["event"], "signed": e2["eventSigned"]},
            ],
            "limit": 200,
            "hasMore": False,
            "nextCursor": None,
            "resumeCursor": "resume-9",
            "snapshotWatermark": 9,
        },
        f"record:{enc1}": {
            "record": e1["record"],
            "signed": e1["recordSigned"],
            "currentState": "published",
            "latestEventPosition": 5,
            "latestEventDigestSha256": e1["eventSigned"]["digestSha256"],
        },
        f"record:{enc2}": {
            "record": e2["record"],
            "signed": e2["recordSigned"],
            "currentState": "published",
            "latestEventPosition": 9,
            "latestEventDigestSha256": e2["eventSigned"]["digestSha256"],
        },
    }
    peers, sync = _create_peer_and_sync_service(fed_env, responses_ok)
    peer = peers.create_peer(
        payload=PeerCreateRequest(
            peerNodeId=NODE_A_ID,
            baseUrl="http://node-a:12104",
            peerName="Node A",
            operatorName="Operator A",
            verificationKey=PeerVerificationKeyRequest(kid="a-k1", fingerprint=ed25519_key_fingerprint_hex(x_a)),
            allowPrivateNetwork=True,
        ),
        actor="admin",
    )
    ok = sync.sync_peer(peer_id=peer.id, trigger_type="manual", max_seconds=10)
    assert ok.status == "complete"

    bad = _record_event_bundle(kid="a-k1", key=key_a, local_id="BAD", version="1", position=9, event_id=str(uuid4()))
    enc_bad = base64.urlsafe_b64encode(bad["record"]["canonicalId"].encode()).decode().rstrip("=")
    responses_bad = dict(responses_ok)
    responses_bad["changes:resume-9"] = {
        "events": [{"payload": bad["event"], "signed": bad["eventSigned"]}],
        "limit": 200,
        "hasMore": False,
        "nextCursor": None,
        "resumeCursor": "resume-bad",
        "snapshotWatermark": 9,
    }
    responses_bad[f"record:{enc_bad}"] = {
        "record": bad["record"],
        "signed": bad["recordSigned"],
        "currentState": "published",
        "latestEventPosition": 9,
        "latestEventDigestSha256": bad["eventSigned"]["digestSha256"],
    }
    sync_bad = FederationInboundSyncService(
        fed_env["db"],
        fed_env["settings"],
        remote_client=_RemoteScenario(fed_env["settings"], responses=responses_bad),
    )
    failed = sync_bad.sync_peer(peer_id=peer.id, trigger_type="manual", max_seconds=10)
    assert failed.status == "failed"
    with fed_env["db"].transaction() as session:
        cursor = session.execute(select(FederationPeerCursor).where(FederationPeerCursor.peer_id == peer.id)).scalar_one()
        assert cursor.cursor == "resume-9"


def test_duplicate_json_key_detection():
    with pytest.raises(DuplicateJsonKeyError):
        loads_json_no_duplicates(b'{"nodeId":"a","nodeId":"b"}')
    with pytest.raises(DuplicateJsonKeyError):
        loads_json_no_duplicates(b'{"kid":"k1","kid":"k2"}')
    with pytest.raises(DuplicateJsonKeyError):
        loads_json_no_duplicates(b'{"eventId":"1","eventId":"2"}')
    with pytest.raises(DuplicateJsonKeyError):
        loads_json_no_duplicates(b'{"eventPosition":1,"eventPosition":2}')
    with pytest.raises(DuplicateJsonKeyError):
        loads_json_no_duplicates(b'{"digestSha256":"x","digestSha256":"y"}')
    with pytest.raises(DuplicateJsonKeyError):
        loads_json_no_duplicates(b'{"canonicalId":"a","canonicalId":"b","authorityNodeId":"z"}')
    with pytest.raises(DuplicateJsonKeyError):
        loads_json_no_duplicates(b'{"authorityNodeId":"a","authorityNodeId":"b"}')


@pytest.mark.parametrize(
    "ip",
    [
        "127.0.0.1",
        "::1",
        "10.0.0.5",
        "::ffff:10.0.0.5",
        "169.254.1.10",
        "169.254.169.254",
    ],
)
def test_ssrf_policy_blocks_forbidden_addresses(fed_env, monkeypatch: pytest.MonkeyPatch, ip: str):
    policy = FederationUrlPolicy(fed_env["settings"])
    monkeypatch.setattr(
        socket,
        "getaddrinfo",
        lambda *_args, **_kwargs: [(socket.AF_INET6 if ":" in ip else socket.AF_INET, 1, 6, "", (ip, 12104, 0, 0))],
    )
    with pytest.raises(UrlSecurityError):
                        policy.validate_and_resolve("http://peer.example:12104/.well-known/lfs")


def test_ssrf_policy_rejects_mixed_dns_answers(fed_env, monkeypatch: pytest.MonkeyPatch):
    policy = FederationUrlPolicy(fed_env["settings"])
    monkeypatch.setattr(
        socket,
        "getaddrinfo",
        lambda *_args, **_kwargs: [
            (socket.AF_INET, 1, 6, "", ("8.8.8.8", 12104)),
            (socket.AF_INET, 1, 6, "", ("127.0.0.1", 12104)),
        ],
    )
    with pytest.raises(UrlSecurityError):
        policy.validate_and_resolve("http://peer.example:12104/.well-known/lfs")


def test_remote_client_rejects_redirect_target(fed_env, monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setattr(
        socket,
        "getaddrinfo",
        lambda *_args, **_kwargs: [(socket.AF_INET, 1, 6, "", ("8.8.8.8", 12104))],
    )

    def handler(_request: httpx.Request) -> httpx.Response:
        return httpx.Response(status_code=302, headers={"Location": "http://127.0.0.1/evil"})

    client = FederationRemoteClient(
        fed_env["settings"],
        http_client=httpx.Client(transport=httpx.MockTransport(handler), follow_redirects=False),
    )
    with pytest.raises(FederationError) as exc:
        client.get_json(
            "http://peer.example:12104/.well-known/lfs",
            limits=_HttpLimits(max_bytes=1000, expected_content_type="application/json"),
        )
    assert exc.value.code == "remote-redirect"


def test_ssrf_policy_allows_explicit_private_hostname(fed_env, monkeypatch: pytest.MonkeyPatch):
    policy = FederationUrlPolicy(fed_env["settings"])
    monkeypatch.setattr(
    socket,
    "getaddrinfo",
    lambda *_args, **_kwargs: [(socket.AF_INET, 1, 6, "", ("10.0.0.5", 12104))],
    )
    resolved = policy.validate_and_resolve(
    "http://node-a:12104/.well-known/lfs",
    allowed_hostnames=("node-a",),
    )
    assert resolved.hostname == "node-a"
    assert resolved.addresses == ("10.0.0.5",)


def test_ssrf_policy_allows_explicit_private_cidr(fed_env, monkeypatch: pytest.MonkeyPatch):
    policy = FederationUrlPolicy(fed_env["settings"])
    monkeypatch.setattr(
        socket,
        "getaddrinfo",
        lambda *_args, **_kwargs: [(socket.AF_INET, 1, 6, "", ("10.0.0.5", 12104))],
    )
    resolved = policy.validate_and_resolve(
        "http://10.0.0.5:12104/.well-known/lfs",
        allowed_cidrs=("10.0.0.0/24",),
    )
    assert resolved.addresses == ("10.0.0.5",)


def test_ssrf_policy_rejects_unlisted_private_destination(fed_env, monkeypatch: pytest.MonkeyPatch):
    policy = FederationUrlPolicy(fed_env["settings"])
    monkeypatch.setattr(
        socket,
        "getaddrinfo",
        lambda *_args, **_kwargs: [(socket.AF_INET, 1, 6, "", ("10.0.0.6", 12104))],
    )
    with pytest.raises(UrlSecurityError):
        policy.validate_and_resolve("http://node-b:12104/.well-known/lfs", allowed_hostnames=("node-a",))


def test_ssrf_policy_enforces_global_allowlist(fed_env, monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setenv("FEDERATION_SYNC_ALLOWED_HOSTNAMES", "global-node")
    settings = FederationSettings.from_env()
    policy = FederationUrlPolicy(settings)
    monkeypatch.setattr(
        socket,
        "getaddrinfo",
        lambda *_args, **_kwargs: [(socket.AF_INET, 1, 6, "", ("10.0.0.7", 12104))],
    )
    resolved = policy.validate_and_resolve("http://global-node:12104/.well-known/lfs")
    assert resolved.hostname == "global-node"


def test_ssrf_policy_rejects_mixed_dns_and_metadata(fed_env, monkeypatch: pytest.MonkeyPatch):
    policy = FederationUrlPolicy(fed_env["settings"])
    monkeypatch.setattr(
        socket,
        "getaddrinfo",
        lambda host, port, **kwargs: [
            (socket.AF_INET, 1, 6, "", ("8.8.8.8", port)),
            (socket.AF_INET, 1, 6, "", ("127.0.0.1", port)),
        ],
    )
    with pytest.raises(UrlSecurityError):
        policy.validate_and_resolve("http://peer.example:12104/.well-known/lfs")
    monkeypatch.setattr(
        socket,
        "getaddrinfo",
        lambda *_args, **_kwargs: [(socket.AF_INET, 1, 6, "", ("169.254.169.254", 12104))],
    )
    with pytest.raises(UrlSecurityError):
        policy.validate_and_resolve("http://metadata.example:12104/.well-known/lfs", allowed_hostnames=("metadata.example",))


@pytest.mark.parametrize(
    "content_length,body,max_bytes,expected_error",
    [
        (None, b'{"ok":true}', 1000, None),
        ("abc", b'{"ok":true}', 1000, "remote-response-size"),
        ("-1", b'{"ok":true}', 1000, "remote-response-size"),
        ("1", b'{"ok":true}', 1000, "remote-response-size"),
        ("100", b'{"ok":true}', 5, "remote-payload-too-large"),
    ],
)
def test_remote_client_streams_and_enforces_content_length(fed_env, monkeypatch: pytest.MonkeyPatch, content_length, body, max_bytes, expected_error):
    monkeypatch.setattr(
        socket,
        "getaddrinfo",
        lambda *_args, **_kwargs: [(socket.AF_INET, 1, 6, "", ("8.8.8.8", 12104))],
    )

    def handler(_request: httpx.Request) -> httpx.Response:
        headers = {"content-type": "application/json"}
        if content_length is not None:
            headers["content-length"] = content_length
        return httpx.Response(status_code=200, headers=headers, stream=httpx.ByteStream(body))

    client = FederationRemoteClient(
        fed_env["settings"],
        http_client=httpx.Client(transport=httpx.MockTransport(handler), follow_redirects=False),
    )
    if expected_error is None:
        assert client.get_json(
            "http://peer.example:12104/.well-known/lfs",
            limits=_HttpLimits(max_bytes=1000, expected_content_type="application/json"),
        ) == {"ok": True}
    else:
        with pytest.raises(FederationError) as exc:
            client.get_json(
                "http://peer.example:12104/.well-known/lfs",
                limits=_HttpLimits(max_bytes=max_bytes, expected_content_type="application/json"),
            )
        assert exc.value.code == expected_error


def test_admin_endpoints_require_admin_role(fed_env):
    with TestClient(create_app()) as client:
        unauth = client.get("/api/v1/admin/federation/status")
        assert unauth.status_code == 401
        curator = client.get(
            "/api/v1/admin/federation/status",
            headers={"Authorization": "Bearer curator-token"},
        )
        assert curator.status_code == 403
        admin = client.get(
            "/api/v1/admin/federation/status",
            headers={"Authorization": "Bearer admin-token"},
        )
        assert admin.status_code == 200


def test_patch_peer_base_url_change_requires_explicit_verification_key(fed_env):
    key_a = Ed25519PrivateKey.generate()
    x_a = _b64url(key_a.public_key().public_bytes(encoding=serialization.Encoding.Raw, format=serialization.PublicFormat.Raw))
    discovery, jwks = _discovery_and_jwks(kid="a-k1", x=x_a)
    peers, _ = _create_peer_and_sync_service(
        fed_env,
        {
            "/.well-known/lfs": discovery,
            "/.well-known/jwks.json": jwks,
        },
    )
    peer = peers.create_peer(
        payload=PeerCreateRequest(
            peerNodeId=NODE_A_ID,
            baseUrl="http://node-a:12104",
            peerName="Node A",
            operatorName="Operator A",
            verificationKey=PeerVerificationKeyRequest(kid="a-k1", fingerprint=ed25519_key_fingerprint_hex(x_a)),
            allowPrivateNetwork=True,
        ),
        actor="admin",
    )
    with pytest.raises(FederationError) as exc:
        peers.patch_peer(
            peer_id=peer.id,
            payload=PeerPatchRequest(baseUrl="http://node-a-new:12104"),
            actor="admin",
        )
    assert exc.value.code == "peer-key-required"
    assert peers.get_peer(peer.id).baseUrl == "http://node-a:12104"


def test_concurrent_sync_triggers_single_runner(fed_env):
    key_a = Ed25519PrivateKey.generate()
    x_a = _b64url(key_a.public_key().public_bytes(encoding=serialization.Encoding.Raw, format=serialization.PublicFormat.Raw))
    discovery, jwks = _discovery_and_jwks(kid="a-k1", x=x_a)
    bundle = _record_event_bundle(kid="a-k1", key=key_a, local_id="LOCK", version="1", position=1, event_id=str(uuid4()))
    enc = base64.urlsafe_b64encode(bundle["record"]["canonicalId"].encode()).decode().rstrip("=")
    responses = {
        "/.well-known/lfs": discovery,
        "/.well-known/jwks.json": jwks,
        "changes:": {
            "events": [{"payload": bundle["event"], "signed": bundle["eventSigned"]}],
            "limit": 200,
            "hasMore": False,
            "nextCursor": None,
            "resumeCursor": "resume-1",
            "snapshotWatermark": 1,
        },
        f"record:{enc}": {
            "record": bundle["record"],
            "signed": bundle["recordSigned"],
            "currentState": "published",
            "latestEventPosition": 1,
            "latestEventDigestSha256": bundle["eventSigned"]["digestSha256"],
        },
    }

    class SlowRemote(_RemoteScenario):
        def get_json(self, url: str, *, limits, allowed_hostnames=(), allowed_cidrs=()):
            if "/api/v1/federation/changes" in url:
                time.sleep(1.0)
            return super().get_json(url, limits=limits, allowed_hostnames=allowed_hostnames, allowed_cidrs=allowed_cidrs)

    remote = SlowRemote(fed_env["settings"], responses=responses)
    peers = FederationPeerService(fed_env["db"], fed_env["settings"], remote_client=remote)
    sync = FederationInboundSyncService(fed_env["db"], fed_env["settings"], remote_client=remote)
    peer = peers.create_peer(
        payload=PeerCreateRequest(
            peerNodeId=NODE_A_ID,
            baseUrl="http://node-a:12104",
            peerName="Node A",
            operatorName="Operator A",
            verificationKey=PeerVerificationKeyRequest(kid="a-k1", fingerprint=ed25519_key_fingerprint_hex(x_a)),
            allowPrivateNetwork=True,
        ),
        actor="admin",
    )

    first_result: list[str] = []

    def run_first():
        first_result.append(sync.sync_peer(peer_id=peer.id, trigger_type="manual", max_seconds=10).status)

    t = threading.Thread(target=run_first)
    t.start()
    time.sleep(0.2)
    second = sync.sync_peer(peer_id=peer.id, trigger_type="manual", max_seconds=10)
    t.join()
    assert "complete" in first_result
    assert second.status == "already-running"


def test_tombstone_keeps_imported_history_and_provenance(fed_env):
    key_a = Ed25519PrivateKey.generate()
    x_a = _b64url(key_a.public_key().public_bytes(encoding=serialization.Encoding.Raw, format=serialization.PublicFormat.Raw))
    discovery, jwks = _discovery_and_jwks(kid="a-k1", x=x_a)
    up = _record_event_bundle(kid="a-k1", key=key_a, local_id="TS", version="1", position=1, event_id=str(uuid4()))
    tombstone_event = dict(up["event"])
    tombstone_event["eventId"] = str(uuid4())
    tombstone_event["eventPosition"] = 3
    tombstone_event["operation"] = "tombstone"
    tombstone_signed = _build_signed(tombstone_event, kid="a-k1", key=key_a)
    enc = base64.urlsafe_b64encode(up["record"]["canonicalId"].encode()).decode().rstrip("=")
    responses = {
        "/.well-known/lfs": discovery,
        "/.well-known/jwks.json": jwks,
        "changes:": {
            "events": [{"payload": up["event"], "signed": up["eventSigned"]}],
            "limit": 200,
            "hasMore": False,
            "nextCursor": None,
            "resumeCursor": "resume-1",
            "snapshotWatermark": 1,
        },
        "changes:resume-1": {
            "events": [{"payload": tombstone_event, "signed": tombstone_signed}],
            "limit": 200,
            "hasMore": False,
            "nextCursor": None,
            "resumeCursor": "resume-3",
            "snapshotWatermark": 3,
        },
        f"record:{enc}": {
            "record": up["record"],
            "signed": up["recordSigned"],
            "currentState": "published",
            "latestEventPosition": 1,
            "latestEventDigestSha256": up["eventSigned"]["digestSha256"],
        },
    }
    peers, sync = _create_peer_and_sync_service(fed_env, responses)
    peer = peers.create_peer(
        payload=PeerCreateRequest(
            peerNodeId=NODE_A_ID,
            baseUrl="http://node-a:12104",
            peerName="Node A",
            operatorName="Operator A",
            verificationKey=PeerVerificationKeyRequest(kid="a-k1", fingerprint=ed25519_key_fingerprint_hex(x_a)),
            allowPrivateNetwork=True,
        ),
        actor="admin",
    )
    assert sync.sync_peer(peer_id=peer.id, trigger_type="manual", max_seconds=10).status == "complete"
    assert sync.sync_peer(peer_id=peer.id, trigger_type="manual", max_seconds=10).status == "complete"
    with fed_env["db"].transaction() as session:
        rec = session.execute(select(FederationRecord).where(FederationRecord.canonical_id == up["record"]["canonicalId"])).scalar_one()
        assert rec.lifecycle_state == "tombstoned"
        prov_count = session.execute(select(func.count()).select_from(FederationRecordProvenance).where(FederationRecordProvenance.record_id == rec.id)).scalar_one()
        assert prov_count >= 1


def test_phase3_migration_repeatability(postgres_url: str):
    _run_alembic(postgres_url, "downgrade", "base")
    _run_alembic(postgres_url, "upgrade", "20260804_02")
    with psycopg.connect(postgres_url.replace("+psycopg", "")) as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                INSERT INTO federation_records (
                  id, authority_node_id, local_id, version, canonical_id, resolving_uuid, is_authoritative,
                  payload, payload_digest_sha256, published_at, imported_from_peer_id, created_at, updated_at
                ) VALUES (%s,%s,%s,%s,%s,%s,true,'{}'::jsonb,'x',now(),NULL,now(),now())
                """,
                (
                    str(uuid4()),
                    NODE_B_ID,
                    "MIG",
                    "1",
                    f"lfs:{NODE_B_ID}:MIG:1",
                    str(uuid4()),
                ),
            )
            conn.commit()
    _run_alembic(postgres_url, "upgrade", "20260804_03")
    with psycopg.connect(postgres_url.replace("+psycopg", "")) as conn:
        with conn.cursor() as cur:
            cur.execute("SELECT to_regclass('public.federation_inbound_events') IS NOT NULL")
            assert cur.fetchone()[0] is True
            cur.execute("SELECT to_regclass('public.federation_peer_signing_keys') IS NOT NULL")
            assert cur.fetchone()[0] is True
            cur.execute("SELECT COUNT(*) FROM federation_records WHERE canonical_id = %s", (f"lfs:{NODE_B_ID}:MIG:1",))
            assert cur.fetchone()[0] == 1
            cur.execute(
                """
                SELECT COUNT(*) FROM information_schema.columns
                WHERE table_name IN ('federation_peer_signing_keys','federation_inbound_events')
                  AND column_name IN ('private_key','privateKey','d')
                """
            )
            assert cur.fetchone()[0] == 0
    _run_alembic(postgres_url, "downgrade", "20260804_02")
    with psycopg.connect(postgres_url.replace("+psycopg", "")) as conn:
        with conn.cursor() as cur:
            cur.execute("SELECT to_regclass('public.federation_inbound_events') IS NULL")
            assert cur.fetchone()[0] is True
            cur.execute("SELECT to_regclass('public.federation_peer_signing_keys') IS NULL")
            assert cur.fetchone()[0] is True
            cur.execute("SELECT COUNT(*) FROM federation_records WHERE canonical_id = %s", (f"lfs:{NODE_B_ID}:MIG:1",))
            assert cur.fetchone()[0] == 1
    _run_alembic(postgres_url, "upgrade", "20260804_03")
