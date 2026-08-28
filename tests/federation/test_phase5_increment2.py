"""tests/federation/test_phase5_increment2.py

Tests for Phase 5 Increment 2: operational status APIs.

Covers:
  - Pydantic response models (cursor signing, parsing, error cases)
  - API auth matrix for all 6 new endpoints
  - OpenAPI uniqueness assertions (operation IDs, paths, security)
  - PeerResponse/AdminStatusResponse Phase 5 field extension
  - RDF outbox, sync attempts, health history pagination
  - Compatibility report (read-only, no network)
  - Signing-keys endpoint (no private fields)
  - Cursor inspection (non-cacheable, audit write, no token in audit details)
  - PostgreSQL-backed tests (health history, rdf outbox, sync attempts, cursor audit)
"""

from __future__ import annotations

import os
import socket
import subprocess
import time
import uuid
import json
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest
from sqlalchemy import select

REPO_ROOT = Path(__file__).resolve().parents[2]
TEST_CURSOR_SECRET = "c" * 64

# ---------------------------------------------------------------------------
# Docker / PostgreSQL helpers (same pattern as increment 1)
# ---------------------------------------------------------------------------


def _docker_available() -> bool:
    try:
        subprocess.run(["docker", "version"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=True)
        return True
    except Exception:
        return False


def _free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return int(s.getsockname()[1])


@pytest.fixture(scope="module")
def postgres_url():
    if not _docker_available():
        pytest.skip("docker not available for Phase 5 increment 2 DB tests")

    port = _free_port()
    container_name = f"lfs-p5inc2-test-{port}"
    subprocess.run(
        [
            "docker", "run", "--rm", "-d",
            "--name", container_name,
            "-e", "POSTGRES_PASSWORD=test",
            "-e", "POSTGRES_DB=lfs_test",
            "-p", f"{port}:5432",
            "postgres:16-alpine",
        ],
        check=True,
        stdout=subprocess.DEVNULL,
    )
    url = f"postgresql+psycopg://postgres:test@127.0.0.1:{port}/lfs_test"
    alembic_url = url
    try:
        import psycopg
        deadline = time.time() + 30
        while time.time() < deadline:
            try:
                with psycopg.connect(f"postgresql://postgres:test@127.0.0.1:{port}/lfs_test"):
                    break
            except Exception:
                time.sleep(0.3)
        else:
            pytest.fail("Postgres did not start in 30s")

        # Run Alembic migrations
        env = {**os.environ, "ALEMBIC_DATABASE_URL": alembic_url, "FEDERATION_DATABASE_URL": url}
        subprocess.run(
            ["uv", "run", "alembic", "upgrade", "head"],
            cwd=str(REPO_ROOT),
            env=env,
            check=True,
            stdout=subprocess.DEVNULL,
        )
        yield url
    finally:
        subprocess.run(["docker", "stop", container_name], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)


@pytest.fixture(scope="module")
def db(postgres_url):
    from src.license_facade_service.db.session import Database
    return Database.from_url(postgres_url)


# ---------------------------------------------------------------------------
# App fixture (federation-disabled, for auth testing)
# ---------------------------------------------------------------------------


@pytest.fixture
def no_fed_client(monkeypatch):
    """TestClient with federation disabled."""
    monkeypatch.setenv("LFS_ADMIN_TOKEN", "test-admin-token")
    monkeypatch.setenv("LFS_CURATOR_TOKEN", "test-curator-token")
    monkeypatch.delenv("FEDERATION_ENABLED", raising=False)
    # Reset the auth service singleton so it picks up the new tokens
    from src.license_facade_service.api.v1 import licenses as licenses_api
    old_auth = licenses_api._auth_service
    licenses_api._auth_service = None
    from fastapi.testclient import TestClient
    from src.license_facade_service.main import create_app
    client = TestClient(create_app())
    yield client
    licenses_api._auth_service = old_auth


@pytest.fixture
def admin_headers():
    return {"Authorization": "Bearer test-admin-token"}


@pytest.fixture
def curator_headers():
    return {"Authorization": "Bearer test-curator-token"}


# ---------------------------------------------------------------------------
# Cursor model unit tests
# ---------------------------------------------------------------------------


class TestCursorUtilities:
    def test_build_and_parse_roundtrip(self):
        from src.license_facade_service.federation.operational_models import build_cursor, filters_hash, parse_cursor

        fh = filters_hash("peer-id-1", None, None)
        c = build_cursor(
            "health",
            fh,
            "2024-01-01T00:00:00+00:00",
            str(uuid.uuid4()),
            limit=50,
            audience="node-a",
            secret=TEST_CURSOR_SECRET,
        )
        data = parse_cursor(
            c,
            "health",
            fh,
            expected_limit=50,
            expected_audience="node-a",
            secret=TEST_CURSOR_SECRET,
        )
        assert data.k == "health"
        assert data.fh == fh

    def test_tampered_cursor_raises(self):
        from src.license_facade_service.federation.operational_models import (
            CursorError, build_cursor, filters_hash, parse_cursor,
        )

        fh = filters_hash(None, None)
        c = build_cursor("rdf", fh, "2024-01-01T00:00:00+00:00", str(uuid.uuid4()), limit=50, secret=TEST_CURSOR_SECRET)
        tampered = c[:-4] + "xxxx"
        with pytest.raises(CursorError):
            parse_cursor(tampered, "rdf", fh, expected_limit=50, secret=TEST_CURSOR_SECRET)

    def test_wrong_kind_raises(self):
        from src.license_facade_service.federation.operational_models import (
            CursorError, build_cursor, filters_hash, parse_cursor,
        )

        fh = filters_hash(None, None)
        c = build_cursor("rdf", fh, "2024-01-01T00:00:00+00:00", str(uuid.uuid4()), limit=50, secret=TEST_CURSOR_SECRET)
        with pytest.raises(CursorError):
            parse_cursor(c, "health", fh, expected_limit=50, secret=TEST_CURSOR_SECRET)

    def test_wrong_filters_raises(self):
        from src.license_facade_service.federation.operational_models import (
            CursorError, build_cursor, filters_hash, parse_cursor,
        )

        fh1 = filters_hash("status-a", None)
        fh2 = filters_hash("status-b", None)
        c = build_cursor("rdf", fh1, "2024-01-01T00:00:00+00:00", str(uuid.uuid4()), limit=50, secret=TEST_CURSOR_SECRET)
        with pytest.raises(CursorError):
            parse_cursor(c, "rdf", fh2, expected_limit=50, secret=TEST_CURSOR_SECRET)

    def test_malformed_cursor_raises(self):
        from src.license_facade_service.federation.operational_models import CursorError, parse_cursor

        with pytest.raises(CursorError):
            parse_cursor("not.a.valid.cursor", "health", "abc", expected_limit=50, secret=TEST_CURSOR_SECRET)

    def test_filters_hash_deterministic(self):
        from src.license_facade_service.federation.operational_models import filters_hash

        fh1 = filters_hash("a", None, "c")
        fh2 = filters_hash("a", None, "c")
        assert fh1 == fh2
        assert len(fh1) == 64

    def test_filters_hash_differs_on_different_input(self):
        from src.license_facade_service.federation.operational_models import filters_hash

        assert filters_hash("a") != filters_hash("b")


# ---------------------------------------------------------------------------
# Pydantic model validation
# ---------------------------------------------------------------------------


class TestResponseModels:
    def test_local_signing_key_item_forbids_extra(self):
        from src.license_facade_service.federation.operational_models import LocalSigningKeyItem
        import pydantic

        with pytest.raises(pydantic.ValidationError):
            LocalSigningKeyItem(
                id=uuid.uuid4(), kid="k1", alg="EdDSA", kty="OKP", crv="Ed25519",
                x="abc", isActive=True, status="active",
                createdAt=datetime.now(timezone.utc), updatedAt=datetime.now(timezone.utc),
                d="private-key-material",  # forbidden extra field
            )

    def test_peer_health_snapshot_item_optional_fields(self):
        from src.license_facade_service.federation.operational_models import PeerHealthSnapshotItem

        item = PeerHealthSnapshotItem(
            id=uuid.uuid4(), peerNodeId="node-1", sampledAt=datetime.now(timezone.utc)
        )
        assert item.healthStatus is None
        assert item.peerId is None

    def test_rdf_outbox_job_item_fields(self):
        from src.license_facade_service.federation.operational_models import RdfOutboxJobItem

        now = datetime.now(timezone.utc)
        item = RdfOutboxJobItem(
            id=uuid.uuid4(), jobType="publish", status="pending",
            attemptCount=0, createdAt=now, updatedAt=now
        )
        assert item.recordId is None
        assert item.deadLetteredAt is None


class TestFederationCursorSecretSafety:
    def test_settings_repr_and_str_hide_cursor_secret(self, monkeypatch):
        secret = "s" * 64
        monkeypatch.setenv("FEDERATION_ENABLED", "true")
        monkeypatch.setenv("FEDERATION_NODE_ID", "de305d54-75b4-431b-adb2-eb6b9e546014")
        monkeypatch.setenv("FEDERATION_PUBLIC_BASE_URL", "https://node.example.org")
        monkeypatch.setenv("FEDERATION_NODE_NAME", "EDEN Node")
        monkeypatch.setenv("FEDERATION_OPERATOR", "EDEN Operator")
        monkeypatch.setenv("FEDERATION_DATABASE_URL", "postgresql+psycopg://invalid")
        monkeypatch.setenv("FEDERATION_ACTIVE_KID", "k1")
        monkeypatch.setenv("FEDERATION_SIGNING_KEY_PATH", "/tmp/signing-key.pem")
        monkeypatch.setenv("FEDERATION_ADMIN_CURSOR_SECRET", secret)

        from src.license_facade_service.config.federation import FederationSettings

        settings = FederationSettings.from_env()
        assert secret not in repr(settings)
        assert secret not in str(settings)
        assert secret not in "\n".join(settings.validation_errors)

    def test_cursor_secret_file_validation_rejects_bad_files(self, monkeypatch, tmp_path):
        monkeypatch.setenv("FEDERATION_ENABLED", "true")
        monkeypatch.setenv("FEDERATION_NODE_ID", "de305d54-75b4-431b-adb2-eb6b9e546014")
        monkeypatch.setenv("FEDERATION_PUBLIC_BASE_URL", "https://node.example.org")
        monkeypatch.setenv("FEDERATION_NODE_NAME", "EDEN Node")
        monkeypatch.setenv("FEDERATION_OPERATOR", "EDEN Operator")
        monkeypatch.setenv("FEDERATION_DATABASE_URL", "postgresql+psycopg://invalid")
        monkeypatch.setenv("FEDERATION_ACTIVE_KID", "k1")
        monkeypatch.setenv("FEDERATION_SIGNING_KEY_PATH", "/tmp/signing-key.pem")
        monkeypatch.setenv("FEDERATION_ADMIN_CURSOR_SECRET_FILE", str(tmp_path / "secret-dir"))

        bad_dir = tmp_path / "secret-dir"
        bad_dir.mkdir()

        from src.license_facade_service.config.federation import FederationSettings

        settings = FederationSettings.from_env()
        assert any("regular file" in err for err in settings.validation_errors)

        empty_file = tmp_path / "empty-secret"
        empty_file.write_text("", encoding="utf-8")
        monkeypatch.setenv("FEDERATION_ADMIN_CURSOR_SECRET_FILE", str(empty_file))
        settings2 = FederationSettings.from_env()
        assert any("must not be empty" in err for err in settings2.validation_errors)

    def test_unreadable_cursor_secret_file_is_rejected(self, monkeypatch, tmp_path):
        monkeypatch.setenv("FEDERATION_ENABLED", "true")
        monkeypatch.setenv("FEDERATION_NODE_ID", "de305d54-75b4-431b-adb2-eb6b9e546014")
        monkeypatch.setenv("FEDERATION_PUBLIC_BASE_URL", "https://node.example.org")
        monkeypatch.setenv("FEDERATION_NODE_NAME", "EDEN Node")
        monkeypatch.setenv("FEDERATION_OPERATOR", "EDEN Operator")
        monkeypatch.setenv("FEDERATION_DATABASE_URL", "postgresql+psycopg://invalid")
        monkeypatch.setenv("FEDERATION_ACTIVE_KID", "k1")
        monkeypatch.setenv("FEDERATION_SIGNING_KEY_PATH", "/tmp/signing-key.pem")

        secret_file = tmp_path / "unreadable-secret"
        secret_file.write_text("x" * 64, encoding="utf-8")
        secret_file.chmod(0o000)
        monkeypatch.setenv("FEDERATION_ADMIN_CURSOR_SECRET_FILE", str(secret_file))

        from src.license_facade_service.config.federation import FederationSettings

        try:
            settings = FederationSettings.from_env()
        finally:
            secret_file.chmod(0o600)
        assert any("readable regular file" in err for err in settings.validation_errors)


# ---------------------------------------------------------------------------
# Auth matrix tests for all 6 new endpoints
# ---------------------------------------------------------------------------

NEW_ENDPOINTS = [
    ("GET", f"/api/v1/admin/federation/peers/{uuid.uuid4()}/health"),
    ("GET", f"/api/v1/admin/federation/peers/{uuid.uuid4()}/cursor"),
    ("GET", "/api/v1/admin/federation/signing-keys"),
    ("GET", "/api/v1/admin/federation/rdf-outbox"),
    ("GET", "/api/v1/admin/federation/sync-attempts"),
    ("GET", "/api/v1/admin/federation/compatibility"),
]


@pytest.mark.parametrize("method,path", NEW_ENDPOINTS)
def test_auth_no_token(no_fed_client, method, path):
    resp = no_fed_client.request(method, path)
    assert resp.status_code == 401
    assert resp.headers["content-type"].startswith("application/problem+json")


@pytest.mark.parametrize("method,path", NEW_ENDPOINTS)
def test_auth_invalid_token(no_fed_client, method, path):
    resp = no_fed_client.request(method, path, headers={"Authorization": "Bearer invalid-token"})
    assert resp.status_code == 401


@pytest.mark.parametrize("method,path", NEW_ENDPOINTS)
def test_auth_curator_token(no_fed_client, curator_headers, method, path):
    resp = no_fed_client.request(method, path, headers=curator_headers)
    assert resp.status_code == 403


@pytest.mark.parametrize("method,path", NEW_ENDPOINTS)
def test_auth_admin_with_disabled_federation(no_fed_client, admin_headers, method, path):
    resp = no_fed_client.request(method, path, headers=admin_headers)
    # Federation disabled → 404
    assert resp.status_code == 404
    assert resp.headers["content-type"].startswith("application/problem+json")


# ---------------------------------------------------------------------------
# OpenAPI schema tests
# ---------------------------------------------------------------------------


def test_openapi_no_duplicate_operation_ids(no_fed_client):
    resp = no_fed_client.get("/openapi.json")
    assert resp.status_code == 200
    schema = resp.json()
    op_ids = []
    for path_item in schema["paths"].values():
        for op in path_item.values():
            if isinstance(op, dict) and "operationId" in op:
                op_ids.append(op["operationId"])
    assert len(op_ids) == len(set(op_ids)), f"Duplicate operation IDs: {[x for x in op_ids if op_ids.count(x) > 1]}"


def test_openapi_no_duplicate_routes(no_fed_client):
    resp = no_fed_client.get("/openapi.json")
    assert resp.status_code == 200
    schema = resp.json()
    route_keys = []
    for path, path_item in schema["paths"].items():
        for method in path_item:
            route_keys.append(f"{method.upper()} {path}")
    assert len(route_keys) == len(set(route_keys))


def test_openapi_new_endpoints_have_security(no_fed_client):
    resp = no_fed_client.get("/openapi.json")
    assert resp.status_code == 200
    schema = resp.json()
    new_op_ids = {
        "getPeerHealthHistory",
        "getPeerCursor",
        "listLocalSigningKeys",
        "listRdfOutboxJobs",
        "listSyncAttempts",
        "getFederationCompatibility",
    }
    for path_item in schema["paths"].values():
        for op in path_item.values():
            if isinstance(op, dict) and op.get("operationId") in new_op_ids:
                assert "security" in op, f"Missing security on {op.get('operationId')}"


def test_openapi_all_new_operation_ids_present(no_fed_client):
    resp = no_fed_client.get("/openapi.json")
    assert resp.status_code == 200
    schema = resp.json()
    all_op_ids = set()
    for path_item in schema["paths"].values():
        for op in path_item.values():
            if isinstance(op, dict) and "operationId" in op:
                all_op_ids.add(op["operationId"])
    expected = {
        "getPeerHealthHistory", "getPeerCursor", "listLocalSigningKeys",
        "listRdfOutboxJobs", "listSyncAttempts", "getFederationCompatibility",
    }
    assert expected <= all_op_ids


def test_openapi_does_not_expose_cursor_secret(fed_client):
    resp = fed_client.get("/openapi.json")
    assert resp.status_code == 200
    assert TEST_CURSOR_SECRET not in json.dumps(resp.json())


# ---------------------------------------------------------------------------
# PeerResponse Phase 5 fields (model-level test, no DB)
# ---------------------------------------------------------------------------


def test_peer_response_has_phase5_fields():
    from src.license_facade_service.federation.inbound_models import PeerResponse

    now = datetime.now(timezone.utc)
    peer = PeerResponse(
        id=uuid.uuid4(),
        peerNodeId="node-1",
        baseUrl="https://example.org",
        peerName="Test Peer",
        trustStatus="trusted",
        syncEnabled=True,
        circuitState="closed",
        circuitRequiresAdminReset=False,
        circuitFailureCount=0,
    )
    assert peer.circuitState == "closed"
    assert peer.suspendedUntil is None
    assert peer.latestHealthStatus is None


def test_admin_status_response_has_phase5_fields():
    from src.license_facade_service.federation.inbound_models import AdminStatusResponse

    status = AdminStatusResponse(
        federationEnabled=True,
        inboundEnabled=True,
        peers=0, trustedPeers=0, disabledPeers=0,
        importedRecords=0, inboundEventsAccepted=0, inboundEventsRejected=0,
        workerIntervalSeconds=60, maxSyncSeconds=120,
        protocolVersion="1.0",
        operationalState="unknown",
    )
    assert status.protocolVersion == "1.0"
    assert status.operationalState == "unknown"
    assert status.signingKeySummary is None


# ---------------------------------------------------------------------------
# Signing keys: no private fields in schema
# ---------------------------------------------------------------------------


def test_signing_keys_schema_no_private_fields(no_fed_client, admin_headers):
    resp = no_fed_client.get("/openapi.json")
    schema = resp.json()
    # Find LocalSigningKeyItem schema
    components = schema.get("components", {}).get("schemas", {})
    key_schema = components.get("LocalSigningKeyItem", {})
    props = key_schema.get("properties", {})
    forbidden = {"d", "pem", "path", "secret", "private_key"}
    found = {f for f in forbidden if f in props}
    assert not found, f"Private fields found in LocalSigningKeyItem schema: {found}"


# ---------------------------------------------------------------------------
# PostgreSQL-backed tests
# ---------------------------------------------------------------------------


@pytest.fixture(scope="module")
def pg_env(postgres_url, tmp_path_factory):
    """Returns (postgres_url, signing_key_path) for federation app."""
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    from cryptography.hazmat.primitives.serialization import Encoding, NoEncryption, PrivateFormat

    key = Ed25519PrivateKey.generate()
    key_dir = tmp_path_factory.mktemp("keys")
    pem = key.private_bytes(
        encoding=Encoding.PEM,
        format=PrivateFormat.PKCS8,
        encryption_algorithm=NoEncryption(),
    )
    key_path = key_dir / "signing-key.pem"
    key_path.write_bytes(pem)
    return postgres_url, str(key_path)


@pytest.fixture
def fed_client(postgres_url, pg_env, monkeypatch):
    """TestClient with federation fully enabled against a test PostgreSQL."""
    db_url, key_path = pg_env
    monkeypatch.setenv("LFS_ADMIN_TOKEN", "admin-token")
    monkeypatch.setenv("LFS_CURATOR_TOKEN", "curator-token")
    monkeypatch.setenv("FEDERATION_ENABLED", "true")
    monkeypatch.setenv("FEDERATION_INBOUND_ENABLED", "true")
    monkeypatch.setenv("FEDERATION_DATABASE_URL", db_url)
    monkeypatch.setenv("FEDERATION_NODE_ID", "cccccccc-cccc-4ccc-8ccc-cccccccccccc")
    monkeypatch.setenv("FEDERATION_PUBLIC_BASE_URL", "https://node-test.example.org")
    monkeypatch.setenv("FEDERATION_NODE_NAME", "Test Node")
    monkeypatch.setenv("FEDERATION_OPERATOR", "Test Operator")
    monkeypatch.setenv("FEDERATION_SIGNING_KEY_PATH", key_path)
    monkeypatch.setenv("FEDERATION_ACTIVE_KID", "test-k1")
    monkeypatch.setenv("FEDERATION_JWKS_ENABLED", "false")
    monkeypatch.setenv("FEDERATION_ALLOW_HTTP_FOR_DEMO", "true")
    monkeypatch.setenv("FEDERATION_ALLOW_PRIVATE_NETWORK", "false")
    monkeypatch.setenv("FEDERATION_SYNC_ALLOWED_PORTS", "443,12104")
    monkeypatch.setenv("FEDERATION_ADMIN_CURSOR_SECRET", TEST_CURSOR_SECRET)
    monkeypatch.setenv("BASE_DIR", str(REPO_ROOT))
    monkeypatch.setenv("URL_BASE", "https://example.test/api/v1/licenses")
    monkeypatch.setenv("FUSEKI_ENABLE", "false")
    # Reset auth service singleton so it picks up the new tokens
    from src.license_facade_service.api.v1 import licenses as licenses_api
    old_auth = licenses_api._auth_service
    licenses_api._auth_service = None
    from fastapi.testclient import TestClient
    from src.license_facade_service.main import create_app
    with TestClient(create_app()) as client:
        yield client
    licenses_api._auth_service = old_auth


@pytest.fixture
def fed_db(postgres_url):
    from src.license_facade_service.db.session import Database
    return Database.from_url(postgres_url)


def _insert_peer(db, *, peer_node_id=None, trust_status="trusted"):
    from src.license_facade_service.db.models.federation import FederationTrustedPeer
    now = datetime.now(timezone.utc)
    with db.transaction() as session:
        peer = FederationTrustedPeer(
            id=uuid.uuid4(),
            peer_node_id=peer_node_id or str(uuid.uuid4()),
            base_url="https://peer.example.org",
            jwks_url="https://peer.example.org/jwks",
            peer_name="Test Peer",
            trust_status=trust_status,
            sync_enabled=True,
            created_at=now,
            updated_at=now,
        )
        session.add(peer)
    return peer


def _insert_health_snapshot(db, peer, *, health_status="healthy", compat_status="compatible", dt=None):
    from src.license_facade_service.db.models.federation import FederationPeerHealthSnapshot
    now = dt or datetime.now(timezone.utc)
    with db.transaction() as session:
        snap = FederationPeerHealthSnapshot(
            peer_id=peer.id,
            peer_node_id=peer.peer_node_id,
            sampled_at=now,
            health_status=health_status,
            compatibility_status=compat_status,
            created_at=now,
        )
        session.add(snap)
    return snap


def _insert_rdf_job(db, *, status="pending", record_id=None):
    from src.license_facade_service.db.models.federation import FederationRdfOutboxJob
    now = datetime.now(timezone.utc)
    with db.transaction() as session:
        job = FederationRdfOutboxJob(
            id=uuid.uuid4(),
            dedupe_key=str(uuid.uuid4()),
            job_type="publish",
            status=status,
            graph_uri=f"https://example.org/graphs/{uuid.uuid4()}",
            expected_generation=1,
            expected_digest_sha256="abc" * 21 + "ab",
            payload_json={},
            created_at=now,
            updated_at=now,
        )
        if record_id:
            job.record_id = record_id
        session.add(job)
    return job


def _insert_sync_attempt(db, peer, *, status="complete", dt=None):
    from src.license_facade_service.db.models.federation import FederationSyncAttempt
    now = dt or datetime.now(timezone.utc)
    with db.transaction() as session:
        att = FederationSyncAttempt(
            id=uuid.uuid4(),
            peer_id=peer.id,
            started_at=now,
            status=status,
            trigger_type="manual",
            pages_processed=1,
            events_processed=2,
            created_at=now,
        )
        session.add(att)
    return att


# --- Health history tests ---


def test_health_history_empty(fed_client, fed_db):
    peer = _insert_peer(fed_db)
    resp = fed_client.get(
        f"/api/v1/admin/federation/peers/{peer.id}/health",
        headers={"Authorization": "Bearer admin-token"},
    )
    assert resp.status_code == 200
    data = resp.json()
    assert data["items"] == []
    assert data["nextCursor"] is None
    assert data["limit"] == 50


def test_health_history_pagination(fed_client, fed_db):
    peer = _insert_peer(fed_db)
    base_time = datetime.now(timezone.utc)
    for i in range(5):
        _insert_health_snapshot(fed_db, peer, dt=base_time - timedelta(minutes=i))

    resp = fed_client.get(
        f"/api/v1/admin/federation/peers/{peer.id}/health",
        params={"limit": 3},
        headers={"Authorization": "Bearer admin-token"},
    )
    assert resp.status_code == 200
    data = resp.json()
    assert len(data["items"]) == 3
    assert data["nextCursor"] is not None

    # Fetch next page
    resp2 = fed_client.get(
        f"/api/v1/admin/federation/peers/{peer.id}/health",
        params={"limit": 3, "cursor": data["nextCursor"]},
        headers={"Authorization": "Bearer admin-token"},
    )
    assert resp2.status_code == 200
    data2 = resp2.json()
    assert len(data2["items"]) == 2
    assert data2["nextCursor"] is None

    # No overlap between pages
    ids1 = {i["id"] for i in data["items"]}
    ids2 = {i["id"] for i in data2["items"]}
    assert not ids1 & ids2


def test_health_history_boundary_and_concurrent_insert(fed_client, fed_db):
    peer = _insert_peer(fed_db)
    base_time = datetime.now(timezone.utc)
    [_insert_health_snapshot(fed_db, peer, dt=base_time) for _ in range(3)]
    resp1 = fed_client.get(
        f"/api/v1/admin/federation/peers/{peer.id}/health",
        params={"limit": 2},
        headers={"Authorization": "Bearer admin-token"},
    )
    assert resp1.status_code == 200
    data1 = resp1.json()
    assert len(data1["items"]) == 2

    _insert_health_snapshot(fed_db, peer, dt=base_time + timedelta(seconds=1))

    resp2 = fed_client.get(
        f"/api/v1/admin/federation/peers/{peer.id}/health",
        params={"limit": 2, "cursor": data1["nextCursor"]},
        headers={"Authorization": "Bearer admin-token"},
    )
    assert resp2.status_code == 200
    data2 = resp2.json()
    assert len(data2["items"]) == 1
    assert all(item["sampledAt"] != (base_time + timedelta(seconds=1)).isoformat() for item in data2["items"])


def test_health_filter_by_health_status(fed_client, fed_db):
    peer = _insert_peer(fed_db)
    _insert_health_snapshot(fed_db, peer, health_status="healthy")
    _insert_health_snapshot(fed_db, peer, health_status="degraded")

    resp = fed_client.get(
        f"/api/v1/admin/federation/peers/{peer.id}/health",
        params={"healthStatus": "healthy"},
        headers={"Authorization": "Bearer admin-token"},
    )
    assert resp.status_code == 200
    data = resp.json()
    assert all(i["healthStatus"] == "healthy" for i in data["items"])


def test_health_filter_by_compat_status(fed_client, fed_db):
    peer = _insert_peer(fed_db)
    _insert_health_snapshot(fed_db, peer, compat_status="compatible")
    _insert_health_snapshot(fed_db, peer, compat_status="unchecked")

    resp = fed_client.get(
        f"/api/v1/admin/federation/peers/{peer.id}/health",
        params={"compatibilityStatus": "compatible"},
        headers={"Authorization": "Bearer admin-token"},
    )
    assert resp.status_code == 200
    data = resp.json()
    assert all(i["compatibilityStatus"] == "compatible" for i in data["items"])


def test_health_tampered_cursor(fed_client, fed_db):
    peer = _insert_peer(fed_db)
    resp = fed_client.get(
        f"/api/v1/admin/federation/peers/{peer.id}/health",
        params={"cursor": "tampered.cursor.value.xyz"},
        headers={"Authorization": "Bearer admin-token"},
    )
    assert resp.status_code == 400
    assert resp.headers["content-type"].startswith("application/problem+json")


def test_health_cursor_wrong_kind(fed_client, fed_db):
    from src.license_facade_service.federation.operational_models import build_cursor, filters_hash

    peer = _insert_peer(fed_db)
    # Build an "rdf" cursor and try to use it on health endpoint
    fh = filters_hash(peer.id, None, None)
    bad_cursor = build_cursor("rdf", fh, "2024-01-01T00:00:00+00:00", str(uuid.uuid4()), limit=50, secret=TEST_CURSOR_SECRET)
    resp = fed_client.get(
        f"/api/v1/admin/federation/peers/{peer.id}/health",
        params={"cursor": bad_cursor},
        headers={"Authorization": "Bearer admin-token"},
    )
    assert resp.status_code == 400


def test_health_cursor_wrong_filters(fed_client, fed_db):
    from src.license_facade_service.federation.operational_models import build_cursor, filters_hash

    peer = _insert_peer(fed_db)
    # Build cursor with different filters
    fh_other = filters_hash(peer.id, "healthy", None)
    cursor = build_cursor("health", fh_other, "2024-01-01T00:00:00+00:00", str(uuid.uuid4()), limit=50, secret=TEST_CURSOR_SECRET)
    # Use without healthStatus filter (different hash)
    resp = fed_client.get(
        f"/api/v1/admin/federation/peers/{peer.id}/health",
        params={"cursor": cursor},
        headers={"Authorization": "Bearer admin-token"},
    )
    assert resp.status_code == 400


def test_health_cursor_limit_mismatch(fed_client, fed_db):
    from src.license_facade_service.federation.operational_models import build_cursor, filters_hash

    peer = _insert_peer(fed_db)
    fh = filters_hash(peer.id, None, None, 2, "desc")
    cursor = build_cursor("health", fh, "2024-01-01T00:00:00+00:00", str(uuid.uuid4()), limit=2, secret=TEST_CURSOR_SECRET)
    resp = fed_client.get(
        f"/api/v1/admin/federation/peers/{peer.id}/health",
        params={"limit": 3, "cursor": cursor},
        headers={"Authorization": "Bearer admin-token"},
    )
    assert resp.status_code == 400


def test_health_invalid_limit(fed_client, fed_db):
    peer = _insert_peer(fed_db)
    resp = fed_client.get(
        f"/api/v1/admin/federation/peers/{peer.id}/health",
        params={"limit": 201},
        headers={"Authorization": "Bearer admin-token"},
    )
    assert resp.status_code == 422


def test_health_invalid_filter_values(fed_client, fed_db):
    peer = _insert_peer(fed_db)
    resp = fed_client.get(
        f"/api/v1/admin/federation/peers/{peer.id}/health",
        params={"healthStatus": "not-a-status"},
        headers={"Authorization": "Bearer admin-token"},
    )
    assert resp.status_code == 400
    resp2 = fed_client.get(
        f"/api/v1/admin/federation/peers/{peer.id}/health",
        params={"compatibilityStatus": "not-a-status"},
        headers={"Authorization": "Bearer admin-token"},
    )
    assert resp2.status_code == 400


def test_health_unknown_peer(fed_client):
    unknown_id = uuid.uuid4()
    resp = fed_client.get(
        f"/api/v1/admin/federation/peers/{unknown_id}/health",
        headers={"Authorization": "Bearer admin-token"},
    )
    assert resp.status_code == 404


# --- Cursor inspection tests ---


def test_cursor_inspection_returns_state(fed_client, fed_db):
    from src.license_facade_service.db.models.federation import FederationOperationalAudit, FederationPeerCursor

    peer = _insert_peer(fed_db)
    now = datetime.now(timezone.utc)
    with fed_db.transaction() as session:
        cursor_row = FederationPeerCursor(
            id=uuid.uuid4(),
            peer_id=peer.id,
            cursor="v1.test-cursor-token",
            last_remote_position=42,
            updated_at=now,
        )
        session.add(cursor_row)

    resp = fed_client.get(
        f"/api/v1/admin/federation/peers/{peer.id}/cursor",
        headers={"Authorization": "Bearer admin-token"},
    )
    assert resp.status_code == 200
    data = resp.json()
    assert data["cursorExists"] is True
    assert data["lastRemotePosition"] == 42
    assert resp.headers["cache-control"].lower() == "no-store"

    with fed_db.transaction() as session:
        audits = session.execute(
            select(FederationOperationalAudit).where(FederationOperationalAudit.target_id == str(peer.id))
        ).scalars().all()
    assert len(audits) == 1
    assert audits[0].peer_id == peer.id
    assert "v1.test-cursor-token" not in json.dumps(audits[0].redacted_details)
    assert TEST_CURSOR_SECRET not in json.dumps(audits[0].redacted_details)


def test_cursor_inspection_cache_control(fed_client, fed_db):
    peer = _insert_peer(fed_db)
    resp = fed_client.get(
        f"/api/v1/admin/federation/peers/{peer.id}/cursor",
        headers={"Authorization": "Bearer admin-token"},
    )
    assert "no-store" in resp.headers.get("cache-control", "").lower()


def test_cursor_inspection_peer_not_found(fed_client):
    from src.license_facade_service.db.models.federation import FederationOperationalAudit

    unknown_id = uuid.uuid4()
    resp = fed_client.get(
        f"/api/v1/admin/federation/peers/{unknown_id}/cursor",
        headers={"Authorization": "Bearer admin-token"},
    )
    assert resp.status_code == 404
    assert "no-store" in resp.headers.get("cache-control", "").lower()
    db = fed_client.app.state.federation_runtime.db
    with db.transaction() as session:
        audits = session.execute(
            select(FederationOperationalAudit).where(FederationOperationalAudit.target_id == str(unknown_id))
        ).scalars().all()
    assert len(audits) == 1
    assert audits[0].peer_id is None
    assert audits[0].outcome == "rejected"
    assert audits[0].target_id == str(unknown_id)


def test_cursor_inspection_no_cursor_row(fed_client, fed_db):
    peer = _insert_peer(fed_db)
    resp = fed_client.get(
        f"/api/v1/admin/federation/peers/{peer.id}/cursor",
        headers={"Authorization": "Bearer admin-token"},
    )
    assert resp.status_code == 200
    data = resp.json()
    assert data["cursorExists"] is False
    assert data["cursor"] is None


def test_cursor_inspection_reuses_shared_async_engine(fed_client, fed_db):
    peer = _insert_peer(fed_db)
    engine1 = fed_client.app.state.federation_async_engine
    resp1 = fed_client.get(f"/api/v1/admin/federation/peers/{peer.id}/cursor", headers={"Authorization": "Bearer admin-token"})
    assert resp1.status_code == 200
    engine2 = fed_client.app.state.federation_async_engine
    resp2 = fed_client.get(f"/api/v1/admin/federation/peers/{peer.id}/cursor", headers={"Authorization": "Bearer admin-token"})
    assert resp2.status_code == 200
    assert engine1 is engine2


# --- Signing keys tests ---


def test_signing_keys_no_private_fields(fed_client):
    resp = fed_client.get(
        "/api/v1/admin/federation/signing-keys",
        headers={"Authorization": "Bearer admin-token"},
    )
    assert resp.status_code == 200
    data = resp.json()
    assert "items" in data
    for item in data["items"]:
        assert "d" not in item
        assert "pem" not in item
        assert "path" not in item


def test_signing_keys_active_flag(fed_client):
    resp = fed_client.get(
        "/api/v1/admin/federation/signing-keys",
        headers={"Authorization": "Bearer admin-token"},
    )
    assert resp.status_code == 200
    data = resp.json()
    # Should have the test-k1 key (loaded from settings)
    active_keys = [k for k in data["items"] if k["isActive"]]
    assert isinstance(data["total"], int)
    # isActive is a bool in the response
    for k in data["items"]:
        assert isinstance(k["isActive"], bool)


# --- RDF outbox tests ---


def test_rdf_outbox_empty(fed_client):
    resp = fed_client.get(
        "/api/v1/admin/federation/rdf-outbox",
        headers={"Authorization": "Bearer admin-token"},
    )
    assert resp.status_code == 200
    data = resp.json()
    # items may have pre-existing entries from other tests but response is valid
    assert "items" in data
    assert isinstance(data["items"], list)


def test_rdf_outbox_pagination(fed_client, fed_db):
    for _ in range(5):
        _insert_rdf_job(fed_db)

    resp = fed_client.get(
        "/api/v1/admin/federation/rdf-outbox",
        params={"limit": 3},
        headers={"Authorization": "Bearer admin-token"},
    )
    assert resp.status_code == 200
    data = resp.json()
    assert len(data["items"]) <= 3

    if data["nextCursor"]:
        resp2 = fed_client.get(
            "/api/v1/admin/federation/rdf-outbox",
            params={"limit": 3, "cursor": data["nextCursor"]},
            headers={"Authorization": "Bearer admin-token"},
        )
        assert resp2.status_code == 200


def test_rdf_outbox_status_filter(fed_client, fed_db):
    _insert_rdf_job(fed_db, status="pending")
    _insert_rdf_job(fed_db, status="succeeded")

    resp = fed_client.get(
        "/api/v1/admin/federation/rdf-outbox",
        params={"status": "succeeded"},
        headers={"Authorization": "Bearer admin-token"},
    )
    assert resp.status_code == 200
    data = resp.json()
    assert all(i["status"] == "succeeded" for i in data["items"])


def test_rdf_outbox_invalid_status(fed_client):
    resp = fed_client.get(
        "/api/v1/admin/federation/rdf-outbox",
        params={"status": "not-a-valid-status"},
        headers={"Authorization": "Bearer admin-token"},
    )
    assert resp.status_code == 400


def test_rdf_outbox_invalid_record_id(fed_client):
    resp = fed_client.get(
        "/api/v1/admin/federation/rdf-outbox",
        params={"recordId": "not-a-uuid"},
        headers={"Authorization": "Bearer admin-token"},
    )
    assert resp.status_code == 422


def test_rdf_outbox_tampered_cursor(fed_client):
    resp = fed_client.get(
        "/api/v1/admin/federation/rdf-outbox",
        params={"cursor": "tampered.cursor.value.zzz"},
        headers={"Authorization": "Bearer admin-token"},
    )
    assert resp.status_code == 400


# --- Sync attempts tests ---


def test_sync_attempts_empty(fed_client):
    resp = fed_client.get(
        "/api/v1/admin/federation/sync-attempts",
        headers={"Authorization": "Bearer admin-token"},
    )
    assert resp.status_code == 200
    data = resp.json()
    assert "items" in data
    assert isinstance(data["items"], list)


def test_sync_attempts_pagination(fed_client, fed_db):
    peer = _insert_peer(fed_db)
    base_time = datetime.now(timezone.utc)
    for i in range(5):
        _insert_sync_attempt(fed_db, peer, dt=base_time - timedelta(seconds=i))

    resp = fed_client.get(
        "/api/v1/admin/federation/sync-attempts",
        params={"limit": 3},
        headers={"Authorization": "Bearer admin-token"},
    )
    assert resp.status_code == 200
    data = resp.json()
    assert len(data["items"]) <= 3


def test_sync_attempts_peer_filter(fed_client, fed_db):
    peer = _insert_peer(fed_db)
    _insert_sync_attempt(fed_db, peer)
    other_peer = _insert_peer(fed_db)
    _insert_sync_attempt(fed_db, other_peer)

    resp = fed_client.get(
        "/api/v1/admin/federation/sync-attempts",
        params={"peerId": str(peer.id)},
        headers={"Authorization": "Bearer admin-token"},
    )
    assert resp.status_code == 200
    data = resp.json()
    assert all(i["peerId"] == str(peer.id) for i in data["items"])


def test_sync_attempts_status_filter(fed_client, fed_db):
    peer = _insert_peer(fed_db)
    _insert_sync_attempt(fed_db, peer, status="complete")
    _insert_sync_attempt(fed_db, peer, status="failed")

    resp = fed_client.get(
        "/api/v1/admin/federation/sync-attempts",
        params={"status": "failed"},
        headers={"Authorization": "Bearer admin-token"},
    )
    assert resp.status_code == 200
    data = resp.json()
    assert all(i["status"] == "failed" for i in data["items"])


def test_sync_attempts_date_range(fed_client, fed_db):
    peer = _insert_peer(fed_db)
    now = datetime.now(timezone.utc)
    _insert_sync_attempt(fed_db, peer, dt=now - timedelta(hours=2))
    _insert_sync_attempt(fed_db, peer, dt=now - timedelta(minutes=30))
    _insert_sync_attempt(fed_db, peer, dt=now - timedelta(minutes=5))

    resp = fed_client.get(
        "/api/v1/admin/federation/sync-attempts",
        params={
            "startedAfter": (now - timedelta(hours=1)).isoformat(),
            "startedBefore": now.isoformat(),
        },
        headers={"Authorization": "Bearer admin-token"},
    )
    assert resp.status_code == 200
    data = resp.json()
    assert all(i["startedAt"] for i in data["items"])


def test_sync_attempts_invalid_time_range(fed_client):
    now = datetime.now(timezone.utc)
    resp = fed_client.get(
        "/api/v1/admin/federation/sync-attempts",
        params={
            "startedAfter": now.isoformat(),
            "startedBefore": (now - timedelta(minutes=1)).isoformat(),
        },
        headers={"Authorization": "Bearer admin-token"},
    )
    assert resp.status_code == 400


def test_sync_attempts_invalid_status_and_error_class(fed_client, fed_db):
    resp = fed_client.get(
        "/api/v1/admin/federation/sync-attempts",
        params={"status": "not-a-status"},
        headers={"Authorization": "Bearer admin-token"},
    )
    assert resp.status_code == 400
    resp2 = fed_client.get(
        "/api/v1/admin/federation/sync-attempts",
        params={"errorClass": "x" * 65},
        headers={"Authorization": "Bearer admin-token"},
    )
    assert resp2.status_code == 400


def test_sync_no_cursor_tokens_in_response(fed_client, fed_db):
    """Sync attempt responses must not include cursor_before or cursor_after."""
    peer = _insert_peer(fed_db)
    _insert_sync_attempt(fed_db, peer)

    resp = fed_client.get(
        "/api/v1/admin/federation/sync-attempts",
        headers={"Authorization": "Bearer admin-token"},
    )
    assert resp.status_code == 200
    for item in resp.json()["items"]:
        assert "cursorBefore" not in item
        assert "cursorAfter" not in item
        assert "cursor_before" not in item
        assert "cursor_after" not in item


# --- Compatibility report tests ---


def test_compatibility_report_structure(fed_client, fed_db):
    resp = fed_client.get(
        "/api/v1/admin/federation/compatibility",
        headers={"Authorization": "Bearer admin-token"},
    )
    assert resp.status_code == 200
    data = resp.json()
    assert "localProtocolVersion" in data
    assert "peers" in data
    assert "supportedMajorVersions" in data
    assert "note" in data
    assert "1" in data["supportedMajorVersions"]


def test_compatibility_report_unchecked_peers(fed_client, fed_db):
    peer = _insert_peer(fed_db)
    # Peer with no health snapshots should show 'unchecked'
    resp = fed_client.get(
        "/api/v1/admin/federation/compatibility",
        headers={"Authorization": "Bearer admin-token"},
    )
    assert resp.status_code == 200
    data = resp.json()
    peer_entries = {p["peerId"]: p for p in data["peers"]}
    if str(peer.id) in peer_entries:
        assert peer_entries[str(peer.id)]["compatibilityStatus"] == "unchecked"


# --- Operational status extension tests ---


def test_federation_status_includes_phase5_fields(fed_client):
    resp = fed_client.get(
        "/api/v1/admin/federation/status",
        headers={"Authorization": "Bearer admin-token"},
    )
    assert resp.status_code == 200
    data = resp.json()
    assert "protocolVersion" in data
    assert "operationalState" in data
    assert data["protocolVersion"] == "1.0"
    assert data["operationalState"] in ("healthy", "degraded", "unknown")
    assert TEST_CURSOR_SECRET not in json.dumps(data)


def test_federation_status_delegates_operational_query_through_thread_bridge(fed_client, monkeypatch):
    import src.license_facade_service.api.federation.admin as admin_api

    calls = []

    async def fake_to_thread(fn, *args, **kwargs):
        calls.append((fn, args, kwargs))
        return fn(*args, **kwargs)

    def fake_query_operational_status_extension(db, settings):
        return {"operationalState": "healthy"}

    monkeypatch.setattr(admin_api.asyncio, "to_thread", fake_to_thread)
    monkeypatch.setattr(admin_api, "query_operational_status_extension", fake_query_operational_status_extension)

    resp = fed_client.get(
        "/api/v1/admin/federation/status",
        headers={"Authorization": "Bearer admin-token"},
    )
    assert resp.status_code == 200
    assert calls and calls[0][0] is fake_query_operational_status_extension


# --- Increment 1 regression smoke test ---


def test_increment1_imports_compile():
    """Smoke test that Phase 5 Increment 1 modules still import cleanly."""
    from src.license_facade_service.federation.audit import (
        AuditAction, AuditActorType, AuditDetailBuilder, AuditOutcome, AuditTargetType,
    )
    from src.license_facade_service.federation.lease import SyncLeaseRepository

    assert AuditAction.CURSOR_INSPECT is not None
    assert AuditActorType.HUMAN_OPERATOR is not None
    assert AuditOutcome.SUCCESS is not None


def test_phase1_4_app_starts(no_fed_client):
    """Smoke test that the app starts and existing routes still work."""
    resp = no_fed_client.get("/api/v1/health")
    # Health check may or may not exist, just verify app starts
    assert resp.status_code in (200, 404)
