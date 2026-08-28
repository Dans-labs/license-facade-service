from __future__ import annotations

import os
import socket
import subprocess
import threading
import time
import uuid
import asyncio
from contextlib import contextmanager
from datetime import datetime, timedelta, timezone
from pathlib import Path
from types import SimpleNamespace

import pytest
from sqlalchemy import select, text

from src.license_facade_service.federation.audit import CircuitFailureReason
from src.license_facade_service.federation.circuit import PeerCircuitService
from src.license_facade_service.federation.inbound_models import RemoteChangesResponse, RemoteDiscoveryResponse, RemoteJwksResponse
from src.license_facade_service.federation.lease import LeaseConflictError, SyncLeaseRepository
from src.license_facade_service.federation.models import JwkKey
from src.license_facade_service.federation.outbound import FederationError

REPO_ROOT = Path(__file__).resolve().parents[2]
TEST_CURSOR_SECRET = "c" * 64


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
        pytest.skip("docker not available for Phase 5 increment 3 DB tests")
    port = _free_port()
    container_name = f"lfs-p5inc3-{port}"
    subprocess.run(
        ["docker", "run", "--rm", "-d", "--name", container_name, "-e", "POSTGRES_PASSWORD=test", "-e", "POSTGRES_DB=lfs_test", "-p", f"{port}:5432", "postgres:16-alpine"],
        check=True,
        stdout=subprocess.DEVNULL,
    )
    url = f"postgresql+psycopg://postgres:test@127.0.0.1:{port}/lfs_test"
    try:
        import psycopg

        deadline = time.time() + 30
        while time.time() < deadline:
            try:
                with psycopg.connect(url.replace("+psycopg", "")):
                    break
            except Exception:
                time.sleep(0.3)
        else:
            pytest.fail("Postgres did not start in 30s")
        env = {**os.environ, "ALEMBIC_DATABASE_URL": url, "FEDERATION_DATABASE_URL": url}
        subprocess.run(["uv", "run", "alembic", "upgrade", "head"], cwd=str(REPO_ROOT), env=env, check=True, stdout=subprocess.DEVNULL)
        yield url
    finally:
        subprocess.run(["docker", "stop", container_name], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)


@pytest.fixture
def fed_client(postgres_url, monkeypatch, tmp_path):
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    from cryptography.hazmat.primitives.serialization import Encoding, NoEncryption, PrivateFormat
    from fastapi.testclient import TestClient
    from src.license_facade_service.api.v1 import licenses as licenses_api
    from src.license_facade_service.main import create_app

    key = Ed25519PrivateKey.generate()
    pem = key.private_bytes(encoding=Encoding.PEM, format=PrivateFormat.PKCS8, encryption_algorithm=NoEncryption())
    key_path = tmp_path / "k.pem"
    key_path.write_bytes(pem)

    monkeypatch.setenv("LFS_ADMIN_TOKEN", "admin-token")
    monkeypatch.setenv("LFS_CURATOR_TOKEN", "curator-token")
    monkeypatch.setenv("FEDERATION_ENABLED", "true")
    monkeypatch.setenv("FEDERATION_INBOUND_ENABLED", "true")
    monkeypatch.setenv("FEDERATION_DATABASE_URL", postgres_url)
    monkeypatch.setenv("FEDERATION_NODE_ID", "cccccccc-cccc-4ccc-8ccc-cccccccccccc")
    monkeypatch.setenv("FEDERATION_PUBLIC_BASE_URL", "https://node-test.example.org")
    monkeypatch.setenv("FEDERATION_NODE_NAME", "Test Node")
    monkeypatch.setenv("FEDERATION_OPERATOR", "Test Operator")
    monkeypatch.setenv("FEDERATION_SIGNING_KEY_PATH", str(key_path))
    monkeypatch.setenv("FEDERATION_ACTIVE_KID", "test-k1")
    monkeypatch.setenv("FEDERATION_ADMIN_CURSOR_SECRET", TEST_CURSOR_SECRET)
    monkeypatch.setenv("FEDERATION_ALLOW_HTTP_FOR_DEMO", "true")
    monkeypatch.setenv("FEDERATION_SYNC_ALLOWED_PORTS", "443,12104")
    monkeypatch.setenv("BASE_DIR", str(REPO_ROOT))
    monkeypatch.setenv("URL_BASE", "https://example.test/api/v1/licenses")
    monkeypatch.setenv("FUSEKI_ENABLE", "false")
    old_auth = licenses_api._auth_service
    licenses_api._auth_service = None
    with TestClient(create_app()) as client:
        yield client
    licenses_api._auth_service = old_auth


def _insert_peer(db, *, node_id: str | None = None):
    from src.license_facade_service.db.models.federation import FederationPeerCursor, FederationPeerSigningKey, FederationTrustedPeer

    now = datetime.now(timezone.utc)
    peer_id = uuid.uuid4()
    node_id = node_id or str(uuid.uuid4())
    x = "AQ" * 16 + "AQ=="  # not used for cryptographic checks in probe test due mocked fetch
    with db.transaction() as s:
        peer = FederationTrustedPeer(
            id=peer_id,
            peer_node_id=node_id,
            base_url="https://peer.example.org",
            jwks_url="https://peer.example.org/.well-known/jwks.json",
            peer_name="Peer",
            trust_status="trusted",
            sync_enabled=True,
            created_at=now,
            updated_at=now,
            expected_key_kid="peer-k1",
            expected_key_fingerprint="f" * 64,
        )
        s.add(peer)
        s.flush()
        s.add(FederationPeerCursor(id=uuid.uuid4(), peer_id=peer_id, cursor="v1.start", last_remote_position=3, synced_at=now, updated_at=now))
        s.add(
            FederationPeerSigningKey(
                id=uuid.uuid4(),
                peer_id=peer_id,
                kid="peer-k1",
                alg="EdDSA",
                kty="OKP",
                crv="Ed25519",
                x="AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
                key_fingerprint="f" * 64,
                key_status="active",
                first_seen_at=now,
                last_seen_at=now,
                created_at=now,
                updated_at=now,
            )
        )
    return peer_id, node_id


@pytest.mark.anyio
async def test_lease_renewal_success_and_stale_rejected(postgres_url):
    from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine

    from src.license_facade_service.db.models.federation import FederationTrustedPeer

    engine = create_async_engine(postgres_url, echo=False)
    try:
        sf = async_sessionmaker(engine, expire_on_commit=False)
        repo = SyncLeaseRepository()
        peer_id = uuid.uuid4()
        owner = uuid.uuid4()
        async with sf() as s:
            now = datetime.now(timezone.utc)
            s.add(FederationTrustedPeer(id=peer_id, peer_node_id=str(uuid.uuid4()), base_url="https://p.example", jwks_url="https://p.example/jwks", peer_name="P", trust_status="trusted", sync_enabled=True, created_at=now, updated_at=now))
            await s.commit()
        async with sf() as s:
            lease = await repo.claim(s, peer_id=peer_id, owner_instance_id=owner, trigger_type="manual", duration_seconds=30)
            await s.commit()
        assert lease is not None
        async with sf() as s:
            expires = await repo.renew(s, peer_id=peer_id, owner_instance_id=owner, fencing_token=lease.fencing_token, duration_seconds=30)
            await s.commit()
        assert expires > lease.expires_at
        async with sf() as s:
            await repo.release(s, peer_id=peer_id, owner_instance_id=owner, fencing_token=lease.fencing_token)
            await s.commit()
        async with sf() as s:
            with pytest.raises(LeaseConflictError):
                await repo.renew(s, peer_id=peer_id, owner_instance_id=owner, fencing_token=lease.fencing_token, duration_seconds=30)
        async with sf() as s:
            lease2 = await repo.claim(s, peer_id=peer_id, owner_instance_id=owner, trigger_type="manual", duration_seconds=30)
            await s.commit()
        assert lease2 is not None
        async with sf() as s:
            with pytest.raises(LeaseConflictError):
                await repo.renew(
                    s,
                    peer_id=peer_id,
                    owner_instance_id=uuid.uuid4(),
                    fencing_token=lease2.fencing_token,
                    duration_seconds=30,
                )
        async with sf() as s:
            with pytest.raises(LeaseConflictError):
                await repo.renew(
                    s,
                    peer_id=peer_id,
                    owner_instance_id=owner,
                    fencing_token=lease2.fencing_token + 1,
                    duration_seconds=30,
                )
    finally:
        await engine.dispose()


@pytest.mark.anyio
async def test_lease_simultaneous_claim_conflict(postgres_url):
    from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine
    from src.license_facade_service.db.models.federation import FederationTrustedPeer

    engine = create_async_engine(postgres_url, echo=False)
    try:
        sf = async_sessionmaker(engine, expire_on_commit=False)
        repo = SyncLeaseRepository()
        peer_id = uuid.uuid4()
        now = datetime.now(timezone.utc)
        async with sf() as s:
            s.add(
                FederationTrustedPeer(
                    id=peer_id,
                    peer_node_id=str(uuid.uuid4()),
                    base_url="https://p.example",
                    jwks_url="https://p.example/jwks",
                    peer_name="P",
                    trust_status="trusted",
                    sync_enabled=True,
                    created_at=now,
                    updated_at=now,
                )
            )
            await s.commit()

        owner_a = uuid.uuid4()
        owner_b = uuid.uuid4()

        async def _claim(owner_id: uuid.UUID, trigger_type: str):
            async with sf() as s:
                lease = await repo.claim(
                    s,
                    peer_id=peer_id,
                    owner_instance_id=owner_id,
                    trigger_type=trigger_type,
                    duration_seconds=30,
                )
                await s.commit()
                return lease

        lease_manual, lease_scheduled = await asyncio.gather(
            _claim(owner_a, "manual"),
            _claim(owner_b, "scheduled"),
        )
        winners = [l for l in [lease_manual, lease_scheduled] if l is not None]
        losers = [l for l in [lease_manual, lease_scheduled] if l is None]
        assert len(winners) == 1
        assert len(losers) == 1
    finally:
        await engine.dispose()


def test_circuit_transient_and_permanent_transitions():
    settings = SimpleNamespace(
        circuit_half_open_probe_limit=2,
        circuit_open_threshold=2,
        circuit_base_open_seconds=10,
        circuit_max_open_seconds=100,
    )
    now = datetime(2026, 1, 1, tzinfo=timezone.utc)
    svc = PeerCircuitService(settings, now_provider=lambda: now, jitter_provider=lambda: 1.0)
    peer = SimpleNamespace(
        circuit_state="closed",
        circuit_requires_admin_reset=False,
        circuit_failure_count=0,
        circuit_opened_at=None,
        circuit_next_attempt_at=None,
        circuit_half_open_probe_count=0,
        circuit_last_failure_reason=None,
        updated_at=now,
    )
    state = svc.mark_failure(peer, classification=svc.classify_failure(FederationError("remote-unreachable", "x"), phase="discovery"))
    assert state.value == "closed"
    state = svc.mark_failure(peer, classification=svc.classify_failure(FederationError("remote-unreachable", "x"), phase="discovery"))
    assert state.value == "open"
    assert peer.circuit_next_attempt_at == now + timedelta(seconds=20)
    gate = svc.evaluate_gate(peer)
    assert not gate.allowed
    peer.circuit_next_attempt_at = now - timedelta(seconds=1)
    gate2 = svc.evaluate_gate(peer)
    assert gate2.allowed and gate2.state.value == "half_open"
    svc.mark_success(peer)
    assert peer.circuit_state == "closed"
    svc.mark_failure(peer, classification=svc.classify_failure(FederationError("invalid-signature", "x"), phase="records"))
    assert peer.circuit_requires_admin_reset is True
    assert peer.circuit_last_failure_reason == CircuitFailureReason.SIGNATURE_INVALID.value


def test_circuit_structured_http_classification_is_code_based():
    settings = SimpleNamespace(
        circuit_half_open_probe_limit=2,
        circuit_open_threshold=2,
        circuit_base_open_seconds=10,
        circuit_max_open_seconds=100,
    )
    svc = PeerCircuitService(settings)
    for code in ("remote-server-error",):
        classified = svc.classify_failure(FederationError(code, "custom detail"), phase="changes")
        assert classified.kind == "transient"
        assert classified.reason == CircuitFailureReason.REMOTE_5XX
    for code in ("remote-http-error",):
        classified = svc.classify_failure(FederationError(code, "HTTP 404"), phase="changes")
        assert classified.kind != "transient"
        assert classified.reason != CircuitFailureReason.REMOTE_5XX
    changed_detail = svc.classify_failure(FederationError("remote-server-error", "anything else"), phase="changes")
    assert changed_detail.kind == "transient"
    assert changed_detail.reason == CircuitFailureReason.REMOTE_5XX


def test_circuit_classifies_trust_and_integrity_codes_as_permanent():
    settings = SimpleNamespace(
        circuit_half_open_probe_limit=2,
        circuit_open_threshold=2,
        circuit_base_open_seconds=10,
        circuit_max_open_seconds=100,
    )
    svc = PeerCircuitService(settings)
    signature_codes = (
        "invalid-signature-alg",
        "invalid-signature",
        "event-id-collision",
        "event-position-collision",
        "event-replay-mismatch",
    )
    for code in signature_codes:
        classified = svc.classify_failure(FederationError(code, "ignored"), phase="records")
        assert classified.kind == "permanent"
        assert classified.reason == CircuitFailureReason.SIGNATURE_INVALID
    identity_codes = ("unknown-signing-key", "peer-key-missing")
    for code in identity_codes:
        classified = svc.classify_failure(FederationError(code, "ignored"), phase="records")
        assert classified.kind == "permanent"
        assert classified.reason == CircuitFailureReason.IDENTITY_MISMATCH


def test_source_regression_no_advisory_lock_across_http():
    source = (REPO_ROOT / "src/license_facade_service/federation/inbound.py").read_text(encoding="utf-8")
    assert "pg_try_advisory_lock" not in source
    assert "pg_advisory_unlock" not in source
    assert "_claim_lease(" in source


def test_source_regression_no_asyncio_run_or_run_async_in_federation_services():
    federation_source = (REPO_ROOT / "src/license_facade_service/federation/inbound.py").read_text(encoding="utf-8")
    worker_source = (REPO_ROOT / "src/license_facade_service/worker.py").read_text(encoding="utf-8")
    assert "asyncio.run(" not in federation_source
    assert "_run_async(" not in federation_source
    assert "asyncio.run(" not in worker_source


def test_source_regression_fenced_page_commit_uses_lease_repository():
    source = (REPO_ROOT / "src/license_facade_service/federation/inbound.py").read_text(encoding="utf-8")
    assert "lease_repo.verify_still_owned_sync(" in source
    assert "lease_repo.renew_sync(" in source
    assert "lease_row.expires_at" not in source


def test_source_regression_probe_compatibility_status_not_hardcoded_compatible():
    source = (REPO_ROOT / "src/license_facade_service/federation/inbound.py").read_text(encoding="utf-8")
    assert 'compatibility_status="compatible"' not in source
    assert 'compatibility_status="unchecked"' in source


def test_source_regression_no_async_bridge_module_or_usage():
    source = (REPO_ROOT / "src/license_facade_service").glob("**/*.py")
    matches: list[str] = []
    for file in source:
        content = file.read_text(encoding="utf-8")
        if "async_bridge" in content or "run_awaitable(" in content or "run_coroutine_threadsafe" in content:
            matches.append(str(file.relative_to(REPO_ROOT)))
    assert matches == []
    assert not (REPO_ROOT / "src/license_facade_service/federation/async_bridge.py").exists()


def test_source_regression_worker_has_no_async_engine_plumbing():
    source = (REPO_ROOT / "src/license_facade_service/worker.py").read_text(encoding="utf-8")
    assert "create_async_engine" not in source
    assert "async_sessionmaker" not in source
    assert "asyncio.run(" not in source


@pytest.mark.parametrize("status_code", [500, 502, 503])
def test_remote_client_returns_remote_server_error_for_5xx(monkeypatch, status_code: int):
    import httpx

    from src.license_facade_service.config.federation import FederationSettings
    from src.license_facade_service.federation.inbound import FederationRemoteClient, _HttpLimits

    monkeypatch.setenv("FEDERATION_ENABLED", "true")
    monkeypatch.setenv("FEDERATION_INBOUND_ENABLED", "true")
    monkeypatch.setenv("FEDERATION_SYNC_RETRY_ATTEMPTS", "1")
    monkeypatch.setenv("FEDERATION_SYNC_ALLOWED_PORTS", "443")
    settings = FederationSettings.from_env()

    def handler(_request: httpx.Request) -> httpx.Response:
        return httpx.Response(status_code=status_code, headers={"content-type": "application/json"}, text="{}")

    client = FederationRemoteClient(settings, http_client=httpx.Client(transport=httpx.MockTransport(handler)))
    monkeypatch.setattr(client.url_policy, "validate_and_resolve", lambda *args, **kwargs: None)
    with pytest.raises(FederationError) as excinfo:
        client.get_json(
            "https://peer.example.org/.well-known/lfs",
            limits=_HttpLimits(max_bytes=1024, expected_content_type="application/json"),
            allowed_hostnames=("peer.example.org",),
            allowed_cidrs=(),
        )
    assert excinfo.value.code == "remote-server-error"


@pytest.mark.parametrize("status_code", [400, 401, 403, 404])
def test_remote_client_keeps_remote_http_error_for_4xx(monkeypatch, status_code: int):
    import httpx

    from src.license_facade_service.config.federation import FederationSettings
    from src.license_facade_service.federation.inbound import FederationRemoteClient, _HttpLimits

    monkeypatch.setenv("FEDERATION_ENABLED", "true")
    monkeypatch.setenv("FEDERATION_INBOUND_ENABLED", "true")
    monkeypatch.setenv("FEDERATION_SYNC_RETRY_ATTEMPTS", "1")
    monkeypatch.setenv("FEDERATION_SYNC_ALLOWED_PORTS", "443")
    settings = FederationSettings.from_env()

    def handler(_request: httpx.Request) -> httpx.Response:
        return httpx.Response(status_code=status_code, headers={"content-type": "application/json"}, text="{}")

    client = FederationRemoteClient(settings, http_client=httpx.Client(transport=httpx.MockTransport(handler)))
    monkeypatch.setattr(client.url_policy, "validate_and_resolve", lambda *args, **kwargs: None)
    with pytest.raises(FederationError) as excinfo:
        client.get_json(
            "https://peer.example.org/.well-known/lfs",
            limits=_HttpLimits(max_bytes=1024, expected_content_type="application/json"),
            allowed_hostnames=("peer.example.org",),
            allowed_cidrs=(),
        )
    assert excinfo.value.code == "remote-http-error"


@pytest.mark.anyio
async def test_audit_writers_produce_equivalent_sanitized_rows(postgres_url):
    from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine

    from src.license_facade_service.db.models.federation import FederationOperationalAudit
    from src.license_facade_service.db.session import Database
    from src.license_facade_service.federation.audit import (
        AuditAction,
        AuditActorType,
        AuditOutcome,
        AuditTargetType,
        write_audit_row,
        write_audit_row_sync,
    )

    details = {
        "authorization": "Bearer abc123secret",
        "db": "postgresql://alice:hunter2@db.example/internal",
        "password": "password=letmein",
        "pem": "-----BEGIN PRIVATE KEY-----\nabc\n-----END PRIVATE KEY-----",
    }
    async_engine = create_async_engine(postgres_url, echo=False)
    try:
        async_factory = async_sessionmaker(async_engine, expire_on_commit=False)
        async with async_factory() as session:
            async_row = await write_audit_row(
                session,
                actor_type=AuditActorType.HUMAN_OPERATOR,
                action=AuditAction.PEER_PROBE,
                target_type=AuditTargetType.PEER,
                target_id=str(uuid.uuid4()),
                outcome=AuditOutcome.SUCCESS,
                actor_id="admin",
                details=details,
            )
            await session.commit()

        db = Database.from_url(postgres_url)
        with db.transaction() as session:
            sync_row = write_audit_row_sync(
                session,
                actor_type=AuditActorType.HUMAN_OPERATOR,
                action=AuditAction.PEER_PROBE,
                target_type=AuditTargetType.PEER,
                target_id=str(uuid.uuid4()),
                outcome=AuditOutcome.SUCCESS,
                actor_id="admin",
                details=details,
            )
        with db.transaction() as session:
            left = session.execute(select(FederationOperationalAudit).where(FederationOperationalAudit.id == async_row.id)).scalar_one()
            right = session.execute(select(FederationOperationalAudit).where(FederationOperationalAudit.id == sync_row.id)).scalar_one()
            assert left.action == right.action
            assert left.actor_type == right.actor_type
            assert left.outcome == right.outcome
            assert left.redacted_details == right.redacted_details
    finally:
        await async_engine.dispose()


def test_new_admin_endpoints_authorization_matrix(fed_client):
    paths = [
        ("/api/v1/admin/federation/peers/00000000-0000-4000-8000-000000000001/suspend", {"reason": "ops"}),
        ("/api/v1/admin/federation/peers/00000000-0000-4000-8000-000000000001/resume", {}),
        ("/api/v1/admin/federation/peers/00000000-0000-4000-8000-000000000001/circuit/reset", {"reason": "ops"}),
        ("/api/v1/admin/federation/peers/00000000-0000-4000-8000-000000000001/probe", None),
    ]
    for path, body in paths:
        if body is None:
            r = fed_client.post(path)
            r_bad = fed_client.post(path, headers={"Authorization": "Bearer invalid-token"})
            r_cur = fed_client.post(path, headers={"Authorization": "Bearer curator-token"})
            r_ok = fed_client.post(path, headers={"Authorization": "Bearer admin-token"})
        else:
            r = fed_client.post(path, json=body)
            r_bad = fed_client.post(path, json=body, headers={"Authorization": "Bearer invalid-token"})
            r_cur = fed_client.post(path, json=body, headers={"Authorization": "Bearer curator-token"})
            r_ok = fed_client.post(path, json=body, headers={"Authorization": "Bearer admin-token"})
        assert r.status_code == 401
        assert r_bad.status_code == 401
        assert r_cur.status_code == 403
        assert r_ok.status_code in {200, 404, 409}


def test_suspend_preserves_sync_enabled_flag(fed_client, postgres_url):
    from src.license_facade_service.db.models.federation import FederationTrustedPeer
    from src.license_facade_service.db.session import Database

    db = Database.from_url(postgres_url)
    peer_id, _ = _insert_peer(db)
    with db.transaction() as s:
        peer = s.execute(select(FederationTrustedPeer).where(FederationTrustedPeer.id == peer_id)).scalar_one()
        peer.sync_enabled = False

    response = fed_client.post(
        f"/api/v1/admin/federation/peers/{peer_id}/suspend",
        json={"reason": "maintenance"},
        headers={"Authorization": "Bearer admin-token"},
    )
    assert response.status_code == 200
    with db.transaction() as s:
        peer = s.execute(select(FederationTrustedPeer).where(FederationTrustedPeer.id == peer_id)).scalar_one()
        assert peer.sync_enabled is False
        assert peer.suspension_reason == "maintenance"


def test_resume_preserves_sync_enabled_flag(fed_client, postgres_url):
    from src.license_facade_service.db.models.federation import FederationTrustedPeer
    from src.license_facade_service.db.session import Database

    db = Database.from_url(postgres_url)
    peer_id, _ = _insert_peer(db)
    with db.transaction() as s:
        peer = s.execute(select(FederationTrustedPeer).where(FederationTrustedPeer.id == peer_id)).scalar_one()
        peer.sync_enabled = False
        peer.suspension_reason = "ops"
        peer.suspended_until = datetime.now(timezone.utc) + timedelta(minutes=5)

    response = fed_client.post(
        f"/api/v1/admin/federation/peers/{peer_id}/resume",
        json={"reason": "done"},
        headers={"Authorization": "Bearer admin-token"},
    )
    assert response.status_code == 200
    with db.transaction() as s:
        peer = s.execute(select(FederationTrustedPeer).where(FederationTrustedPeer.id == peer_id)).scalar_one()
        assert peer.sync_enabled is False
        assert peer.suspension_reason is None
        assert peer.suspended_until is None


def test_concurrent_patch_and_suspend_preserve_sync_enabled(postgres_url, monkeypatch):
    from src.license_facade_service.config.federation import FederationSettings
    from src.license_facade_service.db.models.federation import FederationTrustedPeer
    from src.license_facade_service.db.session import Database
    from src.license_facade_service.federation.inbound import FederationPeerService

    monkeypatch.setenv("FEDERATION_ENABLED", "true")
    monkeypatch.setenv("FEDERATION_DATABASE_URL", postgres_url)
    monkeypatch.setenv("FEDERATION_SYNC_ALLOWED_PORTS", "443")
    settings = FederationSettings.from_env()
    db = Database.from_url(postgres_url)
    service = FederationPeerService(db, settings)
    peer_id, _ = _insert_peer(db)
    suspend_started = threading.Event()
    release_suspend = threading.Event()
    suspend_done = threading.Event()
    update_done = threading.Event()
    errors: list[Exception] = []

    original_write_audit = service._write_operational_audit

    def blocking_write_audit(**kwargs):
        if kwargs["action"].value == "peer.suspend":
            suspend_started.set()
            release_suspend.wait(timeout=3)
        return original_write_audit(**kwargs)

    monkeypatch.setattr(service, "_write_operational_audit", blocking_write_audit)

    def run_suspend():
        try:
            service.suspend_peer(peer_id=peer_id, reason="maintenance", suspended_until=None, actor="admin")
        except Exception as exc:
            errors.append(exc)
        finally:
            suspend_done.set()

    def run_update():
        try:
            with db.transaction() as s:
                peer = s.execute(select(FederationTrustedPeer).where(FederationTrustedPeer.id == peer_id)).scalar_one()
                peer.sync_enabled = False
                peer.peer_name = "Patched"
        except Exception as exc:
            errors.append(exc)
        finally:
            update_done.set()

    suspend_thread = threading.Thread(target=run_suspend)
    suspend_thread.start()
    assert suspend_started.wait(timeout=2)
    update_thread = threading.Thread(target=run_update)
    update_thread.start()
    time.sleep(0.25)
    assert not update_done.is_set()
    release_suspend.set()
    suspend_thread.join(timeout=3)
    update_thread.join(timeout=3)
    assert suspend_done.is_set()
    assert update_done.is_set()
    assert errors == []
    with db.transaction() as s:
        peer = s.execute(select(FederationTrustedPeer).where(FederationTrustedPeer.id == peer_id)).scalar_one()
        assert peer.sync_enabled is False
        assert peer.suspension_reason == "maintenance"


def test_concurrent_patch_and_resume_do_not_enable_disabled_peer(postgres_url, monkeypatch):
    from src.license_facade_service.config.federation import FederationSettings
    from src.license_facade_service.db.models.federation import FederationTrustedPeer
    from src.license_facade_service.db.session import Database
    from src.license_facade_service.federation.inbound import FederationPeerService

    monkeypatch.setenv("FEDERATION_ENABLED", "true")
    monkeypatch.setenv("FEDERATION_DATABASE_URL", postgres_url)
    monkeypatch.setenv("FEDERATION_SYNC_ALLOWED_PORTS", "443")
    settings = FederationSettings.from_env()
    db = Database.from_url(postgres_url)
    service = FederationPeerService(db, settings)
    peer_id, _ = _insert_peer(db)
    with db.transaction() as s:
        peer = s.execute(select(FederationTrustedPeer).where(FederationTrustedPeer.id == peer_id)).scalar_one()
        peer.sync_enabled = False
        peer.suspension_reason = "ops"
        peer.suspended_until = datetime.now(timezone.utc) + timedelta(minutes=5)
    resume_started = threading.Event()
    release_resume = threading.Event()
    resume_done = threading.Event()
    patch_done = threading.Event()
    errors: list[Exception] = []

    original_write_audit = service._write_operational_audit

    def blocking_write_audit(**kwargs):
        if kwargs["action"].value == "peer.resume":
            resume_started.set()
            release_resume.wait(timeout=3)
        return original_write_audit(**kwargs)

    monkeypatch.setattr(service, "_write_operational_audit", blocking_write_audit)

    def run_resume():
        try:
            service.resume_peer(peer_id=peer_id, reason="done", actor="admin")
        except Exception as exc:
            errors.append(exc)
        finally:
            resume_done.set()

    def run_patch():
        try:
            with db.transaction() as s:
                peer = s.execute(select(FederationTrustedPeer).where(FederationTrustedPeer.id == peer_id)).scalar_one()
                peer.peer_name = "Patched"
        except Exception as exc:
            errors.append(exc)
        finally:
            patch_done.set()

    resume_thread = threading.Thread(target=run_resume)
    resume_thread.start()
    assert resume_started.wait(timeout=2)
    patch_thread = threading.Thread(target=run_patch)
    patch_thread.start()
    time.sleep(0.25)
    assert not patch_done.is_set()
    release_resume.set()
    resume_thread.join(timeout=3)
    patch_thread.join(timeout=3)
    assert resume_done.is_set()
    assert patch_done.is_set()
    assert errors == []
    with db.transaction() as s:
        peer = s.execute(select(FederationTrustedPeer).where(FederationTrustedPeer.id == peer_id)).scalar_one()
        assert peer.sync_enabled is False
        assert peer.suspension_reason is None
        assert peer.suspended_until is None


def test_suspend_and_resume_execute_for_update_select(postgres_url, monkeypatch):
    from sqlalchemy import event

    from src.license_facade_service.config.federation import FederationSettings
    from src.license_facade_service.db.session import Database
    from src.license_facade_service.federation.inbound import FederationPeerService

    monkeypatch.setenv("FEDERATION_ENABLED", "true")
    monkeypatch.setenv("FEDERATION_DATABASE_URL", postgres_url)
    monkeypatch.setenv("FEDERATION_SYNC_ALLOWED_PORTS", "443")
    settings = FederationSettings.from_env()
    db = Database.from_url(postgres_url)
    service = FederationPeerService(db, settings)
    peer_id, _ = _insert_peer(db)

    statements: list[str] = []

    def _capture(_conn, _cursor, statement, _parameters, _context, _executemany):
        statements.append(statement.lower())

    event.listen(db.engine, "before_cursor_execute", _capture)
    try:
        service.suspend_peer(peer_id=peer_id, reason="maintenance", suspended_until=None, actor="admin")
        service.resume_peer(peer_id=peer_id, reason="done", actor="admin")
    finally:
        event.remove(db.engine, "before_cursor_execute", _capture)

    peer_selects = [s for s in statements if "from federation_trusted_peers" in s and "where federation_trusted_peers.id" in s]
    locked_selects = [s for s in peer_selects if "for update" in s]
    assert len(locked_selects) >= 2


def test_suspend_rejects_past_timestamp(fed_client):
    peer_id = "00000000-0000-4000-8000-000000000001"
    response = fed_client.post(
        f"/api/v1/admin/federation/peers/{peer_id}/suspend",
        json={"reason": "ops", "suspendedUntil": "2020-01-01T00:00:00+00:00"},
        headers={"Authorization": "Bearer admin-token"},
    )
    assert response.status_code in {400, 422}


def test_probe_keeps_cursor_and_records_unchanged(fed_client, postgres_url, monkeypatch):
    from src.license_facade_service.db.models.federation import (
        FederationOperationalAudit,
        FederationPeerCursor,
        FederationPeerHealthSnapshot,
        FederationRecord,
    )
    from src.license_facade_service.db.session import Database
    from src.license_facade_service.federation import inbound as inbound_mod

    db = Database.from_url(postgres_url)
    peer_id, node_id = _insert_peer(db)

    monkeypatch.setattr(
        inbound_mod.FederationPeerService,
        "_fetch_discovery",
        lambda self, *args, **kwargs: RemoteDiscoveryResponse(
            protocolVersion="1.0",
            nodeId=node_id,
            nodeName="Peer",
            operator="Peer Ops",
            publicBaseUrl="https://peer.example.org",
            currentSigningKid="peer-k1",
            jwksUrl="https://peer.example.org/.well-known/jwks.json",
            catalogUrl="https://peer.example.org/api/v1/federation/catalog",
            changesUrl="https://peer.example.org/api/v1/federation/changes",
            recordUrlTemplate="https://peer.example.org/api/v1/federation/records/{encoded_id}",
            conformance=[],
        ),
    )
    monkeypatch.setattr(
        inbound_mod.FederationPeerService,
        "_fetch_jwks",
        lambda self, *args, **kwargs: RemoteJwksResponse(
            keys=[JwkKey(kty="OKP", use="sig", crv="Ed25519", alg="EdDSA", kid="peer-k1", x="AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA")]
        ),
    )

    with db.transaction() as s:
        before_cursor = s.execute(
            select(FederationPeerCursor.cursor).where(FederationPeerCursor.peer_id == peer_id)
        ).scalar_one()
        before_records = s.execute(select(FederationRecord.id)).all()

    resp = fed_client.post(f"/api/v1/admin/federation/peers/{peer_id}/probe", headers={"Authorization": "Bearer admin-token"})
    assert resp.status_code == 200

    with db.transaction() as s:
        after_cursor = s.execute(
            select(FederationPeerCursor.cursor).where(FederationPeerCursor.peer_id == peer_id)
        ).scalar_one()
        after_records = s.execute(select(FederationRecord.id)).all()
        health_count = s.execute(select(FederationPeerHealthSnapshot.id).where(FederationPeerHealthSnapshot.peer_id == peer_id)).all()
        audits = s.execute(select(FederationOperationalAudit).where(FederationOperationalAudit.peer_id == peer_id)).scalars().all()
    assert before_cursor == after_cursor
    assert before_records == after_records
    assert health_count
    assert any(a.action == "peer.probe" for a in audits)


def test_probe_does_not_mutate_trusted_keys(fed_client, postgres_url, monkeypatch):
    from src.license_facade_service.db.models.federation import FederationPeerSigningKey
    from src.license_facade_service.db.session import Database
    from src.license_facade_service.federation import inbound as inbound_mod

    db = Database.from_url(postgres_url)
    peer_id, node_id = _insert_peer(db)
    with db.transaction() as s:
        before = s.execute(
            select(FederationPeerSigningKey.kid, FederationPeerSigningKey.key_status).where(
                FederationPeerSigningKey.peer_id == peer_id
            )
        ).all()

    monkeypatch.setattr(
        inbound_mod.FederationPeerService,
        "_fetch_discovery",
        lambda self, *args, **kwargs: RemoteDiscoveryResponse(
            protocolVersion="1.0",
            nodeId=node_id,
            nodeName="Peer",
            operator="Peer Ops",
            publicBaseUrl="https://peer.example.org",
            currentSigningKid="peer-k1",
            jwksUrl="https://peer.example.org/.well-known/jwks.json",
            catalogUrl="https://peer.example.org/api/v1/federation/catalog",
            changesUrl="https://peer.example.org/api/v1/federation/changes",
            recordUrlTemplate="https://peer.example.org/api/v1/federation/records/{encoded_id}",
            conformance=[],
        ),
    )
    monkeypatch.setattr(
        inbound_mod.FederationPeerService,
        "_fetch_jwks",
        lambda self, *args, **kwargs: RemoteJwksResponse(
            keys=[JwkKey(kty="OKP", use="sig", crv="Ed25519", alg="EdDSA", kid="peer-k1", x="AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA")]
        ),
    )
    response = fed_client.post(f"/api/v1/admin/federation/peers/{peer_id}/probe", headers={"Authorization": "Bearer admin-token"})
    assert response.status_code == 200
    with db.transaction() as s:
        after = s.execute(
            select(FederationPeerSigningKey.kid, FederationPeerSigningKey.key_status).where(
                FederationPeerSigningKey.peer_id == peer_id
            )
        ).all()
    assert before == after


def test_probe_unknown_or_missing_key_does_not_mutate_trusted_keys(fed_client, postgres_url, monkeypatch):
    from src.license_facade_service.db.models.federation import FederationPeerSigningKey
    from src.license_facade_service.db.session import Database
    from src.license_facade_service.federation import inbound as inbound_mod

    db = Database.from_url(postgres_url)
    peer_id, node_id = _insert_peer(db)
    with db.transaction() as s:
        before = s.execute(
            select(FederationPeerSigningKey.kid, FederationPeerSigningKey.key_status).where(
                FederationPeerSigningKey.peer_id == peer_id
            )
        ).all()

    monkeypatch.setattr(
        inbound_mod.FederationPeerService,
        "_fetch_discovery",
        lambda self, *args, **kwargs: RemoteDiscoveryResponse(
            protocolVersion="1.0",
            nodeId=node_id,
            nodeName="Peer",
            operator="Peer Ops",
            publicBaseUrl="https://peer.example.org",
            currentSigningKid="peer-k1",
            jwksUrl="https://peer.example.org/.well-known/jwks.json",
            catalogUrl="https://peer.example.org/api/v1/federation/catalog",
            changesUrl="https://peer.example.org/api/v1/federation/changes",
            recordUrlTemplate="https://peer.example.org/api/v1/federation/records/{encoded_id}",
            conformance=[],
        ),
    )
    monkeypatch.setattr(
        inbound_mod.FederationPeerService,
        "_fetch_jwks",
        lambda self, *args, **kwargs: RemoteJwksResponse(
            keys=[JwkKey(kty="OKP", use="sig", crv="Ed25519", alg="EdDSA", kid="other-kid", x="AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA")]
        ),
    )
    response = fed_client.post(f"/api/v1/admin/federation/peers/{peer_id}/probe", headers={"Authorization": "Bearer admin-token"})
    assert response.status_code >= 400
    with db.transaction() as s:
        after = s.execute(
            select(FederationPeerSigningKey.kid, FederationPeerSigningKey.key_status).where(
                FederationPeerSigningKey.peer_id == peer_id
            )
        ).all()
    assert before == after


def test_probe_lease_contention_returns_409(fed_client, postgres_url):
    from src.license_facade_service.config.federation import FederationSettings
    from src.license_facade_service.db.session import Database
    from src.license_facade_service.federation.lease import SyncLeaseRepository

    db = Database.from_url(postgres_url)
    peer_id, _ = _insert_peer(db)
    settings = FederationSettings.from_env()
    repo = SyncLeaseRepository()
    owner = uuid.uuid4()
    with db.transaction() as s:
        lease = repo.claim_sync(
            s,
            peer_id=peer_id,
            owner_instance_id=owner,
            trigger_type="probe",
            duration_seconds=settings.sync_lease_duration_seconds,
        )
        assert lease is not None

    response = fed_client.post(f"/api/v1/admin/federation/peers/{peer_id}/probe", headers={"Authorization": "Bearer admin-token"})
    assert response.status_code == 409
    body = response.json()
    assert body["status"] == 409
    assert "already" in body["detail"].lower()


def test_probe_failure_persists_health_timing(fed_client, postgres_url, monkeypatch):
    from src.license_facade_service.db.models.federation import FederationPeerHealthSnapshot
    from src.license_facade_service.db.session import Database
    from src.license_facade_service.federation import inbound as inbound_mod

    db = Database.from_url(postgres_url)
    peer_id, _ = _insert_peer(db)

    def _fail(*_args, **_kwargs):
        raise FederationError("remote-unreachable", "network down")

    monkeypatch.setattr(inbound_mod.FederationPeerService, "_fetch_discovery", _fail)
    response = fed_client.post(f"/api/v1/admin/federation/peers/{peer_id}/probe", headers={"Authorization": "Bearer admin-token"})
    assert response.status_code >= 400
    with db.transaction() as s:
        snap = (
            s.execute(
                select(FederationPeerHealthSnapshot)
                .where(FederationPeerHealthSnapshot.peer_id == peer_id)
                .order_by(FederationPeerHealthSnapshot.created_at.desc())
            )
            .scalars()
            .first()
        )
        assert snap is not None
        assert snap.round_trip_ms is None or snap.round_trip_ms >= 0
        assert snap.health_status in {"degraded", "unreachable"}
        assert snap.compatibility_status in {"unknown", "unchecked"}


def test_probe_health_error_detail_uses_controlled_summary(fed_client, postgres_url, monkeypatch):
    from src.license_facade_service.db.models.federation import FederationPeerHealthSnapshot
    from src.license_facade_service.db.session import Database
    from src.license_facade_service.federation import inbound as inbound_mod

    db = Database.from_url(postgres_url)
    peer_a, _ = _insert_peer(db)
    peer_b, _ = _insert_peer(db)
    details = iter(
        [
            "Bearer token-a postgresql://alice:pw@db/internal password=alpha -----BEGIN PRIVATE KEY-----\nabc\n-----END PRIVATE KEY-----",
            "Bearer token-b postgresql://bob:pw@db/internal password=beta -----BEGIN PRIVATE KEY-----\ndef\n-----END PRIVATE KEY-----",
        ]
    )

    monkeypatch.setattr(
        inbound_mod.FederationPeerService,
        "_fetch_discovery",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(FederationError("custom-probe-error", next(details))),
    )
    response_a = fed_client.post(f"/api/v1/admin/federation/peers/{peer_a}/probe", headers={"Authorization": "Bearer admin-token"})
    response_b = fed_client.post(f"/api/v1/admin/federation/peers/{peer_b}/probe", headers={"Authorization": "Bearer admin-token"})
    assert response_a.status_code >= 400
    assert response_b.status_code >= 400
    with db.transaction() as s:
        snap_a = (
            s.execute(
                select(FederationPeerHealthSnapshot)
                .where(FederationPeerHealthSnapshot.peer_id == peer_a)
                .order_by(FederationPeerHealthSnapshot.created_at.desc())
            )
            .scalars()
            .first()
        )
        snap_b = (
            s.execute(
                select(FederationPeerHealthSnapshot)
                .where(FederationPeerHealthSnapshot.peer_id == peer_b)
                .order_by(FederationPeerHealthSnapshot.created_at.desc())
            )
            .scalars()
            .first()
        )
        assert snap_a is not None
        assert snap_b is not None
        assert snap_a.error_detail == "Federation operation failed."
        assert snap_b.error_detail == "Federation operation failed."


def test_probe_audit_failure_rolls_back_circuit_and_health(fed_client, postgres_url, monkeypatch):
    from src.license_facade_service.config.federation import FederationSettings
    from src.license_facade_service.db.models.federation import FederationOperationalAudit, FederationPeerHealthSnapshot, FederationTrustedPeer
    from src.license_facade_service.db.session import Database
    from src.license_facade_service.federation import inbound as inbound_mod
    from src.license_facade_service.federation.inbound import FederationPeerService

    db = Database.from_url(postgres_url)
    settings = FederationSettings.from_env()
    peer_id, node_id = _insert_peer(db)
    with db.transaction() as s:
        peer = s.execute(select(FederationTrustedPeer).where(FederationTrustedPeer.id == peer_id)).scalar_one()
        peer.circuit_state = "half_open"
        peer.circuit_half_open_probe_count = 0

    monkeypatch.setattr(
        inbound_mod.FederationPeerService,
        "_fetch_discovery",
        lambda self, *_args, **_kwargs: RemoteDiscoveryResponse(
            protocolVersion="1.0",
            nodeId=node_id,
            nodeName="Peer",
            operator="Peer Ops",
            publicBaseUrl="https://peer.example.org",
            currentSigningKid="peer-k1",
            jwksUrl="https://peer.example.org/.well-known/jwks.json",
            catalogUrl="https://peer.example.org/api/v1/federation/catalog",
            changesUrl="https://peer.example.org/api/v1/federation/changes",
            recordUrlTemplate="https://peer.example.org/api/v1/federation/records/{encoded_id}",
            conformance=[],
        ),
    )
    monkeypatch.setattr(
        inbound_mod.FederationPeerService,
        "_fetch_jwks",
        lambda self, *_args, **_kwargs: RemoteJwksResponse(
            keys=[JwkKey(kty="OKP", use="sig", crv="Ed25519", alg="EdDSA", kid="peer-k1", x="AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA")]
        ),
    )

    original = inbound_mod.write_audit_row_sync

    def fail_probe_audit(session, **kwargs):
        if kwargs["action"].value == "peer.probe":
            raise RuntimeError("forced-audit-failure")
        return original(session, **kwargs)

    monkeypatch.setattr(inbound_mod, "write_audit_row_sync", fail_probe_audit)
    service = FederationPeerService(db, settings)
    with pytest.raises(RuntimeError):
        service.probe_peer(peer_id=peer_id, actor="admin")

    with db.transaction() as s:
        peer = s.execute(select(FederationTrustedPeer).where(FederationTrustedPeer.id == peer_id)).scalar_one()
        snaps = s.execute(select(FederationPeerHealthSnapshot.id).where(FederationPeerHealthSnapshot.peer_id == peer_id)).all()
        audits = s.execute(select(FederationOperationalAudit.id).where(FederationOperationalAudit.peer_id == peer_id)).all()
        assert peer.circuit_state != "closed"
        assert snaps == []
        assert audits == []


def test_probe_http_happens_outside_db_transaction(postgres_url, monkeypatch, tmp_path):
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    from cryptography.hazmat.primitives.serialization import Encoding, NoEncryption, PrivateFormat
    from src.license_facade_service.config.federation import FederationSettings
    from src.license_facade_service.db.session import Database
    from src.license_facade_service.federation.inbound import FederationPeerService

    key = Ed25519PrivateKey.generate()
    pem = key.private_bytes(encoding=Encoding.PEM, format=PrivateFormat.PKCS8, encryption_algorithm=NoEncryption())
    key_path = tmp_path / "k.pem"
    key_path.write_bytes(pem)

    monkeypatch.setenv("FEDERATION_ENABLED", "true")
    monkeypatch.setenv("FEDERATION_INBOUND_ENABLED", "true")
    monkeypatch.setenv("FEDERATION_DATABASE_URL", postgres_url)
    monkeypatch.setenv("FEDERATION_NODE_ID", "cccccccc-cccc-4ccc-8ccc-cccccccccccc")
    monkeypatch.setenv("FEDERATION_PUBLIC_BASE_URL", "https://node-test.example.org")
    monkeypatch.setenv("FEDERATION_NODE_NAME", "Test Node")
    monkeypatch.setenv("FEDERATION_OPERATOR", "Test Operator")
    monkeypatch.setenv("FEDERATION_SIGNING_KEY_PATH", str(key_path))
    monkeypatch.setenv("FEDERATION_ACTIVE_KID", "test-k1")
    monkeypatch.setenv("FEDERATION_ADMIN_CURSOR_SECRET", TEST_CURSOR_SECRET)

    db = Database.from_url(postgres_url)
    settings = FederationSettings.from_env()
    peer_id, node_id = _insert_peer(db)
    service = FederationPeerService(db, settings)

    original_transaction = db.transaction
    active_transactions = {"count": 0}

    @contextmanager
    def tracked_transaction():
        with original_transaction() as session:
            active_transactions["count"] += 1
            try:
                yield session
            finally:
                active_transactions["count"] -= 1

    monkeypatch.setattr(db, "transaction", tracked_transaction)

    def fake_get_json(url: str, **_kwargs):
        assert active_transactions["count"] == 0
        if url.endswith("/.well-known/lfs"):
            return {
                "protocolVersion": "1.0",
                "nodeId": node_id,
                "nodeName": "Peer",
                "operator": "Peer Ops",
                "publicBaseUrl": "https://peer.example.org",
                "currentSigningKid": "peer-k1",
                "jwksUrl": "https://peer.example.org/.well-known/jwks.json",
                "catalogUrl": "https://peer.example.org/api/v1/federation/catalog",
                "changesUrl": "https://peer.example.org/api/v1/federation/changes",
                "recordUrlTemplate": "https://peer.example.org/api/v1/federation/records/{encoded_id}",
                "conformance": [],
            }
        if url.endswith("/.well-known/jwks.json"):
            return {
                "keys": [
                    {
                        "kty": "OKP",
                        "use": "sig",
                        "crv": "Ed25519",
                        "alg": "EdDSA",
                        "kid": "peer-k1",
                        "x": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
                    }
                ]
            }
        raise AssertionError(f"Unexpected URL: {url}")

    monkeypatch.setattr(service.remote_client, "get_json", fake_get_json)
    result = service.probe_peer(peer_id=peer_id, actor="admin")
    assert result["reachableDiscovery"] is True
    assert result["reachableJwks"] is True
    assert result["circuitState"] in {"closed", "half_open", "open"}


def test_circuit_reset_with_active_lease_returns_409(fed_client, postgres_url):
    from src.license_facade_service.config.federation import FederationSettings
    from src.license_facade_service.db.session import Database
    from src.license_facade_service.federation.lease import SyncLeaseRepository

    db = Database.from_url(postgres_url)
    settings = FederationSettings.from_env()
    peer_id, _ = _insert_peer(db)
    with db.transaction() as s:
        lease = SyncLeaseRepository().claim_sync(
            s,
            peer_id=peer_id,
            owner_instance_id=uuid.uuid4(),
            trigger_type="scheduled",
            duration_seconds=settings.sync_lease_duration_seconds,
        )
        assert lease is not None

    response = fed_client.post(
        f"/api/v1/admin/federation/peers/{peer_id}/circuit/reset",
        json={"reason": "operator reset"},
        headers={"Authorization": "Bearer admin-token"},
    )
    assert response.status_code == 409


def test_reset_holds_lease_blocks_sync_claims(fed_client, postgres_url, monkeypatch):
    from src.license_facade_service.config.federation import FederationSettings
    from src.license_facade_service.db.session import Database
    from src.license_facade_service.federation.inbound import FederationPeerService
    from src.license_facade_service.federation.lease import SyncLeaseRepository

    db = Database.from_url(postgres_url)
    settings = FederationSettings.from_env()
    peer_id, _ = _insert_peer(db)
    service = FederationPeerService(db, settings)
    claims_seen: list[bool] = []

    original_reset = service.circuit.reset

    def wrapped_reset(peer):
        with db.transaction() as s:
            manual_claim = SyncLeaseRepository().claim_sync(
                s,
                peer_id=peer_id,
                owner_instance_id=uuid.uuid4(),
                trigger_type="manual",
                duration_seconds=settings.sync_lease_duration_seconds,
            )
            scheduled_claim = SyncLeaseRepository().claim_sync(
                s,
                peer_id=peer_id,
                owner_instance_id=uuid.uuid4(),
                trigger_type="scheduled",
                duration_seconds=settings.sync_lease_duration_seconds,
            )
            claims_seen.append(manual_claim is None and scheduled_claim is None)
        original_reset(peer)

    monkeypatch.setattr(service.circuit, "reset", wrapped_reset)
    service.reset_peer_circuit(peer_id=peer_id, reason="ops", expected_state=None, actor="admin")
    assert claims_seen == [True]


def test_circuit_reset_releases_lease_after_success(fed_client, postgres_url):
    from src.license_facade_service.config.federation import FederationSettings
    from src.license_facade_service.db.models.federation import FederationSyncLease
    from src.license_facade_service.db.session import Database
    from src.license_facade_service.federation.inbound import FederationPeerService

    db = Database.from_url(postgres_url)
    settings = FederationSettings.from_env()
    peer_id, _ = _insert_peer(db)
    service = FederationPeerService(db, settings)
    service.reset_peer_circuit(peer_id=peer_id, reason="ops", expected_state=None, actor="admin")
    with db.transaction() as s:
        lease = s.execute(select(FederationSyncLease).where(FederationSyncLease.peer_id == peer_id)).scalar_one_or_none()
        assert lease is None


def test_circuit_reset_releases_lease_after_failure(fed_client, postgres_url):
    from src.license_facade_service.config.federation import FederationSettings
    from src.license_facade_service.db.models.federation import FederationSyncLease, FederationTrustedPeer
    from src.license_facade_service.db.session import Database
    from src.license_facade_service.federation.inbound import FederationPeerService

    db = Database.from_url(postgres_url)
    settings = FederationSettings.from_env()
    peer_id, _ = _insert_peer(db)
    service = FederationPeerService(db, settings)
    with db.transaction() as s:
        peer = s.execute(select(FederationTrustedPeer).where(FederationTrustedPeer.id == peer_id)).scalar_one()
        peer.circuit_state = "open"
    with pytest.raises(FederationError):
        service.reset_peer_circuit(peer_id=peer_id, reason="ops", expected_state="closed", actor="admin")
    with db.transaction() as s:
        lease = s.execute(select(FederationSyncLease).where(FederationSyncLease.peer_id == peer_id)).scalar_one_or_none()
        assert lease is None


def test_circuit_reset_releases_lease_after_audit_failure(fed_client, postgres_url, monkeypatch):
    from src.license_facade_service.config.federation import FederationSettings
    from src.license_facade_service.db.models.federation import FederationSyncLease
    from src.license_facade_service.db.session import Database
    from src.license_facade_service.federation import inbound as inbound_mod
    from src.license_facade_service.federation.inbound import FederationPeerService

    db = Database.from_url(postgres_url)
    settings = FederationSettings.from_env()
    peer_id, _ = _insert_peer(db)
    service = FederationPeerService(db, settings)

    original = inbound_mod.write_audit_row_sync

    def fail_reset_audit(session, **kwargs):
        if kwargs["action"].value == "peer.circuit_reset":
            raise RuntimeError("forced-reset-audit-failure")
        return original(session, **kwargs)

    monkeypatch.setattr(inbound_mod, "write_audit_row_sync", fail_reset_audit)
    with pytest.raises(RuntimeError):
        service.reset_peer_circuit(peer_id=peer_id, reason="ops", expected_state=None, actor="admin")
    with db.transaction() as s:
        lease = s.execute(select(FederationSyncLease).where(FederationSyncLease.peer_id == peer_id)).scalar_one_or_none()
        assert lease is None


def test_release_cannot_delete_successor_lease(postgres_url):
    from src.license_facade_service.db.models.federation import FederationSyncLease, FederationTrustedPeer
    from src.license_facade_service.db.session import Database

    db = Database.from_url(postgres_url)
    repo = SyncLeaseRepository()
    peer_id = uuid.uuid4()
    with db.transaction() as s:
        now = datetime.now(timezone.utc)
        s.add(
            FederationTrustedPeer(
                id=peer_id,
                peer_node_id=str(uuid.uuid4()),
                base_url="https://peer.example.org",
                jwks_url="https://peer.example.org/.well-known/jwks.json",
                peer_name="Peer",
                trust_status="trusted",
                sync_enabled=True,
                created_at=now,
                updated_at=now,
            )
        )
    owner_a = uuid.uuid4()
    owner_b = uuid.uuid4()
    with db.transaction() as s:
        lease_a = repo.claim_sync(
            s,
            peer_id=peer_id,
            owner_instance_id=owner_a,
            trigger_type="scheduled",
            duration_seconds=30,
        )
        assert lease_a is not None
    with db.transaction() as s:
        s.execute(
            select(FederationSyncLease).where(FederationSyncLease.peer_id == peer_id).with_for_update()
        ).scalar_one()
        s.execute(
            text(
                "UPDATE federation_sync_leases "
                "SET acquired_at = now() - interval '2 second', expires_at = now() - interval '1 second' "
                "WHERE peer_id = :peer_id"
            ),
            {"peer_id": peer_id},
        )
    with db.transaction() as s:
        lease_b = repo.claim_sync(
            s,
            peer_id=peer_id,
            owner_instance_id=owner_b,
            trigger_type="manual",
            duration_seconds=30,
        )
        assert lease_b is not None
    with db.transaction() as s:
        deleted = repo.release_sync(
            s,
            peer_id=peer_id,
            owner_instance_id=owner_a,
            fencing_token=lease_a.fencing_token,
        )
        assert deleted is False
    with db.transaction() as s:
        current = s.execute(select(FederationSyncLease).where(FederationSyncLease.peer_id == peer_id)).scalar_one()
        assert current.owner_instance_id == owner_b
        assert current.fencing_token == lease_b.fencing_token


def test_manual_sync_lease_contention_returns_409(fed_client, postgres_url):
    from src.license_facade_service.config.federation import FederationSettings
    from src.license_facade_service.db.session import Database
    from src.license_facade_service.federation.lease import SyncLeaseRepository

    db = Database.from_url(postgres_url)
    settings = FederationSettings.from_env()
    peer_id, _ = _insert_peer(db)
    with db.transaction() as s:
        lease = SyncLeaseRepository().claim_sync(
            s,
            peer_id=peer_id,
            owner_instance_id=uuid.uuid4(),
            trigger_type="scheduled",
            duration_seconds=settings.sync_lease_duration_seconds,
        )
        assert lease is not None

    response = fed_client.post(
        f"/api/v1/admin/federation/peers/{peer_id}/sync",
        json={},
        headers={"Authorization": "Bearer admin-token"},
    )
    assert response.status_code == 409


def test_stale_fencing_rejection_leaves_cursor_unchanged(fed_client, postgres_url, monkeypatch):
    from src.license_facade_service.config.federation import FederationSettings
    from src.license_facade_service.db.models.federation import FederationPeerCursor
    from src.license_facade_service.db.session import Database
    from src.license_facade_service.federation.inbound import FederationInboundSyncService

    db = Database.from_url(postgres_url)
    settings = FederationSettings.from_env()
    peer_id, _ = _insert_peer(db)
    service = FederationInboundSyncService(db, settings)
    lease = service._claim_lease(peer_id=peer_id, trigger_type="manual")
    assert lease is not None
    page = RemoteChangesResponse(events=[], limit=1, hasMore=False, nextCursor=None, resumeCursor="cursor.next", snapshotWatermark=5)
    monkeypatch.setattr(service.lease_repo, "verify_still_owned_sync", lambda *args, **kwargs: False)
    with pytest.raises(FederationError) as excinfo:
        service._process_page(
            peer_id=peer_id,
            page=page,
            allowed_hostnames=(),
            allowed_cidrs=(),
            lease=lease,
        )
    assert excinfo.value.code == "sync-lease-stale"
    with db.transaction() as s:
        cursor = s.execute(select(FederationPeerCursor.cursor).where(FederationPeerCursor.peer_id == peer_id)).scalar_one()
        assert cursor == "v1.start"
    service._release_lease(lease)


def test_sync_cancellation_before_page_commit_keeps_cursor(fed_client, postgres_url, monkeypatch):
    from src.license_facade_service.config.federation import FederationSettings
    from src.license_facade_service.db.models.federation import FederationPeerCursor, FederationSyncAttempt, FederationTrustedPeer
    from src.license_facade_service.db.session import Database
    from src.license_facade_service.federation.inbound import FederationInboundSyncService

    db = Database.from_url(postgres_url)
    settings = FederationSettings.from_env()
    peer_id, _ = _insert_peer(db)
    service = FederationInboundSyncService(db, settings)
    monkeypatch.setattr(service, "_refresh_peer_verification_state", lambda **_kwargs: None)
    monkeypatch.setattr(service, "_fetch_changes_page", lambda **_kwargs: (_ for _ in ()).throw(KeyboardInterrupt()))
    with pytest.raises(KeyboardInterrupt):
        service.sync_peer(peer_id=peer_id, trigger_type="manual", max_seconds=10)
    with db.transaction() as s:
        cursor = s.execute(select(FederationPeerCursor.cursor).where(FederationPeerCursor.peer_id == peer_id)).scalar_one()
        attempt = (
            s.execute(
                select(FederationSyncAttempt)
                .where(FederationSyncAttempt.peer_id == peer_id)
                .order_by(FederationSyncAttempt.created_at.desc())
            )
            .scalars()
            .first()
        )
        peer = s.execute(select(FederationTrustedPeer).where(FederationTrustedPeer.id == peer_id)).scalar_one()
        assert cursor == "v1.start"
        assert attempt is not None
        assert attempt.error_code == "sync-cancelled"
        assert peer.circuit_failure_count == 0


def test_sync_cancellation_after_first_committed_page_preserves_cursor(fed_client, postgres_url, monkeypatch):
    from src.license_facade_service.config.federation import FederationSettings
    from src.license_facade_service.db.models.federation import FederationPeerCursor
    from src.license_facade_service.db.session import Database
    from src.license_facade_service.federation.inbound import FederationInboundSyncService

    db = Database.from_url(postgres_url)
    settings = FederationSettings.from_env()
    peer_id, _ = _insert_peer(db)
    service = FederationInboundSyncService(db, settings)
    monkeypatch.setattr(service, "_refresh_peer_verification_state", lambda **_kwargs: None)
    first = RemoteChangesResponse(events=[], limit=1, hasMore=True, nextCursor="req.next", resumeCursor="resume.1", snapshotWatermark=1)
    calls = {"count": 0}

    def fake_fetch(**_kwargs):
        calls["count"] += 1
        if calls["count"] == 1:
            return first
        raise KeyboardInterrupt()

    monkeypatch.setattr(service, "_fetch_changes_page", fake_fetch)

    def fake_process_page(*, peer_id, page, allowed_hostnames, allowed_cidrs, lease):
        with db.transaction() as s:
            cursor = s.execute(select(FederationPeerCursor).where(FederationPeerCursor.peer_id == peer_id)).scalar_one()
            cursor.cursor = page.resumeCursor
        return (0, 0, None)

    monkeypatch.setattr(service, "_process_page", fake_process_page)
    with pytest.raises(KeyboardInterrupt):
        service.sync_peer(peer_id=peer_id, trigger_type="manual", max_seconds=10)
    with db.transaction() as s:
        cursor = s.execute(select(FederationPeerCursor.cursor).where(FederationPeerCursor.peer_id == peer_id)).scalar_one()
        assert cursor == "resume.1"


def test_multi_page_partial_failure_preserves_prior_cursor(fed_client, postgres_url, monkeypatch):
    from src.license_facade_service.config.federation import FederationSettings
    from src.license_facade_service.db.models.federation import FederationPeerCursor
    from src.license_facade_service.db.session import Database
    from src.license_facade_service.federation.inbound import FederationInboundSyncService

    db = Database.from_url(postgres_url)
    settings = FederationSettings.from_env()
    peer_id, _ = _insert_peer(db)
    service = FederationInboundSyncService(db, settings)
    monkeypatch.setattr(service, "_refresh_peer_verification_state", lambda **_kwargs: None)
    pages = [
        RemoteChangesResponse(events=[], limit=1, hasMore=True, nextCursor="request.2", resumeCursor="resume.1", snapshotWatermark=1),
        RemoteChangesResponse(events=[], limit=1, hasMore=False, nextCursor=None, resumeCursor="resume.2", snapshotWatermark=2),
    ]
    index = {"i": 0}

    def fake_fetch(**_kwargs):
        page = pages[index["i"]]
        index["i"] += 1
        return page

    monkeypatch.setattr(service, "_fetch_changes_page", fake_fetch)

    def fake_process_page(*, peer_id, page, allowed_hostnames, allowed_cidrs, lease):
        if page.resumeCursor == "resume.2":
            raise FederationError("remote-unreachable", "network down")
        with db.transaction() as s:
            cursor = s.execute(select(FederationPeerCursor).where(FederationPeerCursor.peer_id == peer_id)).scalar_one()
            cursor.cursor = page.resumeCursor
        return (0, 0, None)

    monkeypatch.setattr(service, "_process_page", fake_process_page)
    result = service.sync_peer(peer_id=peer_id, trigger_type="scheduled", max_seconds=10)
    assert result.status == "partial"
    with db.transaction() as s:
        cursor = s.execute(select(FederationPeerCursor.cursor).where(FederationPeerCursor.peer_id == peer_id)).scalar_one()
        assert cursor == "resume.1"


def test_suspend_resume_and_circuit_reset_emit_operational_audit(fed_client, postgres_url):
    from src.license_facade_service.db.models.federation import FederationOperationalAudit
    from src.license_facade_service.db.session import Database

    db = Database.from_url(postgres_url)
    peer_id, _ = _insert_peer(db)

    suspend = fed_client.post(
        f"/api/v1/admin/federation/peers/{peer_id}/suspend",
        json={"reason": "maintenance"},
        headers={"Authorization": "Bearer admin-token"},
    )
    resume = fed_client.post(
        f"/api/v1/admin/federation/peers/{peer_id}/resume",
        json={"reason": "done"},
        headers={"Authorization": "Bearer admin-token"},
    )
    reset = fed_client.post(
        f"/api/v1/admin/federation/peers/{peer_id}/circuit/reset",
        json={"reason": "ops"},
        headers={"Authorization": "Bearer admin-token"},
    )
    assert suspend.status_code == 200
    assert resume.status_code == 200
    assert reset.status_code == 200

    with db.transaction() as s:
        actions = s.execute(
            select(FederationOperationalAudit.action).where(FederationOperationalAudit.peer_id == peer_id)
        ).scalars().all()
    assert "peer.suspend" in actions
    assert "peer.resume" in actions
    assert "peer.circuit_reset" in actions


def test_resume_does_not_reset_permanent_circuit(postgres_url, monkeypatch):
    from src.license_facade_service.config.federation import FederationSettings
    from src.license_facade_service.db.models.federation import FederationTrustedPeer
    from src.license_facade_service.db.session import Database
    from src.license_facade_service.federation.inbound import FederationPeerService

    monkeypatch.setenv("FEDERATION_ENABLED", "true")
    monkeypatch.setenv("FEDERATION_DATABASE_URL", postgres_url)
    monkeypatch.setenv("FEDERATION_NODE_ID", "cccccccc-cccc-4ccc-8ccc-cccccccccccc")
    monkeypatch.setenv("FEDERATION_PUBLIC_BASE_URL", "https://node-test.example.org")
    monkeypatch.setenv("FEDERATION_NODE_NAME", "Test Node")
    monkeypatch.setenv("FEDERATION_OPERATOR", "Test Operator")
    monkeypatch.setenv("FEDERATION_SIGNING_KEY_PATH", str(REPO_ROOT / "tests" / "fixtures" / "missing-key.pem"))
    monkeypatch.setenv("FEDERATION_ACTIVE_KID", "test-k1")
    monkeypatch.setenv("FEDERATION_ADMIN_CURSOR_SECRET", TEST_CURSOR_SECRET)
    settings = FederationSettings.from_env()
    db = Database.from_url(postgres_url)
    peer_service = FederationPeerService(db, settings)
    peer_id, _node_id = _insert_peer(db)

    with db.transaction() as s:
        peer = s.execute(select(FederationTrustedPeer).where(FederationTrustedPeer.id == peer_id)).scalar_one()
        peer.circuit_state = "open"
        peer.circuit_requires_admin_reset = True
        peer.circuit_failure_count = 4
        peer.circuit_last_failure_reason = CircuitFailureReason.SIGNATURE_INVALID.value
        peer.suspension_reason = "ops"
        peer.suspended_until = datetime.now(timezone.utc) + timedelta(minutes=5)
        peer.sync_enabled = False

    peer_service.resume_peer(peer_id=peer_id, reason="resume", actor="admin")
    with db.transaction() as s:
        peer = s.execute(select(FederationTrustedPeer).where(FederationTrustedPeer.id == peer_id)).scalar_one()
        assert peer.suspension_reason is None
        assert peer.suspended_until is None
        assert peer.circuit_state == "open"
        assert peer.circuit_requires_admin_reset is True


def test_openapi_contains_increment3_routes_and_unique_operation_ids(fed_client):
    spec = fed_client.get("/openapi.json").json()
    paths = spec["paths"]
    assert "/api/v1/admin/federation/peers/{peer_id}/suspend" in paths
    assert "/api/v1/admin/federation/peers/{peer_id}/resume" in paths
    assert "/api/v1/admin/federation/peers/{peer_id}/circuit/reset" in paths
    assert "/api/v1/admin/federation/peers/{peer_id}/probe" in paths

    op_ids: list[str] = []
    for path_item in paths.values():
        for method_item in path_item.values():
            operation_id = method_item.get("operationId")
            if operation_id:
                op_ids.append(operation_id)
    assert len(op_ids) == len(set(op_ids))
