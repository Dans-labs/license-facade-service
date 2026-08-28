from __future__ import annotations

import base64
import json
import os
import socket
import subprocess
import threading
import time
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Callable
from urllib.parse import parse_qs, urlsplit

import psycopg
import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from fastapi.testclient import TestClient
from sqlalchemy import func, select

from src.license_facade_service.api.v1 import licenses as licenses_api
from src.license_facade_service.config.federation import FederationSettings
from src.license_facade_service.db.models.federation import (
    FederationInboundEvent,
    FederationOperationalAudit,
    FederationPeerCursor,
    FederationPeerHealthSnapshot,
    FederationPeerSigningKey,
    FederationRecord,
    FederationSyncAttempt,
    FederationTrustedPeer,
)
from src.license_facade_service.db.session import Database
from src.license_facade_service.federation.audit import AuditAction, CircuitFailureReason, CircuitState
from src.license_facade_service.federation.canonical_json import canonicalize_to_bytes
from src.license_facade_service.federation.circuit import PeerCircuitService
from src.license_facade_service.federation.digests import canonical_json_sha256_hex, sha256_hex
from src.license_facade_service.federation.inbound import (
    FederationInboundSyncService,
    FederationPeerService,
    FederationRemoteClient,
    PeerKeyVerificationPurpose,
    ed25519_key_fingerprint_hex,
)
from src.license_facade_service.federation.inbound_models import PeerCreateRequest, PeerKeyStatusMutationRequest, PeerVerificationKeyRequest
from src.license_facade_service.federation.outbound import FederationError
from src.license_facade_service.federation.runtime import FederationRuntime
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


class _MutatingRemoteScenario(_RemoteScenario):
    def __init__(
        self,
        settings: FederationSettings,
        responses: dict[str, dict],
        *,
        mutate_on_path: str,
        mutate_once: Callable[[], None],
    ):
        super().__init__(settings, responses, offline=False)
        self._mutate_on_path = mutate_on_path
        self._mutate_once = mutate_once
        self._mutated = False

    def get_json(self, url: str, *, limits, allowed_hostnames=(), allowed_cidrs=()):
        parsed = urlsplit(url)
        if not self._mutated and parsed.path == self._mutate_on_path:
            self._mutate_once()
            self._mutated = True
        return super().get_json(url, limits=limits, allowed_hostnames=allowed_hostnames, allowed_cidrs=allowed_cidrs)


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


@pytest.fixture(scope="module")
def postgres_url():
    if not _docker_available():
        pytest.skip("docker not available for PostgreSQL increment4 tests")
    port = _free_port()
    name = f"lfs-pg-phase5inc4-{uuid.uuid4().hex[:8]}"
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
    monkeypatch.setenv("FEDERATION_ADMIN_CURSOR_SECRET", "c" * 64)
    monkeypatch.setenv("LFS_ADMIN_TOKEN", "admin-token")
    monkeypatch.setenv("LFS_CURATOR_TOKEN", "curator-token")

    service = LicenseService(base_dir=tmp_path, spdx_client=_StaticSpdx())
    licenses_api._license_service = service
    licenses_api._auth_service = AuthService()

    settings = FederationSettings.from_env()
    db = Database.from_url(postgres_url)
    runtime = FederationRuntime(settings)
    assert runtime.initialize().ready
    return {"db": db, "settings": settings}


def _create_services(fed_env, responses: dict[str, dict]):
    remote = _RemoteScenario(fed_env["settings"], responses=responses)
    peers = FederationPeerService(fed_env["db"], fed_env["settings"], remote_client=remote)
    sync = FederationInboundSyncService(fed_env["db"], fed_env["settings"], remote_client=remote)
    return peers, sync


def _create_peer(peers: FederationPeerService, key: Ed25519PrivateKey, *, kid: str = "a-k1", x: str | None = None):
    x_value = x or _b64url(key.public_key().public_bytes(encoding=serialization.Encoding.Raw, format=serialization.PublicFormat.Raw))
    return peers.create_peer(
        payload=PeerCreateRequest(
            peerNodeId=NODE_A_ID,
            baseUrl="http://node-a:12104",
            peerName="Node A",
            operatorName="Operator A",
            verificationKey=PeerVerificationKeyRequest(kid=kid, fingerprint=ed25519_key_fingerprint_hex(x_value)),
            allowPrivateNetwork=True,
        ),
        actor="admin",
    )


def test_inspect_diff_categories_and_no_mutation(fed_env):
    key_a = Ed25519PrivateKey.generate()
    x_a = _b64url(key_a.public_key().public_bytes(encoding=serialization.Encoding.Raw, format=serialization.PublicFormat.Raw))
    key_new = Ed25519PrivateKey.generate()
    x_new = _b64url(key_new.public_key().public_bytes(encoding=serialization.Encoding.Raw, format=serialization.PublicFormat.Raw))
    key_changed = Ed25519PrivateKey.generate()
    x_changed = _b64url(key_changed.public_key().public_bytes(encoding=serialization.Encoding.Raw, format=serialization.PublicFormat.Raw))
    discovery, jwks = _discovery_and_jwks(kid="a-k1", x=x_a)
    peers, _ = _create_services(fed_env, {"/.well-known/lfs": discovery, "/.well-known/jwks.json": jwks})
    peer = _create_peer(peers, key_a, kid="a-k1", x=x_a)
    peers.remote_client.responses["/.well-known/jwks.json"] = {
        "keys": [
            {"kid": "a-k1", "alg": "EdDSA", "kty": "OKP", "crv": "Ed25519", "x": x_a},
            {"kid": "new-k2", "alg": "EdDSA", "kty": "OKP", "crv": "Ed25519", "x": x_new},
            {"kid": "change-k3", "alg": "EdDSA", "kty": "OKP", "crv": "Ed25519", "x": x_changed},
            {"kid": "bad-k", "alg": "RS256", "kty": "OKP", "crv": "Ed25519", "x": x_new},
        ]
    }
    db = fed_env["db"]
    with db.transaction() as s:
        existing = s.execute(
            select(FederationPeerSigningKey).where(
                FederationPeerSigningKey.peer_id == peer.id,
                FederationPeerSigningKey.kid == "change-k3",
            )
        ).scalar_one_or_none()
        now = datetime.now(timezone.utc)
        if existing is None:
            s.add(
                FederationPeerSigningKey(
                    id=uuid.uuid4(),
                    peer_id=peer.id,
                    kid="change-k3",
                    alg="EdDSA",
                    kty="OKP",
                    crv="Ed25519",
                    x=x_a,
                    key_fingerprint=ed25519_key_fingerprint_hex(x_a),
                    key_status="active",
                    first_seen_at=now,
                    last_seen_at=now,
                    valid_from=now - timedelta(days=10),
                    valid_until=now - timedelta(days=1),
                    created_at=now,
                    updated_at=now,
                )
            )
        s.add(
            FederationPeerSigningKey(
                id=uuid.uuid4(),
                peer_id=peer.id,
                kid="removed-k4",
                alg="EdDSA",
                kty="OKP",
                crv="Ed25519",
                x=x_a,
                key_fingerprint=ed25519_key_fingerprint_hex(x_a),
                key_status="retired",
                first_seen_at=now,
                last_seen_at=now,
                valid_from=now - timedelta(days=20),
                valid_until=now - timedelta(days=2),
                created_at=now,
                updated_at=now,
            )
        )
        s.add(
            FederationPeerSigningKey(
                id=uuid.uuid4(),
                peer_id=peer.id,
                kid="removed-k5",
                alg="EdDSA",
                kty="OKP",
                crv="Ed25519",
                x=x_a,
                key_fingerprint=ed25519_key_fingerprint_hex(x_a),
                key_status="active",
                first_seen_at=now,
                last_seen_at=now,
                valid_from=now - timedelta(days=5),
                valid_until=None,
                created_at=now,
                updated_at=now,
            )
        )
        cursor_before = s.execute(select(FederationPeerCursor).where(FederationPeerCursor.peer_id == peer.id)).scalar_one().cursor
        circuit_before = s.execute(select(FederationTrustedPeer).where(FederationTrustedPeer.id == peer.id)).scalar_one().circuit_state
    with db.transaction() as s:
        key_count_before = s.execute(
            select(func.count()).select_from(FederationPeerSigningKey).where(FederationPeerSigningKey.peer_id == peer.id)
        ).scalar_one()
    result = peers.inspect_peer_keys(peer_id=peer.id, reason="inspect", actor="admin")
    assert any(item.kid == "a-k1" for item in result.known)
    assert any(item.kid == "new-k2" for item in result.new)
    assert any(item.kid == "removed-k5" for item in result.removed)
    assert any(item.kid == "change-k3" for item in result.changed)
    assert any(item.reasonCode in {"unsupported-algorithm", "duplicate-kid", "invalid-public-key", "malformed-key"} for item in result.invalid)
    assert any(item.kid == "removed-k4" for item in result.expired)
    assert not any(item.kid == "change-k3" for item in result.expired)
    category_sets = {
        "known": {item.kid for item in result.known if item.kid},
        "new": {item.kid for item in result.new if item.kid},
        "removed": {item.kid for item in result.removed if item.kid},
        "changed": {item.kid for item in result.changed if item.kid},
        "invalid": {item.kid for item in result.invalid if item.kid},
        "expired": {item.kid for item in result.expired if item.kid},
    }
    all_items = list(category_sets.items())
    for i, (_, left) in enumerate(all_items):
        for _, right in all_items[i + 1 :]:
            assert left.isdisjoint(right)
    with db.transaction() as s:
        cursor_after = s.execute(select(FederationPeerCursor).where(FederationPeerCursor.peer_id == peer.id)).scalar_one().cursor
        circuit_after = s.execute(select(FederationTrustedPeer).where(FederationTrustedPeer.id == peer.id)).scalar_one().circuit_state
        key_count_after = s.execute(select(func.count()).select_from(FederationPeerSigningKey).where(FederationPeerSigningKey.peer_id == peer.id)).scalar_one()
    assert cursor_after == cursor_before
    assert circuit_after == circuit_before
    assert key_count_after == key_count_before


def test_inspect_lease_contention_returns_conflict(fed_env):
    key_a = Ed25519PrivateKey.generate()
    x_a = _b64url(key_a.public_key().public_bytes(encoding=serialization.Encoding.Raw, format=serialization.PublicFormat.Raw))
    discovery, jwks = _discovery_and_jwks(kid="a-k1", x=x_a)
    peers, _ = _create_services(fed_env, {"/.well-known/lfs": discovery, "/.well-known/jwks.json": jwks})
    peer = _create_peer(peers, key_a, kid="a-k1", x=x_a)
    lease = peers._claim_lease(peer_id=peer.id, trigger_type="manual")
    assert lease is not None
    try:
        with pytest.raises(Exception) as exc:
            peers.inspect_peer_keys(peer_id=peer.id, reason=None, actor="admin")
        assert getattr(exc.value, "code", "") == "already-running"
    finally:
        peers._release_lease(lease)


def test_approve_success_and_idempotent(fed_env):
    key_a = Ed25519PrivateKey.generate()
    x_a = _b64url(key_a.public_key().public_bytes(encoding=serialization.Encoding.Raw, format=serialization.PublicFormat.Raw))
    discovery, jwks = _discovery_and_jwks(kid="a-k1", x=x_a)
    peers, _ = _create_services(fed_env, {"/.well-known/lfs": discovery, "/.well-known/jwks.json": jwks})
    peer = _create_peer(peers, key_a, kid="a-k1", x=x_a)

    key2 = Ed25519PrivateKey.generate()
    x2 = _b64url(key2.public_key().public_bytes(encoding=serialization.Encoding.Raw, format=serialization.PublicFormat.Raw))
    peers.remote_client.responses["/.well-known/jwks.json"] = {
        "keys": [
            {"kid": "a-k1", "alg": "EdDSA", "kty": "OKP", "crv": "Ed25519", "x": x_a},
            {"kid": "a-k2", "alg": "EdDSA", "kty": "OKP", "crv": "Ed25519", "x": x2},
        ]
    }
    expected = f"sha256:{ed25519_key_fingerprint_hex(x2)}"
    row = peers.approve_peer_key(peer_id=peer.id, kid="a-k2", expected_fingerprint=expected, reason="approve", actor="admin")
    assert row.kid == "a-k2"
    assert row.status == "active"
    row2 = peers.approve_peer_key(peer_id=peer.id, kid="a-k2", expected_fingerprint=expected, reason="approve-again", actor="admin")
    assert row2.kid == "a-k2"
    with fed_env["db"].transaction() as s:
        count = s.execute(
            select(func.count()).select_from(FederationPeerSigningKey).where(
                FederationPeerSigningKey.peer_id == peer.id,
                FederationPeerSigningKey.kid == "a-k2",
            )
        ).scalar_one()
    assert count == 1


def test_approve_wrong_fingerprint_and_duplicate_remote_kid_rejected(fed_env):
    key_a = Ed25519PrivateKey.generate()
    x_a = _b64url(key_a.public_key().public_bytes(encoding=serialization.Encoding.Raw, format=serialization.PublicFormat.Raw))
    key_b = Ed25519PrivateKey.generate()
    x_b = _b64url(key_b.public_key().public_bytes(encoding=serialization.Encoding.Raw, format=serialization.PublicFormat.Raw))
    discovery, jwks = _discovery_and_jwks(kid="a-k1", x=x_a)
    peers, _ = _create_services(fed_env, {"/.well-known/lfs": discovery, "/.well-known/jwks.json": jwks})
    peer = _create_peer(peers, key_a, kid="a-k1", x=x_a)

    with pytest.raises(Exception) as mismatch:
        peers.approve_peer_key(
            peer_id=peer.id,
            kid="a-k1",
            expected_fingerprint="sha256:" + ("0" * 64),
            reason="wrong",
            actor="admin",
        )
    assert getattr(mismatch.value, "code", "") == "peer-key-fingerprint-mismatch"

    peers.remote_client.responses["/.well-known/jwks.json"] = {
        "keys": [
            {"kid": "dup", "alg": "EdDSA", "kty": "OKP", "crv": "Ed25519", "x": x_a},
            {"kid": "dup", "alg": "EdDSA", "kty": "OKP", "crv": "Ed25519", "x": x_b},
        ]
    }
    with pytest.raises(Exception) as dup:
        peers.approve_peer_key(
            peer_id=peer.id,
            kid="dup",
            expected_fingerprint=f"sha256:{ed25519_key_fingerprint_hex(x_a)}",
            reason="dup",
            actor="admin",
        )
    assert getattr(dup.value, "code", "") == "peer-key-invalid-remote"


def test_approve_collision_opens_permanent_circuit(fed_env):
    key_a = Ed25519PrivateKey.generate()
    x_a = _b64url(key_a.public_key().public_bytes(encoding=serialization.Encoding.Raw, format=serialization.PublicFormat.Raw))
    key_b = Ed25519PrivateKey.generate()
    x_b = _b64url(key_b.public_key().public_bytes(encoding=serialization.Encoding.Raw, format=serialization.PublicFormat.Raw))
    discovery, jwks = _discovery_and_jwks(kid="a-k1", x=x_a)
    peers, _ = _create_services(fed_env, {"/.well-known/lfs": discovery, "/.well-known/jwks.json": jwks})
    peer = _create_peer(peers, key_a, kid="a-k1", x=x_a)
    peers.remote_client.responses["/.well-known/jwks.json"] = {"keys": [{"kid": "a-k1", "alg": "EdDSA", "kty": "OKP", "crv": "Ed25519", "x": x_b}]}
    with pytest.raises(Exception) as collision:
        peers.approve_peer_key(
            peer_id=peer.id,
            kid="a-k1",
            expected_fingerprint=f"sha256:{ed25519_key_fingerprint_hex(x_b)}",
            reason="collision",
            actor="admin",
        )
    assert getattr(collision.value, "code", "") == "key-collision"
    with fed_env["db"].transaction() as s:
        updated_peer = s.execute(select(FederationTrustedPeer).where(FederationTrustedPeer.id == peer.id)).scalar_one()
        assert updated_peer.circuit_state == CircuitState.OPEN.value
        assert updated_peer.circuit_requires_admin_reset is True


def test_retire_revoke_rules_and_last_active_protection(fed_env):
    key_a = Ed25519PrivateKey.generate()
    x_a = _b64url(key_a.public_key().public_bytes(encoding=serialization.Encoding.Raw, format=serialization.PublicFormat.Raw))
    key_b = Ed25519PrivateKey.generate()
    x_b = _b64url(key_b.public_key().public_bytes(encoding=serialization.Encoding.Raw, format=serialization.PublicFormat.Raw))
    discovery, jwks = _discovery_and_jwks(kid="a-k1", x=x_a)
    peers, _ = _create_services(fed_env, {"/.well-known/lfs": discovery, "/.well-known/jwks.json": jwks})
    peer = _create_peer(peers, key_a, kid="a-k1", x=x_a)
    peers.remote_client.responses["/.well-known/jwks.json"] = {
        "keys": [
            {"kid": "a-k1", "alg": "EdDSA", "kty": "OKP", "crv": "Ed25519", "x": x_a},
            {"kid": "a-k2", "alg": "EdDSA", "kty": "OKP", "crv": "Ed25519", "x": x_b},
        ]
    }
    peers.approve_peer_key(
        peer_id=peer.id,
        kid="a-k2",
        expected_fingerprint=f"sha256:{ed25519_key_fingerprint_hex(x_b)}",
        reason="second key",
        actor="admin",
    )

    peers.retire_peer_key(peer_id=peer.id, kid="a-k2", reason="rotate", expected_status="active", actor="admin")
    with fed_env["db"].transaction() as s:
        row = s.execute(
            select(FederationPeerSigningKey).where(
                FederationPeerSigningKey.peer_id == peer.id,
                FederationPeerSigningKey.kid == "a-k2",
            )
        ).scalar_one()
        assert row.key_status == "retired"
        assert row.valid_until is not None

    peers.revoke_peer_key(peer_id=peer.id, kid="a-k2", reason="compromise", expected_status="retired", actor="admin")
    with fed_env["db"].transaction() as s:
        row = s.execute(
            select(FederationPeerSigningKey).where(
                FederationPeerSigningKey.peer_id == peer.id,
                FederationPeerSigningKey.kid == "a-k2",
            )
        ).scalar_one()
        assert row.key_status == "revoked"

    with pytest.raises(Exception) as cannot_retire_revoked:
        peers.retire_peer_key(peer_id=peer.id, kid="a-k2", reason="no", expected_status=None, actor="admin")
    assert getattr(cannot_retire_revoked.value, "code", "") == "peer-key-status-conflict"

    with pytest.raises(Exception) as last_active:
        peers.revoke_peer_key(peer_id=peer.id, kid="a-k1", reason="too far", expected_status="active", actor="admin")
    assert getattr(last_active.value, "code", "") == "peer-key-last-active"


def test_revoke_idempotent_and_status_stale_conflict(fed_env):
    key_a = Ed25519PrivateKey.generate()
    x_a = _b64url(key_a.public_key().public_bytes(encoding=serialization.Encoding.Raw, format=serialization.PublicFormat.Raw))
    discovery, jwks = _discovery_and_jwks(kid="a-k1", x=x_a)
    peers, _ = _create_services(fed_env, {"/.well-known/lfs": discovery, "/.well-known/jwks.json": jwks})
    peer = _create_peer(peers, key_a, kid="a-k1", x=x_a)
    with fed_env["db"].transaction() as s:
        peer_row = s.execute(select(FederationTrustedPeer).where(FederationTrustedPeer.id == peer.id)).scalar_one()
        peer_row.sync_enabled = False
    peers.revoke_peer_key(peer_id=peer.id, kid="a-k1", reason="revoke", expected_status="active", actor="admin")
    peers.revoke_peer_key(peer_id=peer.id, kid="a-k1", reason="revoke-again", expected_status=None, actor="admin")
    with pytest.raises(Exception) as stale:
        peers.revoke_peer_key(peer_id=peer.id, kid="a-k1", reason="stale", expected_status="active", actor="admin")
    assert getattr(stale.value, "code", "") == "peer-key-status-stale"


def test_approval_and_retire_and_revoke_block_when_sync_lease_active(fed_env):
    key_a = Ed25519PrivateKey.generate()
    x_a = _b64url(key_a.public_key().public_bytes(encoding=serialization.Encoding.Raw, format=serialization.PublicFormat.Raw))
    discovery, jwks = _discovery_and_jwks(kid="a-k1", x=x_a)
    peers, _ = _create_services(fed_env, {"/.well-known/lfs": discovery, "/.well-known/jwks.json": jwks})
    peer = _create_peer(peers, key_a, kid="a-k1", x=x_a)
    lease = peers._claim_lease(peer_id=peer.id, trigger_type="scheduled")
    assert lease is not None
    try:
        with pytest.raises(Exception):
            peers.approve_peer_key(
                peer_id=peer.id,
                kid="a-k1",
                expected_fingerprint=f"sha256:{ed25519_key_fingerprint_hex(x_a)}",
                reason="blocked",
                actor="admin",
            )
        with pytest.raises(Exception):
            peers.retire_peer_key(peer_id=peer.id, kid="a-k1", reason="blocked", expected_status=None, actor="admin")
        with pytest.raises(Exception):
            peers.revoke_peer_key(peer_id=peer.id, kid="a-k1", reason="blocked", expected_status=None, actor="admin")
    finally:
        peers._release_lease(lease)


def test_approval_concurrency_single_insert(fed_env):
    key_a = Ed25519PrivateKey.generate()
    x_a = _b64url(key_a.public_key().public_bytes(encoding=serialization.Encoding.Raw, format=serialization.PublicFormat.Raw))
    key_b = Ed25519PrivateKey.generate()
    x_b = _b64url(key_b.public_key().public_bytes(encoding=serialization.Encoding.Raw, format=serialization.PublicFormat.Raw))
    discovery, jwks = _discovery_and_jwks(kid="a-k1", x=x_a)
    peers, _ = _create_services(fed_env, {"/.well-known/lfs": discovery, "/.well-known/jwks.json": jwks})
    peer = _create_peer(peers, key_a, kid="a-k1", x=x_a)
    peers.remote_client.responses["/.well-known/jwks.json"] = {"keys": [{"kid": "a-k2", "alg": "EdDSA", "kty": "OKP", "crv": "Ed25519", "x": x_b}]}
    expected = f"sha256:{ed25519_key_fingerprint_hex(x_b)}"
    errors: list[Exception] = []

    def run():
        try:
            peers.approve_peer_key(peer_id=peer.id, kid="a-k2", expected_fingerprint=expected, reason="parallel", actor="admin")
        except Exception as exc:
            errors.append(exc)

    t1 = threading.Thread(target=run)
    t2 = threading.Thread(target=run)
    t1.start()
    t2.start()
    t1.join(timeout=5)
    t2.join(timeout=5)
    assert all(getattr(error, "code", "") in {"already-running"} for error in errors)
    with fed_env["db"].transaction() as s:
        count = s.execute(
            select(func.count()).select_from(FederationPeerSigningKey).where(
                FederationPeerSigningKey.peer_id == peer.id,
                FederationPeerSigningKey.kid == "a-k2",
            )
        ).scalar_one()
    assert count == 1


def test_new_inbound_rejects_retired_key_without_cursor_advance(fed_env):
    key_a = Ed25519PrivateKey.generate()
    x_a = _b64url(key_a.public_key().public_bytes(encoding=serialization.Encoding.Raw, format=serialization.PublicFormat.Raw))
    discovery, jwks = _discovery_and_jwks(kid="a-k1", x=x_a)
    bundle = _record_event_bundle(kid="a-k1", key=key_a, local_id="INC4", version="1", position=10, event_id=str(uuid.uuid4()))
    encoded = base64.urlsafe_b64encode(bundle["record"]["canonicalId"].encode()).decode().rstrip("=")
    peers, sync = _create_services(
        fed_env,
        {
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
            f"record:{encoded}": {
                "record": bundle["record"],
                "signed": bundle["recordSigned"],
                "currentState": "published",
                "latestEventPosition": 10,
                "latestEventDigestSha256": bundle["eventSigned"]["digestSha256"],
            },
        },
    )
    peer = _create_peer(peers, key_a, kid="a-k1", x=x_a)
    with fed_env["db"].transaction() as s:
        row = s.execute(
            select(FederationPeerSigningKey).where(
                FederationPeerSigningKey.peer_id == peer.id,
                FederationPeerSigningKey.kid == "a-k1",
            )
        ).scalar_one()
        row.key_status = "retired"
        row.updated_at = datetime.now(timezone.utc)
        cursor_before = s.execute(select(FederationPeerCursor).where(FederationPeerCursor.peer_id == peer.id)).scalar_one().cursor
    result = sync.sync_peer(peer_id=peer.id, trigger_type="manual", max_seconds=10)
    assert result.status == "failed"
    with fed_env["db"].transaction() as s:
        cursor_after = s.execute(select(FederationPeerCursor).where(FederationPeerCursor.peer_id == peer.id)).scalar_one().cursor
        assert cursor_after == cursor_before



def test_new_inbound_rejects_unknown_key_without_cursor_advance(fed_env):
    key_a = Ed25519PrivateKey.generate()
    x_a = _b64url(key_a.public_key().public_bytes(encoding=serialization.Encoding.Raw, format=serialization.PublicFormat.Raw))
    discovery, jwks = _discovery_and_jwks(kid="a-k1", x=x_a)
    bundle = _record_event_bundle(kid="a-k1", key=key_a, local_id="INC4U", version="1", position=10, event_id=str(uuid.uuid4()))
    bundle["eventSigned"]["signature"]["kid"] = "unknown-k"
    encoded = base64.urlsafe_b64encode(bundle["record"]["canonicalId"].encode()).decode().rstrip("=")
    peers, sync = _create_services(
        fed_env,
        {
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
            f"record:{encoded}": {
                "record": bundle["record"],
                "signed": bundle["recordSigned"],
                "currentState": "published",
                "latestEventPosition": 10,
                "latestEventDigestSha256": bundle["eventSigned"]["digestSha256"],
            },
        },
    )
    peer = _create_peer(peers, key_a, kid="a-k1", x=x_a)
    with fed_env["db"].transaction() as s:
        cursor_before = s.execute(select(FederationPeerCursor).where(FederationPeerCursor.peer_id == peer.id)).scalar_one().cursor
    result = sync.sync_peer(peer_id=peer.id, trigger_type="manual", max_seconds=10)
    assert result.status == "failed"
    with fed_env["db"].transaction() as s:
        cursor_after = s.execute(select(FederationPeerCursor).where(FederationPeerCursor.peer_id == peer.id)).scalar_one().cursor
        assert cursor_after == cursor_before


def test_historical_verification_is_separate_from_authorization(fed_env):
    key_a = Ed25519PrivateKey.generate()
    x_a = _b64url(key_a.public_key().public_bytes(encoding=serialization.Encoding.Raw, format=serialization.PublicFormat.Raw))
    discovery, jwks = _discovery_and_jwks(kid="a-k1", x=x_a)
    peers, sync = _create_services(fed_env, {"/.well-known/lfs": discovery, "/.well-known/jwks.json": jwks})
    peer = _create_peer(peers, key_a, kid="a-k1", x=x_a)
    payload = {"a": 1}
    signed = type(
        "Signed",
        (),
        {
            "digestSha256": sha256_hex(canonicalize_to_bytes(payload)),
            "signature": type("Sig", (), {"kid": "a-k1", "alg": "EdDSA", "value": _b64url(key_a.sign(canonicalize_to_bytes(payload)))})(),
        },
    )()
    with fed_env["db"].transaction() as s:
        row = s.execute(
            select(FederationPeerSigningKey).where(
                FederationPeerSigningKey.peer_id == peer.id,
                FederationPeerSigningKey.kid == "a-k1",
            )
        ).scalar_one()
        row.key_status = "retired"
        row.valid_until = datetime.now(timezone.utc) - timedelta(minutes=1)
        verification_now = s.execute(select(func.now())).scalar_one()
        key_map = {row.kid: row}
    payload_obj = type("Payload", (), {"model_dump": lambda self, mode="json": payload})()
    result = sync._verify_peer_key_signature(
        payload=payload_obj,
        signed=signed,
        key_map=key_map,
        purpose=PeerKeyVerificationPurpose.HISTORICAL_EVIDENCE,
        verification_now=verification_now,
    )
    assert result.signature_valid is True
    assert result.key_found is True
    assert result.trust_status == "retired"
    assert result.eligible_for_application is False
    assert result.rejection_reason is None


def test_new_inbound_verification_enforces_validity_boundaries(fed_env):
    key_a = Ed25519PrivateKey.generate()
    x_a = _b64url(key_a.public_key().public_bytes(encoding=serialization.Encoding.Raw, format=serialization.PublicFormat.Raw))
    discovery, jwks = _discovery_and_jwks(kid="a-k1", x=x_a)
    peers, sync = _create_services(fed_env, {"/.well-known/lfs": discovery, "/.well-known/jwks.json": jwks})
    peer = _create_peer(peers, key_a, kid="a-k1", x=x_a)
    payload = {"a": 1}
    payload_obj = type("Payload", (), {"model_dump": lambda self, mode="json": payload})()
    signed = type(
        "Signed",
        (),
        {
            "digestSha256": sha256_hex(canonicalize_to_bytes(payload)),
            "signature": type("Sig", (), {"kid": "a-k1", "alg": "EdDSA", "value": _b64url(key_a.sign(canonicalize_to_bytes(payload)))})(),
        },
    )()
    with fed_env["db"].transaction() as s:
        row = s.execute(
            select(FederationPeerSigningKey).where(
                FederationPeerSigningKey.peer_id == peer.id,
                FederationPeerSigningKey.kid == "a-k1",
            )
        ).scalar_one()
        db_now = s.execute(select(func.now())).scalar_one()
        key_map = {row.kid: row}

        row.key_status = "active"
        row.valid_from = db_now - timedelta(minutes=5)
        row.valid_until = db_now + timedelta(minutes=5)
        ok = sync._verify_peer_key_signature(
            payload=payload_obj,
            signed=signed,
            key_map=key_map,
            purpose=PeerKeyVerificationPurpose.NEW_INBOUND_EVENT,
            verification_now=db_now,
        )
        assert ok.signature_valid is True
        assert ok.key_found is True
        assert ok.trust_status == "active"
        assert ok.eligible_for_application is True
        assert ok.rejection_reason is None

        row.valid_from = db_now + timedelta(seconds=1)
        row.valid_until = None
        future = sync._verify_peer_key_signature(
            payload=payload_obj,
            signed=signed,
            key_map=key_map,
            purpose=PeerKeyVerificationPurpose.NEW_INBOUND_EVENT,
            verification_now=db_now,
        )
        assert future.signature_valid is True
        assert future.key_found is True
        assert future.trust_status == "active"
        assert future.eligible_for_application is False
        assert future.rejection_reason == "signing-key-not-yet-valid"

        row.valid_from = None
        row.valid_until = db_now
        boundary = sync._verify_peer_key_signature(
            payload=payload_obj,
            signed=signed,
            key_map=key_map,
            purpose=PeerKeyVerificationPurpose.NEW_INBOUND_EVENT,
            verification_now=db_now,
        )
        assert boundary.eligible_for_application is False
        assert boundary.rejection_reason == "signing-key-expired"

        row.valid_until = db_now - timedelta(seconds=1)
        expired = sync._verify_peer_key_signature(
            payload=payload_obj,
            signed=signed,
            key_map=key_map,
            purpose=PeerKeyVerificationPurpose.NEW_INBOUND_EVENT,
            verification_now=db_now,
        )
        assert expired.eligible_for_application is False
        assert expired.rejection_reason == "signing-key-expired"

        row.valid_from = None
        row.valid_until = None
        null_bounds = sync._verify_peer_key_signature(
            payload=payload_obj,
            signed=signed,
            key_map=key_map,
            purpose=PeerKeyVerificationPurpose.NEW_INBOUND_EVENT,
            verification_now=db_now,
        )
        assert null_bounds.eligible_for_application is True
        assert null_bounds.rejection_reason is None

        row.key_status = "retired"
        retired = sync._verify_peer_key_signature(
            payload=payload_obj,
            signed=signed,
            key_map=key_map,
            purpose=PeerKeyVerificationPurpose.NEW_INBOUND_EVENT,
            verification_now=db_now,
        )
        assert retired.eligible_for_application is False
        assert retired.rejection_reason == "retired-signing-key"

        row.key_status = "revoked"
        revoked = sync._verify_peer_key_signature(
            payload=payload_obj,
            signed=signed,
            key_map=key_map,
            purpose=PeerKeyVerificationPurpose.NEW_INBOUND_EVENT,
            verification_now=db_now,
        )
        assert revoked.eligible_for_application is False
        assert revoked.rejection_reason == "revoked-signing-key"


def test_sync_rejects_key_expired_between_initial_verify_and_commit(fed_env):
    key_a = Ed25519PrivateKey.generate()
    x_a = _b64url(key_a.public_key().public_bytes(encoding=serialization.Encoding.Raw, format=serialization.PublicFormat.Raw))
    discovery, jwks = _discovery_and_jwks(kid="a-k1", x=x_a)
    bundle = _record_event_bundle(kid="a-k1", key=key_a, local_id="INC4E", version="1", position=10, event_id=str(uuid.uuid4()))
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
        f"record:{encoded}": {
            "record": bundle["record"],
            "signed": bundle["recordSigned"],
            "currentState": "published",
            "latestEventPosition": 10,
            "latestEventDigestSha256": bundle["eventSigned"]["digestSha256"],
        },
    }
    peer_holder: dict[str, uuid.UUID | None] = {"id": None}

    def expire_key() -> None:
        if peer_holder["id"] is None:
            return
        with fed_env["db"].transaction() as s:
            row = s.execute(
                select(FederationPeerSigningKey).where(
                    FederationPeerSigningKey.peer_id == peer_holder["id"],
                    FederationPeerSigningKey.kid == "a-k1",
                )
            ).scalar_one()
            row.valid_until = s.execute(select(func.now())).scalar_one()

    remote = _MutatingRemoteScenario(
        fed_env["settings"],
        responses,
        mutate_on_path=f"/api/v1/federation/records/{encoded}",
        mutate_once=expire_key,
    )
    peers = FederationPeerService(fed_env["db"], fed_env["settings"], remote_client=remote)
    sync = FederationInboundSyncService(fed_env["db"], fed_env["settings"], remote_client=remote)
    peer = _create_peer(peers, key_a, kid="a-k1", x=x_a)
    peer_holder["id"] = peer.id
    with fed_env["db"].transaction() as s:
        row = s.execute(
            select(FederationPeerSigningKey).where(
                FederationPeerSigningKey.peer_id == peer.id,
                FederationPeerSigningKey.kid == "a-k1",
            )
        ).scalar_one()
        row.valid_from = s.execute(select(func.now())).scalar_one() - timedelta(minutes=1)
        row.valid_until = s.execute(select(func.now())).scalar_one() + timedelta(days=1)
        cursor_before = s.execute(select(FederationPeerCursor).where(FederationPeerCursor.peer_id == peer.id)).scalar_one().cursor
        imported_before = s.execute(
            select(func.count()).select_from(FederationRecord).where(FederationRecord.imported_from_peer_id == peer.id)
        ).scalar_one()
    result = sync.sync_peer(peer_id=peer.id, trigger_type="manual", max_seconds=10)
    assert result.status == "failed"
    with fed_env["db"].transaction() as s:
        attempt = s.execute(
            select(FederationSyncAttempt)
            .where(FederationSyncAttempt.peer_id == peer.id)
            .order_by(FederationSyncAttempt.started_at.desc())
        ).scalar_one()
        cursor_after = s.execute(select(FederationPeerCursor).where(FederationPeerCursor.peer_id == peer.id)).scalar_one().cursor
        imported_after = s.execute(
            select(func.count()).select_from(FederationRecord).where(FederationRecord.imported_from_peer_id == peer.id)
        ).scalar_one()
    assert attempt.error_code == "signing-key-expired"
    assert cursor_after == cursor_before
    assert imported_after == imported_before


@pytest.mark.parametrize(
    ("mutation", "expected_code"),
    [
        ("retired", "retired-signing-key"),
        ("revoked", "revoked-signing-key"),
        ("missing", "unknown-signing-key"),
    ],
)
def test_sync_rejects_commit_time_key_state_changes(fed_env, mutation: str, expected_code: str):
    key_a = Ed25519PrivateKey.generate()
    x_a = _b64url(key_a.public_key().public_bytes(encoding=serialization.Encoding.Raw, format=serialization.PublicFormat.Raw))
    discovery, jwks = _discovery_and_jwks(kid="a-k1", x=x_a)
    bundle = _record_event_bundle(kid="a-k1", key=key_a, local_id=f"INC4-{mutation}", version="1", position=10, event_id=str(uuid.uuid4()))
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
        f"record:{encoded}": {
            "record": bundle["record"],
            "signed": bundle["recordSigned"],
            "currentState": "published",
            "latestEventPosition": 10,
            "latestEventDigestSha256": bundle["eventSigned"]["digestSha256"],
        },
    }
    peer_holder: dict[str, uuid.UUID | None] = {"id": None}

    def mutate_key() -> None:
        if peer_holder["id"] is None:
            return
        with fed_env["db"].transaction() as s:
            row = s.execute(
                select(FederationPeerSigningKey).where(
                    FederationPeerSigningKey.peer_id == peer_holder["id"],
                    FederationPeerSigningKey.kid == "a-k1",
                )
            ).scalar_one()
            if mutation == "retired":
                row.key_status = "retired"
            elif mutation == "revoked":
                row.key_status = "revoked"
            else:
                s.delete(row)

    remote = _MutatingRemoteScenario(
        fed_env["settings"],
        responses,
        mutate_on_path=f"/api/v1/federation/records/{encoded}",
        mutate_once=mutate_key,
    )
    peers = FederationPeerService(fed_env["db"], fed_env["settings"], remote_client=remote)
    sync = FederationInboundSyncService(fed_env["db"], fed_env["settings"], remote_client=remote)
    peer = _create_peer(peers, key_a, kid="a-k1", x=x_a)
    peer_holder["id"] = peer.id
    with fed_env["db"].transaction() as s:
        cursor_before = s.execute(select(FederationPeerCursor).where(FederationPeerCursor.peer_id == peer.id)).scalar_one().cursor
        imported_before = s.execute(
            select(func.count()).select_from(FederationRecord).where(FederationRecord.imported_from_peer_id == peer.id)
        ).scalar_one()
    result = sync.sync_peer(peer_id=peer.id, trigger_type="manual", max_seconds=10)
    assert result.status == "failed"
    with fed_env["db"].transaction() as s:
        attempt = s.execute(
            select(FederationSyncAttempt)
            .where(FederationSyncAttempt.peer_id == peer.id)
            .order_by(FederationSyncAttempt.started_at.desc())
        ).scalar_one()
        cursor_after = s.execute(select(FederationPeerCursor).where(FederationPeerCursor.peer_id == peer.id)).scalar_one().cursor
        imported_after = s.execute(
            select(func.count()).select_from(FederationRecord).where(FederationRecord.imported_from_peer_id == peer.id)
        ).scalar_one()
    assert attempt.error_code == expected_code
    assert cursor_after == cursor_before
    assert imported_after == imported_before


def test_sync_preserves_committed_prior_page_when_later_page_key_expired(fed_env):
    key_a = Ed25519PrivateKey.generate()
    x_a = _b64url(key_a.public_key().public_bytes(encoding=serialization.Encoding.Raw, format=serialization.PublicFormat.Raw))
    key_b = Ed25519PrivateKey.generate()
    x_b = _b64url(key_b.public_key().public_bytes(encoding=serialization.Encoding.Raw, format=serialization.PublicFormat.Raw))
    discovery, _jwks = _discovery_and_jwks(kid="a-k1", x=x_a)
    first = _record_event_bundle(kid="a-k1", key=key_a, local_id="INC4P1", version="1", position=10, event_id=str(uuid.uuid4()))
    second = _record_event_bundle(kid="a-k2", key=key_b, local_id="INC4P2", version="1", position=11, event_id=str(uuid.uuid4()))
    first_encoded = base64.urlsafe_b64encode(first["record"]["canonicalId"].encode()).decode().rstrip("=")
    second_encoded = base64.urlsafe_b64encode(second["record"]["canonicalId"].encode()).decode().rstrip("=")
    peers, sync = _create_services(
        fed_env,
        {
            "/.well-known/lfs": discovery,
            "/.well-known/jwks.json": {
                "keys": [
                    {"kid": "a-k1", "alg": "EdDSA", "kty": "OKP", "crv": "Ed25519", "x": x_a},
                    {"kid": "a-k2", "alg": "EdDSA", "kty": "OKP", "crv": "Ed25519", "x": x_b},
                ]
            },
            "changes:": {
                "events": [{"payload": first["event"], "signed": first["eventSigned"]}],
                "limit": 200,
                "hasMore": True,
                "nextCursor": "cursor-2",
                "resumeCursor": "resume-10",
                "snapshotWatermark": 11,
            },
            "changes:cursor-2": {
                "events": [{"payload": second["event"], "signed": second["eventSigned"]}],
                "limit": 200,
                "hasMore": False,
                "nextCursor": None,
                "resumeCursor": "resume-11",
                "snapshotWatermark": 11,
            },
            f"record:{first_encoded}": {
                "record": first["record"],
                "signed": first["recordSigned"],
                "currentState": "published",
                "latestEventPosition": 10,
                "latestEventDigestSha256": first["eventSigned"]["digestSha256"],
            },
            f"record:{second_encoded}": {
                "record": second["record"],
                "signed": second["recordSigned"],
                "currentState": "published",
                "latestEventPosition": 11,
                "latestEventDigestSha256": second["eventSigned"]["digestSha256"],
            },
        },
    )
    peer = _create_peer(peers, key_a, kid="a-k1", x=x_a)
    peers.approve_peer_key(
        peer_id=peer.id,
        kid="a-k2",
        expected_fingerprint=f"sha256:{ed25519_key_fingerprint_hex(x_b)}",
        reason="add second key",
        actor="admin",
    )
    def expire_second_key() -> None:
        with fed_env["db"].transaction() as s:
            second_key = s.execute(
                select(FederationPeerSigningKey).where(
                    FederationPeerSigningKey.peer_id == peer.id,
                    FederationPeerSigningKey.kid == "a-k2",
                )
            ).scalar_one()
            second_key.valid_until = s.execute(select(func.now())).scalar_one()

    remote = _MutatingRemoteScenario(
        fed_env["settings"],
        peers.remote_client.responses,
        mutate_on_path=f"/api/v1/federation/records/{second_encoded}",
        mutate_once=expire_second_key,
    )
    peers.remote_client = remote
    sync.remote_client = remote
    result = sync.sync_peer(peer_id=peer.id, trigger_type="manual", max_seconds=10)
    assert result.status == "partial"
    assert result.pagesProcessed == 1
    with fed_env["db"].transaction() as s:
        cursor = s.execute(select(FederationPeerCursor).where(FederationPeerCursor.peer_id == peer.id)).scalar_one()
        rows = s.execute(
            select(FederationInboundEvent.remote_event_position, FederationInboundEvent.processing_status)
            .where(FederationInboundEvent.source_peer_id == peer.id)
            .order_by(FederationInboundEvent.remote_event_position)
        ).all()
    assert rows == [(10, "accepted"), (11, "rejected")]
    assert cursor.cursor == "resume-10"
    assert cursor.last_remote_position == 10


def test_sync_reloads_commit_keys_once_per_page_and_valid_key_commits(fed_env):
    key_a = Ed25519PrivateKey.generate()
    x_a = _b64url(key_a.public_key().public_bytes(encoding=serialization.Encoding.Raw, format=serialization.PublicFormat.Raw))
    discovery, jwks = _discovery_and_jwks(kid="a-k1", x=x_a)
    first = _record_event_bundle(kid="a-k1", key=key_a, local_id="INC4B1", version="1", position=10, event_id=str(uuid.uuid4()))
    second = _record_event_bundle(kid="a-k1", key=key_a, local_id="INC4B2", version="1", position=11, event_id=str(uuid.uuid4()))
    first_encoded = base64.urlsafe_b64encode(first["record"]["canonicalId"].encode()).decode().rstrip("=")
    second_encoded = base64.urlsafe_b64encode(second["record"]["canonicalId"].encode()).decode().rstrip("=")
    peers, sync = _create_services(
        fed_env,
        {
            "/.well-known/lfs": discovery,
            "/.well-known/jwks.json": jwks,
            "changes:": {
                "events": [
                    {"payload": first["event"], "signed": first["eventSigned"]},
                    {"payload": second["event"], "signed": second["eventSigned"]},
                ],
                "limit": 200,
                "hasMore": False,
                "nextCursor": None,
                "resumeCursor": "resume-11",
                "snapshotWatermark": 11,
            },
            f"record:{first_encoded}": {
                "record": first["record"],
                "signed": first["recordSigned"],
                "currentState": "published",
                "latestEventPosition": 10,
                "latestEventDigestSha256": first["eventSigned"]["digestSha256"],
            },
            f"record:{second_encoded}": {
                "record": second["record"],
                "signed": second["recordSigned"],
                "currentState": "published",
                "latestEventPosition": 11,
                "latestEventDigestSha256": second["eventSigned"]["digestSha256"],
            },
        },
    )
    peer = _create_peer(peers, key_a, kid="a-k1", x=x_a)
    calls: list[set[str]] = []
    original_loader = sync._load_referenced_signing_keys_for_commit

    def wrapped_loader(session, *, peer_id, referenced_kids):
        calls.append(set(referenced_kids))
        return original_loader(session, peer_id=peer_id, referenced_kids=referenced_kids)

    sync._load_referenced_signing_keys_for_commit = wrapped_loader  # type: ignore[assignment]
    result = sync.sync_peer(peer_id=peer.id, trigger_type="manual", max_seconds=10)
    assert result.status == "complete"
    assert result.pagesProcessed == 1
    assert result.eventsProcessed == 2
    assert result.importedRecords == 2
    assert len(calls) == 1
    assert calls[0] == {"a-k1"}


def test_circuit_classification_for_validity_rejections_is_permanent(fed_env):
    circuit = PeerCircuitService(fed_env["settings"])
    for code in ("signing-key-not-yet-valid", "signing-key-expired"):
        classification = circuit.classify_failure(FederationError(code, "x"), phase="changes")
        assert classification.kind == "permanent"
        assert classification.reason == CircuitFailureReason.IDENTITY_MISMATCH


def test_no_raw_key_material_in_inspect_audit_and_health(fed_env):
    key_a = Ed25519PrivateKey.generate()
    x_a = _b64url(key_a.public_key().public_bytes(encoding=serialization.Encoding.Raw, format=serialization.PublicFormat.Raw))
    discovery, jwks = _discovery_and_jwks(kid="a-k1", x=x_a)
    peers, sync = _create_services(fed_env, {"/.well-known/lfs": discovery, "/.well-known/jwks.json": jwks})
    peer = _create_peer(peers, key_a, kid="a-k1", x=x_a)
    inspect = peers.inspect_peer_keys(peer_id=peer.id, reason="audit", actor="admin")
    serialized = inspect.model_dump_json()
    assert '"x"' not in serialized
    assert "BEGIN PRIVATE KEY" not in serialized

    bundle = _record_event_bundle(kid="a-k1", key=key_a, local_id="INC4S", version="1", position=10, event_id=str(uuid.uuid4()))
    encoded = base64.urlsafe_b64encode(bundle["record"]["canonicalId"].encode()).decode().rstrip("=")
    peers.remote_client.responses["changes:"] = {
        "events": [{"payload": bundle["event"], "signed": bundle["eventSigned"]}],
        "limit": 200,
        "hasMore": False,
        "nextCursor": None,
        "resumeCursor": "resume-10",
        "snapshotWatermark": 10,
    }
    peers.remote_client.responses[f"record:{encoded}"] = {
        "record": bundle["record"],
        "signed": bundle["recordSigned"],
        "currentState": "published",
        "latestEventPosition": 10,
        "latestEventDigestSha256": bundle["eventSigned"]["digestSha256"],
    }
    with fed_env["db"].transaction() as s:
        key = s.execute(
            select(FederationPeerSigningKey).where(
                FederationPeerSigningKey.peer_id == peer.id,
                FederationPeerSigningKey.kid == "a-k1",
            )
        ).scalar_one()
        key.valid_until = s.execute(select(func.now())).scalar_one()
    sync.sync_peer(peer_id=peer.id, trigger_type="manual", max_seconds=10)
    with fed_env["db"].transaction() as s:
        audit_rows = s.execute(
            select(FederationOperationalAudit.redacted_details).where(FederationOperationalAudit.peer_id == peer.id)
        ).scalars().all()
        snapshots = s.execute(
            select(FederationPeerHealthSnapshot.error_code, FederationPeerHealthSnapshot.error_detail)
            .where(FederationPeerHealthSnapshot.peer_id == peer.id)
            .order_by(FederationPeerHealthSnapshot.sampled_at.desc())
        ).all()
    audit_json = json.dumps(audit_rows)
    assert '"x"' not in audit_json
    assert "BEGIN PRIVATE KEY" not in audit_json
    assert x_a not in audit_json
    if snapshots:
        code, detail = snapshots[0]
        assert code == "signing-key-expired"
        assert detail == "Remote event used an expired signing key."


def test_new_key_endpoints_authorization_and_safe_response(fed_env):
    key_a = Ed25519PrivateKey.generate()
    x_a = _b64url(key_a.public_key().public_bytes(encoding=serialization.Encoding.Raw, format=serialization.PublicFormat.Raw))
    discovery, jwks = _discovery_and_jwks(kid="a-k1", x=x_a)
    peers, _ = _create_services(fed_env, {"/.well-known/lfs": discovery, "/.well-known/jwks.json": jwks})
    peer = _create_peer(peers, key_a, kid="a-k1", x=x_a)
    with TestClient(create_app()) as client:
        paths = [
            ("get", f"/api/v1/admin/federation/peers/{peer.id}/keys", None),
            ("post", f"/api/v1/admin/federation/peers/{peer.id}/keys/inspect", {}),
            ("post", f"/api/v1/admin/federation/peers/{peer.id}/keys/approve", {"kid": "a-k1", "expectedFingerprint": f"sha256:{ed25519_key_fingerprint_hex(x_a)}", "reason": "ok"}),
            ("post", f"/api/v1/admin/federation/peers/{peer.id}/keys/a-k1/retire", {"reason": "r"}),
            ("post", f"/api/v1/admin/federation/peers/{peer.id}/keys/a-k1/revoke", {"reason": "r"}),
        ]
        for method, path, body in paths:
            if method == "get":
                r_anon = client.get(path)
                r_bad = client.get(path, headers={"Authorization": "Bearer nope"})
                r_cur = client.get(path, headers={"Authorization": "Bearer curator-token"})
                r_admin = client.get(path, headers={"Authorization": "Bearer admin-token"})
            else:
                r_anon = client.post(path, json=body)
                r_bad = client.post(path, json=body, headers={"Authorization": "Bearer nope"})
                r_cur = client.post(path, json=body, headers={"Authorization": "Bearer curator-token"})
                r_admin = client.post(path, json=body, headers={"Authorization": "Bearer admin-token"})
            assert r_anon.status_code == 401
            assert r_bad.status_code == 401
            assert r_cur.status_code == 403
            assert r_admin.status_code in {200, 404, 409, 422, 503}
        inspect = client.post(
            f"/api/v1/admin/federation/peers/{peer.id}/keys/inspect",
            json={},
            headers={"Authorization": "Bearer admin-token"},
        )
        if inspect.status_code == 200:
            data = inspect.json()
            text = json.dumps(data)
            assert '"x"' not in text


def test_list_peer_keys_returns_public_metadata_without_x(fed_env):
    key_a = Ed25519PrivateKey.generate()
    x_a = _b64url(key_a.public_key().public_bytes(encoding=serialization.Encoding.Raw, format=serialization.PublicFormat.Raw))
    discovery, jwks = _discovery_and_jwks(kid="a-k1", x=x_a)
    peers, _ = _create_services(fed_env, {"/.well-known/lfs": discovery, "/.well-known/jwks.json": jwks})
    peer = _create_peer(peers, key_a, kid="a-k1", x=x_a)
    inventory = peers.list_peer_keys(peer_id=peer.id)
    assert inventory.peerId == peer.id
    assert inventory.items
    assert inventory.items[0].publicFingerprint.startswith("sha256:")
    assert "x" not in inventory.items[0].model_dump()


def test_inspect_duplicate_kid_and_unsupported_curve_are_invalid(fed_env):
    key_a = Ed25519PrivateKey.generate()
    x_a = _b64url(key_a.public_key().public_bytes(encoding=serialization.Encoding.Raw, format=serialization.PublicFormat.Raw))
    discovery, jwks = _discovery_and_jwks(kid="a-k1", x=x_a)
    peers, _ = _create_services(fed_env, {"/.well-known/lfs": discovery, "/.well-known/jwks.json": jwks})
    peer = _create_peer(peers, key_a, kid="a-k1", x=x_a)
    peers.remote_client.responses["/.well-known/jwks.json"] = {
        "keys": [
            {"kid": "dup", "alg": "EdDSA", "kty": "OKP", "crv": "Ed25519", "x": x_a},
            {"kid": "dup", "alg": "EdDSA", "kty": "OKP", "crv": "Ed25519", "x": x_a},
            {"kid": "wrong-curve", "alg": "EdDSA", "kty": "OKP", "crv": "P-256", "x": x_a},
        ]
    }
    diff = peers.inspect_peer_keys(peer_id=peer.id, reason="inspect", actor="admin")
    reasons = {item.reasonCode for item in diff.invalid}
    assert "duplicate-kid" in reasons
    assert "unsupported-curve" in reasons


def test_inspect_persists_audit_counts(fed_env):
    key_a = Ed25519PrivateKey.generate()
    x_a = _b64url(key_a.public_key().public_bytes(encoding=serialization.Encoding.Raw, format=serialization.PublicFormat.Raw))
    discovery, jwks = _discovery_and_jwks(kid="a-k1", x=x_a)
    peers, _ = _create_services(fed_env, {"/.well-known/lfs": discovery, "/.well-known/jwks.json": jwks})
    peer = _create_peer(peers, key_a, kid="a-k1", x=x_a)
    peers.inspect_peer_keys(peer_id=peer.id, reason="inventory", actor="admin")
    with fed_env["db"].transaction() as s:
        row = s.execute(
            select(FederationOperationalAudit)
            .where(
                FederationOperationalAudit.peer_id == peer.id,
                FederationOperationalAudit.action == AuditAction.PEER_KEY_INSPECT.value,
            )
            .order_by(FederationOperationalAudit.occurred_at.desc())
        ).scalar_one()
        assert row.outcome == "success"
        assert "known" in (row.redacted_details or {})


def test_approve_reactivation_of_retired_or_revoked_is_rejected(fed_env):
    key_a = Ed25519PrivateKey.generate()
    x_a = _b64url(key_a.public_key().public_bytes(encoding=serialization.Encoding.Raw, format=serialization.PublicFormat.Raw))
    discovery, jwks = _discovery_and_jwks(kid="a-k1", x=x_a)
    peers, _ = _create_services(fed_env, {"/.well-known/lfs": discovery, "/.well-known/jwks.json": jwks})
    peer = _create_peer(peers, key_a, kid="a-k1", x=x_a)
    with fed_env["db"].transaction() as s:
        row = s.execute(
            select(FederationPeerSigningKey).where(
                FederationPeerSigningKey.peer_id == peer.id,
                FederationPeerSigningKey.kid == "a-k1",
            )
        ).scalar_one()
        row.key_status = "retired"
    with pytest.raises(Exception) as retired:
        peers.approve_peer_key(
            peer_id=peer.id,
            kid="a-k1",
            expected_fingerprint=f"sha256:{ed25519_key_fingerprint_hex(x_a)}",
            reason="reactivate",
            actor="admin",
        )
    assert getattr(retired.value, "code", "") == "peer-key-status-conflict"
    with fed_env["db"].transaction() as s:
        row = s.execute(
            select(FederationPeerSigningKey).where(
                FederationPeerSigningKey.peer_id == peer.id,
                FederationPeerSigningKey.kid == "a-k1",
            )
        ).scalar_one()
        row.key_status = "revoked"
    with pytest.raises(Exception) as revoked:
        peers.approve_peer_key(
            peer_id=peer.id,
            kid="a-k1",
            expected_fingerprint=f"sha256:{ed25519_key_fingerprint_hex(x_a)}",
            reason="reactivate",
            actor="admin",
        )
    assert getattr(revoked.value, "code", "") == "peer-key-status-conflict"


def test_approve_failure_releases_lease(fed_env):
    key_a = Ed25519PrivateKey.generate()
    x_a = _b64url(key_a.public_key().public_bytes(encoding=serialization.Encoding.Raw, format=serialization.PublicFormat.Raw))
    discovery, jwks = _discovery_and_jwks(kid="a-k1", x=x_a)
    peers, _ = _create_services(fed_env, {"/.well-known/lfs": discovery, "/.well-known/jwks.json": jwks})
    peer = _create_peer(peers, key_a, kid="a-k1", x=x_a)
    with pytest.raises(Exception):
        peers.approve_peer_key(
            peer_id=peer.id,
            kid="a-k1",
            expected_fingerprint="sha256:" + ("0" * 64),
            reason="fail",
            actor="admin",
        )
    lease = peers._claim_lease(peer_id=peer.id, trigger_type="manual")
    assert lease is not None
    peers._release_lease(lease)


def test_retire_idempotent_and_unknown_key_404(fed_env):
    key_a = Ed25519PrivateKey.generate()
    x_a = _b64url(key_a.public_key().public_bytes(encoding=serialization.Encoding.Raw, format=serialization.PublicFormat.Raw))
    key_b = Ed25519PrivateKey.generate()
    x_b = _b64url(key_b.public_key().public_bytes(encoding=serialization.Encoding.Raw, format=serialization.PublicFormat.Raw))
    discovery, jwks = _discovery_and_jwks(kid="a-k1", x=x_a)
    peers, _ = _create_services(fed_env, {"/.well-known/lfs": discovery, "/.well-known/jwks.json": jwks})
    peer = _create_peer(peers, key_a, kid="a-k1", x=x_a)
    peers.remote_client.responses["/.well-known/jwks.json"] = {
        "keys": [
            {"kid": "a-k1", "alg": "EdDSA", "kty": "OKP", "crv": "Ed25519", "x": x_a},
            {"kid": "a-k2", "alg": "EdDSA", "kty": "OKP", "crv": "Ed25519", "x": x_b},
        ]
    }
    peers.approve_peer_key(
        peer_id=peer.id,
        kid="a-k2",
        expected_fingerprint=f"sha256:{ed25519_key_fingerprint_hex(x_b)}",
        reason="approve",
        actor="admin",
    )
    first = peers.retire_peer_key(peer_id=peer.id, kid="a-k2", reason="retire", expected_status=None, actor="admin")
    second = peers.retire_peer_key(peer_id=peer.id, kid="a-k2", reason="retire", expected_status=None, actor="admin")
    assert first.status == "retired"
    assert second.status == "retired"
    with pytest.raises(Exception) as missing:
        peers.retire_peer_key(peer_id=peer.id, kid="missing", reason="retire", expected_status=None, actor="admin")
    assert getattr(missing.value, "code", "") == "peer-key-not-found"


def test_revoke_unknown_key_404(fed_env):
    key_a = Ed25519PrivateKey.generate()
    x_a = _b64url(key_a.public_key().public_bytes(encoding=serialization.Encoding.Raw, format=serialization.PublicFormat.Raw))
    discovery, jwks = _discovery_and_jwks(kid="a-k1", x=x_a)
    peers, _ = _create_services(fed_env, {"/.well-known/lfs": discovery, "/.well-known/jwks.json": jwks})
    peer = _create_peer(peers, key_a, kid="a-k1", x=x_a)
    with pytest.raises(Exception) as missing:
        peers.revoke_peer_key(peer_id=peer.id, kid="missing", reason="revoke", expected_status=None, actor="admin")
    assert getattr(missing.value, "code", "") == "peer-key-not-found"


def test_revoke_active_key_opens_circuit_and_writes_audit(fed_env):
    key_a = Ed25519PrivateKey.generate()
    x_a = _b64url(key_a.public_key().public_bytes(encoding=serialization.Encoding.Raw, format=serialization.PublicFormat.Raw))
    discovery, jwks = _discovery_and_jwks(kid="a-k1", x=x_a)
    peers, _ = _create_services(fed_env, {"/.well-known/lfs": discovery, "/.well-known/jwks.json": jwks})
    peer = _create_peer(peers, key_a, kid="a-k1", x=x_a)
    with fed_env["db"].transaction() as s:
        row = s.execute(select(FederationTrustedPeer).where(FederationTrustedPeer.id == peer.id)).scalar_one()
        row.sync_enabled = False
    peers.revoke_peer_key(peer_id=peer.id, kid="a-k1", reason="compromise", expected_status="active", actor="admin")
    with fed_env["db"].transaction() as s:
        peer_row = s.execute(select(FederationTrustedPeer).where(FederationTrustedPeer.id == peer.id)).scalar_one()
        assert peer_row.circuit_state == CircuitState.OPEN.value
        actions = s.execute(
            select(FederationOperationalAudit.action).where(FederationOperationalAudit.peer_id == peer.id)
        ).scalars().all()
    assert AuditAction.PEER_KEY_REVOKE.value in actions
    assert AuditAction.SYNC_CIRCUIT_OPENED.value in actions


def test_new_key_endpoints_return_problem_json_for_errors(fed_env):
    key_a = Ed25519PrivateKey.generate()
    x_a = _b64url(key_a.public_key().public_bytes(encoding=serialization.Encoding.Raw, format=serialization.PublicFormat.Raw))
    discovery, jwks = _discovery_and_jwks(kid="a-k1", x=x_a)
    peers, _ = _create_services(fed_env, {"/.well-known/lfs": discovery, "/.well-known/jwks.json": jwks})
    peer = _create_peer(peers, key_a, kid="a-k1", x=x_a)
    with TestClient(create_app()) as client:
        response = client.post(
            f"/api/v1/admin/federation/peers/{peer.id}/keys/approve",
            json={
                "kid": "a-k1",
                "expectedFingerprint": "sha256:" + ("z" * 64),
                "reason": "wrong",
            },
            headers={"Authorization": "Bearer admin-token"},
        )
    assert response.status_code == 400
    assert response.headers["content-type"].startswith("application/problem+json")


def test_sync_rejects_revoked_key_without_cursor_advance(fed_env):
    key_a = Ed25519PrivateKey.generate()
    x_a = _b64url(key_a.public_key().public_bytes(encoding=serialization.Encoding.Raw, format=serialization.PublicFormat.Raw))
    discovery, jwks = _discovery_and_jwks(kid="a-k1", x=x_a)
    bundle = _record_event_bundle(kid="a-k1", key=key_a, local_id="INC4R", version="1", position=11, event_id=str(uuid.uuid4()))
    encoded = base64.urlsafe_b64encode(bundle["record"]["canonicalId"].encode()).decode().rstrip("=")
    peers, sync = _create_services(
        fed_env,
        {
            "/.well-known/lfs": discovery,
            "/.well-known/jwks.json": jwks,
            "changes:": {
                "events": [{"payload": bundle["event"], "signed": bundle["eventSigned"]}],
                "limit": 200,
                "hasMore": False,
                "nextCursor": None,
                "resumeCursor": "resume-11",
                "snapshotWatermark": 11,
            },
            f"record:{encoded}": {
                "record": bundle["record"],
                "signed": bundle["recordSigned"],
                "currentState": "published",
                "latestEventPosition": 11,
                "latestEventDigestSha256": bundle["eventSigned"]["digestSha256"],
            },
        },
    )
    peer = _create_peer(peers, key_a, kid="a-k1", x=x_a)
    with fed_env["db"].transaction() as s:
        key = s.execute(
            select(FederationPeerSigningKey).where(
                FederationPeerSigningKey.peer_id == peer.id,
                FederationPeerSigningKey.kid == "a-k1",
            )
        ).scalar_one()
        key.key_status = "revoked"
        cursor_before = s.execute(select(FederationPeerCursor).where(FederationPeerCursor.peer_id == peer.id)).scalar_one().cursor
    result = sync.sync_peer(peer_id=peer.id, trigger_type="manual", max_seconds=10)
    assert result.status == "failed"
    with fed_env["db"].transaction() as s:
        cursor_after = s.execute(select(FederationPeerCursor).where(FederationPeerCursor.peer_id == peer.id)).scalar_one().cursor
    assert cursor_after == cursor_before


def test_source_regression_no_increment5_rotation_changes():
    source = (REPO_ROOT / "src/license_facade_service/federation/inbound.py").read_text(encoding="utf-8")
    assert "signing_key.rotation_prepared" not in source
    assert "rotate_local_signing" not in source
    assert "FEDERATION_SIGNING_KEY_ROTATION" not in source


def test_source_regression_new_key_routes_and_no_async_bridge():
    source = (REPO_ROOT / "src/license_facade_service/api/federation/admin.py").read_text(encoding="utf-8")
    assert "/keys/inspect" in source
    assert "/keys/approve" in source
    assert "/keys/{kid}/retire" in source
    assert "/keys/{kid}/revoke" in source
    all_src = (REPO_ROOT / "src/license_facade_service").glob("**/*.py")
    for file in all_src:
        body = file.read_text(encoding="utf-8")
        assert "async_bridge" not in body
