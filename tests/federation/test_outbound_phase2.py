from __future__ import annotations

import json
import os
import socket
import subprocess
import time
from pathlib import Path
from uuid import uuid4

import psycopg
import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from fastapi.testclient import TestClient

from src.license_facade_service.api.v1 import licenses as licenses_api
from src.license_facade_service.config.federation import FederationSettings
from src.license_facade_service.db.session import Database
from src.license_facade_service.federation.canonical_json import canonicalize_to_bytes
from src.license_facade_service.federation.keys import SigningKeyService
from src.license_facade_service.federation.outbound import (
    FederationBackfillService,
    FederationError,
    FederationPublicationService,
    encode_canonical_id,
)
from src.license_facade_service.federation.license_identity import build_canonical_license_identity
from src.license_facade_service.federation.runtime import FederationRuntime
from src.license_facade_service.main import create_app
from src.license_facade_service.services.auth import AuthService
from src.license_facade_service.services.licenses import LicenseService, SPDXClient

REPO_ROOT = Path(__file__).resolve().parents[2]
NODE_ID = "de305d54-75b4-431b-adb2-eb6b9e546014"


class _StaticSpdx(SPDXClient):
    async def fetch_license_list(self):
        return {"licenseListVersion": "1", "licenses": [{"licenseId": "MIT"}]}

    async def fetch_license_details(self, license_id: str):
        return {"licenseId": license_id, "name": "MIT", "licenseText": "x", "crossRef": []}


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


@pytest.fixture(scope="module")
def postgres_url():
    if not _docker_available():
        pytest.skip("docker not available for PostgreSQL phase2 federation tests")
    port = _free_port()
    name = f"lfs-pg-phase2-{uuid4().hex[:8]}"
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
    raw = dsn.replace("+psycopg", "")
    try:
        deadline = time.time() + 45
        while time.time() < deadline:
            try:
                with psycopg.connect(raw):
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

    key = Ed25519PrivateKey.generate()
    pem = key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    key_path = tmp_path / "federation_signing_key.pem"
    key_path.write_bytes(pem)

    monkeypatch.setenv("BASE_DIR", str(REPO_ROOT))
    monkeypatch.setenv("URL_BASE", "https://example.test/api/v1/licenses")
    monkeypatch.setenv("FUSEKI_ENABLE", "false")
    monkeypatch.setenv("FEDERATION_ENABLED", "true")
    monkeypatch.setenv("FEDERATION_DATABASE_URL", postgres_url)
    monkeypatch.setenv("FEDERATION_NODE_ID", NODE_ID)
    monkeypatch.setenv("FEDERATION_PUBLIC_BASE_URL", "https://node.example.org")
    monkeypatch.setenv("FEDERATION_NODE_NAME", "EDEN Node")
    monkeypatch.setenv("FEDERATION_OPERATOR", "EDEN Operator")
    monkeypatch.setenv("FEDERATION_SIGNING_KEY_PATH", str(key_path))
    monkeypatch.setenv("FEDERATION_ACTIVE_KID", "k1")
    monkeypatch.setenv("FEDERATION_JWKS_ENABLED", "true")
    monkeypatch.setenv("RELOAD_ENABLE", "false")

    service = LicenseService(base_dir=tmp_path, spdx_client=_StaticSpdx())
    licenses_api._license_service = service
    licenses_api._auth_service = AuthService()
    settings = FederationSettings.from_env()
    db = Database.from_url(postgres_url)
    runtime = FederationRuntime(settings)
    state = runtime.initialize()
    assert state.ready
    pub = FederationPublicationService(db, settings)
    return {"db": db, "settings": settings, "publisher": pub, "dsn": postgres_url}


def _count(dsn: str, table: str) -> int:
    with psycopg.connect(dsn.replace("+psycopg", "")) as conn:
        with conn.cursor() as cur:
            cur.execute(f"SELECT COUNT(*) FROM {table}")
            return int(cur.fetchone()[0])


def test_disabled_policy_404(monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setenv("BASE_DIR", str(REPO_ROOT))
    monkeypatch.setenv("FEDERATION_ENABLED", "false")
    monkeypatch.setenv("FUSEKI_ENABLE", "false")
    with TestClient(create_app()) as client:
        for path in [
            "/.well-known/lfs",
            "/.well-known/jwks.json",
            "/api/v1/federation/catalog",
            "/api/v1/federation/changes",
            "/api/v1/federation/records/abc",
        ]:
            assert client.get(path).status_code == 404


def test_publication_requires_local_authority_and_deterministic_uuid(fed_env):
    pub: FederationPublicationService = fed_env["publisher"]
    before_records = _count(fed_env["dsn"], "federation_records")
    before_events = _count(fed_env["dsn"], "federation_change_events")
    with pytest.raises(FederationError):
        pub.publish_new_version(
            canonical_id=f"lfs:{NODE_ID}:X:1",
            authority_node_id="00000000-0000-0000-0000-000000000000",
            local_id="X",
            version="1",
            payload={"x": 1},
        )
    assert _count(fed_env["dsn"], "federation_records") == before_records
    assert _count(fed_env["dsn"], "federation_change_events") == before_events

    pub.publish_new_version(
        canonical_id=f"lfs:{NODE_ID}:Apache-2.0:1",
        authority_node_id=NODE_ID,
        local_id="Apache-2.0",
        version="1",
        payload={"licenseId": "Apache-2.0"},
    )
    with psycopg.connect(fed_env["dsn"].replace("+psycopg", "")) as conn:
        with conn.cursor() as cur:
            cur.execute("SELECT resolving_uuid FROM federation_records WHERE canonical_id=%s", (f"lfs:{NODE_ID}:Apache-2.0:1",))
            resolving = str(cur.fetchone()[0])
    expected = build_canonical_license_identity(authority_node_id=NODE_ID, local_id="Apache-2.0", version="1").resolvingUuid
    assert resolving == expected


def test_changes_resume_cursor_and_incremental_visibility(fed_env):
    pub: FederationPublicationService = fed_env["publisher"]
    pub.publish_new_version(
        canonical_id=f"lfs:{NODE_ID}:A:1",
        authority_node_id=NODE_ID,
        local_id="A",
        version="1",
        payload={"licenseId": "A"},
    )
    with TestClient(create_app()) as client:
        first = client.get("/api/v1/federation/changes?limit=10")
        assert first.status_code == 200
        body = first.json()
        assert body["hasMore"] is False
        assert body["resumeCursor"]
        assert body["nextCursor"] is None
        seen = [e["payload"]["eventId"] for e in body["events"]]
        resume = body["resumeCursor"]

        pub.publish_new_version(
            canonical_id=f"lfs:{NODE_ID}:B:1",
            authority_node_id=NODE_ID,
            local_id="B",
            version="1",
            payload={"licenseId": "B"},
        )
        second = client.get(f"/api/v1/federation/changes?since={resume}&limit=10")
        assert second.status_code == 200
        ids = [e["payload"]["eventId"] for e in second.json()["events"]]
        assert len(ids) == 1
        assert ids[0] not in seen


def test_state_transitions_and_record_catalog_consistency(fed_env):
    pub: FederationPublicationService = fed_env["publisher"]
    cid = f"lfs:{NODE_ID}:STATE:1"
    pub.publish_new_version(
        canonical_id=cid,
        authority_node_id=NODE_ID,
        local_id="STATE",
        version="1",
        payload={"licenseId": "STATE"},
    )
    encoded = encode_canonical_id(cid)
    with TestClient(create_app()) as client:
        rec = client.get(f"/api/v1/federation/records/{encoded}")
        assert rec.status_code == 200
        assert rec.json()["currentState"] == "published"
        etag_published = rec.headers["etag"]

        pub.append_state_event(canonical_id=cid, operation="deprecate")
        rec_dep = client.get(f"/api/v1/federation/records/{encoded}")
        assert rec_dep.status_code == 200
        assert rec_dep.json()["currentState"] == "deprecated"
        assert rec_dep.headers["etag"] != etag_published

        cat = client.get("/api/v1/federation/catalog?limit=100")
        item = next(x for x in cat.json()["items"] if x["canonicalId"] == cid)
        assert item["publicationState"] == rec_dep.json()["currentState"]

        with pytest.raises(FederationError):
            pub.append_state_event(canonical_id=cid, operation="deprecate")

        pub.append_state_event(canonical_id=cid, operation="tombstone")
        gone = client.get(f"/api/v1/federation/records/{encoded}")
        assert gone.status_code == 404
        with pytest.raises(FederationError):
            pub.append_state_event(canonical_id=cid, operation="tombstone")
        with pytest.raises(FederationError):
            pub.append_state_event(canonical_id=cid, operation="deprecate")


def test_get_is_read_only_and_event_signatures_stable(fed_env):
    pub: FederationPublicationService = fed_env["publisher"]
    pub.publish_new_version(
        canonical_id=f"lfs:{NODE_ID}:SIG:1",
        authority_node_id=NODE_ID,
        local_id="SIG",
        version="1",
        payload={"licenseId": "SIG"},
    )
    before = _count(fed_env["dsn"], "federation_change_events")
    with TestClient(create_app()) as client:
        r1 = client.get("/api/v1/federation/changes?limit=1")
        r2 = client.get("/api/v1/federation/changes?limit=1")
        assert r1.status_code == 200 and r2.status_code == 200
        e1 = r1.json()["events"][0]
        e2 = r2.json()["events"][0]
        assert e1["payload"] == e2["payload"]
        assert e1["signed"]["digestSha256"] == e2["signed"]["digestSha256"]
        assert e1["signed"]["signature"]["value"] == e2["signed"]["signature"]["value"]
        verifier = SigningKeyService(fed_env["db"], fed_env["settings"])
        assert verifier.verify_bytes(
            canonicalize_to_bytes(e1["payload"]),
            signature_b64url=e1["signed"]["signature"]["value"],
            kid=e1["signed"]["signature"]["kid"],
        )
    after = _count(fed_env["dsn"], "federation_change_events")
    assert before == after


def test_append_only_events_reject_update_delete(fed_env):
    pub: FederationPublicationService = fed_env["publisher"]
    pub.publish_new_version(
        canonical_id=f"lfs:{NODE_ID}:IMM:1",
        authority_node_id=NODE_ID,
        local_id="IMM",
        version="1",
        payload={"licenseId": "IMM"},
    )
    with psycopg.connect(fed_env["dsn"].replace("+psycopg", "")) as conn:
        with conn.cursor() as cur:
            cur.execute("SELECT id FROM federation_change_events ORDER BY event_sequence LIMIT 1")
            event_id = cur.fetchone()[0]
            with pytest.raises(psycopg.errors.RaiseException):
                cur.execute(
                    "UPDATE federation_change_events SET operation='deprecate' WHERE id=%s",
                    (event_id,),
                )
            conn.rollback()
            with pytest.raises(psycopg.errors.RaiseException):
                cur.execute("DELETE FROM federation_change_events WHERE id=%s", (event_id,))


def test_catalog_filters_invalid_without_paging_loss(fed_env):
    pub: FederationPublicationService = fed_env["publisher"]
    pub.publish_new_version(
        canonical_id=f"lfs:{NODE_ID}:A1:1",
        authority_node_id=NODE_ID,
        local_id="A1",
        version="1",
        payload={"licenseId": "A1"},
    )
    pub.publish_new_version(
        canonical_id=f"lfs:{NODE_ID}:C1:1",
        authority_node_id=NODE_ID,
        local_id="C1",
        version="1",
        payload={"licenseId": "C1"},
    )
    with psycopg.connect(fed_env["dsn"].replace("+psycopg", "")) as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                INSERT INTO federation_records (
                  id, authority_node_id, local_id, version, canonical_id, resolving_uuid, is_authoritative,
                  payload, payload_digest_sha256, published_at, imported_from_peer_id, created_at, updated_at
                ) VALUES (%s,%s,'BAD','1','lfs:bad',%s,true,'{}'::jsonb,'x',now(),NULL,now(),now())
                """,
                (str(uuid4()), NODE_ID, str(uuid4())),
            )
    with TestClient(create_app()) as client:
        first = client.get("/api/v1/federation/catalog?limit=1")
        assert first.status_code == 200
        second = client.get(f"/api/v1/federation/catalog?limit=1&cursor={first.json()['nextCursor']}")
        assert second.status_code == 200
        ids = [first.json()["items"][0]["canonicalId"], second.json()["items"][0]["canonicalId"]]
        assert f"lfs:{NODE_ID}:A1:1" in ids
        assert f"lfs:{NODE_ID}:C1:1" in ids


def test_backfill_scans_all_batches_and_idempotent(fed_env):
    with psycopg.connect(fed_env["dsn"].replace("+psycopg", "")) as conn:
        with conn.cursor() as cur:
            for i in range(6):
                cid = f"lfs:{NODE_ID}:BF{i}:1"
                identity = build_canonical_license_identity(authority_node_id=NODE_ID, local_id=f"BF{i}", version="1")
                cur.execute(
                    """
                    INSERT INTO federation_records (
                      id, authority_node_id, local_id, version, canonical_id, resolving_uuid, is_authoritative,
                      payload, payload_digest_sha256, published_at, imported_from_peer_id, created_at, updated_at
                    ) VALUES (%s,%s,%s,'1',%s,%s,true,'{}'::jsonb,'x',now(),NULL,now(),now())
                    """,
                    (str(uuid4()), NODE_ID, f"BF{i}", cid, identity.resolvingUuid),
                )
            conn.commit()
    backfill = FederationBackfillService(fed_env["db"], fed_env["settings"])
    dry = backfill.backfill_missing_events(apply_changes=False, confirm_write=False, batch_size=2)
    assert dry["scanned"] >= 6
    with pytest.raises(FederationError):
        backfill.backfill_missing_events(apply_changes=True, confirm_write=False, batch_size=2)
    applied = backfill.backfill_missing_events(apply_changes=True, confirm_write=True, batch_size=2)
    assert applied["scanned"] >= 6
    second = backfill.backfill_missing_events(apply_changes=True, confirm_write=True, batch_size=2)
    assert second["inserted"] == 0


def test_migration_upgrade_downgrade_upgrade_repeatable(postgres_url: str):
    _run_alembic(postgres_url, "downgrade", "base")
    _run_alembic(postgres_url, "upgrade", "20260804_02")
    with psycopg.connect(postgres_url.replace("+psycopg", "")) as conn:
        with conn.cursor() as cur:
            cur.execute("SELECT nextval('federation_change_event_sequence')")
            assert cur.fetchone()[0] == 1
            cur.execute("SELECT to_regprocedure('lfs_reject_federation_change_events_mutation()') IS NOT NULL")
            assert cur.fetchone()[0] is True
            cur.execute(
                "SELECT COUNT(*) FROM pg_trigger WHERE tgname IN ('trg_federation_change_events_no_update','trg_federation_change_events_no_delete')"
            )
            assert cur.fetchone()[0] == 2
    _run_alembic(postgres_url, "downgrade", "20260804_01")
    with psycopg.connect(postgres_url.replace("+psycopg", "")) as conn:
        with conn.cursor() as cur:
            cur.execute("SELECT to_regprocedure('lfs_reject_federation_change_events_mutation()') IS NULL")
            assert cur.fetchone()[0] is True
            cur.execute("SELECT pg_get_triggerdef(oid) FROM pg_trigger WHERE tgname = 'trg_federation_change_events_no_update'")
            assert "lfs_reject_change_events_mutation" in cur.fetchone()[0]
    _run_alembic(postgres_url, "upgrade", "20260804_02")
    with psycopg.connect(postgres_url.replace("+psycopg", "")) as conn:
        with conn.cursor() as cur:
            cur.execute("SELECT to_regprocedure('lfs_reject_federation_change_events_mutation()') IS NOT NULL")
            assert cur.fetchone()[0] is True


def test_etag_and_if_none_match_semantics(fed_env):
    pub: FederationPublicationService = fed_env["publisher"]
    cid = f"lfs:{NODE_ID}:ETAG:1"
    pub.publish_new_version(
        canonical_id=cid,
        authority_node_id=NODE_ID,
        local_id="ETAG",
        version="1",
        payload={"licenseId": "ETAG"},
    )
    with TestClient(create_app()) as client:
        encoded = encode_canonical_id(cid)
        rec = client.get(f"/api/v1/federation/records/{encoded}")
        assert rec.status_code == 200
        etag = rec.headers["etag"]
        nm = client.get(f"/api/v1/federation/records/{encoded}", headers={"If-None-Match": etag})
        assert nm.status_code == 304
        assert nm.content == b""
