from __future__ import annotations

import json
import os
import socket
import subprocess
import time
import base64
import threading
import copy
from pathlib import Path
from uuid import UUID, uuid4

import psycopg
import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from fastapi.testclient import TestClient
from sqlalchemy import create_engine, select, text
from sqlalchemy.orm import Session, sessionmaker

from src.license_facade_service.api.v1 import licenses as licenses_api
from src.license_facade_service.config.federation import FederationSettings
from src.license_facade_service.db.session import Database
from src.license_facade_service.db.models.federation import FederationChangeEvent, FederationRecord, FederationRdfOutboxJob, FederationSigningKey
from src.license_facade_service.federation.canonical_json import canonicalize_to_bytes
from src.license_facade_service.federation.digests import canonical_json_sha256_hex
from src.license_facade_service.federation.keys import SigningKeyService
from src.license_facade_service.federation.models import SignedFederationChangeEventPayload
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
from tests.schema_init import apply_schema_init_sql, reset_public_schema

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
        apply_schema_init_sql(dsn)
        reset_public_schema(dsn)
        yield dsn
    finally:
        subprocess.run(["docker", "kill", name], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=False)


@pytest.fixture
def fed_env(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, postgres_url: str):
    reset_public_schema(postgres_url)
    _seed_snapshot(tmp_path)

    key = Ed25519PrivateKey.generate()
    pem = key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    key_path = tmp_path / "federation_signing_key.pem"
    key_path.write_bytes(pem)
    key_path.chmod(0o600)

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
    monkeypatch.setenv("FEDERATION_ADMIN_CURSOR_SECRET", "c" * 64)
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


def _fetch_record_row(dsn: str, canonical_id: str) -> tuple[UUID, int, dict, str]:
    with psycopg.connect(dsn.replace("+psycopg", "")) as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                SELECT id, materialized_generation, payload, payload_digest_sha256
                FROM federation_records
                WHERE canonical_id=%s
                """,
                (canonical_id,),
            )
            record_id, generation, payload, digest = cur.fetchone()
            return record_id, int(generation or 0), payload, str(digest)


def _fetch_keyed_events(dsn: str, record_id: UUID) -> list[tuple[UUID, int, UUID | None, dict]]:
    with psycopg.connect(dsn.replace("+psycopg", "")) as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                SELECT id, event_sequence, idempotency_key, signed_payload
                FROM federation_change_events
                WHERE record_id=%s
                ORDER BY event_sequence
                """,
                (str(record_id),),
            )
            return [(row[0], int(row[1]), row[2], row[3]) for row in cur.fetchall()]


def _fetch_rdf_jobs(dsn: str, record_id: UUID) -> list[tuple[str, int, str, dict]]:
    with psycopg.connect(dsn.replace("+psycopg", "")) as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                SELECT dedupe_key, expected_generation, expected_digest_sha256, payload_json
                FROM federation_rdf_outbox_jobs
                WHERE record_id=%s
                ORDER BY dedupe_key
                """,
                (str(record_id),),
            )
            return [(str(row[0]), int(row[1]), str(row[2]), row[3]) for row in cur.fetchall()]





def _insert_legacy_authoritative_record_only(
    dsn: str,
    *,
    canonical_id: str,
    local_id: str,
    version: str,
    payload: dict,
    authority_node_id: str = NODE_ID,
    is_authoritative: bool = True,
    imported_from_peer_id: UUID | None = None,
    published_at_sql: str = "now()",
) -> UUID:
    record_id = uuid4()
    identity = build_canonical_license_identity(authority_node_id=authority_node_id, local_id=local_id, version=version)
    with psycopg.connect(dsn.replace("+psycopg", "")) as conn:
        with conn.cursor() as cur:
            cur.execute(
                f"""
                INSERT INTO federation_records (
                    id, authority_node_id, local_id, version, canonical_id, resolving_uuid, is_authoritative,
                    payload, payload_digest_sha256, published_at, materialized_generation, imported_from_peer_id,
                    lifecycle_state, created_at, updated_at
                ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s::jsonb, %s, {published_at_sql}, 0, %s, 'published', now(), now())
                """,
                (
                    str(record_id),
                    authority_node_id,
                    local_id,
                    version,
                    canonical_id,
                    identity.resolvingUuid,
                    is_authoritative,
                    json.dumps(payload),
                    canonical_json_sha256_hex(payload),
                    None if imported_from_peer_id is None else str(imported_from_peer_id),
                ),
            )
        conn.commit()
    return record_id


def _insert_trusted_peer(dsn: str, *, peer_node_id: str) -> UUID:
    peer_id = uuid4()
    with psycopg.connect(dsn.replace("+psycopg", "")) as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                INSERT INTO federation_trusted_peers (
                    id, peer_node_id, base_url, jwks_url, peer_name, operator_name,
                    trust_status, sync_enabled, allow_private_network, allowed_hostnames,
                    enrollment_mode, last_sync_status, created_at, updated_at
                ) VALUES (%s, %s, %s, %s, %s, %s, 'trusted', true, false, %s, 'strict', 'complete', now(), now())
                """,
                (
                    str(peer_id),
                    peer_node_id,
                    f"https://{peer_node_id}.example.test",
                    f"https://{peer_node_id}.example.test/.well-known/jwks.json",
                    peer_node_id,
                    peer_node_id,
                    peer_node_id,
                ),
            )
        conn.commit()
    return peer_id


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

    with fed_env["db"].transaction() as session:
        record_id, event_id = pub.publish_new_version_in_session(
            session=session,
            canonical_id=f"lfs:{NODE_ID}:Apache-2.0:1",
            authority_node_id=NODE_ID,
            local_id="Apache-2.0",
            version="1",
            payload={"licenseId": "Apache-2.0"},
        )
        assert isinstance(record_id, UUID)
        assert isinstance(event_id, UUID)
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
        SignedFederationChangeEventPayload.model_validate(e1["payload"])
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


def test_changes_fails_safely_on_malformed_stored_event_payload(fed_env):
    pub: FederationPublicationService = fed_env["publisher"]
    canonical = f"lfs:{NODE_ID}:SAFEFAIL:1"
    pub.publish_new_version(
        canonical_id=canonical,
        authority_node_id=NODE_ID,
        local_id="SAFEFAIL",
        version="1",
        payload={"licenseId": "SAFEFAIL"},
    )
    with psycopg.connect(fed_env["dsn"].replace("+psycopg", "")) as conn:
        with conn.cursor() as cur:
            cur.execute("SELECT id FROM federation_records WHERE canonical_id=%s", (canonical,))
            record_id = cur.fetchone()[0]
            cur.execute("SELECT COALESCE(MAX(event_sequence), 0) FROM federation_change_events")
            next_sequence = int(cur.fetchone()[0]) + 1
            cur.execute(
                """
                INSERT INTO federation_change_events (
                  id, event_sequence, event_type, authority_node_id, record_id, operation, generated_at,
                  payload_schema_version, signed_payload, signed_payload_digest_sha256, signature_base64url,
                  signature_kid, signature_alg, provenance_type, event_payload, event_digest_sha256,
                  occurred_at, created_at
                ) VALUES (%s, %s, 'record.changed', %s, %s, 'upsert', now(), '1',
                          '{"tampered": true}'::jsonb, 'bad', 'bad', %s, 'EdDSA', 'publication',
                          '{}'::jsonb, 'bad', now(), now())
                """,
                (str(uuid4()), next_sequence, NODE_ID, record_id, fed_env["settings"].active_kid),
            )
        conn.commit()

    with TestClient(create_app()) as client:
        response = client.get("/api/v1/federation/changes?limit=200")
        assert response.status_code == 500
        body = response.json()
        assert body["type"] == "https://eosc-eden.eu/problems/stored-federation-event-invalid"
        assert "tampered" not in response.text
        assert "ValidationError" not in response.text
        assert "events" not in body


def test_verify_bytes_fallback_rejects_unknown_non_active_kid(fed_env, monkeypatch: pytest.MonkeyPatch):
    verifier = SigningKeyService(fed_env["db"], fed_env["settings"])
    payload = canonicalize_to_bytes({"licenseId": "UNKNOWN-KID"})
    signature = verifier.sign_bytes(payload)
    monkeypatch.setattr(verifier, "_load_private_key", lambda: pytest.fail("private key should not be loaded for unknown kid"))
    with fed_env["db"].transaction() as session:
        session.query(FederationSigningKey).delete()
    assert verifier.verify_bytes(payload, signature_b64url=signature.value, kid="k2") is False


def test_verify_bytes_does_not_bypass_persisted_non_active_key_row(fed_env):
    verifier = SigningKeyService(fed_env["db"], fed_env["settings"])
    payload = canonicalize_to_bytes({"licenseId": "INACTIVE-ROW"})
    signature = verifier.sign_bytes(payload)
    replacement_key = Ed25519PrivateKey.generate().public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    replacement_x = base64.urlsafe_b64encode(replacement_key).decode("ascii").rstrip("=")
    with fed_env["db"].transaction() as session:
        row = session.query(FederationSigningKey).filter(FederationSigningKey.kid == fed_env["settings"].active_kid).one()
        row.status = "retired"
        row.is_active = False
        row.x = replacement_x
    assert verifier.verify_bytes(payload, signature_b64url=signature.value, kid=signature.kid) is False


def test_verify_bytes_fallback_rejects_wrong_signature_for_active_kid(fed_env):
    verifier = SigningKeyService(fed_env["db"], fed_env["settings"])
    payload = canonicalize_to_bytes({"licenseId": "WRONG-SIGNATURE"})
    other_key = Ed25519PrivateKey.generate()
    bad_signature = base64.urlsafe_b64encode(other_key.sign(payload)).decode("ascii").rstrip("=")
    with fed_env["db"].transaction() as session:
        session.query(FederationSigningKey).delete()
    assert verifier.verify_bytes(payload, signature_b64url=bad_signature, kid=fed_env["settings"].active_kid or "") is False


def test_verify_bytes_fallback_returns_boolean_only_and_no_key_material(fed_env):
    verifier = SigningKeyService(fed_env["db"], fed_env["settings"])
    payload = canonicalize_to_bytes({"licenseId": "BOOL-ONLY"})
    signature = verifier.sign_bytes(payload)
    with fed_env["db"].transaction() as session:
        session.query(FederationSigningKey).delete()
    result = verifier.verify_bytes(payload, signature_b64url=signature.value, kid=fed_env["settings"].active_kid or "")
    assert isinstance(result, bool)
    assert result is True


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


def test_schema_init_creates_phase2_change_event_triggers(postgres_url: str):
    reset_public_schema(postgres_url)
    with psycopg.connect(postgres_url.replace("+psycopg", "")) as conn:
        with conn.cursor() as cur:
            cur.execute("SELECT nextval('federation_change_event_sequence')")
            assert cur.fetchone()[0] == 1
            cur.execute("SELECT to_regprocedure('lfs_reject_federation_change_events_mutation()') IS NOT NULL")
            assert cur.fetchone()[0] is True
            cur.execute("SELECT to_regprocedure('lfs_reject_change_events_mutation()') IS NOT NULL")
            assert cur.fetchone()[0] is False
            cur.execute(
                "SELECT COUNT(*) FROM pg_trigger WHERE tgname IN ('trg_federation_change_events_no_update','trg_federation_change_events_no_delete')"
            )
            assert cur.fetchone()[0] == 2


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


def test_append_authoritative_upsert_revision_is_idempotent_and_preserves_immutable_record(fed_env):
    pub: FederationPublicationService = fed_env["publisher"]
    canonical = f"lfs:{NODE_ID}:REV:1"
    pub.publish_new_version(
        canonical_id=canonical,
        authority_node_id=NODE_ID,
        local_id="REV",
        version="1",
        payload={"licenseId": "REV", "name": "v1"},
    )
    key = uuid4()
    with fed_env["db"].transaction() as session:
        record = session.execute(select(FederationRecord).where(FederationRecord.canonical_id == canonical)).scalar_one()
        original_payload = dict(record.payload)
        original_digest = record.payload_digest_sha256
        original_generation = record.materialized_generation
        event = pub.append_authoritative_upsert_in_session(
            session=session,
            record_id=record.id,
            idempotency_key=key,
            payload={"licenseId": "REV", "name": "v2"},
        )
        assert event.idempotency_key == key
        assert record.payload == original_payload
        assert record.payload_digest_sha256 == original_digest
        assert record.materialized_generation == original_generation + 1
        same = pub.append_authoritative_upsert_in_session(
            session=session,
            record_id=record.id,
            idempotency_key=key,
            payload={"licenseId": "REV", "name": "v2"},
        )
        assert same.id == event.id
        assert record.materialized_generation == original_generation + 1

    record_id, generation, persisted_payload, persisted_digest = _fetch_record_row(fed_env["dsn"], canonical)
    events = _fetch_keyed_events(fed_env["dsn"], record_id)
    jobs = _fetch_rdf_jobs(fed_env["dsn"], record_id)
    assert generation == 2
    assert persisted_payload == {"licenseId": "REV", "name": "v1"}
    assert persisted_digest == canonical_json_sha256_hex({"licenseId": "REV", "name": "v1"})
    assert len(events) == 2
    assert events[-1][1] == 2
    assert events[-1][2] == key
    assert len(jobs) == 4
    revision_jobs = [job for job in jobs if job[1] == 2]
    assert len(revision_jobs) == 2
    for _, expected_generation, expected_digest, payload_json in revision_jobs:
        assert expected_generation == 2
        assert payload_json["recordPayload"]["payload"]["name"] == "v2"
        assert payload_json["recordDigestSha256"] == expected_digest


def test_append_authoritative_upsert_collision_and_same_content_new_key(fed_env):
    pub: FederationPublicationService = fed_env["publisher"]
    canonical = f"lfs:{NODE_ID}:COLLIDE:1"
    pub.publish_new_version(
        canonical_id=canonical,
        authority_node_id=NODE_ID,
        local_id="COLLIDE",
        version="1",
        payload={"licenseId": "COLLIDE", "name": "base"},
    )
    with fed_env["db"].transaction() as session:
        record = session.execute(select(FederationRecord).where(FederationRecord.canonical_id == canonical)).scalar_one()
        first = pub.append_authoritative_upsert_in_session(
            session=session,
            record_id=record.id,
            idempotency_key=uuid4(),
            payload={"licenseId": "COLLIDE", "name": "same-content"},
        )
        second = pub.append_authoritative_upsert_in_session(
            session=session,
            record_id=record.id,
            idempotency_key=uuid4(),
            payload={"licenseId": "COLLIDE", "name": "same-content"},
        )
        assert first.id != second.id
        with pytest.raises(FederationError, match="idempotency"):
            pub.append_authoritative_upsert_in_session(
                session=session,
                record_id=record.id,
                idempotency_key=first.idempotency_key,
                payload={"licenseId": "COLLIDE", "name": "different-content"},
            )


def test_append_authoritative_upsert_provenance_is_normalized_and_idempotent(fed_env):
    pub: FederationPublicationService = fed_env["publisher"]
    canonical = f"lfs:{NODE_ID}:PROVENANCE:1"
    pub.publish_new_version(
        canonical_id=canonical,
        authority_node_id=NODE_ID,
        local_id="PROVENANCE",
        version="1",
        payload={"licenseId": "PROVENANCE", "name": "v1"},
    )
    source_provenance = {"actor": "worker", "attempt": 1, "nested": {"reason": "revision"}}
    snapshot = copy.deepcopy(source_provenance)
    key = uuid4()
    with fed_env["db"].transaction() as session:
        record = session.execute(select(FederationRecord).where(FederationRecord.canonical_id == canonical)).scalar_one()
        event = pub.append_authoritative_upsert_in_session(
            session=session,
            record_id=record.id,
            idempotency_key=key,
            payload={"licenseId": "PROVENANCE", "name": "v2"},
            provenance=source_provenance,
        )
        source_provenance["nested"]["reason"] = "mutated"
        replay = pub.append_authoritative_upsert_in_session(
            session=session,
            record_id=record.id,
            idempotency_key=key,
            payload={"licenseId": "PROVENANCE", "name": "v2"},
            provenance=snapshot,
        )
        assert replay.id == event.id
        with pytest.raises(FederationError) as excinfo:
            pub.append_authoritative_upsert_in_session(
                session=session,
                record_id=record.id,
                idempotency_key=key,
                payload={"licenseId": "PROVENANCE", "name": "v2"},
                provenance={"actor": "worker", "attempt": 2, "nested": {"reason": "revision"}},
            )
        assert excinfo.value.code == "idempotency-collision"
    record_id, _, _, _ = _fetch_record_row(fed_env["dsn"], canonical)
    events = _fetch_keyed_events(fed_env["dsn"], record_id)
    jobs = _fetch_rdf_jobs(fed_env["dsn"], record_id)
    revision_payload = events[-1][3]
    assert revision_payload["provenance"] == snapshot
    for _, _, _, payload_json in jobs:
        if payload_json["recordGeneration"] == 2:
            assert payload_json["provenance"] == snapshot


def test_record_and_catalog_project_latest_revision_and_restore(fed_env):
    pub: FederationPublicationService = fed_env["publisher"]
    canonical = f"lfs:{NODE_ID}:PROJ:1"
    pub.publish_new_version(
        canonical_id=canonical,
        authority_node_id=NODE_ID,
        local_id="PROJ",
        version="1",
        payload={"licenseId": "PROJ", "name": "v1"},
    )
    with fed_env["db"].transaction() as session:
        record = session.execute(select(FederationRecord).where(FederationRecord.canonical_id == canonical)).scalar_one()
        pub.append_authoritative_upsert_in_session(
            session=session,
            record_id=record.id,
            idempotency_key=uuid4(),
            payload={"licenseId": "PROJ", "name": "v2"},
        )
        pub.append_authoritative_upsert_in_session(
            session=session,
            record_id=record.id,
            idempotency_key=uuid4(),
            payload={"licenseId": "PROJ", "name": "v1"},
        )
    with TestClient(create_app()) as client:
        encoded = encode_canonical_id(canonical)
        record_resp = client.get(f"/api/v1/federation/records/{encoded}")
        assert record_resp.status_code == 200
        body = record_resp.json()
        assert body["record"]["payload"]["name"] == "v1"
        catalog = client.get("/api/v1/federation/catalog?limit=100")
        item = next(x for x in catalog.json()["items"] if x["canonicalId"] == canonical)
        assert item["payloadDigestSha256"] == body["record"]["payloadDigestSha256"]
        changes = client.get("/api/v1/federation/changes?limit=100").json()["events"]
        matching = [e for e in changes if e["payload"]["record"]["canonicalId"] == canonical]
        assert [e["payload"]["record"]["payload"]["name"] for e in matching] == ["v1", "v2", "v1"]
        record_id, _, immutable_payload, _ = _fetch_record_row(fed_env["dsn"], canonical)
        assert immutable_payload["name"] == "v1"
        _ = record_id


def test_append_authoritative_upsert_concurrent_same_key_creates_one_event(fed_env):
    pub: FederationPublicationService = fed_env["publisher"]
    canonical = f"lfs:{NODE_ID}:CONCURRENT:1"
    pub.publish_new_version(
        canonical_id=canonical,
        authority_node_id=NODE_ID,
        local_id="CONCURRENT",
        version="1",
        payload={"licenseId": "CONCURRENT", "name": "v1"},
    )
    engine = create_engine(fed_env["dsn"], future=True)
    session_local = sessionmaker(bind=engine, class_=Session, expire_on_commit=False, future=True)
    barrier = threading.Barrier(2)
    results: list[dict[str, str]] = []
    key = uuid4()

    def _worker(name: str) -> None:
        session = session_local()
        try:
            record = session.execute(select(FederationRecord).where(FederationRecord.canonical_id == canonical)).scalar_one()
            barrier.wait(timeout=10)
            event = pub.append_authoritative_upsert_in_session(
                session=session,
                record_id=record.id,
                idempotency_key=key,
                payload={"licenseId": "CONCURRENT", "name": "v2"},
            )
            session.commit()
            results.append({"worker": name, "event_id": str(event.id)})
        except Exception as exc:
            session.rollback()
            results.append({"worker": name, "error": exc.__class__.__name__, "detail": str(exc)})
        finally:
            session.close()

    threads = [threading.Thread(target=_worker, args=(f"w{i}",), daemon=True) for i in (1, 2)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join(timeout=15)
        assert thread.is_alive() is False
    engine.dispose()
    assert len(results) == 2, results
    assert all("error" not in result for result in results), results
    assert len({result["event_id"] for result in results}) == 1, results
    record_id, generation, immutable_payload, immutable_digest = _fetch_record_row(fed_env["dsn"], canonical)
    events = _fetch_keyed_events(fed_env["dsn"], record_id)
    jobs = _fetch_rdf_jobs(fed_env["dsn"], record_id)
    assert immutable_payload == {"licenseId": "CONCURRENT", "name": "v1"}
    assert immutable_digest == canonical_json_sha256_hex({"licenseId": "CONCURRENT", "name": "v1"})
    keyed_events = [event for event in events if event[2] == key]
    assert len(keyed_events) == 1
    assert generation == 2
    revision_jobs = [job for job in jobs if job[1] == 2]
    assert len(revision_jobs) == 2


def test_append_authoritative_upsert_cross_record_same_key_collides_without_outer_rollback(fed_env):
    pub: FederationPublicationService = fed_env["publisher"]
    canonical_a = f"lfs:{NODE_ID}:CROSSA:1"
    canonical_b = f"lfs:{NODE_ID}:CROSSB:1"
    pub.publish_new_version(
        canonical_id=canonical_a,
        authority_node_id=NODE_ID,
        local_id="CROSSA",
        version="1",
        payload={"licenseId": "CROSSA", "name": "v1"},
    )
    pub.publish_new_version(
        canonical_id=canonical_b,
        authority_node_id=NODE_ID,
        local_id="CROSSB",
        version="1",
        payload={"licenseId": "CROSSB", "name": "v1"},
    )
    shared_key = uuid4()
    record_b_id, baseline_generation_b, _, _ = _fetch_record_row(fed_env["dsn"], canonical_b)
    baseline_events_b = _fetch_keyed_events(fed_env["dsn"], record_b_id)
    baseline_jobs_b = _fetch_rdf_jobs(fed_env["dsn"], record_b_id)
    baseline_job_keys_b = {job[0] for job in baseline_jobs_b}
    with fed_env["db"].transaction() as session:
        record_a = session.execute(select(FederationRecord).where(FederationRecord.canonical_id == canonical_a)).scalar_one()
        record_b = session.execute(select(FederationRecord).where(FederationRecord.canonical_id == canonical_b)).scalar_one()
        event = pub.append_authoritative_upsert_in_session(
            session=session,
            record_id=record_a.id,
            idempotency_key=shared_key,
            payload={"licenseId": "CROSSA", "name": "v2"},
        )
        session.execute(text("SELECT 1"))
        with pytest.raises(FederationError) as excinfo:
            pub.append_authoritative_upsert_in_session(
                session=session,
                record_id=record_b.id,
                idempotency_key=shared_key,
                payload={"licenseId": "CROSSB", "name": "v2"},
            )
        assert excinfo.value.code == "idempotency-collision"
        session.execute(text("SELECT 1"))
        assert event.idempotency_key == shared_key
    record_a_id, generation_a, _, _ = _fetch_record_row(fed_env["dsn"], canonical_a)
    record_b_id, generation_b, _, _ = _fetch_record_row(fed_env["dsn"], canonical_b)
    post_events_b = _fetch_keyed_events(fed_env["dsn"], record_b_id)
    post_jobs_b = _fetch_rdf_jobs(fed_env["dsn"], record_b_id)
    post_job_keys_b = {job[0] for job in post_jobs_b}
    winning_event = next(event_row for event_row in _fetch_keyed_events(fed_env["dsn"], record_a_id) if event_row[2] == shared_key)
    assert generation_a == winning_event[1]
    assert generation_b == baseline_generation_b
    assert len([event for event in _fetch_keyed_events(fed_env["dsn"], record_a_id) if event[2] == shared_key]) == 1
    assert post_events_b == baseline_events_b
    assert post_jobs_b == baseline_jobs_b
    assert post_job_keys_b == baseline_job_keys_b
    assert len([event for event in post_events_b if event[2] == shared_key]) == 0
    rejected_digest = canonical_json_sha256_hex({"licenseId": "CROSSB", "name": "v2"})
    assert not any(shared_key.hex in job[0] for job in post_jobs_b)
    assert not any(job[2] == rejected_digest and job[1] > baseline_generation_b for job in post_jobs_b)


def test_append_authoritative_upsert_caller_rollback_is_atomic(fed_env):
    pub: FederationPublicationService = fed_env["publisher"]
    canonical = f"lfs:{NODE_ID}:ROLLBACK:1"
    pub.publish_new_version(
        canonical_id=canonical,
        authority_node_id=NODE_ID,
        local_id="ROLLBACK",
        version="1",
        payload={"licenseId": "ROLLBACK", "name": "v1"},
    )
    record_id, before_generation, immutable_payload, immutable_digest = _fetch_record_row(fed_env["dsn"], canonical)
    session = Session(bind=create_engine(fed_env["dsn"], future=True), expire_on_commit=False, future=True)
    try:
        record = session.execute(select(FederationRecord).where(FederationRecord.id == record_id)).scalar_one()
        pub.append_authoritative_upsert_in_session(
            session=session,
            record_id=record.id,
            idempotency_key=uuid4(),
            payload={"licenseId": "ROLLBACK", "name": "v2"},
        )
        session.rollback()
    finally:
        bind = session.get_bind()
        session.close()
        bind.dispose()
    _, after_generation, after_payload, after_digest = _fetch_record_row(fed_env["dsn"], canonical)
    assert after_generation == before_generation
    assert after_payload == immutable_payload
    assert after_digest == immutable_digest
    assert len(_fetch_keyed_events(fed_env["dsn"], record_id)) == 1
    assert len(_fetch_rdf_jobs(fed_env["dsn"], record_id)) == 2


def test_append_authoritative_upsert_caller_commit_persists_event_generation_and_rdf(fed_env):
    pub: FederationPublicationService = fed_env["publisher"]
    canonical = f"lfs:{NODE_ID}:COMMIT:1"
    pub.publish_new_version(
        canonical_id=canonical,
        authority_node_id=NODE_ID,
        local_id="COMMIT",
        version="1",
        payload={"licenseId": "COMMIT", "name": "v1"},
    )
    with fed_env["db"].transaction() as session:
        record = session.execute(select(FederationRecord).where(FederationRecord.canonical_id == canonical)).scalar_one()
        event = pub.append_authoritative_upsert_in_session(
            session=session,
            record_id=record.id,
            idempotency_key=uuid4(),
            payload={"licenseId": "COMMIT", "name": "v2"},
        )
        event_id = event.id
    record_id, generation, immutable_payload, _ = _fetch_record_row(fed_env["dsn"], canonical)
    assert generation == 2
    assert immutable_payload["name"] == "v1"
    events = _fetch_keyed_events(fed_env["dsn"], record_id)
    assert any(event_row[0] == event_id for event_row in events)
    assert len([job for job in _fetch_rdf_jobs(fed_env["dsn"], record_id) if job[1] == 2]) == 2


@pytest.mark.parametrize(
    ("case_name", "record_factory", "idempotency_key", "payload", "provenance", "expected_code"),
    [
        ("missing-record", lambda env: uuid4(), uuid4, lambda: {"licenseId": "X"}, None, "record-not-found"),
        ("null-idempotency", lambda env: env["record_id"], lambda: None, lambda: {"licenseId": "X"}, None, "invalid-idempotency-key"),
        ("string-idempotency", lambda env: env["record_id"], lambda: "not-a-uuid", lambda: {"licenseId": "X"}, None, "invalid-idempotency-key"),
        ("non-dict-payload", lambda env: env["record_id"], uuid4, lambda: ["bad"], None, "invalid-record"),
        ("invalid-provenance", lambda env: env["record_id"], uuid4, lambda: {"licenseId": "X"}, ["bad"], "invalid-event-payload"),
    ],
)
def test_append_authoritative_upsert_rejections_do_not_mutate_basic_cases(
    fed_env, case_name, record_factory, idempotency_key, payload, provenance, expected_code
):
    pub: FederationPublicationService = fed_env["publisher"]
    canonical = f"lfs:{NODE_ID}:REJECTBASIC:1"
    pub.publish_new_version(
        canonical_id=canonical,
        authority_node_id=NODE_ID,
        local_id="REJECTBASIC",
        version="1",
        payload={"licenseId": "X", "name": "v1"},
    )
    record_id, before_generation, before_payload, before_digest = _fetch_record_row(fed_env["dsn"], canonical)
    env = {"record_id": record_id}
    with fed_env["db"].transaction() as session:
        session.execute(text("SELECT 1"))
        with pytest.raises(FederationError) as excinfo:
            pub.append_authoritative_upsert_in_session(
                session=session,
                record_id=record_factory(env),
                idempotency_key=idempotency_key(),
                payload=payload(),
                provenance=provenance,
            )
        session.execute(text("SELECT 1"))
    assert excinfo.value.code == expected_code, case_name
    _, after_generation, after_payload, after_digest = _fetch_record_row(fed_env["dsn"], canonical)
    assert after_generation == before_generation
    assert after_payload == before_payload
    assert after_digest == before_digest
    assert len(_fetch_keyed_events(fed_env["dsn"], record_id)) == 1
    assert len(_fetch_rdf_jobs(fed_env["dsn"], record_id)) == 2


def test_append_authoritative_upsert_rejections_for_record_state_and_authority(fed_env):
    pub: FederationPublicationService = fed_env["publisher"]
    base_canonical = f"lfs:{NODE_ID}:REJECTSTATE:1"
    pub.publish_new_version(
        canonical_id=base_canonical,
        authority_node_id=NODE_ID,
        local_id="REJECTSTATE",
        version="1",
        payload={"licenseId": "REJECTSTATE", "name": "v1"},
    )
    authoritative_id, authoritative_generation, _, _ = _fetch_record_row(fed_env["dsn"], base_canonical)
    imported_peer_id = _insert_trusted_peer(fed_env["dsn"], peer_node_id="11111111-1111-4111-8111-111111111111")
    imported_id = _insert_legacy_authoritative_record_only(
        fed_env["dsn"],
        canonical_id=f"lfs:{NODE_ID}:IMPORTEDLIKE:1",
        local_id="IMPORTEDLIKE",
        version="1",
        payload={"licenseId": "IMPORTEDLIKE", "name": "v1"},
        imported_from_peer_id=imported_peer_id,
    )
    wrong_node_id = _insert_legacy_authoritative_record_only(
        fed_env["dsn"],
        canonical_id="lfs:00000000-0000-0000-0000-000000000000:WRONGNODE:1",
        local_id="WRONGNODE",
        version="1",
        payload={"licenseId": "WRONGNODE", "name": "v1"},
        authority_node_id="00000000-0000-0000-0000-000000000000",
    )
    unpublished_id = _insert_legacy_authoritative_record_only(
        fed_env["dsn"],
        canonical_id=f"lfs:{NODE_ID}:UNPUBLISHED:1",
        local_id="UNPUBLISHED",
        version="1",
        payload={"licenseId": "UNPUBLISHED", "name": "v1"},
        published_at_sql="NULL",
    )
    non_authoritative_id = _insert_legacy_authoritative_record_only(
        fed_env["dsn"],
        canonical_id=f"lfs:{NODE_ID}:NONAUTH-DIRECT:1",
        local_id="NONAUTH",
        version="1",
        payload={"licenseId": "NONAUTH", "name": "v1"},
        is_authoritative=False,
    )
    tombstone_canonical = f"lfs:{NODE_ID}:TOMBSTONED:1"
    pub.publish_new_version(
        canonical_id=tombstone_canonical,
        authority_node_id=NODE_ID,
        local_id="TOMBSTONED",
        version="1",
        payload={"licenseId": "TOMBSTONED", "name": "v1"},
    )
    pub.append_state_event(canonical_id=tombstone_canonical, operation="tombstone")
    tombstone_id, tombstone_generation, tombstone_payload, tombstone_digest = _fetch_record_row(fed_env["dsn"], tombstone_canonical)

    cases = [
        (non_authoritative_id, "non-authoritative-record"),
        (imported_id, "non-authoritative-record"),
        (wrong_node_id, "non-authoritative-record"),
        (unpublished_id, "unpublished-record"),
        (tombstone_id, "invalid-state-transition"),
    ]
    for record_id, expected_code in cases:
        with fed_env["db"].transaction() as session:
            session.execute(text("SELECT 1"))
            with pytest.raises(FederationError) as excinfo:
                pub.append_authoritative_upsert_in_session(
                    session=session,
                    record_id=record_id,
                    idempotency_key=uuid4(),
                    payload={"licenseId": "X", "name": "v2"},
                )
            session.execute(text("SELECT 1"))
        assert excinfo.value.code == expected_code
    _, after_generation, after_payload, after_digest = _fetch_record_row(fed_env["dsn"], tombstone_canonical)
    assert after_generation == tombstone_generation
    assert after_payload == tombstone_payload
    assert after_digest == tombstone_digest
    _, authoritative_after_generation, _, _ = _fetch_record_row(fed_env["dsn"], base_canonical)
    assert authoritative_after_generation == authoritative_generation


def test_revision_etag_projection_and_restore_flow(fed_env):
    pub: FederationPublicationService = fed_env["publisher"]
    canonical = f"lfs:{NODE_ID}:ETAGREV:1"
    initial_payload = {"licenseId": "ETAGREV", "name": "v1", "licenseText": "Initial"}
    revised_payload = {"licenseId": "ETAGREV", "name": "v2", "licenseText": "Revised"}
    pub.publish_new_version(
        canonical_id=canonical,
        authority_node_id=NODE_ID,
        local_id="ETAGREV",
        version="1",
        payload=initial_payload,
    )
    encoded = encode_canonical_id(canonical)
    with TestClient(create_app()) as client:
        initial = client.get(f"/api/v1/federation/records/{encoded}")
        assert initial.status_code == 200
        initial_etag = initial.headers["etag"]
        with fed_env["db"].transaction() as session:
            record = session.execute(select(FederationRecord).where(FederationRecord.canonical_id == canonical)).scalar_one()
            revised_event = pub.append_authoritative_upsert_in_session(
                session=session,
                record_id=record.id,
                idempotency_key=uuid4(),
                payload=revised_payload,
            )
            restored_event = pub.append_authoritative_upsert_in_session(
                session=session,
                record_id=record.id,
                idempotency_key=uuid4(),
                payload=initial_payload,
            )
        revised = client.get(f"/api/v1/federation/records/{encoded}")
        assert revised.status_code == 200
        revised_body = revised.json()
        assert revised_body["record"]["payload"] == initial_payload
        assert revised.headers["etag"] != initial_etag
        assert client.get(f"/api/v1/federation/records/{encoded}", headers={"If-None-Match": initial_etag}).status_code == 200
        assert client.get(f"/api/v1/federation/records/{encoded}", headers={"If-None-Match": revised.headers["etag"]}).status_code == 304
        catalog = client.get("/api/v1/federation/catalog?limit=100").json()
        item = next(entry for entry in catalog["items"] if entry["canonicalId"] == canonical)
        assert item["payloadDigestSha256"] == revised_body["record"]["payloadDigestSha256"]
        changes = client.get("/api/v1/federation/changes?limit=100").json()["events"]
        matching = [entry for entry in changes if entry["payload"]["record"]["canonicalId"] == canonical]
        assert [entry["payload"]["record"]["payload"]["name"] for entry in matching] == ["v1", "v2", "v1"]
        assert matching[-2]["payload"]["eventPosition"] == revised_event.event_sequence
        assert matching[-1]["payload"]["eventPosition"] == restored_event.event_sequence
    _, _, immutable_payload, _ = _fetch_record_row(fed_env["dsn"], canonical)
    assert immutable_payload == initial_payload


def test_revision_signature_and_tamper_proof(fed_env):
    pub: FederationPublicationService = fed_env["publisher"]
    verifier = SigningKeyService(fed_env["db"], fed_env["settings"])
    canonical = f"lfs:{NODE_ID}:SIGREV:1"
    pub.publish_new_version(
        canonical_id=canonical,
        authority_node_id=NODE_ID,
        local_id="SIGREV",
        version="1",
        payload={"licenseId": "SIGREV", "name": "v1"},
    )
    with fed_env["db"].transaction() as session:
        record = session.execute(select(FederationRecord).where(FederationRecord.canonical_id == canonical)).scalar_one()
        event = pub.append_authoritative_upsert_in_session(
            session=session,
            record_id=record.id,
            idempotency_key=uuid4(),
            payload={"licenseId": "SIGREV", "name": "v2"},
        )
        payload = SignedFederationChangeEventPayload.model_validate(event.signed_payload)
        payload_bytes = canonicalize_to_bytes(payload.model_dump(mode="json"))
        assert event.signed_payload_digest_sha256 == canonical_json_sha256_hex(payload.model_dump(mode="json"))
        assert verifier.verify_bytes(payload_bytes, signature_b64url=event.signature_base64url, kid=event.signature_kid)
        assert payload.record.payloadDigestSha256 == canonical_json_sha256_hex(payload.record.payload)
        assert payload.record.canonicalId == record.canonical_id
        assert payload.record.authorityNodeId == record.authority_node_id
        assert payload.record.localId == record.local_id
        assert payload.record.version == record.version
        tampered = payload.model_copy(deep=True)
        tampered.record.payload["name"] = "tampered"
        tampered_bytes = canonicalize_to_bytes(tampered.model_dump(mode="json"))
        assert verifier.verify_bytes(tampered_bytes, signature_b64url=event.signature_base64url, kid=event.signature_kid) is False
