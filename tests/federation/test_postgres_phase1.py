from __future__ import annotations

import json
import os
import socket
import subprocess
import time
from pathlib import Path
from uuid import UUID, uuid4
from uuid import uuid4

import psycopg
import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from fastapi.testclient import TestClient

from src.license_facade_service.api.v1 import licenses as licenses_api
from src.license_facade_service.main import create_app
from src.license_facade_service.services.auth import AuthService
from src.license_facade_service.services.licenses import LicenseService, SPDXClient
from tests.schema_init import apply_schema_init_sql, reset_public_schema

REPO_ROOT = Path(__file__).resolve().parents[2]


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
        pytest.skip("docker not available for PostgreSQL migration test")

    port = _free_port()
    container_name = f"lfs-pg-{uuid4().hex[:8]}"
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
    raw_dsn = f"postgresql://postgres:postgres@127.0.0.1:{port}/lfs_federation"
    try:
        deadline = time.time() + 45
        while time.time() < deadline:
            try:
                with psycopg.connect(raw_dsn):
                    break
            except Exception:
                time.sleep(1)
        else:
            raise RuntimeError("postgres container did not become ready in time")
        apply_schema_init_sql(dsn)
        reset_public_schema(dsn)
        yield dsn
    finally:
        subprocess.run(["docker", "kill", container_name], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=False)


def test_schema_init_creates_phase1_tables(postgres_url: str):
    check_sql = """
    SELECT to_regclass('public.federation_node_identity_state') IS NOT NULL AS identity_exists,
           to_regclass('public.federation_signing_keys') IS NOT NULL AS keys_exists,
           to_regclass('public.federation_trusted_peers') IS NOT NULL AS peers_exists,
           to_regclass('public.federation_records') IS NOT NULL AS records_exists,
           to_regclass('public.federation_record_aliases') IS NOT NULL AS aliases_exists,
           to_regclass('public.federation_record_representations') IS NOT NULL AS reps_exists,
           to_regclass('public.federation_record_provenance') IS NOT NULL AS provenance_exists,
           to_regclass('public.federation_change_events') IS NOT NULL AS events_exists,
           to_regclass('public.federation_peer_cursors') IS NOT NULL AS cursors_exists,
           to_regclass('public.federation_sync_attempts') IS NOT NULL AS sync_exists,
           to_regclass('public.federation_conflicts') IS NOT NULL AS conflicts_exists
    """
    with psycopg.connect(postgres_url.replace("+psycopg", "")) as conn:
        with conn.cursor() as cur:
            cur.execute(check_sql)
            row = cur.fetchone()
            assert row is not None
            assert all(row)


def test_federation_identity_key_readiness_and_jwks(postgres_url: str, tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    _seed_snapshot(tmp_path)

    private_key = Ed25519PrivateKey.generate()
    pem = private_key.private_bytes(
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
    monkeypatch.setenv("FEDERATION_NODE_ID", "de305d54-75b4-431b-adb2-eb6b9e546014")
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
    with TestClient(create_app()) as client:
        ready = client.get("/api/v1/ready")
        assert ready.status_code == 200
        assert ready.json()["federation"]["enabled"] is True
        assert ready.json()["federation"]["ready"] is True

        jwks = client.get("/.well-known/jwks.json")
        assert jwks.status_code == 200
        payload = jwks.json()
        assert "keys" in payload
        assert len(payload["keys"]) >= 1
        assert payload["keys"][0]["kid"] == "k1"
        assert payload["keys"][0]["alg"] == "EdDSA"
        assert payload["keys"][0]["crv"] == "Ed25519"

    monkeypatch.setenv("FEDERATION_NODE_NAME", "Changed Node Name")
    with TestClient(create_app()) as client_changed:
        ready_changed = client_changed.get("/api/v1/ready")
        assert ready_changed.status_code == 200
        assert ready_changed.json()["federation"]["ready"] is False
        assert "configuration changed" in " ".join(ready_changed.json()["federation"]["errors"]).lower()


def test_federation_change_event_idempotency_schema_and_repeatability(postgres_url: str):
    authority_a = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"
    authority_b = "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb"
    key_a = uuid4()
    key_b = uuid4()
    with psycopg.connect(postgres_url.replace("+psycopg", "")) as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                SELECT data_type, is_nullable
                FROM information_schema.columns
                WHERE table_schema = 'public'
                  AND table_name = 'federation_change_events'
                  AND column_name = 'idempotency_key'
                """
            )
            assert cur.fetchone() == ("uuid", "YES")
            cur.execute(
                """
                SELECT indexname, indexdef
                FROM pg_indexes
                WHERE schemaname = 'public'
                  AND tablename = 'federation_change_events'
                  AND indexname = 'uix_fce_authority_idempotency'
                """
            )
            index_row = cur.fetchone()
            assert index_row is not None
            index_name, indexdef = index_row
            assert len(index_name) <= 63
            assert "(authority_node_id, idempotency_key)" in indexdef
            assert "WHERE (idempotency_key IS NOT NULL)" in indexdef
            cur.execute(
                """
                INSERT INTO federation_change_events (
                    id, event_sequence, event_type, authority_node_id, idempotency_key, record_id,
                    operation, generated_at, payload_schema_version, signed_payload,
                    signed_payload_digest_sha256, signature_base64url, signature_kid, signature_alg,
                    provenance_type, event_payload, event_digest_sha256, occurred_at, created_at
                ) VALUES
                (%s, 1, 'record.changed', %s, NULL, NULL, 'upsert', now(), '1', '{}'::jsonb, 'd1', 's1', 'k1', 'EdDSA', 'publication', '{}'::jsonb, 'e1', now(), now()),
                (%s, 2, 'record.changed', %s, NULL, NULL, 'upsert', now(), '1', '{}'::jsonb, 'd2', 's2', 'k1', 'EdDSA', 'publication', '{}'::jsonb, 'e2', now(), now()),
                (%s, 3, 'record.changed', %s, %s, NULL, 'upsert', now(), '1', '{}'::jsonb, 'd3', 's3', 'k1', 'EdDSA', 'publication', '{}'::jsonb, 'e3', now(), now()),
                (%s, 4, 'record.changed', %s, %s, NULL, 'upsert', now(), '1', '{}'::jsonb, 'd4', 's4', 'k1', 'EdDSA', 'publication', '{}'::jsonb, 'e4', now(), now()),
                (%s, 5, 'record.changed', %s, %s, NULL, 'upsert', now(), '1', '{}'::jsonb, 'd5', 's5', 'k1', 'EdDSA', 'publication', '{}'::jsonb, 'e5', now(), now())
                """,
                (
                    str(uuid4()), authority_a,
                    str(uuid4()), authority_a,
                    str(uuid4()), authority_a, key_a,
                    str(uuid4()), authority_a, key_b,
                    str(uuid4()), authority_b, key_a,
                ),
            )
            with pytest.raises(psycopg.errors.UniqueViolation):
                cur.execute("SAVEPOINT duplicate_key_attempt")
                cur.execute(
                    """
                    INSERT INTO federation_change_events (
                        id, event_sequence, event_type, authority_node_id, idempotency_key, record_id,
                        operation, generated_at, payload_schema_version, signed_payload,
                        signed_payload_digest_sha256, signature_base64url, signature_kid, signature_alg,
                        provenance_type, event_payload, event_digest_sha256, occurred_at, created_at
                    ) VALUES (
                        %s, 6, 'record.changed', %s, %s, NULL, 'upsert', now(), '1', '{}'::jsonb,
                        'd6', 's6', 'k1', 'EdDSA', 'publication', '{}'::jsonb, 'e6', now(), now()
                    )
                    """,
                    (str(uuid4()), authority_a, key_a),
                )
            cur.execute("ROLLBACK TO SAVEPOINT duplicate_key_attempt")
            cur.execute("RELEASE SAVEPOINT duplicate_key_attempt")
        conn.commit()

    with psycopg.connect(postgres_url.replace("+psycopg", "")) as conn:
        with conn.cursor() as cur:
            cur.execute("SELECT COUNT(*) FROM federation_change_events WHERE idempotency_key IS NULL")
            assert cur.fetchone()[0] == 2
            cur.execute(
                "SELECT COUNT(*) FROM federation_change_events WHERE authority_node_id = %s AND idempotency_key IS NOT NULL",
                (authority_a,),
            )
            assert cur.fetchone()[0] == 2
            cur.execute(
                "SELECT COUNT(*) FROM federation_change_events WHERE authority_node_id = %s AND idempotency_key = %s",
                (authority_b, key_a),
            )
            assert cur.fetchone()[0] == 1
            cur.execute(
                """
                SELECT COUNT(*)
                FROM pg_indexes
                WHERE schemaname = 'public'
                  AND tablename = 'federation_change_events'
                  AND indexdef ILIKE '%%payload_digest_sha256%%UNIQUE%%'
                """
            )
            assert cur.fetchone()[0] == 0

    from tests.schema_init import read_current_revision, run_alembic

    assert read_current_revision(postgres_url) == "20260904_03"
    run_alembic(postgres_url, "downgrade", "20260904_02")
    with psycopg.connect(postgres_url.replace("+psycopg", "")) as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                SELECT COUNT(*)
                FROM information_schema.columns
                WHERE table_schema = 'public'
                  AND table_name = 'federation_change_events'
                  AND column_name = 'idempotency_key'
                """
            )
            assert cur.fetchone()[0] == 0
            cur.execute(
                """
                SELECT COUNT(*)
                FROM pg_indexes
                WHERE schemaname = 'public'
                  AND tablename = 'federation_change_events'
                  AND indexname = 'uix_fce_authority_idempotency'
                """
            )
            assert cur.fetchone()[0] == 0
    run_alembic(postgres_url, "upgrade", "head")
    assert read_current_revision(postgres_url) == "20260904_03"
    with psycopg.connect(postgres_url.replace("+psycopg", "")) as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                SELECT data_type, is_nullable
                FROM information_schema.columns
                WHERE table_schema = 'public'
                  AND table_name = 'federation_change_events'
                  AND column_name = 'idempotency_key'
                """
            )
            assert cur.fetchone() == ("uuid", "YES")
