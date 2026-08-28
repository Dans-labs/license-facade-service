from __future__ import annotations

import os
import re
import socket
import subprocess
import threading
import time
import uuid
import json
from contextlib import contextmanager
from types import SimpleNamespace
from datetime import datetime, timedelta, timezone
from pathlib import Path

import psycopg
import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec, ed25519
from fastapi.testclient import TestClient
from sqlalchemy import select, text, update

from src.license_facade_service.api.federation import jwks as jwks_api
from src.license_facade_service.api.federation import operational as operational_api
from src.license_facade_service.api.v1 import licenses as licenses_api
from src.license_facade_service import worker as federation_worker
from src.license_facade_service.config.federation import FederationSettings
from src.license_facade_service.db.models.federation import FederationSigningKey, FederationWorkerHeartbeat
from src.license_facade_service.db.session import Database
from src.license_facade_service.federation.audit import AuditAction, AuditValidationError, WorkerStatus
from src.license_facade_service.federation.identity import NodeIdentityService
from src.license_facade_service.federation.keys import SigningKeyService
from src.license_facade_service.federation.outbound import FederationPublicationService, encode_canonical_id
from src.license_facade_service.federation import local_key_lifecycle as lifecycle_mod
from src.license_facade_service.federation.local_key_lifecycle import (
    DirectoryPrivateKeyProvider,
    LocalKeyError,
    LocalKeyErrorCode,
    LocalKeyInspectionResult,
    LocalKeyState,
    SingleFilePrivateKeyProvider,
    SigningKeyLifecycleService,
    b64url_decode,
)
from src.license_facade_service.federation.runtime import FederationRuntime
from src.license_facade_service.main import create_app
from src.license_facade_service.services.auth import AuthService
from src.license_facade_service.services.licenses import LicenseService, SPDXClient

REPO_ROOT = Path(__file__).resolve().parents[2]
INC4_HEAD = "20260814_01"
INC5_HEAD = "c8b534db4b5c"
NODE_ID = "de305d54-75b4-431b-adb2-eb6b9e546014"


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


def _run_alembic(database_url: str, *command: str, expect_success: bool = True) -> subprocess.CompletedProcess:
    env = dict(os.environ)
    env["ALEMBIC_DATABASE_URL"] = database_url
    proc = subprocess.run(
        ["uv", "run", "alembic", "-c", str(REPO_ROOT / "alembic.ini"), *command],
        cwd=REPO_ROOT,
        env=env,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    if expect_success and proc.returncode != 0:
        raise AssertionError(f"Alembic failed: {' '.join(command)}\n{proc.stdout}\n{proc.stderr}")
    if not expect_success and proc.returncode == 0:
        raise AssertionError(f"Alembic unexpectedly succeeded: {' '.join(command)}")
    return proc


def _raw_dsn(database_url: str) -> str:
    return database_url.replace("+psycopg", "")


def _gen_ed25519_pem(path: Path) -> str:
    key = ed25519.Ed25519PrivateKey.generate()
    pem = key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    path.write_bytes(pem)
    path.chmod(0o600)
    return pem.decode("utf-8")


def _gen_non_ed25519_pem(path: Path) -> None:
    key = ec.generate_private_key(ec.SECP256R1())
    pem = key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    path.write_bytes(pem)
    path.chmod(0o600)


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


@pytest.fixture(scope="module")
def postgres_url() -> str:
    if not _docker_available():
        pytest.skip("docker not available for increment 5 postgres-backed tests")
    port = _free_port()
    name = f"lfs-p5i5-{port}"
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
            "POSTGRES_DB=lfs_test",
            "-p",
            f"{port}:5432",
            "postgres:16-alpine",
        ],
        check=True,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    dsn = f"postgresql+psycopg://postgres:postgres@127.0.0.1:{port}/lfs_test"
    raw = _raw_dsn(dsn)
    try:
        deadline = time.time() + 45
        while time.time() < deadline:
            try:
                with psycopg.connect(raw):
                    break
            except Exception:
                time.sleep(0.5)
        else:
            raise RuntimeError("postgres did not start")
        yield dsn
    finally:
        subprocess.run(["docker", "kill", name], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=False)


@pytest.fixture
def configured_env(monkeypatch: pytest.MonkeyPatch, tmp_path: Path, postgres_url: str):
    _reset_public_schema(postgres_url)
    _run_alembic(postgres_url, "upgrade", "head")
    key_dir = tmp_path / "keys"
    key_dir.mkdir(parents=True, exist_ok=True)
    _gen_ed25519_pem(key_dir / "k1.pem")
    monkeypatch.setenv("FEDERATION_ENABLED", "true")
    monkeypatch.setenv("FEDERATION_DATABASE_URL", postgres_url)
    monkeypatch.setenv("FEDERATION_NODE_ID", NODE_ID)
    monkeypatch.setenv("FEDERATION_PUBLIC_BASE_URL", "https://node.example.org")
    monkeypatch.setenv("FEDERATION_NODE_NAME", "EDEN Node")
    monkeypatch.setenv("FEDERATION_OPERATOR", "EDEN Operator")
    monkeypatch.setenv("FEDERATION_SIGNING_KEY_DIR", str(key_dir))
    monkeypatch.setenv("FEDERATION_ACTIVE_KID", "k1")
    monkeypatch.setenv("FEDERATION_ADMIN_CURSOR_SECRET", "c" * 64)
    settings = FederationSettings.from_env()
    db = Database.from_url(postgres_url)
    NodeIdentityService(db, settings).ensure_identity_state()
    return {"settings": settings, "db": db, "key_dir": key_dir}


@pytest.fixture
def federation_api_client(configured_env, monkeypatch: pytest.MonkeyPatch, tmp_path: Path):
    _seed_snapshot(tmp_path)
    monkeypatch.setenv("BASE_DIR", str(REPO_ROOT))
    monkeypatch.setenv("URL_BASE", "https://example.test/api/v1/licenses")
    monkeypatch.setenv("FUSEKI_ENABLE", "false")
    monkeypatch.setenv("LFS_ADMIN_TOKEN", "admin-token")
    monkeypatch.setenv("LFS_CURATOR_TOKEN", "curator-token")
    monkeypatch.setenv("RELOAD_ENABLE", "false")
    licenses_api._license_service = LicenseService(base_dir=tmp_path, spdx_client=_StaticSpdx())
    licenses_api._auth_service = AuthService()
    with TestClient(create_app()) as client:
        yield client, configured_env


def _insert_signing_key(
    dsn: str,
    *,
    kid: str,
    x: str,
    status: str,
    is_active: bool = False,
    rotation_scheduled_at: datetime | None = None,
    created_at: datetime | None = None,
    updated_at: datetime | None = None,
) -> None:
    now = datetime.now(timezone.utc)
    created_at = created_at or now
    updated_at = updated_at or now
    with psycopg.connect(_raw_dsn(dsn)) as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                INSERT INTO federation_signing_keys
                    (id, kid, alg, kty, crv, x, is_active, status, valid_from, rotation_scheduled_at, created_at, updated_at)
                VALUES
                    (%s, %s, 'EdDSA', 'OKP', 'Ed25519', %s, %s, %s, %s, %s, %s, %s)
                """,
                (uuid.uuid4(), kid, x, is_active, status, now, rotation_scheduled_at, created_at, updated_at),
            )
        conn.commit()


def _read_all_keys(dsn: str) -> list[tuple[str, str, bool, str, datetime | None]]:
    with psycopg.connect(_raw_dsn(dsn)) as conn:
        with conn.cursor() as cur:
            cur.execute(
                "SELECT kid, status, is_active, x, rotation_scheduled_at FROM federation_signing_keys ORDER BY kid"
            )
            return list(cur.fetchall())


def _extract_check_values(dsn: str, constraint_name: str) -> set[str]:
    with psycopg.connect(_raw_dsn(dsn)) as conn:
        with conn.cursor() as cur:
            cur.execute("SELECT pg_get_constraintdef(oid) FROM pg_constraint WHERE conname = %s", (constraint_name,))
            row = cur.fetchone()
            assert row is not None
            return set(re.findall(r"'([^']+)'", row[0]))


def _reset_public_schema(dsn: str) -> None:
    with psycopg.connect(_raw_dsn(dsn), autocommit=True) as conn:
        with conn.cursor() as cur:
            cur.execute("DROP SCHEMA IF EXISTS public CASCADE")
            cur.execute("CREATE SCHEMA public")
            cur.execute("GRANT ALL ON SCHEMA public TO postgres")
            cur.execute("GRANT ALL ON SCHEMA public TO public")


def _read_audit_rows(dsn: str) -> list[tuple]:
    with psycopg.connect(_raw_dsn(dsn)) as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                SELECT id, action, target_id, outcome, reason, redacted_details, occurred_at
                FROM federation_operational_audit
                ORDER BY occurred_at, id
                """
            )
            return list(cur.fetchall())


def _assert_audit_append_only(dsn: str) -> None:
    with psycopg.connect(_raw_dsn(dsn)) as conn:
        with conn.cursor() as cur:
            cur.execute("SELECT id FROM federation_operational_audit ORDER BY occurred_at, id LIMIT 1")
            row = cur.fetchone()
            assert row is not None
            with pytest.raises(Exception):
                cur.execute("UPDATE federation_operational_audit SET action = action WHERE id = %s", (row[0],))
            conn.rollback()


def test_migration_upgrade_downgrade_upgrade_preserves_rows(postgres_url: str):
    _reset_public_schema(postgres_url)
    _run_alembic(postgres_url, "downgrade", "base")
    _run_alembic(postgres_url, "upgrade", INC4_HEAD)
    base_x = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
    _insert_signing_key(postgres_url, kid="k-active-old", x=base_x, status="active", is_active=True)
    _insert_signing_key(postgres_url, kid="k-inactive-old", x=base_x, status="inactive", is_active=False)
    _insert_signing_key(postgres_url, kid="k-retired-old", x=base_x, status="retired", is_active=False)
    _insert_signing_key(postgres_url, kid="k-revoked-old", x=base_x, status="revoked", is_active=False)
    _run_alembic(postgres_url, "upgrade", "head")
    rows = _read_all_keys(postgres_url)
    status_map = {kid: status for kid, status, *_ in rows}
    x_map = {kid: x for kid, _, _, x, _ in rows}
    assert status_map["k-inactive-old"] == "staged"
    assert status_map["k-retired-old"] == "retired"
    assert status_map["k-revoked-old"] == "revoked"
    assert status_map["k-active-old"] == "active"
    assert all(x == base_x for x in x_map.values())
    _run_alembic(postgres_url, "downgrade", INC4_HEAD)
    downgraded = _read_all_keys(postgres_url)
    assert any(kid == "k-inactive-old" and status == "inactive" for kid, status, *_ in downgraded)
    _run_alembic(postgres_url, "upgrade", "head")
    upgraded_again = _read_all_keys(postgres_url)
    assert len(upgraded_again) == len(rows)
    assert {kid: x for kid, _, _, x, _ in upgraded_again} == x_map


def test_migration_unknown_status_fails_loudly(postgres_url: str):
    _reset_public_schema(postgres_url)
    _run_alembic(postgres_url, "downgrade", "base")
    _run_alembic(postgres_url, "upgrade", INC4_HEAD)
    with psycopg.connect(_raw_dsn(postgres_url)) as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                INSERT INTO federation_signing_keys
                    (id, kid, alg, kty, crv, x, is_active, status, created_at, updated_at)
                VALUES
                    (%s, %s, 'EdDSA', 'OKP', 'Ed25519', %s, false, 'mystery', now(), now())
                """,
                (uuid.uuid4(), "k-weird", "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"),
            )
        conn.commit()
    proc = _run_alembic(postgres_url, "upgrade", "head", expect_success=False)
    assert "Unknown federation_signing_keys.status values found" in (proc.stdout + proc.stderr)


def test_constraints_enforced(postgres_url: str):
    _reset_public_schema(postgres_url)
    _run_alembic(postgres_url, "downgrade", "base")
    _run_alembic(postgres_url, "upgrade", "head")
    with psycopg.connect(_raw_dsn(postgres_url)) as conn:
        with conn.cursor() as cur:
            with pytest.raises(psycopg.errors.CheckViolation):
                cur.execute(
                    """
                    INSERT INTO federation_signing_keys
                        (id, kid, alg, kty, crv, x, is_active, status, created_at, updated_at)
                    VALUES
                        (%s, %s, 'EdDSA', 'OKP', 'Ed25519', %s, false, 'active', now(), now())
                    """,
                    (uuid.uuid4(), "bad-active-false", "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"),
                )
            conn.rollback()
            with pytest.raises(psycopg.errors.CheckViolation):
                cur.execute(
                    """
                    INSERT INTO federation_signing_keys
                        (id, kid, alg, kty, crv, x, is_active, status, created_at, updated_at)
                    VALUES
                        (%s, %s, 'EdDSA', 'OKP', 'Ed25519', %s, true, 'staged', now(), now())
                    """,
                    (uuid.uuid4(), "bad-staged-true", "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"),
                )
            conn.rollback()
            _insert_signing_key(postgres_url, kid="ok-active", x="AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", status="active", is_active=True)
            with pytest.raises(psycopg.errors.UniqueViolation):
                cur.execute(
                    """
                    INSERT INTO federation_signing_keys
                        (id, kid, alg, kty, crv, x, is_active, status, created_at, updated_at)
                    VALUES
                        (%s, %s, 'EdDSA', 'OKP', 'Ed25519', %s, true, 'active', now(), now())
                    """,
                    (uuid.uuid4(), "another-active", "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB"),
                )
            conn.rollback()


def test_schedule_constraints(postgres_url: str):
    _reset_public_schema(postgres_url)
    _run_alembic(postgres_url, "downgrade", "base")
    _run_alembic(postgres_url, "upgrade", "head")
    with psycopg.connect(_raw_dsn(postgres_url)) as conn:
        with conn.cursor() as cur:
            with pytest.raises(psycopg.errors.CheckViolation):
                cur.execute(
                    """
                    INSERT INTO federation_signing_keys
                        (id, kid, alg, kty, crv, x, is_active, status, rotation_scheduled_at, created_at, updated_at)
                    VALUES
                        (%s, %s, 'EdDSA', 'OKP', 'Ed25519', %s, false, 'retired', now(), now(), now())
                    """,
                    (uuid.uuid4(), "retired-scheduled", "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"),
                )
            conn.rollback()
            _insert_signing_key(
                postgres_url,
                kid="s1",
                x="AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
                status="staged",
                rotation_scheduled_at=datetime.now(timezone.utc),
            )
            with pytest.raises(psycopg.errors.UniqueViolation):
                _insert_signing_key(
                    postgres_url,
                    kid="s2",
                    x="BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB",
                    status="staged",
                    rotation_scheduled_at=datetime.now(timezone.utc) + timedelta(seconds=30),
                )
            conn.rollback()


def test_provider_security_contract(tmp_path: Path):
    key_dir = tmp_path / "keys"
    key_dir.mkdir()
    _gen_ed25519_pem(key_dir / "good-kid.pem")
    provider = DirectoryPrivateKeyProvider(str(key_dir), enforce_permissions=True)
    material = provider.load_private_key("good-kid")
    assert material.kid == "good-kid"
    assert material.public_x
    with pytest.raises(LocalKeyError) as invalid:
        provider.load_private_key("../bad")
    assert invalid.value.code == LocalKeyErrorCode.INVALID_KID
    with pytest.raises(LocalKeyError):
        provider.load_private_key("ünicode")
    outside = tmp_path / "outside.pem"
    _gen_ed25519_pem(outside)
    (key_dir / "escape.pem").symlink_to(outside)
    with pytest.raises(LocalKeyError) as escaped:
        provider.load_private_key("escape")
    assert escaped.value.code in {LocalKeyErrorCode.KEY_PATH_ESCAPE, LocalKeyErrorCode.KEY_NOT_FOUND}
    (key_dir / "empty.pem").write_text("", encoding="utf-8")
    (key_dir / "empty.pem").chmod(0o600)
    with pytest.raises(LocalKeyError) as empty:
        provider.load_private_key("empty")
    assert empty.value.code == LocalKeyErrorCode.KEY_EMPTY
    bad_perm = key_dir / "world.pem"
    _gen_ed25519_pem(bad_perm)
    bad_perm.chmod(0o644)
    with pytest.raises(LocalKeyError) as bad_mode:
        provider.load_private_key("world")
    assert bad_mode.value.code == LocalKeyErrorCode.KEY_UNSAFE_PERMISSIONS
    malformed = key_dir / "malformed.pem"
    malformed.write_text("not-a-pem", encoding="utf-8")
    malformed.chmod(0o600)
    with pytest.raises(LocalKeyError) as bad_pem:
        provider.load_private_key("malformed")
    assert bad_pem.value.code == LocalKeyErrorCode.KEY_MALFORMED
    non_ed = key_dir / "noned.pem"
    _gen_non_ed25519_pem(non_ed)
    with pytest.raises(LocalKeyError) as non_ed_err:
        provider.load_private_key("noned")
    assert non_ed_err.value.code == LocalKeyErrorCode.KEY_NOT_ED25519
    assert str(non_ed) not in str(non_ed_err.value)
    assert "BEGIN PRIVATE KEY" not in str(non_ed_err.value)


def test_bootstrap_and_signing_flow(configured_env):
    db: Database = configured_env["db"]
    settings: FederationSettings = configured_env["settings"]
    service = SigningKeyService(db, settings)
    active = service.ensure_runtime_active_key()
    assert active.kid == "k1"
    sig = service.sign_bytes(b"abc")
    assert sig.kid == "k1"
    assert service.verify_bytes(b"abc", signature_b64url=sig.value, kid=sig.kid)


def test_concurrent_bootstrap_single_winner(configured_env):
    db: Database = configured_env["db"]
    settings: FederationSettings = configured_env["settings"]
    with db.transaction() as session:
        session.execute(update(FederationSigningKey).values(status="staged", is_active=False, rotation_scheduled_at=None))
    results: list[str] = []
    errors: list[str] = []

    def _run() -> None:
        try:
            svc = SigningKeyService(db, settings)
            results.append(svc.ensure_runtime_active_key().kid)
        except Exception as exc:
            errors.append(str(exc))

    threads = [threading.Thread(target=_run) for _ in range(4)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert not errors
    assert results
    with db.transaction() as session:
        rows = (
            session.execute(
                select(FederationSigningKey).where(
                    FederationSigningKey.status == "active", FederationSigningKey.is_active.is_(True)
                )
            )
            .scalars()
            .all()
        )
    assert len(rows) == 1


def test_restart_does_not_rewrite_db_active(configured_env, monkeypatch: pytest.MonkeyPatch):
    db: Database = configured_env["db"]
    key_dir: Path = configured_env["key_dir"]
    settings = configured_env["settings"]
    SigningKeyService(db, settings).ensure_runtime_active_key()
    _gen_ed25519_pem(key_dir / "k2.pem")
    monkeypatch.setenv("FEDERATION_ACTIVE_KID", "k2")
    changed = FederationSettings.from_env()
    svc = SigningKeyService(db, changed)
    assert svc.ensure_runtime_active_key().kid == "k1"


def test_missing_or_mismatched_active_material_fails_readiness(configured_env):
    db: Database = configured_env["db"]
    settings: FederationSettings = configured_env["settings"]
    svc = SigningKeyService(db, settings)
    svc.ensure_runtime_active_key()
    key_path = configured_env["key_dir"] / "k1.pem"
    key_path.unlink()
    state_missing = FederationRuntime(settings=settings).initialize()
    assert state_missing.ready is False
    _gen_ed25519_pem(key_path)
    with db.transaction() as session:
        active = session.execute(
            select(FederationSigningKey).where(FederationSigningKey.status == "active", FederationSigningKey.is_active.is_(True))
        ).scalar_one()
        active.x = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
    state_mismatch = FederationRuntime(settings=settings).initialize()
    assert state_mismatch.ready is False


def test_non_active_states_cannot_sign(configured_env):
    db: Database = configured_env["db"]
    settings: FederationSettings = configured_env["settings"]
    svc = SigningKeyService(db, settings)
    svc.ensure_runtime_active_key()
    with db.transaction() as session:
        active = session.execute(
            select(FederationSigningKey).where(FederationSigningKey.status == "active", FederationSigningKey.is_active.is_(True))
        ).scalar_one()
        active.status = "staged"
        active.is_active = False
    with pytest.raises(LocalKeyError) as exc:
        svc.sign_bytes(b"x")
    assert exc.value.code == LocalKeyErrorCode.ACTIVE_KEY_MISSING


def test_lifecycle_foundation_ops(configured_env):
    db: Database = configured_env["db"]
    settings: FederationSettings = configured_env["settings"]
    provider = DirectoryPrivateKeyProvider(str(configured_env["key_dir"]), enforce_permissions=True)
    lifecycle = SigningKeyLifecycleService(db, provider)
    SigningKeyService(db, settings).ensure_runtime_active_key()

    _gen_ed25519_pem(configured_env["key_dir"] / "k2.pem")
    staged = lifecycle.stage_candidate(kid="k2", reason="stage")
    assert staged.status == LocalKeyState.STAGED
    again = lifecycle.stage_candidate(kid="k2", reason="stage-again", expected_state=LocalKeyState.STAGED)
    assert again.reason_code == "staged-idempotent"
    schedule = lifecycle.schedule_activation(
        kid="k2",
        activate_at=datetime.now(timezone.utc) + timedelta(seconds=1),
        reason="schedule",
    )
    assert schedule.rotation_scheduled_at is not None
    with pytest.raises(LocalKeyError) as second_sched:
        _gen_ed25519_pem(configured_env["key_dir"] / "k3.pem")
        lifecycle.stage_candidate(kid="k3", reason="stage-k3")
        lifecycle.schedule_activation(
            kid="k3",
            activate_at=datetime.now(timezone.utc) + timedelta(seconds=2),
            reason="second-schedule",
        )
    assert second_sched.value.code == LocalKeyErrorCode.SCHEDULE_CONFLICT
    cancelled = lifecycle.cancel_schedule(kid="k2", reason="cancel")
    assert cancelled.reason_code == "schedule-cancelled"
    lifecycle.schedule_activation(
        kid="k2",
        activate_at=datetime.now(timezone.utc),
        reason="schedule-now",
    )
    activated = lifecycle.activate_staged_key(kid="k2", reason="activate")
    assert activated.status == LocalKeyState.ACTIVE
    with db.transaction() as session:
        current = session.execute(
            select(FederationSigningKey).where(FederationSigningKey.kid.in_(["k1", "k2"])).order_by(FederationSigningKey.kid)
        ).scalars().all()
    row = {r.kid: r for r in current}
    assert row["k2"].status == "active"
    assert row["k1"].status == "retired"


def test_retire_and_emergency_revoke_policy(configured_env):
    db: Database = configured_env["db"]
    settings: FederationSettings = configured_env["settings"]
    provider = DirectoryPrivateKeyProvider(str(configured_env["key_dir"]), enforce_permissions=True)
    lifecycle = SigningKeyLifecycleService(db, provider)
    SigningKeyService(db, settings).ensure_runtime_active_key()
    _gen_ed25519_pem(configured_env["key_dir"] / "kr.pem")
    lifecycle.stage_candidate(kid="kr", reason="stage")
    lifecycle.schedule_activation(kid="kr", activate_at=datetime.now(timezone.utc), reason="sched")
    retired = lifecycle.retire_staged_key(kid="kr", reason="retire")
    assert retired.status == LocalKeyState.RETIRED
    with pytest.raises(LocalKeyError) as active_retire:
        lifecycle.retire_staged_key(kid="k1", reason="bad", expected_state=LocalKeyState.ACTIVE)
    assert active_retire.value.code == LocalKeyErrorCode.TRANSITION_FORBIDDEN
    with db.transaction() as session:
        row = session.execute(select(FederationSigningKey).where(FederationSigningKey.kid == "kr")).scalar_one()
        row.status = "revoked"
    with pytest.raises(LocalKeyError) as revoked_retire:
        lifecycle.retire_staged_key(kid="kr", reason="bad")
    assert revoked_retire.value.code == LocalKeyErrorCode.TRANSITION_FORBIDDEN

    _gen_ed25519_pem(configured_env["key_dir"] / "k-next.pem")
    lifecycle.stage_candidate(kid="k-next", reason="stage-successor")
    result = lifecycle.emergency_revoke_with_successor(
        active_kid=SigningKeyService(db, settings).get_active_kid(),
        successor_kid="k-next",
        reason="emergency",
    )
    assert result.status == LocalKeyState.REVOKED
    with db.transaction() as session:
        active_rows = session.execute(
            select(FederationSigningKey).where(FederationSigningKey.status == "active", FederationSigningKey.is_active.is_(True))
        ).scalars().all()
    assert len(active_rows) == 1
    assert active_rows[0].kid == "k-next"


def test_concurrent_activation_and_signing_race(configured_env):
    db: Database = configured_env["db"]
    settings: FederationSettings = configured_env["settings"]
    key_dir: Path = configured_env["key_dir"]
    signing = SigningKeyService(db, settings)
    signing.ensure_runtime_active_key()
    provider = DirectoryPrivateKeyProvider(str(key_dir), enforce_permissions=True)
    lifecycle = SigningKeyLifecycleService(db, provider)
    _gen_ed25519_pem(key_dir / "k-race.pem")
    lifecycle.stage_candidate(kid="k-race", reason="stage-race")
    lifecycle.schedule_activation(kid="k-race", activate_at=datetime.now(timezone.utc), reason="schedule-race")

    signatures: list[tuple[str, str]] = []
    failures: list[str] = []
    stop = threading.Event()

    def _signer():
        while not stop.is_set():
            try:
                env = signing.sign_bytes(b"payload")
                signatures.append((env.kid, env.value))
            except Exception as exc:
                failures.append(str(exc))
                break

    t = threading.Thread(target=_signer)
    t.start()
    time.sleep(0.2)
    lifecycle.activate_due_scheduled(reason="worker-activate")
    stop.set()
    t.join()
    assert signatures
    assert not failures
    for kid, sig in signatures:
        assert signing.verify_bytes(b"payload", signature_b64url=sig, kid=kid)
        assert b64url_decode(sig)


def test_jwks_policy_and_ordering(configured_env):
    db: Database = configured_env["db"]
    settings: FederationSettings = configured_env["settings"]
    key_dir: Path = configured_env["key_dir"]
    svc = SigningKeyService(db, settings)
    svc.ensure_runtime_active_key()
    provider = DirectoryPrivateKeyProvider(str(key_dir), enforce_permissions=True)
    lifecycle = SigningKeyLifecycleService(db, provider)
    _gen_ed25519_pem(key_dir / "k-staged.pem")
    lifecycle.stage_candidate(kid="k-staged", reason="stage")
    _gen_ed25519_pem(key_dir / "k-active2.pem")
    lifecycle.stage_candidate(kid="k-active2", reason="stage")
    lifecycle.activate_staged_key(kid="k-active2", reason="activate")
    with db.transaction() as session:
        row = session.execute(select(FederationSigningKey).where(FederationSigningKey.kid == "k1")).scalar_one_or_none()
        if row is not None:
            row.status = "revoked"
            row.is_active = False
    jwks = svc.jwks()
    kids = [k.kid for k in jwks.keys]
    assert "k-active2" in kids
    assert "k-staged" in kids
    assert "k1" not in kids
    # deterministic ordering: active first, then staged, then retired (created_at then kid)
    assert kids[0] == "k-active2"
    assert all("BEGIN PRIVATE KEY" not in str(item.model_dump()) for item in jwks.keys)


def test_stage_candidate_create_and_idempotent_audits(configured_env):
    db: Database = configured_env["db"]
    key_dir: Path = configured_env["key_dir"]
    provider = DirectoryPrivateKeyProvider(str(key_dir), enforce_permissions=True)
    lifecycle = SigningKeyLifecycleService(db, provider)

    _gen_ed25519_pem(key_dir / "k-stage-audit.pem")
    created = lifecycle.stage_candidate(kid="k-stage-audit", reason="create")
    assert created.reason_code == "staged-created"
    with db.transaction() as session:
        before = session.execute(select(FederationSigningKey).where(FederationSigningKey.kid == "k-stage-audit")).scalar_one()
        before_updated_at = before.updated_at
        before_schedule = before.rotation_scheduled_at
    again = lifecycle.stage_candidate(kid="k-stage-audit", reason="create-again", expected_state=LocalKeyState.STAGED)
    assert again.reason_code == "staged-idempotent"
    with db.transaction() as session:
        after = session.execute(select(FederationSigningKey).where(FederationSigningKey.kid == "k-stage-audit")).scalar_one()
    assert after.updated_at == before_updated_at
    assert after.rotation_scheduled_at == before_schedule
    with db.transaction() as session:
        rows = session.execute(
            text(
                """
                SELECT action, outcome, reason, redacted_details
                FROM federation_operational_audit
                WHERE target_id = 'k-stage-audit'
                ORDER BY occurred_at, id
                """
            )
        ).all()
    assert [r[0] for r in rows] == ["local_key.stage", "local_key.stage"]
    assert rows[0][3]["outcomeCode"] == "staged-created"
    assert rows[1][3]["outcomeCode"] == "staged-idempotent"


def test_stage_candidate_rejects_state_transitions_and_preserves_active(configured_env):
    db: Database = configured_env["db"]
    settings: FederationSettings = configured_env["settings"]
    key_dir: Path = configured_env["key_dir"]
    provider = DirectoryPrivateKeyProvider(str(key_dir), enforce_permissions=True)
    lifecycle = SigningKeyLifecycleService(db, provider)
    SigningKeyService(db, settings).ensure_runtime_active_key()
    _gen_ed25519_pem(key_dir / "k-stage-reject.pem")
    _gen_ed25519_pem(key_dir / "k-retired.pem")
    _gen_ed25519_pem(key_dir / "k-revoked.pem")
    lifecycle.stage_candidate(kid="k-retired", reason="seed-retired")
    lifecycle.retire_staged_key(kid="k-retired", reason="retire")
    lifecycle.stage_candidate(kid="k-revoked", reason="seed-revoked")
    with db.transaction() as session:
        revoked = session.execute(select(FederationSigningKey).where(FederationSigningKey.kid == "k-revoked")).scalar_one()
        revoked.status = "revoked"
        revoked.is_active = False

    with pytest.raises(LocalKeyError) as active_err:
        lifecycle.stage_candidate(kid="k1", reason="reject-active", expected_state=None)
    assert active_err.value.code == LocalKeyErrorCode.TRANSITION_FORBIDDEN
    with pytest.raises(LocalKeyError) as retired_err:
        lifecycle.stage_candidate(kid="k-retired", reason="reject-retired", expected_state=None)
    assert retired_err.value.code == LocalKeyErrorCode.TRANSITION_FORBIDDEN
    with pytest.raises(LocalKeyError) as revoked_err:
        lifecycle.stage_candidate(kid="k-revoked", reason="reject-revoked", expected_state=None)
    assert revoked_err.value.code == LocalKeyErrorCode.TRANSITION_FORBIDDEN

    with db.transaction() as session:
        active_rows = session.execute(
            select(FederationSigningKey).where(FederationSigningKey.status == "active", FederationSigningKey.is_active.is_(True))
        ).scalars().all()
    assert len(active_rows) == 1
    assert active_rows[0].kid == "k1"


def test_stage_candidate_collision_emits_material_mismatch_audit(configured_env):
    db: Database = configured_env["db"]
    key_dir: Path = configured_env["key_dir"]
    provider = DirectoryPrivateKeyProvider(str(key_dir), enforce_permissions=True)
    lifecycle = SigningKeyLifecycleService(db, provider)
    _gen_ed25519_pem(key_dir / "k-collision.pem")
    lifecycle.stage_candidate(kid="k-collision", reason="seed")
    _gen_ed25519_pem(key_dir / "k-collision.pem")
    with pytest.raises(LocalKeyError) as exc:
        lifecycle.stage_candidate(kid="k-collision", reason="collision")
    assert exc.value.code == LocalKeyErrorCode.COLLISION
    with db.transaction() as session:
        action = session.execute(
            text(
                """
                SELECT action
                FROM federation_operational_audit
                WHERE target_id='k-collision'
                ORDER BY occurred_at DESC, id DESC
                LIMIT 1
                """
            )
        ).scalar_one()
    assert action == AuditAction.LOCAL_KEY_MATERIAL_MISMATCH.value


def test_inspect_candidate_audits_success_and_failure(configured_env):
    db: Database = configured_env["db"]
    key_dir: Path = configured_env["key_dir"]
    provider = DirectoryPrivateKeyProvider(str(key_dir), enforce_permissions=True)
    lifecycle = SigningKeyLifecycleService(db, provider)
    _gen_ed25519_pem(key_dir / "k-inspect.pem")
    inspected = lifecycle.inspect_candidate(kid="k-inspect", reason="inspect")
    assert isinstance(inspected, LocalKeyInspectionResult)
    assert not hasattr(inspected, "private_key")
    with pytest.raises(LocalKeyError) as missing:
        lifecycle.inspect_candidate(kid="k-missing", reason="inspect")
    assert missing.value.code == LocalKeyErrorCode.KEY_NOT_FOUND
    with db.transaction() as session:
        rows = session.execute(
            text(
                """
                SELECT action, outcome, reason, redacted_details
                FROM federation_operational_audit
                WHERE target_id IN ('k-inspect','k-missing')
                ORDER BY occurred_at, id
                """
            )
        ).all()
    assert any(r[0] == "local_key.inspect" and r[1] == "success" for r in rows)
    failed = [r for r in rows if r[0] == "local_key.inspect" and r[1] == "rejected"]
    assert failed
    serialized = str(rows)
    assert "BEGIN PRIVATE KEY" not in serialized
    assert "password=" not in serialized
    assert str(key_dir) not in serialized


def test_activation_failures_audit_without_duplicates(configured_env):
    db: Database = configured_env["db"]
    settings: FederationSettings = configured_env["settings"]
    key_dir: Path = configured_env["key_dir"]
    provider = DirectoryPrivateKeyProvider(str(key_dir), enforce_permissions=True)
    lifecycle = SigningKeyLifecycleService(db, provider)
    SigningKeyService(db, settings).ensure_runtime_active_key()
    _gen_ed25519_pem(key_dir / "k-mismatch.pem")
    lifecycle.stage_candidate(kid="k-mismatch", reason="stage")
    with db.transaction() as session:
        row = session.execute(select(FederationSigningKey).where(FederationSigningKey.kid == "k-mismatch")).scalar_one()
        row.x = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
    with pytest.raises(LocalKeyError) as mismatch:
        lifecycle.activate_staged_key(kid="k-mismatch", reason="activate")
    assert mismatch.value.code == LocalKeyErrorCode.MATERIAL_MISMATCH

    _gen_ed25519_pem(key_dir / "k-missing-material.pem")
    lifecycle.stage_candidate(kid="k-missing-material", reason="stage")
    (key_dir / "k-missing-material.pem").unlink()
    with pytest.raises(LocalKeyError) as missing:
        lifecycle.activate_staged_key(kid="k-missing-material", reason="activate")
    assert missing.value.code == LocalKeyErrorCode.KEY_NOT_FOUND

    with db.transaction() as session:
        mismatch_rows = session.execute(
            text(
                """
                SELECT count(*) FROM federation_operational_audit
                WHERE target_id='k-mismatch' AND action='local_key.material_mismatch'
                """
            )
        ).scalar_one()
        failed_rows = session.execute(
            text(
                """
                SELECT count(*) FROM federation_operational_audit
                WHERE target_id='k-missing-material' AND action='local_key.activation_failed'
                """
            )
        ).scalar_one()
    assert int(mismatch_rows) == 1
    assert int(failed_rows) == 1


def test_schedule_semantics_and_boundaries(configured_env):
    db: Database = configured_env["db"]
    settings: FederationSettings = configured_env["settings"]
    key_dir: Path = configured_env["key_dir"]
    provider = DirectoryPrivateKeyProvider(str(key_dir), enforce_permissions=True)
    lifecycle = SigningKeyLifecycleService(db, provider)
    SigningKeyService(db, settings).ensure_runtime_active_key()
    _gen_ed25519_pem(key_dir / "k-schedule-a.pem")
    _gen_ed25519_pem(key_dir / "k-schedule-b.pem")
    lifecycle.stage_candidate(kid="k-schedule-a", reason="stage")
    lifecycle.stage_candidate(kid="k-schedule-b", reason="stage")
    with pytest.raises(LocalKeyError) as naive:
        lifecycle.schedule_activation(kid="k-schedule-a", activate_at=datetime.now(), reason="naive")
    assert naive.value.code == LocalKeyErrorCode.INVALID_ACTIVATION_TIME
    with db.transaction() as session:
        scheduled_time = session.execute(text("SELECT now()")).scalar_one()
    first = lifecycle.schedule_activation(kid="k-schedule-a", activate_at=scheduled_time, reason="same")
    assert first.reason_code == "scheduled-immediate"
    second = lifecycle.schedule_activation(kid="k-schedule-a", activate_at=scheduled_time, reason="same-again")
    assert second.reason_code == "scheduled-idempotent"
    with pytest.raises(LocalKeyError) as second_key:
        lifecycle.schedule_activation(
            kid="k-schedule-b",
            activate_at=scheduled_time + timedelta(seconds=1),
            reason="second-key",
        )
    assert second_key.value.code == LocalKeyErrorCode.SCHEDULE_CONFLICT


def test_normal_activation_requires_existing_active_and_sets_valid_from_db_time(configured_env):
    db: Database = configured_env["db"]
    settings: FederationSettings = configured_env["settings"]
    key_dir: Path = configured_env["key_dir"]
    provider = DirectoryPrivateKeyProvider(str(key_dir), enforce_permissions=True)
    lifecycle = SigningKeyLifecycleService(db, provider)
    SigningKeyService(db, settings).ensure_runtime_active_key()
    _gen_ed25519_pem(key_dir / "k-new-active.pem")
    lifecycle.stage_candidate(kid="k-new-active", reason="stage")
    with db.transaction() as session:
        row = session.execute(select(FederationSigningKey).where(FederationSigningKey.kid == "k-new-active")).scalar_one()
        old_valid_from = datetime(2001, 1, 1, tzinfo=timezone.utc)
        row.valid_from = old_valid_from
    activated = lifecycle.activate_staged_key(kid="k-new-active", reason="activate")
    assert activated.status == LocalKeyState.ACTIVE
    with db.transaction() as session:
        row = session.execute(select(FederationSigningKey).where(FederationSigningKey.kid == "k-new-active")).scalar_one()
        retired_old = session.execute(select(FederationSigningKey).where(FederationSigningKey.kid == "k1")).scalar_one()
        now_db = session.execute(text("SELECT now()")).scalar_one()
    assert row.valid_from is not None
    assert row.valid_from > old_valid_from
    assert row.valid_from <= now_db
    assert retired_old.valid_until is not None

    _gen_ed25519_pem(key_dir / "k-no-active.pem")
    lifecycle.stage_candidate(kid="k-no-active", reason="stage")
    with db.transaction() as session:
        session.execute(
            update(FederationSigningKey).values(
                status="staged",
                is_active=False,
                rotated_to_kid=None,
                valid_until=None,
            )
        )
    with pytest.raises(LocalKeyError) as zero:
        lifecycle.activate_staged_key(kid="k-no-active", reason="activate-without-active")
    assert zero.value.code == LocalKeyErrorCode.ACTIVE_KEY_MISSING


def test_emergency_revoke_writes_atomic_dual_audits(configured_env):
    db: Database = configured_env["db"]
    settings: FederationSettings = configured_env["settings"]
    key_dir: Path = configured_env["key_dir"]
    provider = DirectoryPrivateKeyProvider(str(key_dir), enforce_permissions=True)
    lifecycle = SigningKeyLifecycleService(db, provider)
    signing = SigningKeyService(db, settings)
    active_kid = signing.ensure_runtime_active_key().kid
    _gen_ed25519_pem(key_dir / "k-emergency-next.pem")
    lifecycle.stage_candidate(kid="k-emergency-next", reason="stage")
    lifecycle.schedule_activation(kid="k-emergency-next", activate_at=datetime.now(timezone.utc), reason="sched")
    lifecycle.emergency_revoke_with_successor(
        active_kid=active_kid,
        successor_kid="k-emergency-next",
        reason="emergency",
    )
    with db.transaction() as session:
        old_row = session.execute(select(FederationSigningKey).where(FederationSigningKey.kid == active_kid)).scalar_one()
        new_row = session.execute(select(FederationSigningKey).where(FederationSigningKey.kid == "k-emergency-next")).scalar_one()
        actions = session.execute(
            text(
                """
                SELECT action, redacted_details
                FROM federation_operational_audit
                WHERE target_id IN (:old_kid, 'k-emergency-next')
                ORDER BY occurred_at DESC, id DESC
                LIMIT 2
                """
            ),
            {"old_kid": active_kid},
        ).all()
    assert old_row.status == "revoked"
    assert old_row.rotated_to_kid == "k-emergency-next"
    assert old_row.valid_until is not None
    assert new_row.status == "active"
    assert new_row.rotation_scheduled_at is None
    assert new_row.valid_from is not None
    assert {a for a, _ in actions} == {"local_key.revoke", "local_key.activate"}


@pytest.mark.parametrize("failing_action", [AuditAction.LOCAL_KEY_REVOKE.value, AuditAction.LOCAL_KEY_ACTIVATE.value])
def test_emergency_revoke_rolls_back_on_each_audit_failure(configured_env, monkeypatch: pytest.MonkeyPatch, failing_action: str):
    db: Database = configured_env["db"]
    settings: FederationSettings = configured_env["settings"]
    key_dir: Path = configured_env["key_dir"]
    provider = DirectoryPrivateKeyProvider(str(key_dir), enforce_permissions=True)
    lifecycle = SigningKeyLifecycleService(db, provider)
    signing = SigningKeyService(db, settings)
    active_kid = signing.ensure_runtime_active_key().kid
    _gen_ed25519_pem(key_dir / "k-fail-next.pem")
    lifecycle.stage_candidate(kid="k-fail-next", reason="stage")

    original = lifecycle_mod.write_audit_row_sync

    def fail_once(session, **kwargs):
        if kwargs["action"].value == failing_action:
            raise RuntimeError("forced-audit-failure")
        return original(session, **kwargs)

    monkeypatch.setattr(lifecycle_mod, "write_audit_row_sync", fail_once)
    with pytest.raises(LocalKeyError) as err:
        lifecycle.emergency_revoke_with_successor(active_kid=active_kid, successor_kid="k-fail-next", reason="emergency")
    assert err.value.code == LocalKeyErrorCode.AUDIT_FAILED
    with db.transaction() as session:
        old_row = session.execute(select(FederationSigningKey).where(FederationSigningKey.kid == active_kid)).scalar_one()
        new_row = session.execute(select(FederationSigningKey).where(FederationSigningKey.kid == "k-fail-next")).scalar_one()
    assert old_row.status == "active"
    assert old_row.is_active is True
    assert new_row.status == "staged"
    assert new_row.is_active is False


def test_single_file_provider_safety(tmp_path: Path):
    key_file = tmp_path / "single.pem"
    _gen_ed25519_pem(key_file)
    provider = SingleFilePrivateKeyProvider(key_file=str(key_file), bootstrap_kid="bootstrap-k1", enforce_permissions=True)
    loaded = provider.load_private_key("bootstrap-k1")
    assert loaded.kid == "bootstrap-k1"
    bad_perm = tmp_path / "bad-perm.pem"
    _gen_ed25519_pem(bad_perm)
    bad_perm.chmod(0o644)
    with pytest.raises(LocalKeyError) as mode:
        SingleFilePrivateKeyProvider(
            key_file=str(bad_perm),
            bootstrap_kid="bootstrap-k1",
            enforce_permissions=True,
        ).load_private_key("bootstrap-k1")
    assert mode.value.code == LocalKeyErrorCode.KEY_UNSAFE_PERMISSIONS
    relaxed = SingleFilePrivateKeyProvider(
        key_file=str(bad_perm),
        bootstrap_kid="bootstrap-k1",
        enforce_permissions=False,
    ).load_private_key("bootstrap-k1")
    assert relaxed.kid == "bootstrap-k1"
    empty = tmp_path / "empty.pem"
    empty.write_text("", encoding="utf-8")
    empty.chmod(0o600)
    with pytest.raises(LocalKeyError) as empty_err:
        SingleFilePrivateKeyProvider(key_file=str(empty), bootstrap_kid="bootstrap-k1", enforce_permissions=True).load_private_key("bootstrap-k1")
    assert empty_err.value.code == LocalKeyErrorCode.KEY_EMPTY
    symlink = tmp_path / "sym.pem"
    symlink.symlink_to(key_file)
    with pytest.raises(LocalKeyError) as sym:
        SingleFilePrivateKeyProvider(key_file=str(symlink), bootstrap_kid="bootstrap-k1", enforce_permissions=True).load_private_key("bootstrap-k1")
    assert sym.value.code == LocalKeyErrorCode.KEY_NOT_REGULAR_FILE


def test_lifecycle_reason_validation_and_sanitized_errors(configured_env):
    db: Database = configured_env["db"]
    key_dir: Path = configured_env["key_dir"]
    provider = DirectoryPrivateKeyProvider(str(key_dir), enforce_permissions=True)
    lifecycle = SigningKeyLifecycleService(db, provider)
    _gen_ed25519_pem(key_dir / "k-reason-limit.pem")
    with pytest.raises(LocalKeyError) as too_long:
        lifecycle.stage_candidate(kid="k-reason-limit", reason="x" * 2000)
    assert too_long.value.code == LocalKeyErrorCode.INVALID_REASON
    with db.transaction() as session:
        row = session.execute(select(FederationSigningKey).where(FederationSigningKey.kid == "k-reason-limit")).scalar_one_or_none()
    assert row is None
    with pytest.raises(LocalKeyError) as missing:
        lifecycle.inspect_candidate(kid="missing-kid", reason="inspect")
    assert "BEGIN PRIVATE KEY" not in missing.value.detail
    assert str(key_dir) not in missing.value.detail


@pytest.mark.parametrize("bad_reason", ["", "   ", "\n\t "])
def test_reason_validation_rejects_empty_or_whitespace(configured_env, bad_reason: str):
    db: Database = configured_env["db"]
    key_dir: Path = configured_env["key_dir"]
    provider = DirectoryPrivateKeyProvider(str(key_dir), enforce_permissions=True)
    lifecycle = SigningKeyLifecycleService(db, provider)
    _gen_ed25519_pem(key_dir / "k-reason-empty.pem")
    with pytest.raises(LocalKeyError) as exc:
        lifecycle.stage_candidate(kid="k-reason-empty", reason=bad_reason)
    assert exc.value.code == LocalKeyErrorCode.INVALID_REASON


def test_reason_validation_accepts_exact_boundary(configured_env):
    db: Database = configured_env["db"]
    key_dir: Path = configured_env["key_dir"]
    provider = DirectoryPrivateKeyProvider(str(key_dir), enforce_permissions=True)
    lifecycle = SigningKeyLifecycleService(db, provider)
    _gen_ed25519_pem(key_dir / "k-reason-boundary.pem")
    result = lifecycle.stage_candidate(kid="k-reason-boundary", reason="x" * 1024)
    assert result.reason_code == "staged-created"


@pytest.mark.parametrize("invalid_kid", ["k" * 1000, "../traversal", "ünicode", "bad\x00kid"])
def test_invalid_kid_audit_safety_and_no_masking(configured_env, invalid_kid: str):
    db: Database = configured_env["db"]
    key_dir: Path = configured_env["key_dir"]
    provider = DirectoryPrivateKeyProvider(str(key_dir), enforce_permissions=True)
    lifecycle = SigningKeyLifecycleService(db, provider)

    with pytest.raises(LocalKeyError) as stage_exc:
        lifecycle.stage_candidate(kid=invalid_kid, reason="stage-invalid")
    assert stage_exc.value.code == LocalKeyErrorCode.INVALID_KID
    assert invalid_kid not in stage_exc.value.detail

    with pytest.raises(LocalKeyError) as inspect_exc:
        lifecycle.inspect_candidate(kid=invalid_kid, reason="inspect-invalid")
    assert inspect_exc.value.code == LocalKeyErrorCode.INVALID_KID
    assert invalid_kid not in inspect_exc.value.detail

    with pytest.raises(LocalKeyError) as activate_exc:
        lifecycle.activate_staged_key(kid=invalid_kid, reason="activate-invalid")
    assert activate_exc.value.code == LocalKeyErrorCode.INVALID_KID
    assert invalid_kid not in activate_exc.value.detail

    with db.transaction() as session:
        rows = session.execute(
            text(
                """
                SELECT target_id, reason, redacted_details
                FROM federation_operational_audit
                WHERE target_id = 'invalid-signing-key-identifier'
                ORDER BY occurred_at DESC, id DESC
                LIMIT 3
                """
            )
        ).all()
    assert len(rows) == 3
    serialized = str(rows)
    assert invalid_kid not in serialized
    assert "BEGIN PRIVATE KEY" not in serialized
    assert str(key_dir) not in serialized


def test_stage_provider_failure_audit_mapping(configured_env):
    db: Database = configured_env["db"]
    key_dir: Path = configured_env["key_dir"]
    provider = DirectoryPrivateKeyProvider(str(key_dir), enforce_permissions=True)
    lifecycle = SigningKeyLifecycleService(db, provider)
    _gen_ed25519_pem(key_dir / "k-stage-provider.pem")
    (key_dir / "k-stage-provider.pem").unlink()
    with pytest.raises(LocalKeyError) as exc:
        lifecycle.stage_candidate(kid="k-stage-provider", reason="stage")
    assert exc.value.code == LocalKeyErrorCode.KEY_NOT_FOUND
    with db.transaction() as session:
        action = session.execute(
            text(
                """
                SELECT action
                FROM federation_operational_audit
                WHERE target_id='k-stage-provider'
                ORDER BY occurred_at DESC, id DESC
                LIMIT 1
                """
            )
        ).scalar_one()
    assert action == AuditAction.LOCAL_KEY_STAGE.value


def test_emergency_preparation_failures_audit_mapping(configured_env):
    db: Database = configured_env["db"]
    settings: FederationSettings = configured_env["settings"]
    key_dir: Path = configured_env["key_dir"]
    provider = DirectoryPrivateKeyProvider(str(key_dir), enforce_permissions=True)
    lifecycle = SigningKeyLifecycleService(db, provider)
    active_kid = SigningKeyService(db, settings).ensure_runtime_active_key().kid
    _gen_ed25519_pem(key_dir / "k-emergency-missing.pem")
    lifecycle.stage_candidate(kid="k-emergency-missing", reason="stage")
    (key_dir / "k-emergency-missing.pem").unlink()
    with pytest.raises(LocalKeyError) as missing:
        lifecycle.emergency_revoke_with_successor(
            active_kid=active_kid,
            successor_kid="k-emergency-missing",
            reason="emergency",
        )
    assert missing.value.code == LocalKeyErrorCode.KEY_NOT_FOUND

    _gen_ed25519_pem(key_dir / "k-emergency-mismatch.pem")
    lifecycle.stage_candidate(kid="k-emergency-mismatch", reason="stage")
    with db.transaction() as session:
        row = session.execute(select(FederationSigningKey).where(FederationSigningKey.kid == "k-emergency-mismatch")).scalar_one()
        row.x = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
    with pytest.raises(LocalKeyError) as mismatch:
        lifecycle.emergency_revoke_with_successor(
            active_kid=active_kid,
            successor_kid="k-emergency-mismatch",
            reason="emergency",
        )
    assert mismatch.value.code == LocalKeyErrorCode.MATERIAL_MISMATCH

    with db.transaction() as session:
        actions = session.execute(
            text(
                """
                SELECT action
                FROM federation_operational_audit
                WHERE target_id IN ('k-emergency-missing','k-emergency-mismatch')
                ORDER BY occurred_at DESC, id DESC
                """
            )
        ).all()
    values = [a[0] for a in actions]
    assert AuditAction.LOCAL_KEY_ACTIVATION_FAILED.value in values
    assert AuditAction.LOCAL_KEY_MATERIAL_MISMATCH.value in values


def test_idempotent_retire_and_cancel_are_audited(configured_env):
    db: Database = configured_env["db"]
    settings: FederationSettings = configured_env["settings"]
    key_dir: Path = configured_env["key_dir"]
    provider = DirectoryPrivateKeyProvider(str(key_dir), enforce_permissions=True)
    lifecycle = SigningKeyLifecycleService(db, provider)
    SigningKeyService(db, settings).ensure_runtime_active_key()
    _gen_ed25519_pem(key_dir / "k-idempotent.pem")
    lifecycle.stage_candidate(kid="k-idempotent", reason="stage")
    lifecycle.cancel_schedule(kid="k-idempotent", reason="cancel-on-empty")
    retired = lifecycle.retire_staged_key(kid="k-idempotent", reason="retire")
    assert retired.reason_code == "retired"
    retired_again = lifecycle.retire_staged_key(kid="k-idempotent", reason="retire-again")
    assert retired_again.reason_code == "already-retired"
    with db.transaction() as session:
        rows = session.execute(
            text(
                """
                SELECT action, redacted_details
                FROM federation_operational_audit
                WHERE target_id='k-idempotent'
                ORDER BY occurred_at, id
                """
            )
        ).all()
    assert any(r[0] == AuditAction.LOCAL_KEY_SCHEDULE_CANCEL.value and r[1].get("reasonCode") == "schedule-already-unscheduled" for r in rows)
    assert any(r[0] == AuditAction.LOCAL_KEY_RETIRE.value and r[1].get("reasonCode") == "already-retired" for r in rows)


def test_no_duplicate_failure_audit_rows_per_failure(configured_env):
    db: Database = configured_env["db"]
    settings: FederationSettings = configured_env["settings"]
    key_dir: Path = configured_env["key_dir"]
    provider = DirectoryPrivateKeyProvider(str(key_dir), enforce_permissions=True)
    lifecycle = SigningKeyLifecycleService(db, provider)
    active_kid = SigningKeyService(db, settings).ensure_runtime_active_key().kid
    _gen_ed25519_pem(key_dir / "k-dup-mismatch.pem")
    lifecycle.stage_candidate(kid="k-dup-mismatch", reason="stage")
    with db.transaction() as session:
        row = session.execute(select(FederationSigningKey).where(FederationSigningKey.kid == "k-dup-mismatch")).scalar_one()
        row.x = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
    with pytest.raises(LocalKeyError):
        lifecycle.emergency_revoke_with_successor(
            active_kid=active_kid,
            successor_kid="k-dup-mismatch",
            reason="emergency",
        )
    with db.transaction() as session:
        count_rows = session.execute(
            text(
                """
                SELECT count(*)
                FROM federation_operational_audit
                WHERE target_id='k-dup-mismatch' AND action='local_key.material_mismatch'
                """
            )
        ).scalar_one()
    assert int(count_rows) == 1


def test_migration_downgrade_refuses_local_key_audit_history_and_preserves_rows(postgres_url: str):
    _reset_public_schema(postgres_url)
    _run_alembic(postgres_url, "downgrade", "base")
    _run_alembic(postgres_url, "upgrade", "head")
    before = _read_audit_rows(postgres_url)
    with psycopg.connect(_raw_dsn(postgres_url)) as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                INSERT INTO federation_operational_audit
                    (request_id, actor_type, actor_id, action, target_type, target_id, outcome, reason, redacted_details)
                VALUES
                    (NULL, 'system', NULL, 'local_key.inspect', 'signing_key', 'k1', 'success', 'inspected', '{"kid":"k1"}'::jsonb)
                """
            )
        conn.commit()
    with_local = _read_audit_rows(postgres_url)
    proc = _run_alembic(postgres_url, "downgrade", INC4_HEAD, expect_success=False)
    assert "contains local_key.* history" in (proc.stdout + proc.stderr)
    after_failed = _read_audit_rows(postgres_url)
    assert after_failed == with_local
    assert after_failed != before
    _assert_audit_append_only(postgres_url)


def test_migration_roundtrip_without_increment5_audits_and_append_only(postgres_url: str):
    _reset_public_schema(postgres_url)
    _run_alembic(postgres_url, "downgrade", "base")
    _run_alembic(postgres_url, "upgrade", "head")
    with psycopg.connect(_raw_dsn(postgres_url)) as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                INSERT INTO federation_operational_audit
                    (request_id, actor_type, actor_id, action, target_type, target_id, outcome, reason, redacted_details)
                VALUES
                    (NULL, 'system', NULL, 'peer.probe', 'peer', 'peer-1', 'success', 'ok', '{"peer":"peer-1"}'::jsonb)
                """
            )
        conn.commit()
    _assert_audit_append_only(postgres_url)
    _run_alembic(postgres_url, "downgrade", INC4_HEAD)
    _run_alembic(postgres_url, "upgrade", "head")
    _assert_audit_append_only(postgres_url)


def test_enum_vocabularies_match_db_constraints(postgres_url: str):
    _reset_public_schema(postgres_url)
    _run_alembic(postgres_url, "downgrade", "base")
    _run_alembic(postgres_url, "upgrade", "head")
    status_values = _extract_check_values(postgres_url, "ck_fsk_status_v5")
    assert status_values == {item.value for item in LocalKeyState}
    actions = _extract_check_values(postgres_url, "ck_foa_action")
    required_actions = {
        AuditAction.LOCAL_KEY_INSPECT.value,
        AuditAction.LOCAL_KEY_STAGE.value,
        AuditAction.LOCAL_KEY_SCHEDULE.value,
        AuditAction.LOCAL_KEY_SCHEDULE_CANCEL.value,
        AuditAction.LOCAL_KEY_ACTIVATE.value,
        AuditAction.LOCAL_KEY_RETIRE.value,
        AuditAction.LOCAL_KEY_REVOKE.value,
        AuditAction.LOCAL_KEY_ACTIVATION_FAILED.value,
        AuditAction.LOCAL_KEY_MATERIAL_MISMATCH.value,
    }
    assert required_actions.issubset(actions)


def test_admin_signing_key_routes_authorization_matrix(federation_api_client):
    client, env = federation_api_client
    db: Database = env["db"]
    key_dir: Path = env["key_dir"]
    provider = DirectoryPrivateKeyProvider(str(key_dir), enforce_permissions=True)
    lifecycle = SigningKeyLifecycleService(db, provider)
    active_kid = SigningKeyService(db, env["settings"]).ensure_runtime_active_key().kid
    _gen_ed25519_pem(key_dir / "k-admin-routes.pem")
    lifecycle.stage_candidate(kid="k-admin-routes", reason="stage")
    routes = [
        ("post", "/api/v1/admin/federation/signing-keys/inspect", {"kid": "k-admin-routes", "reason": "inspect"}),
        (
            "post",
            "/api/v1/admin/federation/signing-keys/stage",
            {"kid": "k-admin-routes", "expectedState": "staged", "reason": "stage"},
        ),
        (
            "post",
            "/api/v1/admin/federation/signing-keys/k-admin-routes/schedule-activation",
            {"activateAt": datetime.now(timezone.utc).isoformat(), "expectedState": "staged", "reason": "schedule"},
        ),
        (
            "post",
            "/api/v1/admin/federation/signing-keys/k-admin-routes/cancel-schedule",
            {"expectedState": "staged", "reason": "cancel"},
        ),
        (
            "post",
            "/api/v1/admin/federation/signing-keys/k-admin-routes/activate",
            {"expectedState": "staged", "reason": "activate", "warningAck": True},
        ),
        (
            "post",
            "/api/v1/admin/federation/signing-keys/k-admin-routes/retire",
            {"expectedState": "staged", "reason": "retire"},
        ),
        (
            "post",
            f"/api/v1/admin/federation/signing-keys/{active_kid}/revoke-emergency",
            {
                "expectedState": "active",
                "successorKid": "k-admin-routes",
                "successorExpectedState": "staged",
                "reason": "emergency",
                "warningAck": True,
            },
        ),
    ]
    for method, path, body in routes:
        unauth = client.request(method, path, json=body)
        curator = client.request(method, path, json=body, headers={"Authorization": "Bearer curator-token"})
        admin = client.request(method, path, json=body, headers={"Authorization": "Bearer admin-token"})
        assert unauth.status_code == 401
        assert curator.status_code == 403
        assert admin.status_code in {200, 400, 404, 409, 422, 503}
    listing = client.get("/api/v1/admin/federation/signing-keys", headers={"Authorization": "Bearer admin-token"})
    assert listing.status_code == 200


def test_authorization_runs_before_warning_ack_and_side_effects(federation_api_client, monkeypatch: pytest.MonkeyPatch):
    client, env = federation_api_client
    key_dir: Path = env["key_dir"]
    _gen_ed25519_pem(key_dir / "k-auth-order.pem")
    SigningKeyLifecycleService(
        env["db"], DirectoryPrivateKeyProvider(str(key_dir), enforce_permissions=True)
    ).stage_candidate(kid="k-auth-order", reason="stage")
    active_kid = SigningKeyService(env["db"], env["settings"]).ensure_runtime_active_key().kid

    counters = {"services": 0, "provider": 0, "audit": 0}
    original_services = operational_api._local_key_services
    original_provider_load = lifecycle_mod.DirectoryPrivateKeyProvider.load_private_key
    original_audit_write = lifecycle_mod.write_audit_row_sync

    def spy_services(request):
        counters["services"] += 1
        return original_services(request)

    def spy_provider_load(self, kid):
        counters["provider"] += 1
        return original_provider_load(self, kid)

    def spy_audit_write(*args, **kwargs):
        counters["audit"] += 1
        return original_audit_write(*args, **kwargs)

    monkeypatch.setattr(operational_api, "_local_key_services", spy_services)
    monkeypatch.setattr(lifecycle_mod.DirectoryPrivateKeyProvider, "load_private_key", spy_provider_load)
    monkeypatch.setattr(lifecycle_mod, "write_audit_row_sync", spy_audit_write)

    activate_false = {"expectedState": "staged", "reason": "activate", "warningAck": False}
    activate_missing = {"expectedState": "staged", "reason": "activate"}
    emergency_false = {
        "expectedState": "active",
        "successorKid": "k-auth-order",
        "successorExpectedState": "staged",
        "reason": "emergency",
        "warningAck": False,
    }
    emergency_missing = {
        "expectedState": "active",
        "successorKid": "k-auth-order",
        "successorExpectedState": "staged",
        "reason": "emergency",
    }
    activate_transition_conflict = {"expectedState": "staged", "reason": "activate", "warningAck": True}
    emergency_invalid_successor = {
        "expectedState": "active",
        "successorKid": "missing-successor",
        "successorExpectedState": "staged",
        "reason": "emergency",
        "warningAck": True,
    }

    assert client.post(f"/api/v1/admin/federation/signing-keys/{active_kid}/activate", json=activate_false).status_code == 401
    assert (
        client.post(
            f"/api/v1/admin/federation/signing-keys/{active_kid}/activate",
            json=activate_false,
            headers={"Authorization": "Bearer curator-token"},
        ).status_code
        == 403
    )
    assert client.post(f"/api/v1/admin/federation/signing-keys/{active_kid}/activate", json=activate_missing).status_code == 401
    assert (
        client.post(
            f"/api/v1/admin/federation/signing-keys/{active_kid}/activate",
            json=activate_missing,
            headers={"Authorization": "Bearer curator-token"},
        ).status_code
        == 403
    )
    assert (
        client.post(
            f"/api/v1/admin/federation/signing-keys/{active_kid}/revoke-emergency",
            json=emergency_false,
        ).status_code
        == 401
    )
    assert (
        client.post(
            f"/api/v1/admin/federation/signing-keys/{active_kid}/revoke-emergency",
            json=emergency_false,
            headers={"Authorization": "Bearer curator-token"},
        ).status_code
        == 403
    )
    assert (
        client.post(
            f"/api/v1/admin/federation/signing-keys/{active_kid}/revoke-emergency",
            json=emergency_missing,
        ).status_code
        == 401
    )
    assert (
        client.post(
            f"/api/v1/admin/federation/signing-keys/{active_kid}/revoke-emergency",
            json=emergency_missing,
            headers={"Authorization": "Bearer curator-token"},
        ).status_code
        == 403
    )
    assert (
        client.post(
            f"/api/v1/admin/federation/signing-keys/{active_kid}/activate",
            json=activate_transition_conflict,
        ).status_code
        == 401
    )
    assert (
        client.post(
            f"/api/v1/admin/federation/signing-keys/{active_kid}/activate",
            json=activate_transition_conflict,
            headers={"Authorization": "Bearer curator-token"},
        ).status_code
        == 403
    )
    assert (
        client.post(
            f"/api/v1/admin/federation/signing-keys/{active_kid}/revoke-emergency",
            json=emergency_invalid_successor,
        ).status_code
        == 401
    )
    assert (
        client.post(
            f"/api/v1/admin/federation/signing-keys/{active_kid}/revoke-emergency",
            json=emergency_invalid_successor,
            headers={"Authorization": "Bearer curator-token"},
        ).status_code
        == 403
    )
    assert counters == {"services": 0, "provider": 0, "audit": 0}


@pytest.mark.parametrize(
    ("path", "payload"),
    [
        (
            "/api/v1/admin/federation/signing-keys/inspect",
            {"kid": "k1", "reason": "ok", "privateKey": "nope"},
        ),
        (
            "/api/v1/admin/federation/signing-keys/stage",
            {"kid": "k1", "reason": "ok", "providerPath": "/secret"},
        ),
        (
            "/api/v1/admin/federation/signing-keys/k1/schedule-activation",
            {"activateAt": datetime.now(timezone.utc).isoformat(), "expectedState": "staged", "reason": "ok", "pem": "x"},
        ),
    ],
)
def test_admin_signing_key_strict_schema_rejects_unknown_fields(federation_api_client, path: str, payload: dict):
    client, _ = federation_api_client
    response = client.post(path, json=payload, headers={"Authorization": "Bearer admin-token"})
    assert response.status_code == 422
    assert response.headers["content-type"].startswith("application/problem+json")


def test_admin_signing_key_validation_and_warning_ack_errors(federation_api_client):
    client, env = federation_api_client
    active_kid = SigningKeyService(env["db"], env["settings"]).ensure_runtime_active_key().kid
    invalid_kid = client.post(
        "/api/v1/admin/federation/signing-keys/inspect",
        json={"kid": "../bad", "reason": "inspect"},
        headers={"Authorization": "Bearer admin-token"},
    )
    assert invalid_kid.status_code == 422

    missing_reason = client.post(
        "/api/v1/admin/federation/signing-keys/stage",
        json={"kid": "k1", "reason": ""},
        headers={"Authorization": "Bearer admin-token"},
    )
    assert missing_reason.status_code == 422

    naive_time = client.post(
        "/api/v1/admin/federation/signing-keys/k1/schedule-activation",
        json={"activateAt": datetime.now().isoformat(), "expectedState": "staged", "reason": "naive"},
        headers={"Authorization": "Bearer admin-token"},
    )
    assert naive_time.status_code == 422

    warning_ack = client.post(
        f"/api/v1/admin/federation/signing-keys/{active_kid}/activate",
        json={"expectedState": "staged", "reason": "activate", "warningAck": False},
        headers={"Authorization": "Bearer admin-token"},
    )
    assert warning_ack.status_code == 400
    assert warning_ack.json()["type"].endswith("/warning-ack-required")

    missing_warning_ack = client.post(
        f"/api/v1/admin/federation/signing-keys/{active_kid}/activate",
        json={"expectedState": "staged", "reason": "activate"},
        headers={"Authorization": "Bearer admin-token"},
    )
    assert missing_warning_ack.status_code == 400
    assert missing_warning_ack.json()["type"].endswith("/warning-ack-required")


def test_admin_signing_key_inventory_public_only_and_deterministic(federation_api_client):
    client, env = federation_api_client
    db: Database = env["db"]
    key_dir: Path = env["key_dir"]
    provider = DirectoryPrivateKeyProvider(str(key_dir), enforce_permissions=True)
    lifecycle = SigningKeyLifecycleService(db, provider)
    SigningKeyService(db, env["settings"]).ensure_runtime_active_key()
    _gen_ed25519_pem(key_dir / "k-api-inventory.pem")
    lifecycle.stage_candidate(kid="k-api-inventory", reason="stage")

    first = client.get("/api/v1/admin/federation/signing-keys", headers={"Authorization": "Bearer admin-token"})
    second = client.get("/api/v1/admin/federation/signing-keys", headers={"Authorization": "Bearer admin-token"})
    assert first.status_code == 200
    assert second.status_code == 200
    assert [item["kid"] for item in first.json()["items"]] == [item["kid"] for item in second.json()["items"]]
    text_dump = json.dumps(first.json())
    assert "private_key" not in text_dump
    assert "BEGIN PRIVATE KEY" not in text_dump
    assert str(key_dir) not in text_dump
    item = next(row for row in first.json()["items"] if row["kid"] == "k-api-inventory")
    assert {"kid", "publicFingerprint", "status", "isActive", "validFrom", "validUntil", "rotationScheduledAt", "rotatedToKid", "createdAt", "updatedAt", "materialStatus"}.issubset(item.keys())


def test_admin_signing_key_lifecycle_routes_and_emergency_atomicity(federation_api_client):
    client, env = federation_api_client
    key_dir: Path = env["key_dir"]
    active_kid = SigningKeyService(env["db"], env["settings"]).ensure_runtime_active_key().kid
    _gen_ed25519_pem(key_dir / "k-route-lifecycle.pem")

    stage = client.post(
        "/api/v1/admin/federation/signing-keys/stage",
        json={"kid": "k-route-lifecycle", "reason": "stage"},
        headers={"Authorization": "Bearer admin-token"},
    )
    assert stage.status_code == 200
    assert stage.json()["status"] == "staged"

    stage_again = client.post(
        "/api/v1/admin/federation/signing-keys/stage",
        json={"kid": "k-route-lifecycle", "expectedState": "staged", "reason": "stage-again"},
        headers={"Authorization": "Bearer admin-token"},
    )
    assert stage_again.status_code == 200
    assert stage_again.json()["resultCode"] == "staged-idempotent"

    schedule = client.post(
        "/api/v1/admin/federation/signing-keys/k-route-lifecycle/schedule-activation",
        json={"activateAt": datetime.now(timezone.utc).isoformat(), "expectedState": "staged", "reason": "schedule"},
        headers={"Authorization": "Bearer admin-token"},
    )
    assert schedule.status_code == 200

    cancel = client.post(
        "/api/v1/admin/federation/signing-keys/k-route-lifecycle/cancel-schedule",
        json={"expectedState": "staged", "reason": "cancel"},
        headers={"Authorization": "Bearer admin-token"},
    )
    assert cancel.status_code == 200

    emergency = client.post(
        f"/api/v1/admin/federation/signing-keys/{active_kid}/revoke-emergency",
        json={
            "expectedState": "active",
            "successorKid": "k-route-lifecycle",
            "successorExpectedState": "staged",
            "reason": "emergency",
            "warningAck": True,
        },
        headers={"Authorization": "Bearer admin-token"},
    )
    assert emergency.status_code == 200
    body = emergency.json()
    assert body["revokedKid"] == active_kid
    assert body["successorKid"] == "k-route-lifecycle"
    assert body["successorStatus"] == "active"


def test_outbound_signing_switches_after_activation_without_rewriting_history(federation_api_client):
    client, env = federation_api_client
    db: Database = env["db"]
    settings: FederationSettings = env["settings"]
    key_dir: Path = env["key_dir"]
    pub = FederationPublicationService(db, settings)
    old_active_kid = SigningKeyService(db, settings).ensure_runtime_active_key().kid
    old_canonical = f"lfs:{NODE_ID}:STEP4OLD:1"
    pub.publish_new_version(
        canonical_id=old_canonical,
        authority_node_id=NODE_ID,
        local_id="STEP4OLD",
        version="1",
        payload={"licenseId": "STEP4OLD"},
    )

    _gen_ed25519_pem(key_dir / "k-step4-new.pem")
    stage = client.post(
        "/api/v1/admin/federation/signing-keys/stage",
        json={"kid": "k-step4-new", "reason": "stage"},
        headers={"Authorization": "Bearer admin-token"},
    )
    assert stage.status_code == 200
    activate = client.post(
        "/api/v1/admin/federation/signing-keys/k-step4-new/activate",
        json={"expectedState": "staged", "reason": "activate", "warningAck": True},
        headers={"Authorization": "Bearer admin-token"},
    )
    assert activate.status_code == 200
    assert activate.json()["status"] == "active"

    new_canonical = f"lfs:{NODE_ID}:STEP4NEW:1"
    pub.publish_new_version(
        canonical_id=new_canonical,
        authority_node_id=NODE_ID,
        local_id="STEP4NEW",
        version="1",
        payload={"licenseId": "STEP4NEW"},
    )
    discovery = client.get("/.well-known/lfs")
    assert discovery.status_code == 200
    assert discovery.json()["currentSigningKid"] == "k-step4-new"

    changes = client.get("/api/v1/federation/changes?limit=200")
    assert changes.status_code == 200
    events = changes.json()["events"]
    old_event = next(e for e in events if e["payload"]["record"]["canonicalId"] == old_canonical)
    new_event = next(e for e in events if e["payload"]["record"]["canonicalId"] == new_canonical)
    assert old_event["signed"]["signature"]["kid"] == old_active_kid
    assert new_event["signed"]["signature"]["kid"] == "k-step4-new"

    old_record = client.get(f"/api/v1/federation/records/{encode_canonical_id(old_canonical)}")
    new_record = client.get(f"/api/v1/federation/records/{encode_canonical_id(new_canonical)}")
    assert old_record.status_code == 200
    assert new_record.status_code == 200
    assert old_record.json()["record"]["canonicalId"] == old_canonical
    assert old_record.json()["latestEventDigestSha256"] == old_event["signed"]["digestSha256"]
    assert new_record.json()["signed"]["signature"]["kid"] == "k-step4-new"


def test_jwks_etag_changes_and_revoked_key_exclusion(federation_api_client):
    client, env = federation_api_client
    key_dir: Path = env["key_dir"]
    active_kid = SigningKeyService(env["db"], env["settings"]).ensure_runtime_active_key().kid
    first = client.get("/.well-known/jwks.json")
    assert first.status_code == 200
    etag1 = first.headers["etag"]

    _gen_ed25519_pem(key_dir / "k-jwks-stage.pem")
    stage = client.post(
        "/api/v1/admin/federation/signing-keys/stage",
        json={"kid": "k-jwks-stage", "reason": "stage"},
        headers={"Authorization": "Bearer admin-token"},
    )
    assert stage.status_code == 200
    second = client.get("/.well-known/jwks.json")
    assert second.status_code == 200
    etag2 = second.headers["etag"]
    assert etag2 != etag1
    assert "k-jwks-stage" in [k["kid"] for k in second.json()["keys"]]

    _gen_ed25519_pem(key_dir / "k-jwks-next.pem")
    stage2 = client.post(
        "/api/v1/admin/federation/signing-keys/stage",
        json={"kid": "k-jwks-next", "reason": "stage"},
        headers={"Authorization": "Bearer admin-token"},
    )
    assert stage2.status_code == 200
    emergency = client.post(
        f"/api/v1/admin/federation/signing-keys/{active_kid}/revoke-emergency",
        json={
            "expectedState": "active",
            "successorKid": "k-jwks-next",
            "successorExpectedState": "staged",
            "reason": "emergency",
            "warningAck": True,
        },
        headers={"Authorization": "Bearer admin-token"},
    )
    assert emergency.status_code == 200
    third = client.get("/.well-known/jwks.json")
    assert third.status_code == 200
    etag3 = third.headers["etag"]
    assert etag3 != etag2
    kids = [k["kid"] for k in third.json()["keys"]]
    assert "k-jwks-next" in kids
    assert active_kid not in kids


def test_admin_signing_key_schema_constraints(federation_api_client):
    client, env = federation_api_client
    active_kid = SigningKeyService(env["db"], env["settings"]).ensure_runtime_active_key().kid
    cases = [
        ("/api/v1/admin/federation/signing-keys/inspect", {"kid": "k" * 129, "reason": "inspect"}),
        ("/api/v1/admin/federation/signing-keys/inspect", {"kid": 123, "reason": "inspect"}),
        ("/api/v1/admin/federation/signing-keys/inspect", {"kid": "../bad", "reason": "inspect"}),
        ("/api/v1/admin/federation/signing-keys/stage", {"kid": "k1", "reason": ""}),
        ("/api/v1/admin/federation/signing-keys/stage", {"kid": "k1", "reason": "   "}),
        ("/api/v1/admin/federation/signing-keys/stage", {"kid": "k1", "reason": "x" * 1025}),
        (
            f"/api/v1/admin/federation/signing-keys/{active_kid}/activate",
            {"expectedState": "staged", "reason": "activate", "warningAck": "true"},
        ),
        (
            "/api/v1/admin/federation/signing-keys/k1/schedule-activation",
            {"activateAt": datetime.now().isoformat(), "expectedState": "staged", "reason": "naive"},
        ),
        (
            f"/api/v1/admin/federation/signing-keys/{active_kid}/retire",
            {"reason": "retire"},
        ),
        (
            "/api/v1/admin/federation/signing-keys/stage",
            {"kid": "k1", "reason": "ok", "privateKeyPath": "/tmp/key.pem"},
        ),
    ]
    for path, payload in cases:
        response = client.post(path, json=payload, headers={"Authorization": "Bearer admin-token"})
        assert response.status_code == 422
        assert response.headers["content-type"].startswith("application/problem+json")


def test_thread_bridge_for_inventory_mutation_emergency_and_jwks(
    federation_api_client, monkeypatch: pytest.MonkeyPatch
):
    client, env = federation_api_client
    key_dir: Path = env["key_dir"]
    calls: list[tuple[str, int, int]] = []
    original_to_thread = operational_api.asyncio.to_thread

    async def spy_to_thread(func, *args, **kwargs):
        caller_tid = threading.get_ident()

        def wrapped():
            worker_tid = threading.get_ident()
            calls.append((getattr(func, "__name__", "unknown"), caller_tid, worker_tid))
            return func(*args, **kwargs)

        return await original_to_thread(wrapped)

    monkeypatch.setattr(operational_api.asyncio, "to_thread", spy_to_thread)
    _gen_ed25519_pem(key_dir / "k-thread-stage.pem")
    stage = client.post(
        "/api/v1/admin/federation/signing-keys/stage",
        json={"kid": "k-thread-stage", "reason": "stage"},
        headers={"Authorization": "Bearer admin-token"},
    )
    assert stage.status_code == 200

    inventory = client.get("/api/v1/admin/federation/signing-keys", headers={"Authorization": "Bearer admin-token"})
    assert inventory.status_code == 200
    assert any(name == "_build_signing_key_inventory_response" and caller != worker for name, caller, worker in calls)

    inspect = client.post(
        "/api/v1/admin/federation/signing-keys/inspect",
        json={"kid": "k-thread-stage", "reason": "inspect"},
        headers={"Authorization": "Bearer admin-token"},
    )
    assert inspect.status_code == 200
    assert any(name == "inspect_candidate" and caller != worker for name, caller, worker in calls)

    activate = client.post(
        "/api/v1/admin/federation/signing-keys/k-thread-stage/activate",
        json={"expectedState": "staged", "reason": "activate", "warningAck": True},
        headers={"Authorization": "Bearer admin-token"},
    )
    assert activate.status_code == 200
    assert any(name == "_lifecycle_response_from_result" and caller != worker for name, caller, worker in calls)

    _gen_ed25519_pem(key_dir / "k-thread-next.pem")
    stage_next = client.post(
        "/api/v1/admin/federation/signing-keys/stage",
        json={"kid": "k-thread-next", "reason": "stage"},
        headers={"Authorization": "Bearer admin-token"},
    )
    assert stage_next.status_code == 200
    emergency = client.post(
        "/api/v1/admin/federation/signing-keys/k-thread-stage/revoke-emergency",
        json={
            "expectedState": "active",
            "successorKid": "k-thread-next",
            "successorExpectedState": "staged",
            "reason": "emergency",
            "warningAck": True,
        },
        headers={"Authorization": "Bearer admin-token"},
    )
    assert emergency.status_code == 200
    assert any(name == "_load_signing_key_snapshot_pair" and caller != worker for name, caller, worker in calls)

    jwks_calls: list[tuple[str, int, int]] = []
    original_jwks_to_thread = jwks_api.asyncio.to_thread

    async def spy_jwks_to_thread(func, *args, **kwargs):
        caller_tid = threading.get_ident()

        def wrapped():
            worker_tid = threading.get_ident()
            jwks_calls.append((getattr(func, "__name__", "unknown"), caller_tid, worker_tid))
            return func(*args, **kwargs)

        return await original_jwks_to_thread(wrapped)

    monkeypatch.setattr(jwks_api.asyncio, "to_thread", spy_jwks_to_thread)
    jwks = client.get("/.well-known/jwks.json")
    assert jwks.status_code == 200
    assert any(name == "jwks" and caller != worker for name, caller, worker in jwks_calls)


def test_inventory_provider_failure_and_service_failure_are_safe(
    federation_api_client, monkeypatch: pytest.MonkeyPatch
):
    client, env = federation_api_client
    key_dir: Path = env["key_dir"]
    _gen_ed25519_pem(key_dir / "k-safe-inventory.pem")
    SigningKeyLifecycleService(
        env["db"], DirectoryPrivateKeyProvider(str(key_dir), enforce_permissions=True)
    ).stage_candidate(kid="k-safe-inventory", reason="stage")

    original_provider_load = lifecycle_mod.DirectoryPrivateKeyProvider.load_private_key

    def failing_load(self, kid):
        if kid == "k-safe-inventory":
            raise LocalKeyError(LocalKeyErrorCode.KEY_UNREADABLE, "hidden")
        return original_provider_load(self, kid)

    monkeypatch.setattr(lifecycle_mod.DirectoryPrivateKeyProvider, "load_private_key", failing_load)
    inventory = client.get("/api/v1/admin/federation/signing-keys", headers={"Authorization": "Bearer admin-token"})
    assert inventory.status_code == 200
    row = next(item for item in inventory.json()["items"] if item["kid"] == "k-safe-inventory")
    assert row["materialStatus"] == LocalKeyErrorCode.KEY_UNREADABLE.value
    serialized = json.dumps(inventory.json())
    assert str(key_dir) not in serialized
    assert "BEGIN PRIVATE KEY" not in serialized

    def failing_services(_request):
        raise RuntimeError("sensitive-path:/secret/key.pem")

    monkeypatch.setattr(operational_api, "_local_key_services", failing_services)
    failed = client.get("/api/v1/admin/federation/signing-keys", headers={"Authorization": "Bearer admin-token"})
    assert failed.status_code == 503
    problem = failed.json()
    assert problem["detail"] == "Federation signing-key operation is unavailable."
    assert "/secret/key.pem" not in json.dumps(problem)


def test_rotation_worker_settings_defaults_and_repr_safety(configured_env):
    settings: FederationSettings = configured_env["settings"]
    assert settings.worker_instance_id is None
    assert settings.rotation_worker_enabled is True
    assert settings.rotation_poll_interval_seconds == 60
    assert settings.rotation_failure_backoff_min_seconds == 30
    assert settings.rotation_failure_backoff_max_seconds == 900
    assert settings.rotation_backoff_jitter_enabled is True
    assert settings.rotation_max_operations_per_pass == 1
    rendered = repr(settings)
    assert configured_env["settings"].signing_key_dir is not None
    assert configured_env["settings"].signing_key_dir not in rendered
    assert "FEDERATION_ADMIN_CURSOR_SECRET" not in rendered


def test_rotation_worker_settings_validation(monkeypatch: pytest.MonkeyPatch, configured_env):
    monkeypatch.setenv("FEDERATION_ROTATION_POLL_INTERVAL_SECONDS", "0")
    invalid_poll = FederationSettings.from_env()
    assert "FEDERATION_ROTATION_POLL_INTERVAL_SECONDS must be positive" in invalid_poll.validation_errors
    monkeypatch.setenv("FEDERATION_ROTATION_POLL_INTERVAL_SECONDS", "60")
    monkeypatch.setenv("FEDERATION_ROTATION_FAILURE_BACKOFF_MIN_SECONDS", "90")
    monkeypatch.setenv("FEDERATION_ROTATION_FAILURE_BACKOFF_MAX_SECONDS", "30")
    invalid_backoff = FederationSettings.from_env()
    assert any("FEDERATION_ROTATION_FAILURE_BACKOFF_MIN_SECONDS must be <=" in err for err in invalid_backoff.validation_errors)
    monkeypatch.setenv("FEDERATION_ROTATION_FAILURE_BACKOFF_MIN_SECONDS", "30")
    monkeypatch.setenv("FEDERATION_ROTATION_FAILURE_BACKOFF_MAX_SECONDS", "900")
    monkeypatch.setenv("FEDERATION_ROTATION_MAX_OPERATIONS_PER_PASS", "2")
    invalid_ops = FederationSettings.from_env()
    assert "FEDERATION_ROTATION_MAX_OPERATIONS_PER_PASS must be 1" in invalid_ops.validation_errors
    monkeypatch.setenv("FEDERATION_WORKER_INSTANCE_ID", "not-a-uuid")
    invalid_worker_id = FederationSettings.from_env()
    assert "FEDERATION_WORKER_INSTANCE_ID must be a valid UUID string" in invalid_worker_id.validation_errors


def test_rotation_worker_not_due_is_noop(configured_env):
    db: Database = configured_env["db"]
    settings: FederationSettings = configured_env["settings"]
    key_dir: Path = configured_env["key_dir"]
    signing = SigningKeyService(db, settings)
    signing.ensure_runtime_active_key()
    lifecycle = SigningKeyLifecycleService(db, signing.provider)
    _gen_ed25519_pem(key_dir / "k-rot-not-due.pem")
    lifecycle.stage_candidate(kid="k-rot-not-due", reason="stage")
    lifecycle.schedule_activation(
        kid="k-rot-not-due",
        activate_at=datetime.now(timezone.utc) + timedelta(seconds=600),
        reason="schedule-not-due",
    )
    backoff = federation_worker._RotationBackoffState()
    result = federation_worker._run_rotation_pass(
        lifecycle=lifecycle,
        signing=signing,
        db=db,
        instance_id=uuid.uuid4(),
        backoff=backoff,
    )
    assert result.code == "rotation_deferred_not_due"
    with db.transaction() as session:
        active = session.execute(
            select(FederationSigningKey).where(FederationSigningKey.status == "active", FederationSigningKey.is_active.is_(True))
        ).scalar_one()
        staged = session.execute(select(FederationSigningKey).where(FederationSigningKey.kid == "k-rot-not-due")).scalar_one()
    assert active.kid == "k1"
    assert staged.status == "staged"
    assert staged.rotation_scheduled_at is not None


def test_rotation_worker_due_activation_commits_once(configured_env):
    db: Database = configured_env["db"]
    settings: FederationSettings = configured_env["settings"]
    key_dir: Path = configured_env["key_dir"]
    signing = SigningKeyService(db, settings)
    old_active = signing.ensure_runtime_active_key().kid
    lifecycle = SigningKeyLifecycleService(db, signing.provider)
    _gen_ed25519_pem(key_dir / "k-rot-due.pem")
    lifecycle.stage_candidate(kid="k-rot-due", reason="stage")
    lifecycle.schedule_activation(kid="k-rot-due", activate_at=datetime.now(timezone.utc), reason="schedule-now")
    backoff = federation_worker._RotationBackoffState()
    result = federation_worker._run_rotation_pass(
        lifecycle=lifecycle,
        signing=signing,
        db=db,
        instance_id=uuid.uuid4(),
        backoff=backoff,
    )
    assert result.code == "rotation_activation_succeeded"
    with db.transaction() as session:
        keys = session.execute(
            select(FederationSigningKey).where(FederationSigningKey.kid.in_([old_active, "k-rot-due"])).order_by(FederationSigningKey.kid)
        ).scalars().all()
    by_kid = {row.kid: row for row in keys}
    assert by_kid["k-rot-due"].status == "active"
    assert by_kid["k-rot-due"].is_active is True
    assert by_kid["k-rot-due"].rotation_scheduled_at is None
    assert by_kid[old_active].status == "retired"
    assert by_kid[old_active].is_active is False
    assert signing.sign_bytes(b"outbound").kid == "k-rot-due"


def test_rotation_worker_material_mismatch_blocks_without_switching_active(configured_env):
    db: Database = configured_env["db"]
    settings: FederationSettings = configured_env["settings"]
    key_dir: Path = configured_env["key_dir"]
    signing = SigningKeyService(db, settings)
    old_active = signing.ensure_runtime_active_key().kid
    lifecycle = SigningKeyLifecycleService(db, signing.provider)
    _gen_ed25519_pem(key_dir / "k-rot-mismatch.pem")
    lifecycle.stage_candidate(kid="k-rot-mismatch", reason="stage")
    with db.transaction() as session:
        row = session.execute(select(FederationSigningKey).where(FederationSigningKey.kid == "k-rot-mismatch")).scalar_one()
        row.x = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
    lifecycle.schedule_activation(kid="k-rot-mismatch", activate_at=datetime.now(timezone.utc), reason="schedule-now")
    backoff = federation_worker._RotationBackoffState()
    result = federation_worker._run_rotation_pass(
        lifecycle=lifecycle,
        signing=signing,
        db=db,
        instance_id=uuid.uuid4(),
        backoff=backoff,
    )
    assert result.code == "rotation_blocked_operator"
    assert result.permanent is True
    with db.transaction() as session:
        active = session.execute(
            select(FederationSigningKey).where(FederationSigningKey.status == "active", FederationSigningKey.is_active.is_(True))
        ).scalar_one()
        mismatch = session.execute(select(FederationSigningKey).where(FederationSigningKey.kid == "k-rot-mismatch")).scalar_one()
        mismatch_audits = session.execute(
            text(
                """
                SELECT count(*)
                FROM federation_operational_audit
                WHERE target_id = 'k-rot-mismatch' AND action = 'local_key.material_mismatch'
                """
            )
        ).scalar_one()
    assert active.kid == old_active
    assert mismatch.status == "staged"
    assert mismatch.rotation_scheduled_at is not None
    assert int(mismatch_audits) == 1


def test_rotation_worker_missing_material_retries_then_blocks(configured_env):
    db: Database = configured_env["db"]
    settings: FederationSettings = configured_env["settings"]
    key_dir: Path = configured_env["key_dir"]
    signing = SigningKeyService(db, settings)
    signing.ensure_runtime_active_key()
    lifecycle = SigningKeyLifecycleService(db, signing.provider)
    _gen_ed25519_pem(key_dir / "k-rot-missing.pem")
    lifecycle.stage_candidate(kid="k-rot-missing", reason="stage")
    lifecycle.schedule_activation(kid="k-rot-missing", activate_at=datetime.now(timezone.utc), reason="schedule-now")
    (key_dir / "k-rot-missing.pem").unlink()
    backoff = federation_worker._RotationBackoffState()
    retry_codes: list[str] = []
    for _ in range(3):
        result = federation_worker._run_rotation_pass(
            lifecycle=lifecycle,
            signing=signing,
            db=db,
            instance_id=uuid.uuid4(),
            backoff=backoff,
        )
        retry_codes.append(result.code)
        federation_worker._advance_rotation_backoff(
            settings=settings,
            backoff=backoff,
            result=result,
            now_monotonic=time.monotonic(),
        )
    assert retry_codes == ["rotation_retry_missing_material"] * 3
    blocked = federation_worker._run_rotation_pass(
        lifecycle=lifecycle,
        signing=signing,
        db=db,
        instance_id=uuid.uuid4(),
        backoff=backoff,
    )
    assert blocked.code == "rotation_blocked_missing_material"
    assert blocked.permanent is True
    with db.transaction() as session:
        row = session.execute(select(FederationSigningKey).where(FederationSigningKey.kid == "k-rot-missing")).scalar_one()
        active = session.execute(
            select(FederationSigningKey).where(FederationSigningKey.status == "active", FederationSigningKey.is_active.is_(True))
        ).scalar_one()
    assert row.status == "staged"
    assert row.rotation_scheduled_at is not None
    assert active.kid == "k1"


@pytest.mark.parametrize(
    ("inbound_enabled", "rotation_enabled", "expect_sync_ctor", "expect_rotation_ctor"),
    [
        (True, False, True, False),
        (False, True, False, True),
        (True, True, True, True),
        (False, False, False, False),
    ],
)
def test_worker_mode_matrix(monkeypatch: pytest.MonkeyPatch, inbound_enabled: bool, rotation_enabled: bool, expect_sync_ctor: bool, expect_rotation_ctor: bool):
    federation_worker._STOP = False

    class _FakeDb:
        pass

    class _FakeResult:
        def __init__(self, status: str) -> None:
            self.status = status

    class _FakeSync:
        def __init__(self, _db, _settings) -> None:
            self.calls = 0

        def sync_all_trusted_peers_once(self, *, max_seconds_per_peer: int):
            self.calls += 1
            if self.calls == 1:
                return [(uuid.uuid4(), _FakeResult("complete"))]
            federation_worker._mark_stop()
            return [(uuid.uuid4(), _FakeResult("already-running"))]

    class _FakeSigning:
        constructed = 0

        def __init__(self, _db, _settings) -> None:
            _FakeSigning.constructed += 1

        @property
        def provider(self):
            return object()

        def ensure_runtime_active_key(self):
            return None

    class _FakeLifecycle:
        constructed = 0

        def __init__(self, _db, _provider) -> None:
            _FakeLifecycle.constructed += 1

    monkeypatch.setenv("FEDERATION_ENABLED", "true")
    monkeypatch.setenv("FEDERATION_INBOUND_ENABLED", "true" if inbound_enabled else "false")
    monkeypatch.setenv("FEDERATION_NODE_ID", NODE_ID)
    monkeypatch.setenv("FEDERATION_PUBLIC_BASE_URL", "https://node.example.org")
    monkeypatch.setenv("FEDERATION_NODE_NAME", "EDEN Node")
    monkeypatch.setenv("FEDERATION_OPERATOR", "EDEN Operator")
    monkeypatch.setenv("FEDERATION_DATABASE_URL", "postgresql+psycopg://test")
    monkeypatch.setenv("FEDERATION_ACTIVE_KID", "k1")
    monkeypatch.setenv("FEDERATION_SIGNING_KEY_PATH", "/tmp/k1.pem")
    monkeypatch.setenv("FEDERATION_ADMIN_CURSOR_SECRET", "s" * 64)
    monkeypatch.setenv("FEDERATION_ROTATION_WORKER_ENABLED", "true" if rotation_enabled else "false")
    monkeypatch.setenv("FEDERATION_ROTATION_POLL_INTERVAL_SECONDS", "5")
    monkeypatch.delenv("FEDERATION_WORKER_INSTANCE_ID", raising=False)

    ctor = {"sync": 0}

    monkeypatch.setattr(federation_worker, "Database", type("_FakeDatabaseFactory", (), {"from_url": staticmethod(lambda _url: _FakeDb())}))
    def _sync_ctor(db, settings):
        ctor["sync"] += 1
        return _FakeSync(db, settings)
    monkeypatch.setattr(federation_worker, "FederationInboundSyncService", _sync_ctor)
    monkeypatch.setattr(federation_worker, "SigningKeyService", _FakeSigning)
    monkeypatch.setattr(federation_worker, "SigningKeyLifecycleService", _FakeLifecycle)
    monkeypatch.setattr(federation_worker, "_safe_heartbeat", lambda *args, **kwargs: True)
    monkeypatch.setattr(federation_worker, "_safe_worker_audit", lambda *args, **kwargs: True)
    monkeypatch.setattr(federation_worker, "_worker_loop", lambda **kwargs: None)

    rc = federation_worker.main()
    assert rc == 0
    assert (ctor["sync"] == 1) is expect_sync_ctor
    assert (_FakeSigning.constructed == 1) is expect_rotation_ctor
    assert (_FakeLifecycle.constructed == 1) is expect_rotation_ctor


def test_worker_instance_id_behavior(monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setenv("FEDERATION_ENABLED", "true")
    monkeypatch.setenv("FEDERATION_NODE_ID", NODE_ID)
    monkeypatch.setenv("FEDERATION_PUBLIC_BASE_URL", "https://node.example.org")
    monkeypatch.setenv("FEDERATION_NODE_NAME", "EDEN Node")
    monkeypatch.setenv("FEDERATION_OPERATOR", "EDEN Operator")
    monkeypatch.setenv("FEDERATION_DATABASE_URL", "postgresql+psycopg://x")
    monkeypatch.setenv("FEDERATION_ACTIVE_KID", "k1")
    monkeypatch.setenv("FEDERATION_SIGNING_KEY_PATH", "/tmp/k1.pem")
    monkeypatch.setenv("FEDERATION_ADMIN_CURSOR_SECRET", "s" * 64)
    monkeypatch.delenv("FEDERATION_WORKER_INSTANCE_ID", raising=False)
    settings = FederationSettings.from_env()
    first = federation_worker._resolve_worker_instance_id(settings)
    second = federation_worker._resolve_worker_instance_id(settings)
    assert first != second
    configured = str(uuid.uuid4())
    monkeypatch.setenv("FEDERATION_WORKER_INSTANCE_ID", configured)
    configured_settings = FederationSettings.from_env()
    assert configured_settings.worker_instance_id == configured
    assert federation_worker._resolve_worker_instance_id(configured_settings) == uuid.UUID(configured)


def test_rotation_only_worker_heartbeat_start_stop(configured_env):
    db: Database = configured_env["db"]
    instance = uuid.uuid4()
    assert federation_worker._safe_heartbeat(
        db,
        instance_id=instance,
        hostname="host-a",
        status=WorkerStatus.RUNNING,
        last_error_class=None,
        mark_success=False,
    )
    assert federation_worker._safe_heartbeat(
        db,
        instance_id=instance,
        hostname="host-a",
        status=WorkerStatus.STOPPED,
        last_error_class=None,
        mark_success=False,
    )
    with db.transaction() as session:
        rows = session.execute(
            select(FederationWorkerHeartbeat)
            .where(FederationWorkerHeartbeat.worker_type == "sync")
            .order_by(FederationWorkerHeartbeat.instance_id.asc())
        ).scalars().all()
    assert len(rows) >= 1
    row = next(r for r in rows if r.instance_id == instance)
    assert row.status == "stopped"
    assert row.last_error_class is None


def test_worker_heartbeat_rows_do_not_overwrite_each_other(configured_env):
    db: Database = configured_env["db"]
    first = uuid.uuid4()
    second = uuid.uuid4()
    assert federation_worker._safe_heartbeat(
        db, instance_id=first, hostname="host-a", status=WorkerStatus.RUNNING, last_error_class=None, mark_success=True
    )
    assert federation_worker._safe_heartbeat(
        db, instance_id=second, hostname="host-b", status=WorkerStatus.RUNNING, last_error_class=None, mark_success=True
    )
    with db.transaction() as session:
        rows = session.execute(
            select(FederationWorkerHeartbeat).where(
                FederationWorkerHeartbeat.worker_type == "sync",
                FederationWorkerHeartbeat.instance_id.in_([first, second]),
            )
        ).scalars().all()
    assert len(rows) == 2


def test_rotation_error_classification_and_missing_material_backoff_tracking():
    backoff = federation_worker._RotationBackoffState()
    backoff.reset_for_candidate("k-a")
    permanent_codes = [
        LocalKeyErrorCode.KEY_NOT_REGULAR_FILE,
        LocalKeyErrorCode.KEY_EMPTY,
        LocalKeyErrorCode.KEY_PATH_ESCAPE,
        LocalKeyErrorCode.KEY_MALFORMED,
        LocalKeyErrorCode.KEY_NOT_ED25519,
        LocalKeyErrorCode.KEY_UNSAFE_PERMISSIONS,
        LocalKeyErrorCode.MATERIAL_MISMATCH,
        LocalKeyErrorCode.COLLISION,
        LocalKeyErrorCode.TRANSITION_FORBIDDEN,
        LocalKeyErrorCode.SCHEDULE_CONFLICT,
        LocalKeyErrorCode.ACTIVE_KEY_MISSING,
        LocalKeyErrorCode.AMBIGUOUS_ACTIVE_KEY,
    ]
    for code in permanent_codes:
        result = federation_worker._classify_rotation_error(LocalKeyError(code, "x"), backoff)
        assert result.permanent is True
    for _ in range(3):
        result = federation_worker._classify_rotation_error(LocalKeyError(LocalKeyErrorCode.KEY_NOT_FOUND, "x"), backoff)
        assert result.code == "rotation_retry_missing_material"
        federation_worker._advance_rotation_backoff(
            settings=SimpleNamespace(
                rotation_poll_interval_seconds=10,
                rotation_failure_backoff_min_seconds=10,
                rotation_failure_backoff_max_seconds=120,
                rotation_backoff_jitter_enabled=False,
            ),
            backoff=backoff,
            result=result,
            now_monotonic=100.0,
        )
    blocked = federation_worker._classify_rotation_error(LocalKeyError(LocalKeyErrorCode.KEY_NOT_FOUND, "x"), backoff)
    assert blocked.code == "rotation_blocked_missing_material"
    other_retryable = federation_worker._RotationPassResult(code="rotation_failed_retrying", retryable=True)
    before = backoff.missing_material_failures
    federation_worker._advance_rotation_backoff(
        settings=SimpleNamespace(
            rotation_poll_interval_seconds=10,
            rotation_failure_backoff_min_seconds=10,
            rotation_failure_backoff_max_seconds=120,
            rotation_backoff_jitter_enabled=False,
        ),
        backoff=backoff,
        result=other_retryable,
        now_monotonic=120.0,
    )
    assert backoff.missing_material_failures == before
    backoff.reset_for_candidate("k-b")
    assert backoff.missing_material_failures == 0


def test_audit_failed_does_not_recursively_audit(monkeypatch: pytest.MonkeyPatch):
    class _FailingLifecycle:
        def activate_due_scheduled(self, **_kwargs):
            raise LocalKeyError(LocalKeyErrorCode.AUDIT_FAILED, "audit-failed") from AuditValidationError("bad")

    class _NoopSigning:
        def ensure_runtime_active_key(self):
            return None

        def sign_bytes(self, _payload):
            return None

    called = {"supplemental": 0}
    monkeypatch.setattr(
        federation_worker,
        "_next_rotation_candidate",
        lambda _db: federation_worker._RotationCandidate(kid="k-audit", scheduled_at=datetime.now(timezone.utc), due=True),
    )
    monkeypatch.setattr(
        federation_worker,
        "_write_supplemental_failure_audit",
        lambda **_kwargs: called.__setitem__("supplemental", called["supplemental"] + 1) or True,
    )
    result = federation_worker._run_rotation_pass(
        lifecycle=_FailingLifecycle(),
        signing=_NoopSigning(),
        db=object(),
        instance_id=uuid.uuid4(),
        backoff=federation_worker._RotationBackoffState(),
    )
    assert result.code == "rotation_blocked_audit_failure"
    assert called["supplemental"] == 0


def test_supplemental_audit_failure_is_contained(monkeypatch: pytest.MonkeyPatch):
    class _FailingLifecycle:
        def activate_due_scheduled(self, **_kwargs):
            raise LocalKeyError(LocalKeyErrorCode.INVALID_REASON, "x")

    class _NoopSigning:
        def ensure_runtime_active_key(self):
            return None

        def sign_bytes(self, _payload):
            return None

    monkeypatch.setattr(
        federation_worker,
        "_next_rotation_candidate",
        lambda _db: federation_worker._RotationCandidate(kid="k-supp", scheduled_at=datetime.now(timezone.utc), due=True),
    )
    monkeypatch.setattr(federation_worker, "_write_supplemental_failure_audit", lambda **_kwargs: False)
    result = federation_worker._run_rotation_pass(
        lifecycle=_FailingLifecycle(),
        signing=_NoopSigning(),
        db=object(),
        instance_id=uuid.uuid4(),
        backoff=federation_worker._RotationBackoffState(),
    )
    assert result.code == "rotation_degraded_audit_persist_failure"
    assert result.degraded is True


def test_worker_loop_failure_boundaries_and_cadence(monkeypatch: pytest.MonkeyPatch):
    class _FakeResult:
        def __init__(self, status: str) -> None:
            self.status = status

    class _SyncService:
        def __init__(self) -> None:
            self.calls = 0

        def sync_all_trusted_peers_once(self, *, max_seconds_per_peer: int):
            _ = max_seconds_per_peer
            self.calls += 1
            if self.calls == 1:
                raise RuntimeError("sync boom")
            return [(uuid.uuid4(), _FakeResult("complete"))]

    sync = _SyncService()
    rotation_calls = {"count": 0}
    heartbeat_calls: list[tuple[str, str | None, bool]] = []
    timeline = {"t": 0.0, "sleep_calls": 0}

    def fake_mono() -> float:
        return timeline["t"]

    def fake_sleep(seconds: float) -> None:
        timeline["sleep_calls"] += 1
        timeline["t"] += max(0.01, seconds)
        if timeline["sleep_calls"] >= 6:
            federation_worker._mark_stop()

    def fake_rotation(**_kwargs):
        rotation_calls["count"] += 1
        if rotation_calls["count"] == 1:
            raise RuntimeError("rotation boom")
        if rotation_calls["count"] == 2:
            return federation_worker._RotationPassResult(code="rotation_idle_no_due")
        return federation_worker._RotationPassResult(code="rotation_activation_succeeded")

    monkeypatch.setattr(federation_worker, "_run_rotation_pass", fake_rotation)
    monkeypatch.setattr(
        federation_worker,
        "_safe_heartbeat",
        lambda _db, *, instance_id, hostname, status, last_error_class, mark_success: heartbeat_calls.append(
            (status.value, last_error_class, mark_success)
        )
        or True,
    )

    federation_worker._STOP = False
    federation_worker._worker_loop(
        db=object(),
        settings=SimpleNamespace(
            worker_max_sync_seconds=5,
            worker_interval_seconds=1,
            rotation_worker_enabled=True,
            rotation_poll_interval_seconds=1,
            rotation_failure_backoff_min_seconds=1,
            rotation_failure_backoff_max_seconds=4,
            rotation_backoff_jitter_enabled=False,
        ),
        instance_id=uuid.uuid4(),
        hostname="host",
        sync_service=sync,
        signing_service=object(),
        rotation_service=object(),
        monotonic_fn=fake_mono,
        sleep_fn=fake_sleep,
    )
    assert sync.calls >= 2
    assert rotation_calls["count"] >= 2
    assert timeline["sleep_calls"] > 0
    assert any(status == "error" and code == "sync_exception" for status, code, _ in heartbeat_calls)
    assert any(status == "running" and code is None and success is True for status, code, success in heartbeat_calls)


def test_worker_loop_rotation_noop_heartbeat_not_error(monkeypatch: pytest.MonkeyPatch):
    timeline = {"t": 0.0, "sleep_calls": 0}
    heartbeats: list[tuple[str, str | None, bool]] = []

    def fake_mono() -> float:
        return timeline["t"]

    def fake_sleep(seconds: float) -> None:
        timeline["sleep_calls"] += 1
        timeline["t"] += max(0.01, seconds)
        federation_worker._mark_stop()

    monkeypatch.setattr(
        federation_worker,
        "_run_rotation_pass",
        lambda **_kwargs: federation_worker._RotationPassResult(code="rotation_idle_no_due"),
    )
    monkeypatch.setattr(
        federation_worker,
        "_safe_heartbeat",
        lambda _db, *, instance_id, hostname, status, last_error_class, mark_success: heartbeats.append(
            (status.value, last_error_class, mark_success)
        )
        or True,
    )
    federation_worker._STOP = False
    federation_worker._worker_loop(
        db=object(),
        settings=SimpleNamespace(
            worker_max_sync_seconds=5,
            worker_interval_seconds=60,
            rotation_worker_enabled=True,
            rotation_poll_interval_seconds=60,
            rotation_failure_backoff_min_seconds=10,
            rotation_failure_backoff_max_seconds=120,
            rotation_backoff_jitter_enabled=False,
        ),
        instance_id=uuid.uuid4(),
        hostname="host",
        sync_service=None,
        signing_service=object(),
        rotation_service=object(),
        monotonic_fn=fake_mono,
        sleep_fn=fake_sleep,
    )
    assert heartbeats
    status, code, mark_success = heartbeats[0]
    assert status == "idle"
    assert code is None
    assert mark_success is False


def test_rotation_only_outbound_node_path(monkeypatch: pytest.MonkeyPatch):
    federation_worker._STOP = False
    monkeypatch.setenv("FEDERATION_ENABLED", "true")
    monkeypatch.setenv("FEDERATION_INBOUND_ENABLED", "false")
    monkeypatch.setenv("FEDERATION_ROTATION_WORKER_ENABLED", "true")
    monkeypatch.setenv("FEDERATION_NODE_ID", NODE_ID)
    monkeypatch.setenv("FEDERATION_PUBLIC_BASE_URL", "https://node.example.org")
    monkeypatch.setenv("FEDERATION_NODE_NAME", "EDEN Node")
    monkeypatch.setenv("FEDERATION_OPERATOR", "EDEN Operator")
    monkeypatch.setenv("FEDERATION_DATABASE_URL", "postgresql+psycopg://test")
    monkeypatch.setenv("FEDERATION_ACTIVE_KID", "k1")
    monkeypatch.setenv("FEDERATION_SIGNING_KEY_PATH", "/tmp/k1.pem")
    monkeypatch.setenv("FEDERATION_ADMIN_CURSOR_SECRET", "s" * 64)

    class _FakeDb:
        pass

    class _FakeSigning:
        def __init__(self, _db, _settings):
            pass

        @property
        def provider(self):
            return object()

        def ensure_runtime_active_key(self):
            return None

    invoked = {"sync_ctor": 0, "loop": 0}
    monkeypatch.setattr(federation_worker, "Database", type("_DBFactory", (), {"from_url": staticmethod(lambda _u: _FakeDb())}))
    monkeypatch.setattr(federation_worker, "FederationInboundSyncService", lambda *_args, **_kwargs: invoked.__setitem__("sync_ctor", invoked["sync_ctor"] + 1))
    monkeypatch.setattr(federation_worker, "SigningKeyService", _FakeSigning)
    monkeypatch.setattr(federation_worker, "SigningKeyLifecycleService", lambda *_args, **_kwargs: object())
    monkeypatch.setattr(federation_worker, "_safe_heartbeat", lambda *args, **kwargs: True)
    monkeypatch.setattr(federation_worker, "_safe_worker_audit", lambda *args, **kwargs: True)
    monkeypatch.setattr(federation_worker, "_worker_loop", lambda **kwargs: invoked.__setitem__("loop", invoked["loop"] + 1))

    assert federation_worker.main() == 0
    assert invoked["sync_ctor"] == 0
    assert invoked["loop"] == 1


def test_activate_due_scheduled_cancellation_before_phase_b_no_mutation(configured_env):
    db: Database = configured_env["db"]
    settings: FederationSettings = configured_env["settings"]
    key_dir: Path = configured_env["key_dir"]
    signing = SigningKeyService(db, settings)
    old_active = signing.ensure_runtime_active_key().kid
    lifecycle = SigningKeyLifecycleService(db, signing.provider)
    _gen_ed25519_pem(key_dir / "k-cancel-before-phase-b.pem")
    lifecycle.stage_candidate(kid="k-cancel-before-phase-b", reason="stage")
    lifecycle.schedule_activation(
        kid="k-cancel-before-phase-b",
        activate_at=datetime.now(timezone.utc),
        reason="schedule",
    )
    result = lifecycle.activate_due_scheduled(
        reason="worker-scheduled-activation",
        should_cancel=lambda: True,
    )
    assert result is not None
    assert result.reason_code == "activation-canceled"
    with db.transaction() as session:
        staged = session.execute(
            select(FederationSigningKey).where(FederationSigningKey.kid == "k-cancel-before-phase-b")
        ).scalar_one()
        active = session.execute(
            select(FederationSigningKey).where(
                FederationSigningKey.status == "active",
                FederationSigningKey.is_active.is_(True),
            )
        ).scalar_one()
        activate_count = session.execute(
            text(
                """
                SELECT count(*) FROM federation_operational_audit
                WHERE target_id = 'k-cancel-before-phase-b' AND action = 'local_key.activate'
                """
            )
        ).scalar_one()
        failed_count = session.execute(
            text(
                """
                SELECT count(*) FROM federation_operational_audit
                WHERE target_id = 'k-cancel-before-phase-b' AND action IN ('local_key.activation_failed', 'local_key.material_mismatch')
                """
            )
        ).scalar_one()
    assert staged.status == "staged"
    assert staged.rotation_scheduled_at is not None
    assert active.kid == old_active
    assert int(activate_count) == 0
    assert int(failed_count) == 0


def test_activate_due_scheduled_cancellation_callback_outside_transaction(configured_env, monkeypatch: pytest.MonkeyPatch):
    db: Database = configured_env["db"]
    settings: FederationSettings = configured_env["settings"]
    key_dir: Path = configured_env["key_dir"]
    signing = SigningKeyService(db, settings)
    signing.ensure_runtime_active_key()
    lifecycle = SigningKeyLifecycleService(db, signing.provider)
    _gen_ed25519_pem(key_dir / "k-cancel-tx-boundary.pem")
    lifecycle.stage_candidate(kid="k-cancel-tx-boundary", reason="stage")
    lifecycle.schedule_activation(
        kid="k-cancel-tx-boundary",
        activate_at=datetime.now(timezone.utc),
        reason="schedule",
    )
    in_tx = {"count": 0}
    observed: list[int] = []
    original_transaction = db.transaction

    @contextmanager
    def tracked_transaction():
        with original_transaction() as session:
            in_tx["count"] += 1
            try:
                yield session
            finally:
                in_tx["count"] -= 1

    monkeypatch.setattr(db, "transaction", tracked_transaction)
    result = lifecycle.activate_due_scheduled(
        reason="worker-scheduled-activation",
        should_cancel=lambda: observed.append(in_tx["count"]) or True,
    )
    assert result is not None
    assert result.reason_code == "activation-canceled"
    assert observed == [0]


def test_benign_race_manual_activation_cancel_retire_no_failure_audit(configured_env, monkeypatch: pytest.MonkeyPatch):
    db: Database = configured_env["db"]
    settings: FederationSettings = configured_env["settings"]
    key_dir: Path = configured_env["key_dir"]
    signing = SigningKeyService(db, settings)
    lifecycle = SigningKeyLifecycleService(db, signing.provider)
    signing.ensure_runtime_active_key()
    backoff = federation_worker._RotationBackoffState()
    worker_id = uuid.uuid4()

    # manual activation wins
    _gen_ed25519_pem(key_dir / "k-race-manual.pem")
    lifecycle.stage_candidate(kid="k-race-manual", reason="stage")
    lifecycle.schedule_activation(kid="k-race-manual", activate_at=datetime.now(timezone.utc), reason="schedule")
    candidate_manual = federation_worker._RotationCandidate(
        kid="k-race-manual",
        scheduled_at=datetime.now(timezone.utc),
        due=True,
    )
    monkeypatch.setattr(federation_worker, "_next_rotation_candidate", lambda _db: candidate_manual)
    lifecycle.activate_staged_key(kid="k-race-manual", reason="manual-activate")
    result_manual = federation_worker._run_rotation_pass(
        lifecycle=lifecycle,
        signing=signing,
        db=db,
        instance_id=worker_id,
        backoff=backoff,
    )
    assert result_manual.is_noop

    # cancellation wins
    _gen_ed25519_pem(key_dir / "k-race-cancel.pem")
    lifecycle.stage_candidate(kid="k-race-cancel", reason="stage")
    lifecycle.schedule_activation(kid="k-race-cancel", activate_at=datetime.now(timezone.utc), reason="schedule")
    candidate_cancel = federation_worker._RotationCandidate(
        kid="k-race-cancel",
        scheduled_at=datetime.now(timezone.utc),
        due=True,
    )
    monkeypatch.setattr(federation_worker, "_next_rotation_candidate", lambda _db: candidate_cancel)
    lifecycle.cancel_schedule(kid="k-race-cancel", reason="cancel-before-phase-b")
    result_cancel = federation_worker._run_rotation_pass(
        lifecycle=lifecycle,
        signing=signing,
        db=db,
        instance_id=worker_id,
        backoff=backoff,
    )
    assert result_cancel.is_noop

    # staged retirement wins
    _gen_ed25519_pem(key_dir / "k-race-retire.pem")
    lifecycle.stage_candidate(kid="k-race-retire", reason="stage")
    lifecycle.schedule_activation(kid="k-race-retire", activate_at=datetime.now(timezone.utc), reason="schedule")
    candidate_retire = federation_worker._RotationCandidate(
        kid="k-race-retire",
        scheduled_at=datetime.now(timezone.utc),
        due=True,
    )
    monkeypatch.setattr(federation_worker, "_next_rotation_candidate", lambda _db: candidate_retire)
    lifecycle.retire_staged_key(kid="k-race-retire", reason="retire-before-phase-b")
    result_retire = federation_worker._run_rotation_pass(
        lifecycle=lifecycle,
        signing=signing,
        db=db,
        instance_id=worker_id,
        backoff=backoff,
    )
    assert result_retire.is_noop

    with db.transaction() as session:
        failed_rows = session.execute(
            text(
                """
                SELECT count(*)
                FROM federation_operational_audit
                WHERE target_id IN ('k-race-manual', 'k-race-cancel', 'k-race-retire')
                  AND action IN ('local_key.activation_failed', 'local_key.material_mismatch')
                """
            )
        ).scalar_one()
    assert int(failed_rows) == 0


def test_two_worker_phase_a_barrier_single_activation_audit_no_failures(configured_env):
    db: Database = configured_env["db"]
    settings: FederationSettings = configured_env["settings"]
    key_dir: Path = configured_env["key_dir"]
    signing = SigningKeyService(db, settings)
    signing.ensure_runtime_active_key()
    lifecycle = SigningKeyLifecycleService(db, signing.provider)
    _gen_ed25519_pem(key_dir / "k-two-worker-race.pem")
    lifecycle.stage_candidate(kid="k-two-worker-race", reason="stage")
    lifecycle.schedule_activation(
        kid="k-two-worker-race",
        activate_at=datetime.now(timezone.utc),
        reason="schedule",
    )

    barrier = threading.Barrier(2)
    results: list[federation_worker._RotationPassResult] = []
    lock = threading.Lock()

    def run_one(instance_id: uuid.UUID) -> None:
        res = federation_worker._run_rotation_pass(
            lifecycle=lifecycle,
            signing=signing,
            db=db,
            instance_id=instance_id,
            backoff=federation_worker._RotationBackoffState(),
            should_cancel=lambda: barrier.wait(timeout=5) is None and False,
        )
        with lock:
            results.append(res)

    t1 = threading.Thread(target=run_one, args=(uuid.uuid4(),))
    t2 = threading.Thread(target=run_one, args=(uuid.uuid4(),))
    t1.start()
    t2.start()
    t1.join()
    t2.join()

    assert len(results) == 2
    success_count = sum(1 for r in results if r.code == "rotation_activation_succeeded")
    noop_count = sum(1 for r in results if r.is_noop)
    assert success_count == 1
    assert noop_count == 1

    with db.transaction() as session:
        active_rows = session.execute(
            select(FederationSigningKey).where(
                FederationSigningKey.status == "active",
                FederationSigningKey.is_active.is_(True),
            )
        ).scalars().all()
        race_row = session.execute(
            select(FederationSigningKey).where(FederationSigningKey.kid == "k-two-worker-race")
        ).scalar_one()
        old_row = session.execute(select(FederationSigningKey).where(FederationSigningKey.kid == "k1")).scalar_one()
        activate_count = session.execute(
            text(
                """
                SELECT count(*) FROM federation_operational_audit
                WHERE target_id='k-two-worker-race' AND action='local_key.activate'
                """
            )
        ).scalar_one()
        fail_count = session.execute(
            text(
                """
                SELECT count(*) FROM federation_operational_audit
                WHERE target_id='k-two-worker-race' AND action='local_key.activation_failed'
                """
            )
        ).scalar_one()
    assert len(active_rows) == 1
    assert active_rows[0].kid == "k-two-worker-race"
    assert race_row.rotation_scheduled_at is None
    assert old_row.status == "retired"
    assert int(activate_count) == 1
    assert int(fail_count) == 0


def test_candidate_scoped_backoff_resets_after_cancel_then_new_candidate(configured_env):
    db: Database = configured_env["db"]
    settings: FederationSettings = configured_env["settings"]
    key_dir: Path = configured_env["key_dir"]
    signing = SigningKeyService(db, settings)
    lifecycle = SigningKeyLifecycleService(db, signing.provider)
    signing.ensure_runtime_active_key()
    backoff = federation_worker._RotationBackoffState()
    worker_id = uuid.uuid4()

    _gen_ed25519_pem(key_dir / "k-backoff-a.pem")
    lifecycle.stage_candidate(kid="k-backoff-a", reason="stage")
    lifecycle.schedule_activation(kid="k-backoff-a", activate_at=datetime.now(timezone.utc), reason="schedule")
    (key_dir / "k-backoff-a.pem").unlink()
    for _ in range(3):
        result = federation_worker._run_rotation_pass(
            lifecycle=lifecycle,
            signing=signing,
            db=db,
            instance_id=worker_id,
            backoff=backoff,
        )
        assert result.code == "rotation_retry_missing_material"
        federation_worker._advance_rotation_backoff(
            settings=settings,
            backoff=backoff,
            result=result,
            now_monotonic=time.monotonic(),
        )
    assert backoff.missing_material_failures == 3
    lifecycle.cancel_schedule(kid="k-backoff-a", reason="cancel")

    _gen_ed25519_pem(key_dir / "k-backoff-b.pem")
    lifecycle.stage_candidate(kid="k-backoff-b", reason="stage")
    lifecycle.schedule_activation(kid="k-backoff-b", activate_at=datetime.now(timezone.utc), reason="schedule")
    (key_dir / "k-backoff-b.pem").unlink()
    result_b = federation_worker._run_rotation_pass(
        lifecycle=lifecycle,
        signing=signing,
        db=db,
        instance_id=worker_id,
        backoff=backoff,
    )
    assert result_b.code == "rotation_retry_missing_material"
    assert backoff.candidate_kid == "k-backoff-b"
    assert backoff.missing_material_failures == 0


def test_worker_cadence_uses_fresh_monotonic_after_long_sync():
    class _SyncService:
        def __init__(self, timeline: dict[str, float]):
            self.calls = 0
            self.timeline = timeline

        def sync_all_trusted_peers_once(self, *, max_seconds_per_peer: int):
            _ = max_seconds_per_peer
            self.calls += 1
            self.timeline["t"] += 10.0
            return []

    timeline = {"t": 0.0, "sleep_calls": 0}
    sync = _SyncService(timeline)

    def fake_mono() -> float:
        return timeline["t"]

    def fake_sleep(seconds: float) -> None:
        timeline["sleep_calls"] += 1
        timeline["t"] += max(seconds, 0.01)
        federation_worker._mark_stop()

    federation_worker._STOP = False
    federation_worker._worker_loop(
        db=object(),
        settings=SimpleNamespace(
            worker_max_sync_seconds=10,
            worker_interval_seconds=5,
            rotation_worker_enabled=False,
            rotation_poll_interval_seconds=5,
            rotation_failure_backoff_min_seconds=1,
            rotation_failure_backoff_max_seconds=10,
            rotation_backoff_jitter_enabled=False,
        ),
        instance_id=uuid.uuid4(),
        hostname="host",
        sync_service=sync,
        signing_service=None,
        rotation_service=None,
        monotonic_fn=fake_mono,
        sleep_fn=fake_sleep,
    )
    assert sync.calls == 1
    assert timeline["sleep_calls"] >= 1


def test_worker_cadence_uses_fresh_monotonic_after_long_rotation(monkeypatch: pytest.MonkeyPatch):
    timeline = {"t": 0.0, "sleep_calls": 0, "rotation_calls": 0}

    def fake_mono() -> float:
        return timeline["t"]

    def fake_sleep(seconds: float) -> None:
        timeline["sleep_calls"] += 1
        timeline["t"] += max(seconds, 0.01)
        federation_worker._mark_stop()

    def fake_rotation(**_kwargs):
        timeline["rotation_calls"] += 1
        timeline["t"] += 10.0
        return federation_worker._RotationPassResult(code="rotation_idle_no_due")

    monkeypatch.setattr(federation_worker, "_run_rotation_pass", fake_rotation)
    federation_worker._STOP = False
    federation_worker._worker_loop(
        db=object(),
        settings=SimpleNamespace(
            worker_max_sync_seconds=10,
            worker_interval_seconds=5,
            rotation_worker_enabled=True,
            rotation_poll_interval_seconds=5,
            rotation_failure_backoff_min_seconds=1,
            rotation_failure_backoff_max_seconds=10,
            rotation_backoff_jitter_enabled=False,
        ),
        instance_id=uuid.uuid4(),
        hostname="host",
        sync_service=None,
        signing_service=object(),
        rotation_service=object(),
        monotonic_fn=fake_mono,
        sleep_fn=fake_sleep,
    )
    assert timeline["rotation_calls"] == 1
    assert timeline["sleep_calls"] >= 1


def test_rotation_backoff_does_not_delay_sync(monkeypatch: pytest.MonkeyPatch):
    class _SyncService:
        def __init__(self):
            self.calls = 0

        def sync_all_trusted_peers_once(self, *, max_seconds_per_peer: int):
            _ = max_seconds_per_peer
            self.calls += 1
            return []

    timeline = {"t": 0.0, "sleep_calls": 0, "rotation_calls": 0}
    sync = _SyncService()

    def fake_mono() -> float:
        return timeline["t"]

    def fake_sleep(seconds: float) -> None:
        timeline["sleep_calls"] += 1
        timeline["t"] += max(0.2, seconds)
        if timeline["sleep_calls"] >= 8:
            federation_worker._mark_stop()

    def fake_rotation(**_kwargs):
        timeline["rotation_calls"] += 1
        return federation_worker._RotationPassResult(code="rotation_blocked_operator", permanent=True)

    monkeypatch.setattr(federation_worker, "_run_rotation_pass", fake_rotation)
    federation_worker._STOP = False
    federation_worker._worker_loop(
        db=object(),
        settings=SimpleNamespace(
            worker_max_sync_seconds=10,
            worker_interval_seconds=1,
            rotation_worker_enabled=True,
            rotation_poll_interval_seconds=1,
            rotation_failure_backoff_min_seconds=2,
            rotation_failure_backoff_max_seconds=120,
            rotation_backoff_jitter_enabled=False,
        ),
        instance_id=uuid.uuid4(),
        hostname="host",
        sync_service=sync,
        signing_service=object(),
        rotation_service=object(),
        monotonic_fn=fake_mono,
        sleep_fn=fake_sleep,
    )
    assert sync.calls >= 3
    assert timeline["rotation_calls"] == 1


def test_worker_source_regressions_step5():
    source = (REPO_ROOT / "src/license_facade_service/worker.py").read_text(encoding="utf-8")
    assert "activate_due_scheduled(" in source
    assert "rotation_poll_interval_seconds" in source
    assert "rotation_failure_backoff_min_seconds" in source
    assert "rotation_failure_backoff_max_seconds" in source
    assert "FEDERATION_WORKER_INSTANCE_ID" in (REPO_ROOT / "src/license_facade_service/config/federation.py").read_text(encoding="utf-8")
    assert "settings.node_id" not in source
    assert "random.uniform(0.75, 1.25)" in source
    assert "asyncio.run(" not in source
    assert "run_coroutine_threadsafe" not in source


def test_step6_compose_topology_rotation_demo():
    compose = (REPO_ROOT / "docker-compose.yaml").read_text(encoding="utf-8")
    assert "node-a-worker:" in compose
    assert "FEDERATION_INBOUND_ENABLED: \"false\"" in compose
    assert "FEDERATION_ROTATION_WORKER_ENABLED: \"true\"" in compose
    assert "FEDERATION_DEMO_NODE_A_KEY_DIR" in compose
    assert "FEDERATION_DEMO_NODE_B_KEY_DIR" in compose
    assert "FEDERATION_SIGNING_KEY_DIR: /run/keys/node-a" in compose
    assert "FEDERATION_SIGNING_KEY_DIR: /run/keys/node-b" in compose
    assert "FEDERATION_SIGNING_KEY_PATH: /run/secrets/node-a-signing-key.pem" not in compose
    assert "FEDERATION_SIGNING_KEY_PATH: /run/secrets/node-b-signing-key.pem" not in compose


def test_step6_demo_script_rotation_assertions_present():
    script = (REPO_ROOT / "scripts/demo-federation.sh").read_text(encoding="utf-8")
    assert "set -euo pipefail" in script
    assert "FEDERATION_DEMO_NODE_A_KEY_DIR" in script
    assert "FEDERATION_DEMO_NODE_B_KEY_DIR" in script
    assert "node-a-worker" in script
    assert "/signing-keys/stage" in script
    assert "/schedule-activation" in script
    assert "/keys/inspect" in script
    assert "/keys/approve" in script
    assert "/circuit/reset" in script
    assert "warningAck" in script
    assert "Private-key/path stage fields rejected: yes" in script
    assert "Unknown-key rejection on B preserved cursor and prior imports" in script
    assert "R1 historical A1 signature unchanged and verifiable" in script
    assert "Security leak scan: passed" in script
    assert "Federation demo: PASSED" in script
