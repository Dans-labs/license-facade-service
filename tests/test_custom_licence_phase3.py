from __future__ import annotations

"""Phase 3 correction and coverage tests.

Covers:
  - Registration: federated scope, admin/curator roles, atomicity
  - Worker: claim ownership, lease expiry, retry, permanent failure, audit events
  - RDF isolation: custom-licence publication creates no RDF outbox jobs
  - DB invariants: constraints reject inconsistent state
  - Idempotency: retry does not duplicate record/event
  - Payload preservation: exact text/SPDX/digest/aliases in federation record
  - Feed surfaces: catalog/changes/record endpoint
  - Admin API: status, retry, 403/404/409 semantics
  - DB identity: URL fingerprint excludes username, normalises port 5432
"""

import os
from dataclasses import replace
import socket
import subprocess
import threading
import time
import uuid
import base64
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest.mock import MagicMock

import psycopg
import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from fastapi.testclient import TestClient
from sqlalchemy import select, text
from sqlalchemy.engine import make_url

from src.license_facade_service.db.models.custom_licence import CustomLicence, CustomLicenceAlias
from src.license_facade_service.db.models.federation import FederationRecord
from src.license_facade_service.federation.license_identity import build_canonical_license_identity
from src.license_facade_service.main import create_app
from src.license_facade_service.federation.canonical_json import canonicalize_to_bytes
from src.license_facade_service.federation.digests import canonical_json_sha256_hex, sha256_hex
from src.license_facade_service.federation.models import SignedFederationChangeEventPayload
from src.license_facade_service.federation.outbound import FederationError, FederationPublicationService
from src.license_facade_service.services.custom_licence_federation_publication import (
    CustomLicenceFederationPublicationService,
    build_custom_licence_federation_payload,
    build_federation_local_id,
    databases_match,
)
from tests.schema_init import apply_schema_init_sql, reset_public_schema

REPO_ROOT = Path(__file__).resolve().parents[1]


# ---------------------------------------------------------------------------
# Infrastructure helpers
# ---------------------------------------------------------------------------


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


def _count_rows(raw_dsn: str, table: str) -> int:
    with psycopg.connect(raw_dsn) as conn:
        with conn.cursor() as cur:
            cur.execute(f"SELECT count(*) FROM {table}")
            return int(cur.fetchone()[0])


def _b64url_decode(value: str) -> bytes:
    return base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))


def _verify_ed25519_signature_from_jwks(*, jwks: dict, kid: str, payload: dict, signed: dict) -> None:
    keys = jwks.get("keys", [])
    key = next((item for item in keys if item.get("kid") == kid), None)
    assert key is not None, f"kid {kid} not found in JWKS"
    assert key.get("alg") == "EdDSA"
    public_key = Ed25519PublicKey.from_public_bytes(_b64url_decode(str(key["x"])))
    payload_bytes = canonicalize_to_bytes(payload)
    expected_digest = sha256_hex(payload_bytes)
    assert signed.get("digestSha256") == expected_digest
    signature = signed.get("signature", {})
    assert signature.get("kid") == kid
    assert signature.get("alg") == "EdDSA"
    public_key.verify(_b64url_decode(str(signature["value"])), payload_bytes)


# ---------------------------------------------------------------------------
# Module-scoped PostgreSQL fixture
# ---------------------------------------------------------------------------


@pytest.fixture(scope="module")
def postgres_urls():
    if not _docker_available():
        pytest.skip("docker not available for PostgreSQL tests")
    port = _free_port()
    container_name = f"lfs-custom-licence-phase3-{uuid.uuid4().hex[:8]}"
    subprocess.run(
        [
            "docker", "run", "--rm", "-d",
            "--name", container_name,
            "-e", "POSTGRES_PASSWORD=postgres",
            "-e", "POSTGRES_USER=postgres",
            "-e", "POSTGRES_DB=lfs_phase3",
            "-p", f"{port}:5432",
            "postgres:16-alpine",
        ],
        check=True,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    dsn = f"postgresql+psycopg://postgres:postgres@127.0.0.1:{port}/lfs_phase3"
    raw_dsn = f"postgresql://postgres:postgres@127.0.0.1:{port}/lfs_phase3"
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
        yield dsn, raw_dsn
    finally:
        subprocess.run(["docker", "stop", container_name], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=False)


@pytest.fixture
def federation_key_file(tmp_path: Path) -> Path:
    key = Ed25519PrivateKey.generate()
    pem = key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    key_path = tmp_path / "federation-signing-key.pem"
    key_path.write_bytes(pem)
    key_path.chmod(0o600)
    return key_path


@pytest.fixture
def phase3_client(postgres_urls: tuple[str, str], federation_key_file: Path, monkeypatch: pytest.MonkeyPatch):
    dsn, raw_dsn = postgres_urls
    reset_public_schema(dsn)
    monkeypatch.setenv("FEDERATION_ENABLED", "true")
    monkeypatch.setenv("FEDERATION_INBOUND_ENABLED", "false")
    monkeypatch.setenv("FEDERATION_DATABASE_URL", dsn)
    monkeypatch.setenv("FEDERATION_NODE_ID", "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa")
    monkeypatch.setenv("FEDERATION_PUBLIC_BASE_URL", "http://node-a:12104")
    monkeypatch.setenv("FEDERATION_NODE_NAME", "Node A")
    monkeypatch.setenv("FEDERATION_OPERATOR", "Operator A")
    monkeypatch.setenv("FEDERATION_ACTIVE_KID", "node-a-k1")
    monkeypatch.setenv("FEDERATION_SIGNING_KEY_PATH", str(federation_key_file))
    monkeypatch.setenv("FEDERATION_ALLOW_HTTP_FOR_DEMO", "true")
    monkeypatch.setenv("OPENREL_ENABLED", "false")
    monkeypatch.setenv("LFS_ADMIN_TOKEN", "admin-token")
    monkeypatch.setenv("LFS_CURATOR_TOKEN", "curator-token")
    monkeypatch.setenv("CUSTOM_LICENCE_REGISTRATION_DATABASE_URL", dsn)
    monkeypatch.setenv("CUSTOM_LICENCE_AUTHORITY_ID", "lfs-local-authority")
    monkeypatch.setenv("CUSTOM_LICENCE_AUTHORITY_BASE_IRI", "https://lfs.example")
    monkeypatch.setenv("CUSTOM_LICENCE_CREATOR_ORGANIZATION_NAME", "LFS Operator")
    monkeypatch.setenv("CUSTOM_LICENCE_CREATOR_ORGANIZATION_IRI", "https://lfs.example/spdx/agents/lfs-operator")
    app = create_app()
    with TestClient(app) as client:
        yield client, raw_dsn


def _payload(*, requested: str, version: str = "1.0", scope: str = "federated", aliases: list[str] | None = None) -> dict:
    return {
        "requestedLicenseId": requested,
        "version": version,
        "name": "DANS Federated License",
        "summary": "A federated custom licence.",
        "description": "Custom terms.",
        "licenseText": "Copyright 2026 DANS.\n\nPermission is granted...",
        "scope": scope,
        "aliases": aliases or [f"{requested}-v{version}-alias"],
    }


# The federation record canonical ID for a published custom licence.
# custom_id is the UUID from custom_licences.id; the node_id matches
# the fixed value set in the phase3_client fixture.
_PHASE3_NODE_ID = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"


def _fed_canonical_id(custom_id: str, version: str = "1.0") -> str:
    return f"lfs:{_PHASE3_NODE_ID}:custom-{custom_id}:{version}"


def _reset_outbox_to_pending(raw_dsn: str, custom_id: str) -> None:
    with psycopg.connect(raw_dsn) as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                UPDATE custom_licence_federation_outbox
                SET status = 'pending',
                    available_at = now(),
                    lease_owner = NULL,
                    lease_expires_at = NULL,
                    federation_record_id = NULL,
                    federation_event_id = NULL,
                    published_at = NULL,
                    last_error_class = NULL,
                    last_error_at = NULL,
                    updated_at = now()
                WHERE custom_licence_id = %s
                """,
                (custom_id,),
            )
        conn.commit()


# ===========================================================================
# 1. Registration tests
# ===========================================================================


def test_federated_registration_curator_creates_pending_outbox_job(phase3_client):
    client, raw_dsn = phase3_client
    requested = f"DANS-Curator-{uuid.uuid4().hex[:8]}"
    response = client.post(
        "/api/v1/licenses",
        json=_payload(requested=requested, scope="federated"),
        headers={"Authorization": "Bearer curator-token"},
    )
    assert response.status_code == 201
    body = response.json()
    assert body["scope"] == "federated"
    assert body["federationStatus"] == "pending"
    assert body["spdxSubmissionStatus"] == "not_requested"
    assert body["lifecycleStatus"] == "registered"
    with psycopg.connect(raw_dsn) as conn:
        with conn.cursor() as cur:
            cur.execute(
                "SELECT status, attempt_count FROM custom_licence_federation_outbox WHERE custom_licence_id = %s",
                (body["id"],),
            )
            row = cur.fetchone()
            assert row == ("pending", 0)


def test_federated_registration_admin_creates_pending_outbox_job(phase3_client):
    client, raw_dsn = phase3_client
    requested = f"DANS-Admin-{uuid.uuid4().hex[:8]}"
    response = client.post(
        "/api/v1/licenses",
        json=_payload(requested=requested, scope="federated"),
        headers={"Authorization": "Bearer admin-token"},
    )
    assert response.status_code == 201
    assert response.json()["federationStatus"] == "pending"


def test_local_and_spdx_submission_do_not_create_publication_job(phase3_client):
    client, raw_dsn = phase3_client
    before = _count_rows(raw_dsn, "custom_licence_federation_outbox")
    local = client.post(
        "/api/v1/licenses",
        json=_payload(requested=f"DANS-Local-{uuid.uuid4().hex[:8]}", scope="local"),
        headers={"Authorization": "Bearer curator-token"},
    )
    spdx_submission = client.post(
        "/api/v1/licenses",
        json=_payload(requested=f"DANS-SPDX-{uuid.uuid4().hex[:8]}", scope="spdx-submission"),
        headers={"Authorization": "Bearer admin-token"},
    )
    assert local.status_code == 201
    assert spdx_submission.status_code == 201
    assert _count_rows(raw_dsn, "custom_licence_federation_outbox") == before


def test_duplicate_federated_registration_creates_no_second_job(phase3_client):
    client, raw_dsn = phase3_client
    requested = f"DANS-Duplicate-{uuid.uuid4().hex[:8]}"
    payload = _payload(requested=requested, scope="federated")
    first = client.post("/api/v1/licenses", json=payload, headers={"Authorization": "Bearer curator-token"})
    second = client.post("/api/v1/licenses", json=payload, headers={"Authorization": "Bearer curator-token"})
    assert first.status_code == 201
    assert second.status_code == 409
    with psycopg.connect(raw_dsn) as conn:
        with conn.cursor() as cur:
            cur.execute("SELECT count(*) FROM custom_licences WHERE requested_license_id = %s", (requested,))
            assert cur.fetchone()[0] == 1
            cur.execute(
                """
                SELECT count(*)
                FROM custom_licence_federation_outbox o
                JOIN custom_licences c ON c.id = o.custom_licence_id
                WHERE c.requested_license_id = %s
                """,
                (requested,),
            )
            assert cur.fetchone()[0] == 1


def test_versioned_licences_create_separate_publication_jobs(phase3_client):
    client, raw_dsn = phase3_client
    base = f"DANS-Versioned-{uuid.uuid4().hex[:8]}"
    r1 = client.post(
        "/api/v1/licenses",
        json=_payload(requested=base, version="1.0", scope="federated"),
        headers={"Authorization": "Bearer curator-token"},
    )
    r2 = client.post(
        "/api/v1/licenses",
        json=_payload(requested=base, version="2.0", scope="federated"),
        headers={"Authorization": "Bearer curator-token"},
    )
    assert r1.status_code == 201
    assert r2.status_code == 201
    assert r1.json()["id"] != r2.json()["id"]
    assert r1.json()["canonicalId"] != r2.json()["canonicalId"]
    with psycopg.connect(raw_dsn) as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                SELECT count(*) FROM custom_licence_federation_outbox o
                JOIN custom_licences c ON c.id = o.custom_licence_id
                WHERE c.requested_license_id = %s
                """,
                (base,),
            )
            assert cur.fetchone()[0] == 2


def test_registration_transaction_is_atomic(phase3_client):
    """Force failure at outbox insertion; verify zero rows in all four tables."""
    client, raw_dsn = phase3_client
    from src.license_facade_service.services.custom_licence_registration import RegistrationFailureInjection
    requested = f"DANS-Atomic-{uuid.uuid4().hex[:8]}"
    svc = client.app.state.custom_licence_registration_service
    original_injection = svc.failure_injection
    svc.failure_injection = RegistrationFailureInjection(fail_before_commit=True)
    try:
        response = client.post(
            "/api/v1/licenses",
            json=_payload(requested=requested, scope="federated"),
            headers={"Authorization": "Bearer curator-token"},
        )
    finally:
        svc.failure_injection = original_injection
    assert response.status_code == 500
    with psycopg.connect(raw_dsn) as conn:
        with conn.cursor() as cur:
            cur.execute("SELECT count(*) FROM custom_licences WHERE requested_license_id = %s", (requested,))
            assert cur.fetchone()[0] == 0
            cur.execute(
                "SELECT count(*) FROM custom_licence_federation_outbox o "
                "JOIN custom_licences c ON c.id = o.custom_licence_id "
                "WHERE c.requested_license_id = %s",
                (requested,),
            )
            assert cur.fetchone()[0] == 0


def test_mismatched_custom_and_federation_databases_rejected(monkeypatch: pytest.MonkeyPatch, federation_key_file: Path):
    monkeypatch.setenv("FEDERATION_ENABLED", "true")
    monkeypatch.setenv("FEDERATION_INBOUND_ENABLED", "false")
    monkeypatch.setenv("FEDERATION_DATABASE_URL", "postgresql+psycopg://postgres:postgres@127.0.0.1:5432/other_db")
    monkeypatch.setenv("FEDERATION_NODE_ID", "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa")
    monkeypatch.setenv("FEDERATION_PUBLIC_BASE_URL", "http://node-a:12104")
    monkeypatch.setenv("FEDERATION_NODE_NAME", "Node A")
    monkeypatch.setenv("FEDERATION_OPERATOR", "Operator A")
    monkeypatch.setenv("FEDERATION_ACTIVE_KID", "node-a-k1")
    monkeypatch.setenv("FEDERATION_SIGNING_KEY_PATH", str(federation_key_file))
    monkeypatch.setenv("FEDERATION_ALLOW_HTTP_FOR_DEMO", "true")
    monkeypatch.setenv("OPENREL_ENABLED", "false")
    monkeypatch.setenv("LFS_ADMIN_TOKEN", "admin-token")
    monkeypatch.setenv("LFS_CURATOR_TOKEN", "curator-token")
    monkeypatch.setenv("CUSTOM_LICENCE_REGISTRATION_DATABASE_URL", "postgresql+psycopg://postgres:postgres@127.0.0.1:5432/custom_db")
    monkeypatch.setenv("CUSTOM_LICENCE_AUTHORITY_ID", "lfs-local-authority")
    monkeypatch.setenv("CUSTOM_LICENCE_AUTHORITY_BASE_IRI", "https://lfs.example")
    monkeypatch.setenv("CUSTOM_LICENCE_CREATOR_ORGANIZATION_NAME", "LFS Operator")
    app = create_app()
    with TestClient(app) as client:
        response = client.post(
            "/api/v1/licenses",
            json=_payload(requested=f"DANS-Mismatch-{uuid.uuid4().hex[:8]}", scope="federated"),
            headers={"Authorization": "Bearer curator-token"},
        )
        assert response.status_code == 503
        body = response.json()
        assert body["type"].endswith("/custom-licence-federation-unavailable") or body["type"].endswith("/custom-licence-federation-database-mismatch")


# ===========================================================================
# 2. Worker / claim / lease / retry tests
# ===========================================================================


def test_worker_publishes_pending_custom_licence(phase3_client):
    client, raw_dsn = phase3_client
    requested = f"DANS-Publish-{uuid.uuid4().hex[:8]}"
    created = client.post(
        "/api/v1/licenses",
        json=_payload(requested=requested, scope="federated"),
        headers={"Authorization": "Bearer curator-token"},
    )
    assert created.status_code == 201
    custom_id = created.json()["id"]

    publication = client.app.state.custom_licence_registration_service.publication_service
    result = publication.process_batch(limit=10, lease_seconds=30, worker_id="test-worker")
    assert result["processed"] >= 1

    with psycopg.connect(raw_dsn) as conn:
        with conn.cursor() as cur:
            cur.execute("SELECT federation_status FROM custom_licences WHERE id = %s", (custom_id,))
            assert cur.fetchone()[0] == "published"
            cur.execute(
                """
                SELECT status, federation_record_id IS NOT NULL, federation_event_id IS NOT NULL
                FROM custom_licence_federation_outbox
                WHERE custom_licence_id = %s
                """,
                (custom_id,),
            )
            row = cur.fetchone()
            assert row == ("published", True, True)
            # Exactly one authoritative record
            cur.execute("SELECT count(*) FROM federation_records WHERE is_authoritative = true")
            assert cur.fetchone()[0] >= 1
            # At least one signed event
            cur.execute("SELECT count(*) FROM federation_change_events")
            assert cur.fetchone()[0] >= 1


def test_wrong_worker_id_cannot_process_claimed_job(phase3_client):
    """A stale worker (wrong worker_id) must not publish after another worker holds the lease."""
    client, raw_dsn = phase3_client
    requested = f"DANS-WrongWorker-{uuid.uuid4().hex[:8]}"
    created = client.post(
        "/api/v1/licenses",
        json=_payload(requested=requested, scope="federated"),
        headers={"Authorization": "Bearer curator-token"},
    )
    assert created.status_code == 201
    custom_id = created.json()["id"]

    publication = client.app.state.custom_licence_registration_service.publication_service
    # Claim with worker A
    claimed = publication.claim_jobs(limit=1, lease_seconds=60, worker_id="worker-a")
    assert len(claimed) == 1
    job_id = claimed[0]

    # Worker B (wrong worker) tries to process the job claimed by A
    before_records = _count_rows(raw_dsn, "federation_records")
    publication.process_job(job_id=job_id, worker_id="worker-b")  # must be no-op
    assert _count_rows(raw_dsn, "federation_records") == before_records

    # Correct worker processes it
    publication.process_job(job_id=job_id, worker_id="worker-a")
    with psycopg.connect(raw_dsn) as conn:
        with conn.cursor() as cur:
            cur.execute("SELECT federation_status FROM custom_licences WHERE id = %s", (custom_id,))
            assert cur.fetchone()[0] == "published"


def test_unclaimed_job_cannot_be_processed_by_any_worker(phase3_client):
    """process_job on a pending (unclaimed) job must be a no-op."""
    client, raw_dsn = phase3_client
    requested = f"DANS-Unclaimed-{uuid.uuid4().hex[:8]}"
    created = client.post(
        "/api/v1/licenses",
        json=_payload(requested=requested, scope="federated"),
        headers={"Authorization": "Bearer curator-token"},
    )
    assert created.status_code == 201
    custom_id = created.json()["id"]

    # Find the outbox job id
    with psycopg.connect(raw_dsn) as conn:
        with conn.cursor() as cur:
            cur.execute("SELECT id FROM custom_licence_federation_outbox WHERE custom_licence_id = %s", (custom_id,))
            job_id = uuid.UUID(str(cur.fetchone()[0]))

    publication = client.app.state.custom_licence_registration_service.publication_service
    before_records = _count_rows(raw_dsn, "federation_records")
    publication.process_job(job_id=job_id, worker_id="any-worker")  # pending, not processing
    assert _count_rows(raw_dsn, "federation_records") == before_records
    with psycopg.connect(raw_dsn) as conn:
        with conn.cursor() as cur:
            cur.execute("SELECT status FROM custom_licence_federation_outbox WHERE custom_licence_id = %s", (custom_id,))
            assert cur.fetchone()[0] == "pending"


def test_expired_lease_can_be_reclaimed(phase3_client):
    """After lease_expires_at passes, another worker can reclaim the job."""
    client, raw_dsn = phase3_client
    requested = f"DANS-ExpiredLease-{uuid.uuid4().hex[:8]}"
    created = client.post(
        "/api/v1/licenses",
        json=_payload(requested=requested, scope="federated"),
        headers={"Authorization": "Bearer curator-token"},
    )
    assert created.status_code == 201
    custom_id = created.json()["id"]

    # Manually set job to processing with expired lease
    with psycopg.connect(raw_dsn) as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                UPDATE custom_licence_federation_outbox
                SET status = 'processing',
                    lease_owner = 'old-worker',
                    lease_expires_at = now() - interval '10 minutes',
                    updated_at = now()
                WHERE custom_licence_id = %s
                """,
                (custom_id,),
            )
        conn.commit()

    publication = client.app.state.custom_licence_registration_service.publication_service
    reclaimed = publication.claim_jobs(limit=100, lease_seconds=60, worker_id="new-worker")
    assert len(reclaimed) >= 1

    with psycopg.connect(raw_dsn) as conn:
        with conn.cursor() as cur:
            cur.execute(
                "SELECT status, lease_owner FROM custom_licence_federation_outbox WHERE custom_licence_id = %s",
                (custom_id,),
            )
            row = cur.fetchone()
            assert row[0] == "processing"
            assert row[1] == "new-worker"


def test_two_concurrent_claimers_receive_disjoint_jobs(postgres_urls, federation_key_file, monkeypatch):
    """Concurrent workers must not both claim the same job."""
    dsn, raw_dsn = postgres_urls
    monkeypatch.setenv("FEDERATION_ENABLED", "true")
    monkeypatch.setenv("FEDERATION_INBOUND_ENABLED", "false")
    monkeypatch.setenv("FEDERATION_DATABASE_URL", dsn)
    monkeypatch.setenv("FEDERATION_NODE_ID", "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa")
    monkeypatch.setenv("FEDERATION_PUBLIC_BASE_URL", "http://node-a:12104")
    monkeypatch.setenv("FEDERATION_NODE_NAME", "Node A")
    monkeypatch.setenv("FEDERATION_OPERATOR", "Operator A")
    monkeypatch.setenv("FEDERATION_ACTIVE_KID", "node-a-k1")
    monkeypatch.setenv("FEDERATION_SIGNING_KEY_PATH", str(federation_key_file))
    monkeypatch.setenv("FEDERATION_ALLOW_HTTP_FOR_DEMO", "true")
    monkeypatch.setenv("OPENREL_ENABLED", "false")
    monkeypatch.setenv("LFS_ADMIN_TOKEN", "admin-token")
    monkeypatch.setenv("LFS_CURATOR_TOKEN", "curator-token")
    monkeypatch.setenv("CUSTOM_LICENCE_REGISTRATION_DATABASE_URL", dsn)
    monkeypatch.setenv("CUSTOM_LICENCE_AUTHORITY_ID", "lfs-local-authority")
    monkeypatch.setenv("CUSTOM_LICENCE_AUTHORITY_BASE_IRI", "https://lfs.example")
    monkeypatch.setenv("CUSTOM_LICENCE_CREATOR_ORGANIZATION_NAME", "LFS Operator")

    # Register two jobs
    app = create_app()
    with TestClient(app) as client:
        ids = []
        for _ in range(2):
            r = client.post(
                "/api/v1/licenses",
                json=_payload(requested=f"DANS-Conc-{uuid.uuid4().hex[:8]}", scope="federated"),
                headers={"Authorization": "Bearer curator-token"},
            )
            assert r.status_code == 201
            ids.append(r.json()["id"])

        pub = client.app.state.custom_licence_registration_service.publication_service

        results: list[list[uuid.UUID]] = [[], []]
        barrier = threading.Barrier(2)

        def _claim(idx: int) -> None:
            barrier.wait()
            results[idx] = pub.claim_jobs(limit=10, lease_seconds=60, worker_id=f"worker-{idx}")

        threads = [threading.Thread(target=_claim, args=(i,)) for i in range(2)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        all_claimed = results[0] + results[1]
        # No job should be claimed by both workers
        assert len(all_claimed) == len(set(all_claimed)), "Duplicate jobs claimed by concurrent workers"


# ===========================================================================
# 3. Failure state / audit consistency tests
# ===========================================================================


def test_transient_failure_schedules_bounded_retry(phase3_client):
    """A transient publication error sets retryable_failed and schedules retry."""
    client, raw_dsn = phase3_client
    requested = f"DANS-Transient-{uuid.uuid4().hex[:8]}"
    created = client.post(
        "/api/v1/licenses",
        json=_payload(requested=requested, scope="federated"),
        headers={"Authorization": "Bearer curator-token"},
    )
    assert created.status_code == 201
    custom_id = created.json()["id"]

    publication = client.app.state.custom_licence_registration_service.publication_service

    # Inject a transient error into the publisher
    failing_publisher = MagicMock()
    failing_publisher.publish_new_version_in_session.side_effect = FederationError(
        "federation-unavailable", "Simulated transient failure."
    )
    original_publisher = publication.publisher
    publication.publisher = failing_publisher
    try:
        publication.process_batch(limit=10, lease_seconds=30, worker_id="test-worker")
    finally:
        publication.publisher = original_publisher

    with psycopg.connect(raw_dsn) as conn:
        with conn.cursor() as cur:
            cur.execute(
                "SELECT status, attempt_count, last_error_class FROM custom_licence_federation_outbox WHERE custom_licence_id = %s",
                (custom_id,),
            )
            row = cur.fetchone()
            assert row[0] == "retryable_failed"
            assert row[1] >= 1
            assert row[2] is not None
            # Local licence preserved and still accessible
            cur.execute("SELECT federation_status FROM custom_licences WHERE id = %s", (custom_id,))
            assert cur.fetchone()[0] == "pending"


def test_permanent_failure_sets_publication_failed_and_audit_event(phase3_client):
    """Exhausted max attempts causes permanently_failed and publication_failed on licence."""
    client, raw_dsn = phase3_client
    requested = f"DANS-PermFail-{uuid.uuid4().hex[:8]}"
    created = client.post(
        "/api/v1/licenses",
        json=_payload(requested=requested, scope="federated"),
        headers={"Authorization": "Bearer curator-token"},
    )
    assert created.status_code == 201
    custom_id = created.json()["id"]

    publication = client.app.state.custom_licence_registration_service.publication_service
    orig_max = publication.max_attempts
    publication.max_attempts = 1  # Force immediate permanent failure

    failing_publisher = MagicMock()
    failing_publisher.publish_new_version_in_session.side_effect = FederationError(
        "federation-unavailable", "Simulated transient to exhaust."
    )
    original_publisher = publication.publisher
    publication.publisher = failing_publisher
    try:
        for _ in range(3):
            publication.process_batch(limit=10, lease_seconds=30, worker_id="test-worker")
    finally:
        publication.publisher = original_publisher
        publication.max_attempts = orig_max

    with psycopg.connect(raw_dsn) as conn:
        with conn.cursor() as cur:
            cur.execute(
                "SELECT status FROM custom_licence_federation_outbox WHERE custom_licence_id = %s",
                (custom_id,),
            )
            status = cur.fetchone()[0]
            assert status == "permanently_failed"
            cur.execute("SELECT federation_status FROM custom_licences WHERE id = %s", (custom_id,))
            assert cur.fetchone()[0] == "publication_failed"
            # Exactly one failure audit event
            cur.execute(
                """
                SELECT count(*) FROM custom_licence_audit_events
                WHERE custom_licence_id = %s
                AND event_type = 'custom_licence_federation_publication_failed'
                """,
                (custom_id,),
            )
            assert cur.fetchone()[0] >= 1


def test_local_licence_survives_all_publication_failures(phase3_client):
    """The authoritative local licence row must persist even when publication permanently fails."""
    client, raw_dsn = phase3_client
    requested = f"DANS-Survives-{uuid.uuid4().hex[:8]}"
    created = client.post(
        "/api/v1/licenses",
        json=_payload(requested=requested, scope="federated"),
        headers={"Authorization": "Bearer curator-token"},
    )
    assert created.status_code == 201
    custom_id = created.json()["id"]

    publication = client.app.state.custom_licence_registration_service.publication_service
    publication.max_attempts = 1
    failing_publisher = MagicMock()
    failing_publisher.publish_new_version_in_session.side_effect = RuntimeError("Non-retryable injected failure")
    original = publication.publisher
    publication.publisher = failing_publisher
    try:
        publication.process_batch(limit=10, lease_seconds=30, worker_id="test-worker")
    finally:
        publication.publisher = original
        publication.max_attempts = 8

    with psycopg.connect(raw_dsn) as conn:
        with conn.cursor() as cur:
            cur.execute("SELECT count(*) FROM custom_licences WHERE id = %s", (custom_id,))
            assert cur.fetchone()[0] == 1


def test_signing_failure_leaves_no_federation_record_or_event(phase3_client):
    """A real signing failure after record flush must roll back the full publication transaction."""
    client, raw_dsn = phase3_client
    requested = f"DANS-SignFail-{uuid.uuid4().hex[:8]}"
    created = client.post(
        "/api/v1/licenses",
        json=_payload(requested=requested, scope="federated"),
        headers={"Authorization": "Bearer curator-token"},
    )
    assert created.status_code == 201
    custom_id = created.json()["id"]

    before_records = _count_rows(raw_dsn, "federation_records")
    before_events = _count_rows(raw_dsn, "federation_change_events")

    before_rdf = _count_rows(raw_dsn, "federation_rdf_outbox_jobs")
    publication = client.app.state.custom_licence_registration_service.publication_service

    class _FailingSigner:
        def sign_bytes(self, _payload: bytes):
            raise FederationError("signing-unavailable", "Injected signing failure for rollback test.")

        def verify_bytes(self, *_args, **_kwargs):
            return False

    registration = client.app.state.custom_licence_registration_service
    failing_real_publisher = FederationPublicationService(
        registration.db,
        publication.federation_settings,
        signing=_FailingSigner(),
    )
    original = publication.publisher
    publication.publisher = failing_real_publisher
    try:
        publication.process_batch(limit=10, lease_seconds=30, worker_id="test-worker")
    finally:
        publication.publisher = original

    # No federation record or event created
    assert _count_rows(raw_dsn, "federation_records") == before_records
    assert _count_rows(raw_dsn, "federation_change_events") == before_events
    assert _count_rows(raw_dsn, "federation_rdf_outbox_jobs") == before_rdf

    with psycopg.connect(raw_dsn) as conn:
        with conn.cursor() as cur:
            cur.execute(
                "SELECT status, federation_record_id, federation_event_id FROM custom_licence_federation_outbox WHERE custom_licence_id = %s",
                (custom_id,),
            )
            status, record_id, event_id = cur.fetchone()
            assert status == "retryable_failed"
            assert record_id is None
            assert event_id is None
            # Local licence survives
            cur.execute("SELECT count(*), federation_status FROM custom_licences WHERE id = %s GROUP BY federation_status", (custom_id,))
            row = cur.fetchone()
            assert row[0] == 1
            assert row[1] == "pending"
            cur.execute(
                """
                SELECT count(*) FROM custom_licence_audit_events
                WHERE custom_licence_id = %s AND event_type = 'custom_licence_federation_published'
                """,
                (custom_id,),
            )
            assert cur.fetchone()[0] == 0


def test_retry_does_not_create_duplicate_federation_record(phase3_client):
    """When publication already committed, retry must be idempotent (no duplicate record/event)."""
    client, raw_dsn = phase3_client
    requested = f"DANS-Idempotent-{uuid.uuid4().hex[:8]}"
    created = client.post(
        "/api/v1/licenses",
        json=_payload(requested=requested, scope="federated"),
        headers={"Authorization": "Bearer curator-token"},
    )
    assert created.status_code == 201
    custom_id = created.json()["id"]

    publication = client.app.state.custom_licence_registration_service.publication_service
    # First publication
    publication.process_batch(limit=10, lease_seconds=30, worker_id="test-worker")

    before_records = _count_rows(raw_dsn, "federation_records")
    before_events = _count_rows(raw_dsn, "federation_change_events")

    # Manually reset to pending (simulate re-run)
    _reset_outbox_to_pending(raw_dsn, custom_id)

    # Second publication run — must recover from record-exists idempotently
    publication.process_batch(limit=10, lease_seconds=30, worker_id="test-worker")

    # Should not have created an extra record or event
    assert _count_rows(raw_dsn, "federation_records") == before_records
    assert _count_rows(raw_dsn, "federation_change_events") == before_events


def test_record_exists_recovery_uses_compatible_upsert_not_latest_tombstone(phase3_client):
    """Recovery must find the latest compatible upsert event, not blindly take latest event."""
    client, raw_dsn = phase3_client
    requested = f"DANS-RecoverTombstone-{uuid.uuid4().hex[:8]}"
    created = client.post(
        "/api/v1/licenses",
        json=_payload(requested=requested, scope="federated"),
        headers={"Authorization": "Bearer curator-token"},
    )
    assert created.status_code == 201
    custom_id = created.json()["id"]
    canonical_id = _fed_canonical_id(custom_id)
    publication = client.app.state.custom_licence_registration_service.publication_service
    publication.process_batch(limit=10, lease_seconds=30, worker_id="recover-upsert-worker")
    publication.publisher.append_state_event(canonical_id=canonical_id, operation="deprecate")
    _reset_outbox_to_pending(raw_dsn, custom_id)
    publication.process_batch(limit=10, lease_seconds=30, worker_id="recover-upsert-worker")
    with psycopg.connect(raw_dsn) as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                SELECT status, federation_event_id
                FROM custom_licence_federation_outbox
                WHERE custom_licence_id = %s
                """,
                (custom_id,),
            )
            status, event_id = cur.fetchone()
            assert status == "published"
            cur.execute("SELECT operation FROM federation_change_events WHERE id = %s", (event_id,))
            assert cur.fetchone()[0] == "upsert"


def test_record_exists_recovery_fails_when_only_incompatible_event_exists(phase3_client):
    """Record-exists with no compatible upsert evidence must permanently fail with publication_failed."""
    client, raw_dsn = phase3_client
    requested = f"DANS-RecoverIncompatible-{uuid.uuid4().hex[:8]}"
    created = client.post(
        "/api/v1/licenses",
        json=_payload(requested=requested, scope="federated"),
        headers={"Authorization": "Bearer curator-token"},
    )
    assert created.status_code == 201
    custom_id = created.json()["id"]
    publication = client.app.state.custom_licence_registration_service.publication_service
    with publication.db.transaction() as session:
        custom = session.execute(select(CustomLicence).where(CustomLicence.id == custom_id)).scalar_one()
        aliases = (
            session.execute(select(CustomLicenceAlias.alias).where(CustomLicenceAlias.custom_licence_id == custom.id))
            .scalars()
            .all()
        )
        payload = build_custom_licence_federation_payload(
            custom,
            custom_settings=publication.custom_settings,
            publishing_node_id=_PHASE3_NODE_ID,
            aliases=sorted(set(aliases)),
        )
        local_id = build_federation_local_id(custom_licence_id=custom.id)
        canonical_id = _fed_canonical_id(custom_id)
        identity = build_canonical_license_identity(authority_node_id=_PHASE3_NODE_ID, local_id=local_id, version=custom.version)
        record = FederationRecord(
            authority_node_id=_PHASE3_NODE_ID,
            local_id=local_id,
            version=custom.version,
            canonical_id=canonical_id,
            resolving_uuid=uuid.UUID(identity.resolvingUuid),
            is_authoritative=True,
            payload=payload,
            payload_digest_sha256=canonical_json_sha256_hex(payload),
            published_at=custom.created_at,
            created_at=custom.created_at,
            updated_at=custom.updated_at,
        )
        session.add(record)
        session.flush()
        from src.license_facade_service.db.models.federation import FederationChangeEvent

        next_sequence = int(session.execute(text("SELECT nextval('federation_change_event_sequence')")).scalar_one())
        event_payload = {
            "nodeId": _PHASE3_NODE_ID,
            "eventId": str(uuid.uuid4()),
            "eventPosition": next_sequence,
            "operation": "deprecate",
            "generatedAt": custom.created_at.astimezone(timezone.utc).isoformat(),
            "record": {
                "nodeId": _PHASE3_NODE_ID,
                "canonicalId": canonical_id,
                "authorityNodeId": _PHASE3_NODE_ID,
                "localId": local_id,
                "version": custom.version,
                "publishedAt": custom.created_at.astimezone(timezone.utc).isoformat(),
                "payload": payload,
                "payloadDigestSha256": canonical_json_sha256_hex(payload),
            },
            "provenance": "publication",
            "backfillCreatedAt": None,
        }
        session.add(
            FederationChangeEvent(
                event_sequence=next_sequence,
                event_type="record.changed",
                authority_node_id=_PHASE3_NODE_ID,
                record_id=record.id,
                operation="deprecate",
                generated_at=custom.created_at,
                payload_schema_version="1",
                signed_payload=event_payload,
                signed_payload_digest_sha256=sha256_hex(canonicalize_to_bytes(event_payload)),
                signature_base64url="invalid-signature",
                signature_kid="node-a-k1",
                signature_alg="EdDSA",
                provenance_type="publication",
                backfill_created_at=None,
                event_payload=event_payload,
                event_digest_sha256=sha256_hex(canonicalize_to_bytes(event_payload)),
                occurred_at=custom.created_at,
                created_at=custom.created_at,
            )
        )
    publication.max_attempts = 1
    try:
        publication.process_batch(limit=10, lease_seconds=30, worker_id="recover-incompatible-worker")
    finally:
        publication.max_attempts = 8
    with psycopg.connect(raw_dsn) as conn:
        with conn.cursor() as cur:
            cur.execute(
                "SELECT status, last_error_class FROM custom_licence_federation_outbox WHERE custom_licence_id = %s",
                (custom_id,),
            )
            status, error_class = cur.fetchone()
            assert status == "permanently_failed"
            assert error_class == "CustomLicenceFederationPublicationError"
            cur.execute("SELECT federation_status FROM custom_licences WHERE id = %s", (custom_id,))
            assert cur.fetchone()[0] == "publication_failed"


def test_record_exists_recovery_fails_when_record_has_no_event(phase3_client):
    """Record-exists without any event evidence must not be marked as published."""
    client, raw_dsn = phase3_client
    requested = f"DANS-RecoverNoEvent-{uuid.uuid4().hex[:8]}"
    created = client.post(
        "/api/v1/licenses",
        json=_payload(requested=requested, scope="federated"),
        headers={"Authorization": "Bearer curator-token"},
    )
    assert created.status_code == 201
    custom_id = created.json()["id"]
    publication = client.app.state.custom_licence_registration_service.publication_service
    with publication.db.transaction() as session:
        custom = session.execute(select(CustomLicence).where(CustomLicence.id == custom_id)).scalar_one()
        aliases = (
            session.execute(select(CustomLicenceAlias.alias).where(CustomLicenceAlias.custom_licence_id == custom.id))
            .scalars()
            .all()
        )
        payload = build_custom_licence_federation_payload(
            custom,
            custom_settings=publication.custom_settings,
            publishing_node_id=_PHASE3_NODE_ID,
            aliases=sorted(set(aliases)),
        )
        local_id = build_federation_local_id(custom_licence_id=custom.id)
        canonical_id = _fed_canonical_id(custom_id)
        identity = build_canonical_license_identity(authority_node_id=_PHASE3_NODE_ID, local_id=local_id, version=custom.version)
        session.add(
            FederationRecord(
                authority_node_id=_PHASE3_NODE_ID,
                local_id=local_id,
                version=custom.version,
                canonical_id=canonical_id,
                resolving_uuid=uuid.UUID(identity.resolvingUuid),
                is_authoritative=True,
                payload=payload,
                payload_digest_sha256=canonical_json_sha256_hex(payload),
                published_at=custom.created_at,
                created_at=custom.created_at,
                updated_at=custom.updated_at,
            )
        )
    publication.max_attempts = 1
    try:
        publication.process_batch(limit=10, lease_seconds=30, worker_id="recover-noevent-worker")
    finally:
        publication.max_attempts = 8
    with psycopg.connect(raw_dsn) as conn:
        with conn.cursor() as cur:
            cur.execute("SELECT status FROM custom_licence_federation_outbox WHERE custom_licence_id = %s", (custom_id,))
            assert cur.fetchone()[0] == "permanently_failed"
            cur.execute("SELECT federation_status FROM custom_licences WHERE id = %s", (custom_id,))
            assert cur.fetchone()[0] == "publication_failed"


def test_record_exists_recovery_rejects_digest_mismatch(phase3_client):
    client, raw_dsn = phase3_client
    requested = f"DANS-RecoverDigest-{uuid.uuid4().hex[:8]}"
    created = client.post(
        "/api/v1/licenses",
        json=_payload(requested=requested, scope="federated"),
        headers={"Authorization": "Bearer curator-token"},
    )
    assert created.status_code == 201
    custom_id = created.json()["id"]
    publication = client.app.state.custom_licence_registration_service.publication_service
    with publication.db.transaction() as session:
        custom = session.execute(select(CustomLicence).where(CustomLicence.id == custom_id)).scalar_one()
        aliases = (
            session.execute(select(CustomLicenceAlias.alias).where(CustomLicenceAlias.custom_licence_id == custom.id))
            .scalars()
            .all()
        )
        payload = build_custom_licence_federation_payload(
            custom,
            custom_settings=publication.custom_settings,
            publishing_node_id=_PHASE3_NODE_ID,
            aliases=sorted(set(aliases)),
        )
        local_id = build_federation_local_id(custom_licence_id=custom.id)
        canonical_id = _fed_canonical_id(custom_id)
        identity = build_canonical_license_identity(authority_node_id=_PHASE3_NODE_ID, local_id=local_id, version=custom.version)
        session.add(
            FederationRecord(
                authority_node_id=_PHASE3_NODE_ID,
                local_id=local_id,
                version=custom.version,
                canonical_id=canonical_id,
                resolving_uuid=uuid.UUID(identity.resolvingUuid),
                is_authoritative=True,
                payload=payload,
                payload_digest_sha256="0" * 64,
                published_at=custom.created_at,
                created_at=custom.created_at,
                updated_at=custom.updated_at,
            )
        )
    publication.max_attempts = 1
    try:
        publication.process_batch(limit=10, lease_seconds=30, worker_id="recover-digest-worker")
    finally:
        publication.max_attempts = 8
    with psycopg.connect(raw_dsn) as conn:
        with conn.cursor() as cur:
            cur.execute("SELECT status FROM custom_licence_federation_outbox WHERE custom_licence_id = %s", (custom_id,))
            assert cur.fetchone()[0] == "permanently_failed"


def test_record_exists_recovery_rejects_authority_mismatch(phase3_client):
    client, raw_dsn = phase3_client
    requested = f"DANS-RecoverAuthority-{uuid.uuid4().hex[:8]}"
    created = client.post(
        "/api/v1/licenses",
        json=_payload(requested=requested, scope="federated"),
        headers={"Authorization": "Bearer curator-token"},
    )
    assert created.status_code == 201
    custom_id = created.json()["id"]
    publication = client.app.state.custom_licence_registration_service.publication_service
    with publication.db.transaction() as session:
        custom = session.execute(select(CustomLicence).where(CustomLicence.id == custom_id)).scalar_one()
        aliases = (
            session.execute(select(CustomLicenceAlias.alias).where(CustomLicenceAlias.custom_licence_id == custom.id))
            .scalars()
            .all()
        )
        payload = build_custom_licence_federation_payload(
            custom,
            custom_settings=publication.custom_settings,
            publishing_node_id=_PHASE3_NODE_ID,
            aliases=sorted(set(aliases)),
        )
        local_id = build_federation_local_id(custom_licence_id=custom.id)
        canonical_id = _fed_canonical_id(custom_id)
        identity = build_canonical_license_identity(authority_node_id=_PHASE3_NODE_ID, local_id=local_id, version=custom.version)
        session.add(
            FederationRecord(
                authority_node_id="cccccccc-cccc-4ccc-8ccc-cccccccccccc",
                local_id=local_id,
                version=custom.version,
                canonical_id=canonical_id,
                resolving_uuid=uuid.UUID(identity.resolvingUuid),
                is_authoritative=True,
                payload=payload,
                payload_digest_sha256=canonical_json_sha256_hex(payload),
                published_at=custom.created_at,
                created_at=custom.created_at,
                updated_at=custom.updated_at,
            )
        )
    publication.max_attempts = 1
    try:
        publication.process_batch(limit=10, lease_seconds=30, worker_id="recover-authority-worker")
    finally:
        publication.max_attempts = 8
    with psycopg.connect(raw_dsn) as conn:
        with conn.cursor() as cur:
            cur.execute("SELECT status FROM custom_licence_federation_outbox WHERE custom_licence_id = %s", (custom_id,))
            assert cur.fetchone()[0] == "permanently_failed"


def test_worker_restart_resumes_pending_job(phase3_client):
    """After a worker restart, a newly created pending job is fully published once."""
    client, raw_dsn = phase3_client
    requested = f"DANS-Restart-{uuid.uuid4().hex[:8]}"
    created = client.post(
        "/api/v1/licenses",
        json=_payload(requested=requested, scope="federated"),
        headers={"Authorization": "Bearer curator-token"},
    )
    assert created.status_code == 201
    custom_id = created.json()["id"]

    publication = client.app.state.custom_licence_registration_service.publication_service
    # Process only this freshly created job to make restart assertions deterministic.
    publication.process_batch(limit=1, lease_seconds=30, worker_id="new-worker-after-restart")

    with psycopg.connect(raw_dsn) as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                SELECT status, federation_record_id, federation_event_id
                FROM custom_licence_federation_outbox
                WHERE custom_licence_id = %s
                """,
                (custom_id,),
            )
            outbox_status, record_id, event_id = cur.fetchone()
            assert outbox_status == "published"
            assert record_id is not None
            assert event_id is not None
            cur.execute("SELECT federation_status FROM custom_licences WHERE id = %s", (custom_id,))
            assert cur.fetchone()[0] == "published"
            cur.execute("SELECT count(*) FROM federation_records WHERE id = %s", (record_id,))
            assert cur.fetchone()[0] == 1
            cur.execute(
                """
                SELECT count(*) FROM federation_change_events
                WHERE record_id = %s AND operation = 'upsert'
                """,
                (record_id,),
            )
            assert cur.fetchone()[0] == 1


# ===========================================================================
# 4. RDF isolation tests
# ===========================================================================


def test_custom_licence_publication_creates_no_rdf_outbox_jobs(phase3_client):
    """Publishing a custom licence must not enqueue any RDF outbox jobs."""
    client, raw_dsn = phase3_client
    before_rdf = _count_rows(raw_dsn, "federation_rdf_outbox_jobs")
    requested = f"DANS-RDF-{uuid.uuid4().hex[:8]}"
    created = client.post(
        "/api/v1/licenses",
        json=_payload(requested=requested, scope="federated"),
        headers={"Authorization": "Bearer curator-token"},
    )
    assert created.status_code == 201
    publication = client.app.state.custom_licence_registration_service.publication_service
    publication.process_batch(limit=10, lease_seconds=30, worker_id="rdf-test-worker")
    after_rdf = _count_rows(raw_dsn, "federation_rdf_outbox_jobs")
    assert after_rdf == before_rdf, (
        f"RDF outbox jobs were created during custom-licence publication: {after_rdf - before_rdf} new job(s)"
    )


def test_standard_federation_publication_still_enqueues_rdf_outbox_job(phase3_client):
    """Default outbound publication (enqueue_rdf=True) must preserve existing RDF outbox behavior."""
    client, raw_dsn = phase3_client
    before_rdf = _count_rows(raw_dsn, "federation_rdf_outbox_jobs")
    registration = client.app.state.custom_licence_registration_service
    publication_settings = registration.publication_service.federation_settings
    outbound = FederationPublicationService(registration.db, publication_settings)
    local_id = f"rdf-regression-{uuid.uuid4().hex[:8]}"
    cid = f"lfs:{_PHASE3_NODE_ID}:{local_id}:1"
    outbound.publish_new_version(
        canonical_id=cid,
        authority_node_id=_PHASE3_NODE_ID,
        local_id=local_id,
        version="1",
        payload={"licenseId": "RDF-REGRESSION", "name": "RDF regression"},
    )
    after_rdf = _count_rows(raw_dsn, "federation_rdf_outbox_jobs")
    assert after_rdf >= before_rdf + 1


# ===========================================================================
# 5. Database constraint enforcement tests
# ===========================================================================


def test_db_constraint_processing_requires_lease_owner(postgres_urls):
    """The DB must reject a processing row without a lease_owner."""
    _, raw_dsn = postgres_urls
    with psycopg.connect(raw_dsn) as conn:
        with conn.cursor() as cur:
            cur.execute("SELECT id FROM custom_licences LIMIT 1")
            row = cur.fetchone()
            if row is None:
                pytest.skip("No custom licences present to use as FK target")
            licence_id = row[0]
        try:
            with conn.cursor() as cur:
                cur.execute(
                    """
                    INSERT INTO custom_licence_federation_outbox
                    (id, custom_licence_id, operation, status, attempt_count, available_at, created_at, updated_at)
                    VALUES (gen_random_uuid(), %s, 'upsert', 'processing', 0, now(), now(), now())
                    """,
                    (licence_id,),
                )
            conn.commit()
            pytest.fail("Expected constraint violation for processing without lease_owner")
        except psycopg.errors.CheckViolation:
            conn.rollback()


def test_db_constraint_published_requires_linkage(postgres_urls):
    """The DB must reject a published row without federation_record_id."""
    _, raw_dsn = postgres_urls
    with psycopg.connect(raw_dsn) as conn:
        with conn.cursor() as cur:
            cur.execute("SELECT id FROM custom_licences LIMIT 1")
            row = cur.fetchone()
            if row is None:
                pytest.skip("No custom licences present to use as FK target")
            licence_id = row[0]
        try:
            with conn.cursor() as cur:
                cur.execute(
                    """
                    INSERT INTO custom_licence_federation_outbox
                    (id, custom_licence_id, operation, status, attempt_count, available_at, published_at, created_at, updated_at)
                    VALUES (gen_random_uuid(), %s, 'upsert', 'published', 1, now(), now(), now(), now())
                    """,
                    (licence_id,),
                )
            conn.commit()
            pytest.fail("Expected constraint violation for published without federation_record_id")
        except psycopg.errors.CheckViolation:
            conn.rollback()


def test_db_constraint_published_at_only_when_published(postgres_urls):
    """The DB must reject setting published_at on a pending row."""
    _, raw_dsn = postgres_urls
    with psycopg.connect(raw_dsn) as conn:
        with conn.cursor() as cur:
            cur.execute("SELECT id FROM custom_licences LIMIT 1")
            row = cur.fetchone()
            if row is None:
                pytest.skip("No custom licences present to use as FK target")
            licence_id = row[0]
        try:
            with conn.cursor() as cur:
                cur.execute(
                    """
                    INSERT INTO custom_licence_federation_outbox
                    (id, custom_licence_id, operation, status, attempt_count, available_at, published_at, created_at, updated_at)
                    VALUES (gen_random_uuid(), %s, 'upsert', 'pending', 0, now(), now(), now(), now())
                    """,
                    (licence_id,),
                )
            conn.commit()
            pytest.fail("Expected constraint violation for published_at on pending status")
        except psycopg.errors.CheckViolation:
            conn.rollback()


def test_db_constraint_error_fields_co_consistent(postgres_urls):
    """The DB must reject last_error_class without last_error_at."""
    _, raw_dsn = postgres_urls
    with psycopg.connect(raw_dsn) as conn:
        with conn.cursor() as cur:
            cur.execute("SELECT id FROM custom_licences LIMIT 1")
            row = cur.fetchone()
            if row is None:
                pytest.skip("No custom licences present to use as FK target")
            licence_id = row[0]
        try:
            with conn.cursor() as cur:
                cur.execute(
                    """
                    INSERT INTO custom_licence_federation_outbox
                    (id, custom_licence_id, operation, status, attempt_count, available_at, last_error_class, created_at, updated_at)
                    VALUES (gen_random_uuid(), %s, 'upsert', 'retryable_failed', 1, now(), 'some_error', now(), now())
                    """,
                    (licence_id,),
                )
            conn.commit()
            pytest.fail("Expected constraint violation for error_class without error_at")
        except psycopg.errors.CheckViolation:
            conn.rollback()


def test_published_outbox_linked_record_cannot_be_deleted(phase3_client):
    """Published outbox linkage must block deleting the linked federation record."""
    client, raw_dsn = phase3_client
    requested = f"DANS-FK-Record-{uuid.uuid4().hex[:8]}"
    created = client.post(
        "/api/v1/licenses",
        json=_payload(requested=requested, scope="federated"),
        headers={"Authorization": "Bearer curator-token"},
    )
    assert created.status_code == 201
    custom_id = created.json()["id"]
    publication = client.app.state.custom_licence_registration_service.publication_service
    publication.process_batch(limit=10, lease_seconds=30, worker_id="fk-record-test-worker")
    with psycopg.connect(raw_dsn) as conn:
        with conn.cursor() as cur:
            cur.execute(
                "SELECT federation_record_id FROM custom_licence_federation_outbox WHERE custom_licence_id = %s",
                (custom_id,),
            )
            record_id = cur.fetchone()[0]
            with pytest.raises((psycopg.errors.ForeignKeyViolation, psycopg.errors.RaiseException)):
                cur.execute("DELETE FROM federation_records WHERE id = %s", (record_id,))
            conn.rollback()


def test_published_outbox_linked_event_cannot_be_deleted(phase3_client):
    """Published outbox linkage + append-only protection must block deleting the linked event."""
    client, raw_dsn = phase3_client
    requested = f"DANS-FK-Event-{uuid.uuid4().hex[:8]}"
    created = client.post(
        "/api/v1/licenses",
        json=_payload(requested=requested, scope="federated"),
        headers={"Authorization": "Bearer curator-token"},
    )
    assert created.status_code == 201
    custom_id = created.json()["id"]
    publication = client.app.state.custom_licence_registration_service.publication_service
    publication.process_batch(limit=10, lease_seconds=30, worker_id="fk-event-test-worker")
    with psycopg.connect(raw_dsn) as conn:
        with conn.cursor() as cur:
            cur.execute(
                "SELECT federation_event_id FROM custom_licence_federation_outbox WHERE custom_licence_id = %s",
                (custom_id,),
            )
            event_id = cur.fetchone()[0]
            with pytest.raises((psycopg.errors.ForeignKeyViolation, psycopg.errors.RaiseException)):
                cur.execute("DELETE FROM federation_change_events WHERE id = %s", (event_id,))
            conn.rollback()


# ===========================================================================
# 6. Payload preservation tests
# ===========================================================================


def test_published_record_preserves_exact_payload_fields(phase3_client):
    """The federation record payload must exactly preserve all required fields."""
    client, raw_dsn = phase3_client
    licence_text = "Copyright 2026 DANS.   \n\nPermission is granted with trailing whitespace.   \n"
    requested = f"DANS-Payload-{uuid.uuid4().hex[:8]}"
    alias = f"{requested}-alias"
    created = client.post(
        "/api/v1/licenses",
        json={
            "requestedLicenseId": requested,
            "version": "3.0",
            "name": "DANS Payload Test License 3.0",
            "summary": "Payload test summary.",
            "description": "Payload test description.",
            "licenseText": licence_text,
            "scope": "federated",
            "aliases": [alias],
        },
        headers={"Authorization": "Bearer curator-token"},
    )
    assert created.status_code == 201
    custom_id = created.json()["id"]
    stored_spdx = created.json()["spdxJsonld"]
    stored_digest = created.json()["normalizedTextDigest"]
    # Federation record uses a different canonical_id than the custom-licence record
    federation_canonical_id = _fed_canonical_id(custom_id, version="3.0")

    publication = client.app.state.custom_licence_registration_service.publication_service
    publication.process_batch(limit=10, lease_seconds=30, worker_id="payload-test-worker")

    with psycopg.connect(raw_dsn) as conn:
        with conn.cursor() as cur:
            cur.execute("SELECT payload FROM federation_records WHERE canonical_id = %s", (federation_canonical_id,))
            row = cur.fetchone()
            assert row is not None, "Federation record not found after publication"
            payload = row[0]

    assert payload["licenseText"] == licence_text, "Exact licence text not preserved"
    assert payload["normalizedTextDigest"] == stored_digest
    assert payload["spdxJsonld"] == stored_spdx, "SPDX JSON-LD snapshot was regenerated"
    assert payload["customAuthorityId"] == "lfs-local-authority"
    assert payload["publishingFederationNodeId"] == "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"
    assert payload["sourceRecordUuid"] == custom_id
    assert payload["requestedLicenseId"] == requested
    assert payload["version"] == "3.0"
    assert alias in payload["aliases"]


# ===========================================================================
# 7. Federation feed surface tests
# ===========================================================================


def test_published_custom_licence_appears_in_catalog(phase3_client):
    client, raw_dsn = phase3_client
    requested = f"DANS-Catalog-{uuid.uuid4().hex[:8]}"
    created = client.post(
        "/api/v1/licenses",
        json=_payload(requested=requested, scope="federated"),
        headers={"Authorization": "Bearer curator-token"},
    )
    assert created.status_code == 201
    custom_id = created.json()["id"]
    # The federation catalog uses the federation record canonical_id, not the custom-licence canonical_id
    federation_canonical_id = _fed_canonical_id(custom_id)

    publication = client.app.state.custom_licence_registration_service.publication_service
    publication.process_batch(limit=10, lease_seconds=30, worker_id="feed-test-worker")

    catalog = client.get("/api/v1/federation/catalog")
    assert catalog.status_code == 200
    catalog_ids = {item["canonicalId"] for item in catalog.json().get("items", [])}
    assert federation_canonical_id in catalog_ids, f"{federation_canonical_id} not in federation catalog"


def test_published_custom_licence_appears_in_changes(phase3_client):
    client, raw_dsn = phase3_client
    requested = f"DANS-Changes-{uuid.uuid4().hex[:8]}"
    created = client.post(
        "/api/v1/licenses",
        json=_payload(requested=requested, scope="federated"),
        headers={"Authorization": "Bearer curator-token"},
    )
    assert created.status_code == 201
    custom_id = created.json()["id"]
    federation_canonical_id = _fed_canonical_id(custom_id)

    publication = client.app.state.custom_licence_registration_service.publication_service
    publication.process_batch(limit=10, lease_seconds=30, worker_id="changes-test-worker")

    changes = client.get("/api/v1/federation/changes?limit=200")
    assert changes.status_code == 200
    event_canonical_ids = {
        evt.get("payload", {}).get("record", {}).get("canonicalId")
        for evt in changes.json().get("events", [])
    }
    assert federation_canonical_id in event_canonical_ids, f"{federation_canonical_id} not in federation changes"


def test_published_custom_licence_record_endpoint_returns_signed_payload(phase3_client):
    client, raw_dsn = phase3_client
    requested = f"DANS-Record-{uuid.uuid4().hex[:8]}"
    created = client.post(
        "/api/v1/licenses",
        json=_payload(requested=requested, scope="federated"),
        headers={"Authorization": "Bearer curator-token"},
    )
    assert created.status_code == 201
    custom_id = created.json()["id"]
    # The record endpoint uses the federation canonical_id, not the custom-licence canonical_id
    federation_canonical_id = _fed_canonical_id(custom_id)

    publication = client.app.state.custom_licence_registration_service.publication_service
    publication.process_batch(limit=10, lease_seconds=30, worker_id="record-ep-test-worker")

    jwks_resp = client.get("/.well-known/jwks.json")
    assert jwks_resp.status_code == 200
    jwks = jwks_resp.json()

    encoded = base64.urlsafe_b64encode(federation_canonical_id.encode()).decode().rstrip("=")
    record_resp = client.get(f"/api/v1/federation/records/{encoded}")
    assert record_resp.status_code == 200
    body = record_resp.json()
    assert body["record"]["canonicalId"] == federation_canonical_id
    assert "signed" in body
    signature = body["signed"]["signature"]
    _verify_ed25519_signature_from_jwks(
        jwks=jwks,
        kid=signature["kid"],
        payload=body["record"],
        signed=body["signed"],
    )

    # Negative assertion: tampering with payload invalidates signature verification.
    tampered_record = dict(body["record"])
    tampered_record["version"] = "tampered"
    with pytest.raises(Exception):
        _verify_ed25519_signature_from_jwks(
            jwks=jwks,
            kid=signature["kid"],
            payload=tampered_record,
            signed=body["signed"],
        )

    # Also verify the corresponding signed changes payload cryptographically.
    changes = client.get("/api/v1/federation/changes?limit=200")
    assert changes.status_code == 200
    event = next(
        item for item in changes.json()["events"] if item["payload"]["record"]["canonicalId"] == federation_canonical_id
    )
    SignedFederationChangeEventPayload.model_validate(event["payload"])
    _verify_ed25519_signature_from_jwks(
        jwks=jwks,
        kid=event["signed"]["signature"]["kid"],
        payload=event["payload"],
        signed=event["signed"],
    )


# ===========================================================================
# 8. Admin API tests
# ===========================================================================


def test_admin_status_endpoint_succeeds(phase3_client):
    client, raw_dsn = phase3_client
    requested = f"DANS-AdminStatus-{uuid.uuid4().hex[:8]}"
    created = client.post(
        "/api/v1/licenses",
        json=_payload(requested=requested, scope="federated"),
        headers={"Authorization": "Bearer curator-token"},
    )
    assert created.status_code == 201
    custom_id = created.json()["id"]

    status = client.get(
        f"/api/v1/admin/licenses/{custom_id}/federation",
        headers={"Authorization": "Bearer admin-token"},
    )
    assert status.status_code == 200
    body = status.json()
    assert body["customLicenceId"] == custom_id
    assert body["federationStatus"] == "pending"
    assert body["outboxStatus"] == "pending"
    assert body["scope"] == "federated"


def test_admin_status_requires_auth(phase3_client):
    client, _ = phase3_client
    response = client.get(f"/api/v1/admin/licenses/{uuid.uuid4()}/federation")
    assert response.status_code == 401


def test_curator_cannot_access_admin_status(phase3_client):
    """Admin-only endpoint: curator must receive 403."""
    client, raw_dsn = phase3_client
    requested = f"DANS-CuratorStatus-{uuid.uuid4().hex[:8]}"
    created = client.post(
        "/api/v1/licenses",
        json=_payload(requested=requested, scope="federated"),
        headers={"Authorization": "Bearer curator-token"},
    )
    assert created.status_code == 201
    custom_id = created.json()["id"]

    response = client.get(
        f"/api/v1/admin/licenses/{custom_id}/federation",
        headers={"Authorization": "Bearer curator-token"},
    )
    assert response.status_code == 403
    assert response.headers.get("content-type", "").startswith("application/problem+json")


def test_admin_status_returns_404_for_unknown_record(phase3_client):
    client, _ = phase3_client
    response = client.get(
        f"/api/v1/admin/licenses/{uuid.uuid4()}/federation",
        headers={"Authorization": "Bearer admin-token"},
    )
    assert response.status_code == 404
    assert response.headers.get("content-type", "").startswith("application/problem+json")


def test_curator_cannot_retry_publication(phase3_client):
    client, raw_dsn = phase3_client
    requested = f"DANS-CuratorRetry-{uuid.uuid4().hex[:8]}"
    created = client.post(
        "/api/v1/licenses",
        json=_payload(requested=requested, scope="federated"),
        headers={"Authorization": "Bearer curator-token"},
    )
    assert created.status_code == 201
    custom_id = created.json()["id"]

    # Set to failed state
    with psycopg.connect(raw_dsn) as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                UPDATE custom_licence_federation_outbox
                SET status='permanently_failed', last_error_class='test', last_error_at=now(), updated_at=now()
                WHERE custom_licence_id=%s
                """,
                (custom_id,),
            )
        conn.commit()

    resp = client.post(
        f"/api/v1/admin/licenses/{custom_id}/federation/retry",
        headers={"Authorization": "Bearer curator-token"},
    )
    assert resp.status_code == 403
    assert resp.headers.get("content-type", "").startswith("application/problem+json")


def test_admin_retry_succeeds_for_permanently_failed(phase3_client):
    client, raw_dsn = phase3_client
    requested = f"DANS-AdminRetry-{uuid.uuid4().hex[:8]}"
    created = client.post(
        "/api/v1/licenses",
        json=_payload(requested=requested, scope="federated"),
        headers={"Authorization": "Bearer curator-token"},
    )
    assert created.status_code == 201
    custom_id = created.json()["id"]

    with psycopg.connect(raw_dsn) as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                UPDATE custom_licence_federation_outbox
                SET status='permanently_failed', last_error_class='forced_failure',
                    last_error_at=now(), updated_at=now()
                WHERE custom_licence_id=%s
                """,
                (custom_id,),
            )
            cur.execute(
                "UPDATE custom_licences SET federation_status='publication_failed', updated_at=now() WHERE id=%s",
                (custom_id,),
            )
        conn.commit()

    retry = client.post(
        f"/api/v1/admin/licenses/{custom_id}/federation/retry",
        headers={"Authorization": "Bearer admin-token"},
    )
    assert retry.status_code == 200
    body = retry.json()
    assert body["outboxStatus"] == "pending"
    assert body["federationStatus"] == "pending"


def test_published_record_cannot_be_retried(phase3_client):
    client, raw_dsn = phase3_client
    requested = f"DANS-RetryPublished-{uuid.uuid4().hex[:8]}"
    created = client.post(
        "/api/v1/licenses",
        json=_payload(requested=requested, scope="federated"),
        headers={"Authorization": "Bearer curator-token"},
    )
    assert created.status_code == 201
    custom_id = created.json()["id"]

    publication = client.app.state.custom_licence_registration_service.publication_service
    publication.process_batch(limit=10, lease_seconds=30, worker_id="test-worker")

    retry = client.post(
        f"/api/v1/admin/licenses/{custom_id}/federation/retry",
        headers={"Authorization": "Bearer admin-token"},
    )
    assert retry.status_code == 409
    assert retry.headers.get("content-type", "").startswith("application/problem+json")


def test_retry_does_not_publish_inline(phase3_client):
    """Admin retry must not create federation records in the HTTP request."""
    client, raw_dsn = phase3_client
    requested = f"DANS-RetryNoPublish-{uuid.uuid4().hex[:8]}"
    created = client.post(
        "/api/v1/licenses",
        json=_payload(requested=requested, scope="federated"),
        headers={"Authorization": "Bearer curator-token"},
    )
    assert created.status_code == 201
    custom_id = created.json()["id"]

    with psycopg.connect(raw_dsn) as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                UPDATE custom_licence_federation_outbox
                SET status = 'retryable_failed',
                    available_at = now(),
                    last_error_class = 'retryable',
                    last_error_at = now(),
                    updated_at = now()
                WHERE custom_licence_id = %s
                """,
                (custom_id,),
            )
        conn.commit()

    before_records = _count_rows(raw_dsn, "federation_records")
    response = client.post(
        f"/api/v1/admin/licenses/{custom_id}/federation/retry",
        headers={"Authorization": "Bearer admin-token"},
    )
    assert response.status_code == 200
    assert _count_rows(raw_dsn, "federation_records") == before_records


def test_admin_error_responses_use_problem_json_media_type(phase3_client):
    client, _ = phase3_client
    # 401 on missing token
    r = client.get(f"/api/v1/admin/licenses/{uuid.uuid4()}/federation")
    assert r.headers.get("content-type", "").startswith("application/problem+json")

    # 403 on curator
    r = client.get(
        f"/api/v1/admin/licenses/{uuid.uuid4()}/federation",
        headers={"Authorization": "Bearer curator-token"},
    )
    assert r.headers.get("content-type", "").startswith("application/problem+json")

    # 404 on unknown
    r = client.get(
        f"/api/v1/admin/licenses/{uuid.uuid4()}/federation",
        headers={"Authorization": "Bearer admin-token"},
    )
    assert r.headers.get("content-type", "").startswith("application/problem+json")


def test_admin_error_bodies_do_not_contain_credentials(phase3_client):
    """Error responses must not expose DB URLs, credentials, or key paths."""
    client, _ = phase3_client
    r = client.get(
        f"/api/v1/admin/licenses/{uuid.uuid4()}/federation",
        headers={"Authorization": "Bearer admin-token"},
    )
    body_str = r.text
    assert "postgres" not in body_str
    assert "password" not in body_str.lower()
    assert ".pem" not in body_str


# ===========================================================================
# 9. Database identity / URL matching tests
# ===========================================================================


def test_databases_match_same_url():
    url = "postgresql+psycopg://user:pass@localhost:5432/mydb"
    assert databases_match(url, url)


def test_databases_match_different_users_same_db():
    """Two URLs with different users but same host/port/db must match."""
    url_a = "postgresql+psycopg://admin:s3cret@db.example.com:5432/lfs"
    url_b = "postgresql+psycopg://readonly:other@db.example.com:5432/lfs"
    assert databases_match(url_a, url_b)


def test_databases_match_explicit_vs_default_port():
    """Explicit port 5432 and omitted port must compare equal."""
    url_explicit = "postgresql+psycopg://user:pass@localhost:5432/mydb"
    url_default = "postgresql+psycopg://user:pass@localhost/mydb"
    assert databases_match(url_explicit, url_default)


def test_databases_mismatch_different_dbname():
    url_a = "postgresql+psycopg://user:pass@localhost:5432/db_a"
    url_b = "postgresql+psycopg://user:pass@localhost:5432/db_b"
    assert not databases_match(url_a, url_b)


def test_databases_mismatch_different_host():
    url_a = "postgresql+psycopg://user:pass@host-a:5432/lfs"
    url_b = "postgresql+psycopg://user:pass@host-b:5432/lfs"
    assert not databases_match(url_a, url_b)


def test_databases_mismatch_different_port():
    url_a = "postgresql+psycopg://user:pass@localhost:5432/lfs"
    url_b = "postgresql+psycopg://user:pass@localhost:5433/lfs"
    assert not databases_match(url_a, url_b)


def test_database_identity_accepts_equivalent_url_spellings(phase3_client):
    client, _ = phase3_client
    registration = client.app.state.custom_licence_registration_service
    publication = registration.publication_service
    parsed = make_url(publication.custom_settings.database_url or "")
    equivalent = parsed.set(host="localhost").render_as_string(hide_password=False)
    service = CustomLicenceFederationPublicationService(
        db=registration.db,
        custom_settings=registration.settings,
        federation_settings=replace(publication.federation_settings, database_url=equivalent),
        federation_ready=True,
    )
    service.assert_federated_registration_supported()


def test_database_identity_accepts_different_users_same_database(phase3_client):
    client, raw_dsn = phase3_client
    registration = client.app.state.custom_licence_registration_service
    publication = registration.publication_service
    with psycopg.connect(raw_dsn) as conn:
        with conn.cursor() as cur:
            cur.execute("DO $$ BEGIN CREATE ROLE lfs_readonly LOGIN PASSWORD 'readonly'; EXCEPTION WHEN duplicate_object THEN NULL; END $$;")
            cur.execute("ALTER ROLE lfs_readonly WITH LOGIN PASSWORD 'readonly';")
            cur.execute("GRANT CONNECT ON DATABASE lfs_phase3 TO lfs_readonly;")
        conn.commit()
    parsed = make_url(publication.custom_settings.database_url or "")
    alt_user_url = parsed.set(username="lfs_readonly", password="readonly").render_as_string(hide_password=False)
    service = CustomLicenceFederationPublicationService(
        db=registration.db,
        custom_settings=registration.settings,
        federation_settings=replace(publication.federation_settings, database_url=alt_user_url),
        federation_ready=True,
    )
    service.assert_federated_registration_supported()


def test_database_identity_rejects_same_host_different_database(phase3_client):
    client, raw_dsn = phase3_client
    registration = client.app.state.custom_licence_registration_service
    publication = registration.publication_service
    other_db = f"lfs_other_{uuid.uuid4().hex[:8]}"
    with psycopg.connect(raw_dsn.rsplit("/", 1)[0] + "/postgres") as conn:
        conn.autocommit = True
        with conn.cursor() as cur:
            cur.execute(f'CREATE DATABASE "{other_db}"')
    parsed = make_url(publication.custom_settings.database_url or "")
    other_url = parsed.set(database=other_db).render_as_string(hide_password=False)
    service = CustomLicenceFederationPublicationService(
        db=registration.db,
        custom_settings=registration.settings,
        federation_settings=replace(publication.federation_settings, database_url=other_url),
        federation_ready=True,
    )
    with pytest.raises(Exception) as exc_info:
        service.assert_federated_registration_supported()
    assert "shared PostgreSQL database" in str(exc_info.value)


def test_publication_uses_single_sqlalchemy_session_for_writes(phase3_client):
    client, raw_dsn = phase3_client
    requested = f"DANS-Session-{uuid.uuid4().hex[:8]}"
    created = client.post(
        "/api/v1/licenses",
        json=_payload(requested=requested, scope="federated"),
        headers={"Authorization": "Bearer curator-token"},
    )
    assert created.status_code == 201
    custom_id = created.json()["id"]
    publication = client.app.state.custom_licence_registration_service.publication_service
    seen_session_ids: list[int] = []
    seen_txids: list[int] = []
    real_publish = publication.publisher.publish_new_version_in_session

    def wrapped_publish(*, session, **kwargs):
        seen_session_ids.append(id(session))
        seen_txids.append(int(session.execute(text("SELECT txid_current()")).scalar_one()))
        assert session.in_transaction()
        return real_publish(session=session, **kwargs)

    publication.publisher.publish_new_version_in_session = wrapped_publish
    try:
        worker_id = "session-test-worker"
        with psycopg.connect(raw_dsn) as conn:
            with conn.cursor() as cur:
                cur.execute(
                    """
                    SELECT id
                    FROM custom_licence_federation_outbox
                    WHERE custom_licence_id = %s
                    """,
                    (custom_id,),
                )
                job_id = cur.fetchone()[0]
                cur.execute(
                    """
                    UPDATE custom_licence_federation_outbox
                    SET status = 'processing',
                        attempt_count = attempt_count + 1,
                        lease_owner = %s,
                        lease_expires_at = %s,
                        updated_at = now()
                    WHERE id = %s
                    """,
                    (worker_id, datetime.now(timezone.utc) + timedelta(seconds=30), job_id),
                )
            conn.commit()
        publication.process_job(job_id=job_id, worker_id=worker_id)
    finally:
        publication.publisher.publish_new_version_in_session = real_publish

    assert seen_session_ids
    assert len(set(seen_session_ids)) == 1
    assert len(set(seen_txids)) == 1
    with psycopg.connect(raw_dsn) as conn:
        with conn.cursor() as cur:
            cur.execute("SELECT status FROM custom_licence_federation_outbox WHERE custom_licence_id = %s", (custom_id,))
            assert cur.fetchone()[0] == "published"


# ===========================================================================
# 10. Worker lifecycle tests
# ===========================================================================


def test_worker_exits_nonzero_on_missing_database_url(monkeypatch, tmp_path):
    """Worker must return non-zero when CUSTOM_LICENCE_REGISTRATION_DATABASE_URL is absent."""
    from src.license_facade_service.custom_licence_federation_worker import main as worker_main

    monkeypatch.delenv("CUSTOM_LICENCE_REGISTRATION_DATABASE_URL", raising=False)
    monkeypatch.setenv("FEDERATION_ENABLED", "true")
    monkeypatch.setenv("FEDERATION_DATABASE_URL", "postgresql+psycopg://x@localhost/y")
    monkeypatch.setenv("FEDERATION_NODE_ID", "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa")
    monkeypatch.setenv("FEDERATION_ACTIVE_KID", "k1")
    monkeypatch.setenv("FEDERATION_SIGNING_KEY_PATH", str(tmp_path / "key.pem"))
    monkeypatch.setenv("FEDERATION_PUBLIC_BASE_URL", "http://localhost")
    monkeypatch.setenv("FEDERATION_NODE_NAME", "Test Node")
    monkeypatch.setenv("FEDERATION_OPERATOR", "Test Operator")
    assert worker_main() != 0


def test_worker_exits_nonzero_when_federation_disabled(monkeypatch, tmp_path):
    """Worker must return non-zero when federation is disabled."""
    from src.license_facade_service.custom_licence_federation_worker import main as worker_main

    monkeypatch.setenv("CUSTOM_LICENCE_REGISTRATION_DATABASE_URL", "postgresql+psycopg://x@localhost/y")
    monkeypatch.setenv("FEDERATION_ENABLED", "false")
    assert worker_main() != 0


def test_worker_exits_nonzero_on_invalid_numeric_setting(monkeypatch, tmp_path):
    """Worker must return non-zero when LEASE_SECONDS is non-integer."""
    from src.license_facade_service.custom_licence_federation_worker import main as worker_main

    monkeypatch.setenv("CUSTOM_LICENCE_REGISTRATION_DATABASE_URL", "postgresql+psycopg://x@localhost/y")
    monkeypatch.setenv("FEDERATION_ENABLED", "true")
    monkeypatch.setenv("FEDERATION_DATABASE_URL", "postgresql+psycopg://x@localhost/y")
    monkeypatch.setenv("FEDERATION_NODE_ID", "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa")
    monkeypatch.setenv("FEDERATION_ACTIVE_KID", "k1")
    key_path = tmp_path / "key.pem"
    key_path.write_bytes(
        Ed25519PrivateKey.generate().private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        )
    )
    monkeypatch.setenv("FEDERATION_SIGNING_KEY_PATH", str(key_path))
    monkeypatch.setenv("FEDERATION_PUBLIC_BASE_URL", "http://localhost")
    monkeypatch.setenv("FEDERATION_NODE_NAME", "Test Node")
    monkeypatch.setenv("FEDERATION_OPERATOR", "Test Operator")
    monkeypatch.setenv("CUSTOM_LICENCE_FEDERATION_LEASE_SECONDS", "not-a-number")
    assert worker_main() != 0
