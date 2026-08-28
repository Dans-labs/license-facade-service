from __future__ import annotations

import inspect
import os
import socket
import subprocess
import time
import uuid
from pathlib import Path
from urllib.parse import quote

import httpx
import psycopg
import pytest
from fastapi.testclient import TestClient
from sqlalchemy.exc import SQLAlchemyError

from src.license_facade_service.api.v1 import licenses as licenses_api
from src.license_facade_service.main import OpenRelClient, create_app
from src.license_facade_service.services.auth import AuthService, AuthorizationError, Principal
from src.license_facade_service.services.custom_licence_registration import (
    CustomLicenceRegistrationService,
    RegistrationFailureInjection,
    build_canonical_id,
    build_resolving_uuid,
    build_spdx_custom_license_identifier,
    build_versioned_requested_id_alias,
    compute_normalized_text_digest,
    normalize_legal_text_for_digest,
)
from src.license_facade_service.services.spdx_validation import SpdxStructuralValidationError
from tests.schema_init import apply_schema_init_sql, reset_public_schema

REPO_ROOT = Path(__file__).resolve().parents[1]


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
def postgres_urls():
    if not _docker_available():
        pytest.skip("docker not available for PostgreSQL tests")
    port = _free_port()
    container_name = f"lfs-custom-licence-phase2-{uuid.uuid4().hex[:8]}"
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
            "POSTGRES_DB=lfs_custom_licence_phase2",
            "-p",
            f"{port}:5432",
            "postgres:16-alpine",
        ],
        check=True,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    dsn = f"postgresql+psycopg://postgres:postgres@127.0.0.1:{port}/lfs_custom_licence_phase2"
    raw_dsn = f"postgresql://postgres:postgres@127.0.0.1:{port}/lfs_custom_licence_phase2"
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
        subprocess.run(["docker", "kill", container_name], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=False)


@pytest.fixture
def registration_client(postgres_urls: tuple[str, str], monkeypatch: pytest.MonkeyPatch):
    dsn, raw_dsn = postgres_urls
    monkeypatch.setenv("FEDERATION_ENABLED", "false")
    monkeypatch.setenv("OPENREL_ENABLED", "false")
    monkeypatch.setenv("LFS_ADMIN_TOKEN", "admin-token")
    monkeypatch.setenv("LFS_CURATOR_TOKEN", "curator-token")
    monkeypatch.setenv("CUSTOM_LICENCE_REGISTRATION_DATABASE_URL", dsn)
    monkeypatch.setenv("CUSTOM_LICENCE_AUTHORITY_ID", "lfs-local-authority")
    monkeypatch.setenv("CUSTOM_LICENCE_AUTHORITY_BASE_IRI", "https://lfs.example")
    monkeypatch.setenv("CUSTOM_LICENCE_CREATOR_ORGANIZATION_NAME", "LFS Operator")
    monkeypatch.setenv("CUSTOM_LICENCE_CREATOR_ORGANIZATION_IRI", "https://lfs.example/spdx/agents/lfs-operator")
    licenses_api._license_service = None
    licenses_api._auth_service = AuthService()
    app = create_app()
    with TestClient(app) as client:
        yield client, raw_dsn


def _payload(
    scope: str = "local",
    *,
    requested: str | None = None,
    version: str = "1.0",
    aliases: list[str] | None = None,
) -> dict:
    request_id = requested or f"DANS-Custom-{uuid.uuid4().hex[:8]}"
    return {
        "requestedLicenseId": request_id,
        "version": version,
        "name": "DANS Custom License 1.0",
        "summary": "A custom licence maintained by DANS.",
        "description": "Terms for reuse of selected DANS materials.",
        "licenseText": "  DANS custom licence text.\n\nCopyright 2026 DANS.\n",
        "scope": scope,
        "aliases": aliases or [f"{request_id} Alias", f"{request_id.lower()}  alias"],
    }


def _count_registration_rows(raw_dsn: str, requested_license_id: str) -> tuple[int, int, int]:
    with psycopg.connect(raw_dsn) as conn:
        with conn.cursor() as cur:
            cur.execute("SELECT count(*) FROM custom_licences WHERE requested_license_id = %s", (requested_license_id,))
            licences = cur.fetchone()[0]
            cur.execute(
                """
                SELECT count(*)
                FROM custom_licence_aliases a
                JOIN custom_licences c ON c.id = a.custom_licence_id
                WHERE c.requested_license_id = %s
                """,
                (requested_license_id,),
            )
            aliases = cur.fetchone()[0]
            cur.execute(
                """
                SELECT count(*)
                FROM custom_licence_audit_events e
                JOIN custom_licences c ON c.id = e.custom_licence_id
                WHERE c.requested_license_id = %s
                """,
                (requested_license_id,),
            )
            audits = cur.fetchone()[0]
            return licences, aliases, audits


def test_registration_route_is_sync_def():
    route = next(route for route in licenses_api.router.routes if getattr(route, "name", "") == "register_custom_licence")
    assert inspect.iscoroutinefunction(route.endpoint) is False


def test_create_app_does_not_open_db_connection(monkeypatch: pytest.MonkeyPatch):
    from src.license_facade_service.db.session import Database

    called = {"value": False}

    def _fail_from_url(*args, **kwargs):
        called["value"] = True
        raise AssertionError("Database.from_url should not be called during create_app")

    monkeypatch.setattr(Database, "from_url", _fail_from_url)
    create_app()
    assert called["value"] is False


def test_two_app_instances_do_not_share_registration_service_or_settings(monkeypatch: pytest.MonkeyPatch, postgres_urls):
    dsn, _ = postgres_urls
    monkeypatch.setenv("CUSTOM_LICENCE_REGISTRATION_DATABASE_URL", dsn)
    monkeypatch.setenv("CUSTOM_LICENCE_AUTHORITY_ID", "authority-a")
    monkeypatch.setenv("CUSTOM_LICENCE_AUTHORITY_BASE_IRI", "https://node-a.example")
    monkeypatch.setenv("CUSTOM_LICENCE_CREATOR_ORGANIZATION_NAME", "Node A Operator")
    app_a = create_app()

    monkeypatch.setenv("CUSTOM_LICENCE_AUTHORITY_ID", "authority-b")
    monkeypatch.setenv("CUSTOM_LICENCE_AUTHORITY_BASE_IRI", "https://node-b.example")
    monkeypatch.setenv("CUSTOM_LICENCE_CREATOR_ORGANIZATION_NAME", "Node B Operator")
    app_b = create_app()

    with TestClient(app_a):
        with TestClient(app_b):
            assert app_a.state.custom_licence_registration_service is not app_b.state.custom_licence_registration_service
            assert (
                app_a.state.custom_licence_registration_service.settings.authority_id
                != app_b.state.custom_licence_registration_service.settings.authority_id
            )


def test_lifespan_disposes_engine_and_clears_service(registration_client, monkeypatch: pytest.MonkeyPatch):
    client, _ = registration_client
    service = client.app.state.custom_licence_registration_service
    client.post("/api/v1/licenses", json=_payload(), headers={"Authorization": "Bearer curator-token"})
    assert service is not None
    assert service._db is not None


def test_engine_is_disposed_on_shutdown(monkeypatch: pytest.MonkeyPatch, postgres_urls):
    dsn, _ = postgres_urls
    monkeypatch.setenv("FEDERATION_ENABLED", "false")
    monkeypatch.setenv("OPENREL_ENABLED", "false")
    monkeypatch.setenv("LFS_ADMIN_TOKEN", "admin-token")
    monkeypatch.setenv("LFS_CURATOR_TOKEN", "curator-token")
    monkeypatch.setenv("CUSTOM_LICENCE_REGISTRATION_DATABASE_URL", dsn)
    monkeypatch.setenv("CUSTOM_LICENCE_AUTHORITY_ID", "lfs-local-authority")
    monkeypatch.setenv("CUSTOM_LICENCE_AUTHORITY_BASE_IRI", "https://lfs.example")
    monkeypatch.setenv("CUSTOM_LICENCE_CREATOR_ORGANIZATION_NAME", "LFS Operator")
    app = create_app()
    disposed = {"value": False}
    with TestClient(app) as client:
        client.post("/api/v1/licenses", json=_payload(), headers={"Authorization": "Bearer curator-token"})
        service = client.app.state.custom_licence_registration_service
        assert service._db is not None
        original_dispose = service._db.engine.dispose

        def _dispose():
            disposed["value"] = True
            original_dispose()

        monkeypatch.setattr(service._db.engine, "dispose", _dispose)
    assert disposed["value"] is True
    assert app.state.custom_licence_registration_service is None


def test_shutdown_cleanup_clears_app_state_even_if_close_raises(monkeypatch: pytest.MonkeyPatch, postgres_urls):
    dsn, _ = postgres_urls
    monkeypatch.setenv("CUSTOM_LICENCE_REGISTRATION_DATABASE_URL", dsn)
    monkeypatch.setenv("CUSTOM_LICENCE_AUTHORITY_ID", "lfs-local-authority")
    monkeypatch.setenv("CUSTOM_LICENCE_AUTHORITY_BASE_IRI", "https://lfs.example")
    monkeypatch.setenv("CUSTOM_LICENCE_CREATOR_ORGANIZATION_NAME", "LFS Operator")
    app = create_app()
    with pytest.raises(RuntimeError, match="forced-close-failure"):
        with TestClient(app) as client:
            service = client.app.state.custom_licence_registration_service

            def _raise_close():
                raise RuntimeError("forced-close-failure")

            service.close = _raise_close  # type: ignore[assignment]
    assert app.state.custom_licence_registration_service is None


def test_shutdown_still_closes_registration_if_openrel_close_raises(monkeypatch: pytest.MonkeyPatch, postgres_urls):
    dsn, _ = postgres_urls
    monkeypatch.setenv("CUSTOM_LICENCE_REGISTRATION_DATABASE_URL", dsn)
    monkeypatch.setenv("CUSTOM_LICENCE_AUTHORITY_ID", "lfs-local-authority")
    monkeypatch.setenv("CUSTOM_LICENCE_AUTHORITY_BASE_IRI", "https://lfs.example")
    monkeypatch.setenv("CUSTOM_LICENCE_CREATOR_ORGANIZATION_NAME", "LFS Operator")
    app = create_app()
    close_called = {"openrel": False, "registration": False}

    async def _raise_aclose(self):
        close_called["openrel"] = True
        raise RuntimeError("forced-openrel-close-failure")

    def _close_registration(self):
        close_called["registration"] = True

    monkeypatch.setattr(OpenRelClient, "aclose", _raise_aclose)
    monkeypatch.setattr(CustomLicenceRegistrationService, "close", _close_registration)
    with pytest.raises(RuntimeError, match="forced-openrel-close-failure"):
        with TestClient(app):
            pass
    assert close_called["openrel"] is True
    assert close_called["registration"] is True
    assert app.state.openrel_client is None
    assert app.state.custom_licence_registration_service is None


def test_curator_registration_succeeds_for_local_scope(registration_client):
    client, raw_dsn = registration_client
    payload = _payload(scope="local")
    response = client.post("/api/v1/licenses", json=payload, headers={"Authorization": "Bearer curator-token"})
    assert response.status_code == 201
    body = response.json()
    assert body["scope"] == "local"
    assert body["federationStatus"] == "not_published"
    assert body["spdxSubmissionStatus"] == "not_requested"
    assert body["lifecycleStatus"] == "registered"
    assert body["spdxJsonld"]["@graph"][2]["simplelicensing_licenseText"] == payload["licenseText"]
    assert body["normalizedTextDigest"] == compute_normalized_text_digest(payload["licenseText"])

    with psycopg.connect(raw_dsn) as conn:
        with conn.cursor() as cur:
            cur.execute("SELECT creator_role, license_text FROM custom_licences WHERE id = %s", (body["id"],))
            row = cur.fetchone()
            assert row is not None
            assert row[0] == "curator"
            assert row[1] == payload["licenseText"]


def test_admin_registration_succeeds_for_spdx_submission_scope(registration_client):
    client, _ = registration_client
    payload = _payload(scope="spdx-submission")
    response = client.post("/api/v1/licenses", json=payload, headers={"Authorization": "Bearer admin-token"})
    assert response.status_code == 201
    body = response.json()
    assert body["scope"] == "spdx-submission"
    assert body["federationStatus"] == "not_published"
    assert body["spdxSubmissionStatus"] == "ready_for_review"
    assert body["lifecycleStatus"] == "registered"


def test_missing_invalid_and_unauthorized_authentication(registration_client):
    class ViewerAuthService(AuthService):
        def authenticate(self, request):  # type: ignore[override]
            return Principal(role="viewer")

        def authorize(self, principal, allowed_roles):  # type: ignore[override]
            raise AuthorizationError("Insufficient permissions")

    client, _ = registration_client
    payload = _payload()
    assert client.post("/api/v1/licenses", json=payload).status_code == 401
    assert client.post("/api/v1/licenses", json=payload, headers={"Authorization": "Bearer nope"}).status_code == 401
    licenses_api._auth_service = ViewerAuthService()
    assert client.post("/api/v1/licenses", json=payload, headers={"Authorization": "Bearer viewer"}).status_code == 403


def test_federated_scope_requires_federation_configuration(registration_client):
    client, raw_dsn = registration_client
    requested = f"DANS-Deferred-{uuid.uuid4().hex[:8]}"
    response = client.post(
        "/api/v1/licenses",
        json=_payload(scope="federated", requested=requested),
        headers={"Authorization": "Bearer curator-token"},
    )
    assert response.status_code == 503
    assert response.json()["type"].endswith("/custom-licence-federation-unavailable")
    assert _count_registration_rows(raw_dsn, requested) == (0, 0, 0)


def test_deterministic_identity_and_duplicate_conflict(registration_client):
    client, raw_dsn = registration_client
    requested = f"DANS-Deterministic-{uuid.uuid4().hex[:8]}"
    payload = _payload(scope="local", requested=requested)
    first = client.post("/api/v1/licenses", json=payload, headers={"Authorization": "Bearer curator-token"})
    assert first.status_code == 201
    body = first.json()
    assert body["canonicalId"] == build_canonical_id(
        authority_id="lfs-local-authority",
        requested_license_id=requested,
        version="1.0",
    )
    assert body["resolvingUuid"] == str(
        build_resolving_uuid(
            authority_id="lfs-local-authority",
            requested_license_id=requested,
            version="1.0",
        )
    )
    duplicate = client.post("/api/v1/licenses", json=payload, headers={"Authorization": "Bearer curator-token"})
    assert duplicate.status_code == 409
    assert duplicate.json()["type"].endswith("/custom-licence-already-exists")
    licences, _, audits = _count_registration_rows(raw_dsn, requested)
    assert licences == 1
    assert audits == 1


def test_requested_id_multiple_versions_coexist_with_distinct_identity(registration_client):
    client, raw_dsn = registration_client
    requested = f"DANS-Custom-{uuid.uuid4().hex[:8]}"
    first_payload = _payload(scope="local", requested=requested, version="1.0", aliases=["Versioned Alias One"])
    second_payload = _payload(scope="local", requested=requested, version="2.0", aliases=["Versioned Alias Two"])
    first = client.post("/api/v1/licenses", json=first_payload, headers={"Authorization": "Bearer curator-token"})
    second = client.post("/api/v1/licenses", json=second_payload, headers={"Authorization": "Bearer curator-token"})
    assert first.status_code == 201
    assert second.status_code == 201
    first_body = first.json()
    second_body = second.json()

    assert first_body["id"] != second_body["id"]
    assert first_body["canonicalId"] != second_body["canonicalId"]
    assert first_body["resolvingUuid"] != second_body["resolvingUuid"]
    assert first_body["resolvingUri"] != second_body["resolvingUri"]
    assert first_body["spdxJsonld"]["@graph"][2]["spdxId"] != second_body["spdxJsonld"]["@graph"][2]["spdxId"]

    assert first_body["canonicalId"] == build_canonical_id(
        authority_id="lfs-local-authority",
        requested_license_id=requested,
        version="1.0",
    )
    assert second_body["canonicalId"] == build_canonical_id(
        authority_id="lfs-local-authority",
        requested_license_id=requested,
        version="2.0",
    )
    assert first_body["resolvingUuid"] == str(
        build_resolving_uuid(authority_id="lfs-local-authority", requested_license_id=requested, version="1.0")
    )
    assert second_body["resolvingUuid"] == str(
        build_resolving_uuid(authority_id="lfs-local-authority", requested_license_id=requested, version="2.0")
    )
    assert first_body["spdxJsonld"]["@graph"][2]["spdxId"].endswith(
        build_spdx_custom_license_identifier(resolving_uuid=uuid.UUID(first_body["resolvingUuid"]))
    )
    assert second_body["spdxJsonld"]["@graph"][2]["spdxId"].endswith(
        build_spdx_custom_license_identifier(resolving_uuid=uuid.UUID(second_body["resolvingUuid"]))
    )

    duplicate = client.post("/api/v1/licenses", json=first_payload, headers={"Authorization": "Bearer curator-token"})
    assert duplicate.status_code == 409
    assert duplicate.json()["type"].endswith("/custom-licence-already-exists")

    with psycopg.connect(raw_dsn) as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                SELECT id::text, version, canonical_id
                FROM custom_licences
                WHERE requested_license_id = %s
                ORDER BY version
                """,
                (requested,),
            )
            rows = cur.fetchall()
            assert len(rows) == 2
            assert [row[1] for row in rows] == ["1.0", "2.0"]
            assert {row[0] for row in rows} == {first_body["id"], second_body["id"]}
            cur.execute(
                """
                SELECT alias_type, alias
                FROM custom_licence_aliases a
                JOIN custom_licences c ON c.id = a.custom_licence_id
                WHERE c.requested_license_id = %s AND alias_type = 'requested_id'
                ORDER BY alias
                """,
                (requested,),
            )
            alias_rows = cur.fetchall()
            assert alias_rows == [
                ("requested_id", build_versioned_requested_id_alias(requested_license_id=requested, version="1.0")),
                ("requested_id", build_versioned_requested_id_alias(requested_license_id=requested, version="2.0")),
            ]


def test_local_custom_resolves_by_public_identifiers(registration_client):
    client, _ = registration_client
    requested = f"DANS-Resolve-{uuid.uuid4().hex[:8]}"
    alias = "Demo Alias"
    created = client.post(
        "/api/v1/licenses",
        json=_payload(scope="local", requested=requested, aliases=[alias]),
        headers={"Authorization": "Bearer curator-token"},
    )
    assert created.status_code == 201
    registration = created.json()

    for identifier in (
        registration["canonicalId"],
        registration["resolvingUuid"],
        quote(registration["resolvingUri"], safe=""),
        quote(alias, safe=""),
    ):
        response = client.get(f"/api/v1/licenses/{identifier}")
        assert response.status_code == 200
        body = response.json()
        assert body["canonicalId"] == registration["canonicalId"]
        assert body["requestedLicenseId"] == requested
        assert body["scope"] == "local"

    requested_response = client.get(f"/api/v1/licenses/{quote(requested, safe='')}")
    assert requested_response.status_code == 200
    assert requested_response.json()["canonicalId"] == registration["canonicalId"]

    by_uri_resolution = client.get("/api/v1/licenses/resolution", params={"identifier": registration["resolvingUri"]})
    assert by_uri_resolution.status_code == 200
    resolved = by_uri_resolution.json()
    assert resolved["resolutionOutcome"] == "local-authoritative"
    assert resolved["canonicalId"] == registration["canonicalId"]


def test_requested_identifier_with_multiple_versions_is_not_arbitrarily_selected(registration_client):
    client, _ = registration_client
    requested = f"DANS-Multi-{uuid.uuid4().hex[:8]}"
    one = client.post(
        "/api/v1/licenses",
        json=_payload(scope="local", requested=requested, version="1.0", aliases=["multi-version-one"]),
        headers={"Authorization": "Bearer curator-token"},
    )
    two = client.post(
        "/api/v1/licenses",
        json=_payload(scope="local", requested=requested, version="2.0", aliases=["multi-version-two"]),
        headers={"Authorization": "Bearer curator-token"},
    )
    assert one.status_code == 201
    assert two.status_code == 201

    unresolved = client.get(f"/api/v1/licenses/{quote(requested, safe='')}")
    assert unresolved.status_code == 404

    requested_v1 = build_versioned_requested_id_alias(requested_license_id=requested, version="1.0")
    requested_v2 = build_versioned_requested_id_alias(requested_license_id=requested, version="2.0")
    assert client.get(f"/api/v1/licenses/{quote(requested_v1, safe='')}").status_code == 200
    assert client.get(f"/api/v1/licenses/{quote(requested_v2, safe='')}").status_code == 200


def test_same_legacy_alias_across_versions_conflicts(registration_client):
    client, raw_dsn = registration_client
    requested = f"DANS-Legacy-{uuid.uuid4().hex[:8]}"
    first = client.post(
        "/api/v1/licenses",
        json=_payload(scope="local", requested=requested, version="1.0", aliases=["Shared Legacy Alias"]),
        headers={"Authorization": "Bearer curator-token"},
    )
    assert first.status_code == 201
    second = client.post(
        "/api/v1/licenses",
        json=_payload(scope="local", requested=requested, version="2.0", aliases=["shared legacy   alias"]),
        headers={"Authorization": "Bearer curator-token"},
    )
    assert second.status_code == 409
    assert second.json()["type"].endswith("/custom-licence-alias-conflict")
    assert _count_registration_rows(raw_dsn, requested) == (1, 5, 1)


def test_spdx_identity_is_unambiguous_for_separator_like_inputs():
    uuid_a = build_resolving_uuid(authority_id="a", requested_license_id="Alpha__v__Beta", version="1")
    uuid_b = build_resolving_uuid(authority_id="a", requested_license_id="Alpha", version="Beta__v__1")
    assert uuid_a != uuid_b
    assert build_spdx_custom_license_identifier(resolving_uuid=uuid_a) != build_spdx_custom_license_identifier(
        resolving_uuid=uuid_b
    )


def test_aliases_are_normalized_and_deduplicated(registration_client):
    client, raw_dsn = registration_client
    requested = f"DANS-Alias-{uuid.uuid4().hex[:8]}"
    payload = _payload(scope="local", requested=requested, aliases=["DANS Custom License", "dans   custom license", "DANS Custom License"])
    response = client.post("/api/v1/licenses", json=payload, headers={"Authorization": "Bearer curator-token"})
    assert response.status_code == 201
    custom_id = response.json()["id"]
    with psycopg.connect(raw_dsn) as conn:
        with conn.cursor() as cur:
            cur.execute(
                "SELECT alias_type, normalized_alias FROM custom_licence_aliases WHERE custom_licence_id = %s",
                (custom_id,),
            )
            rows = cur.fetchall()
            normalized = [row[1] for row in rows]
            assert len(normalized) == len(set(normalized))
            assert any(row[0] == "legacy" for row in rows)


def test_alias_collision_returns_conflict_with_no_second_registration_rows(registration_client):
    client, raw_dsn = registration_client
    requested_a = f"DANS-A-{uuid.uuid4().hex[:8]}"
    requested_b = f"DANS-B-{uuid.uuid4().hex[:8]}"
    first = client.post(
        "/api/v1/licenses",
        json=_payload(scope="local", requested=requested_a, aliases=["Colliding Alias"]),
        headers={"Authorization": "Bearer curator-token"},
    )
    assert first.status_code == 201
    second = client.post(
        "/api/v1/licenses",
        json=_payload(scope="local", requested=requested_b, aliases=["colliding   alias"]),
        headers={"Authorization": "Bearer curator-token"},
    )
    assert second.status_code == 409
    assert second.json()["type"].endswith("/custom-licence-alias-conflict")
    assert _count_registration_rows(raw_dsn, requested_b) == (0, 0, 0)


def test_audit_snapshot_is_sanitized_and_no_federation_events_are_created(registration_client):
    client, raw_dsn = registration_client
    requested = f"DANS-Audit-{uuid.uuid4().hex[:8]}"
    response = client.post(
        "/api/v1/licenses",
        json=_payload(scope="local", requested=requested),
        headers={"Authorization": "Bearer curator-token"},
    )
    assert response.status_code == 201
    custom_id = response.json()["id"]
    with psycopg.connect(raw_dsn) as conn:
        with conn.cursor() as cur:
            cur.execute(
                "SELECT event_type, actor_role, before_state, after_state FROM custom_licence_audit_events WHERE custom_licence_id = %s",
                (custom_id,),
            )
            row = cur.fetchone()
            assert row is not None
            assert row[0] == "custom_licence_registered"
            assert row[1] == "curator"
            assert row[2] is None
            assert "licenseText" not in str(row[3])
            assert "token" not in str(row[3]).lower()
            cur.execute("SELECT count(*) FROM federation_records")
            assert cur.fetchone()[0] == 0
            cur.execute("SELECT count(*) FROM federation_change_events")
            assert cur.fetchone()[0] == 0


def test_legal_text_digest_normalization_algorithm_is_deterministic():
    lf = "Line A\nLine B\n"
    crlf = "Line A\r\nLine B\r\n"
    no_final_newline = "Line A\nLine B"
    composed = "Café"
    decomposed = "Cafe\u0301"
    with_spaces = "  Line A\nLine B\n  "
    assert normalize_legal_text_for_digest(crlf) == normalize_legal_text_for_digest(lf)
    assert compute_normalized_text_digest(crlf) == compute_normalized_text_digest(lf)
    assert compute_normalized_text_digest(no_final_newline) != compute_normalized_text_digest(lf)
    assert compute_normalized_text_digest(composed) == compute_normalized_text_digest(decomposed)
    assert compute_normalized_text_digest(with_spaces) != compute_normalized_text_digest(lf)


def test_registration_performs_no_external_http_calls(registration_client, monkeypatch: pytest.MonkeyPatch):
    client, _ = registration_client

    def _raise_http(*args, **kwargs):
        raise AssertionError("unexpected external HTTP call")

    monkeypatch.setattr(httpx._transports.default.HTTPTransport, "handle_request", _raise_http)
    monkeypatch.setattr(httpx._transports.default.AsyncHTTPTransport, "handle_async_request", _raise_http)
    response = client.post("/api/v1/licenses", json=_payload(), headers={"Authorization": "Bearer curator-token"})
    assert response.status_code == 201


def test_unauthenticated_request_does_not_start_registration_work(registration_client, monkeypatch: pytest.MonkeyPatch):
    from src.license_facade_service.db.session import Database

    client, _ = registration_client
    service = client.app.state.custom_licence_registration_service
    observed = {"from_url": False, "spdx_build": False}

    def _spy_from_url(*args, **kwargs):
        observed["from_url"] = True
        raise AssertionError("Database.from_url should not be called for unauthorized request")

    def _spy_spdx_build(*args, **kwargs):
        observed["spdx_build"] = True
        raise AssertionError("SPDX builder should not run for unauthorized request")

    monkeypatch.setattr(Database, "from_url", _spy_from_url)
    service.spdx_builder.build = _spy_spdx_build  # type: ignore[assignment]

    response = client.post("/api/v1/licenses", json=_payload())
    assert response.status_code == 401
    assert observed["from_url"] is False
    assert observed["spdx_build"] is False
    assert service._db is None


def test_structural_validation_failure_rolls_back_everything(registration_client):
    client, raw_dsn = registration_client
    service = client.app.state.custom_licence_registration_service

    def _raise_structural_error(*args, **kwargs):
        raise SpdxStructuralValidationError("forced")

    service.spdx_builder.build = _raise_structural_error  # type: ignore[assignment]
    requested = f"DANS-Rollback-{uuid.uuid4().hex[:8]}"
    response = client.post(
        "/api/v1/licenses",
        json=_payload(requested=requested),
        headers={"Authorization": "Bearer curator-token"},
    )
    assert response.status_code == 422
    assert _count_registration_rows(raw_dsn, requested) == (0, 0, 0)


def test_forced_alias_insert_failure_rolls_back_everything(registration_client):
    client, raw_dsn = registration_client
    client.app.state.custom_licence_registration_service.failure_injection = RegistrationFailureInjection(
        fail_alias_insert=True
    )
    requested = f"DANS-AliasFail-{uuid.uuid4().hex[:8]}"
    response = client.post(
        "/api/v1/licenses",
        json=_payload(requested=requested),
        headers={"Authorization": "Bearer curator-token"},
    )
    assert response.status_code == 500
    assert _count_registration_rows(raw_dsn, requested) == (0, 0, 0)
    client.app.state.custom_licence_registration_service.failure_injection = RegistrationFailureInjection()


def test_forced_audit_insert_failure_rolls_back_everything(registration_client):
    client, raw_dsn = registration_client
    client.app.state.custom_licence_registration_service.failure_injection = RegistrationFailureInjection(
        fail_audit_insert=True
    )
    requested = f"DANS-AuditFail-{uuid.uuid4().hex[:8]}"
    response = client.post(
        "/api/v1/licenses",
        json=_payload(requested=requested),
        headers={"Authorization": "Bearer curator-token"},
    )
    assert response.status_code == 500
    assert _count_registration_rows(raw_dsn, requested) == (0, 0, 0)
    client.app.state.custom_licence_registration_service.failure_injection = RegistrationFailureInjection()


def test_forced_pre_commit_failure_rolls_back_everything(registration_client):
    client, raw_dsn = registration_client
    client.app.state.custom_licence_registration_service.failure_injection = RegistrationFailureInjection(
        fail_before_commit=True
    )
    requested = f"DANS-CommitFail-{uuid.uuid4().hex[:8]}"
    response = client.post(
        "/api/v1/licenses",
        json=_payload(requested=requested),
        headers={"Authorization": "Bearer curator-token"},
    )
    assert response.status_code == 500
    assert _count_registration_rows(raw_dsn, requested) == (0, 0, 0)
    client.app.state.custom_licence_registration_service.failure_injection = RegistrationFailureInjection()


def test_request_validation_errors_use_problem_details(registration_client):
    client, _ = registration_client
    bad_requests = [
        ({}, "missing required field"),
        ({**_payload(), "unknownField": "x"}, "unknown field"),
        ({**_payload(), "scope": "invalid-scope"}, "invalid scope"),
        ({**_payload(), "requestedLicenseId": " "}, "blank identifier"),
        ({**_payload(), "aliases": [f"a-{i}" for i in range(80)]}, "excessive alias count"),
    ]
    for body, _ in bad_requests:
        response = client.post("/api/v1/licenses", json=body, headers={"Authorization": "Bearer curator-token"})
        assert response.status_code == 422
        assert response.headers["content-type"].startswith("application/problem+json")
        payload = response.json()
        assert payload["type"].endswith("/custom-licence-request-invalid")
        assert payload["status"] == 422
        assert payload["title"] == "Invalid Registration Request"


def test_generated_identity_length_overflow_returns_422(registration_client):
    client, _ = registration_client
    response = client.post(
        "/api/v1/licenses",
        json=_payload(requested="é" * 256),
        headers={"Authorization": "Bearer curator-token"},
    )
    assert response.status_code == 422
    payload = response.json()
    assert payload["type"].endswith("/custom-licence-generated-identity-too-long")


def test_invalid_registration_configuration_is_isolated_and_sanitized(monkeypatch: pytest.MonkeyPatch, postgres_urls):
    dsn, _ = postgres_urls
    monkeypatch.setenv("FEDERATION_ENABLED", "false")
    monkeypatch.setenv("OPENREL_ENABLED", "false")
    monkeypatch.setenv("LFS_ADMIN_TOKEN", "admin-token")
    monkeypatch.setenv("LFS_CURATOR_TOKEN", "curator-token")
    monkeypatch.setenv("CUSTOM_LICENCE_REGISTRATION_DATABASE_URL", dsn)
    monkeypatch.setenv("CUSTOM_LICENCE_AUTHORITY_ID", "lfs-local-authority")
    monkeypatch.setenv("CUSTOM_LICENCE_AUTHORITY_BASE_IRI", "https://example.org?")
    monkeypatch.setenv("CUSTOM_LICENCE_CREATOR_ORGANIZATION_NAME", "LFS Operator")
    app = create_app()
    with TestClient(app) as client:
        registration = client.post("/api/v1/licenses", json=_payload(), headers={"Authorization": "Bearer curator-token"})
        assert registration.status_code == 503
        body = registration.json()
        assert "configurationErrors" not in body
        serialized = str(body)
        assert "CUSTOM_LICENCE_" not in serialized
        assert "postgresql://" not in serialized
        health = client.get("/api/v1/health")
        assert health.status_code == 200


def test_database_unavailable_returns_503(monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setenv("FEDERATION_ENABLED", "false")
    monkeypatch.setenv("OPENREL_ENABLED", "false")
    monkeypatch.setenv("LFS_ADMIN_TOKEN", "admin-token")
    monkeypatch.setenv("LFS_CURATOR_TOKEN", "curator-token")
    monkeypatch.setenv("CUSTOM_LICENCE_REGISTRATION_DATABASE_URL", "postgresql+psycopg://postgres:postgres@127.0.0.1:1/lfs")
    monkeypatch.setenv("CUSTOM_LICENCE_AUTHORITY_ID", "lfs-local-authority")
    monkeypatch.setenv("CUSTOM_LICENCE_AUTHORITY_BASE_IRI", "https://lfs.example")
    monkeypatch.setenv("CUSTOM_LICENCE_CREATOR_ORGANIZATION_NAME", "LFS Operator")
    app = create_app()
    with TestClient(app) as client:
        response = client.post("/api/v1/licenses", json=_payload(), headers={"Authorization": "Bearer curator-token"})
        assert response.status_code == 503
        assert response.json()["type"].endswith("/custom-licence-database-unavailable")


def test_unexpected_sqlalchemy_error_returns_500(registration_client, monkeypatch: pytest.MonkeyPatch):
    client, _ = registration_client
    service = client.app.state.custom_licence_registration_service
    db = service.db

    def _raise_sqlalchemy_error():
        raise SQLAlchemyError("forced-sqlalchemy-error")

    monkeypatch.setattr(db, "transaction", _raise_sqlalchemy_error)
    response = client.post("/api/v1/licenses", json=_payload(), headers={"Authorization": "Bearer curator-token"})
    assert response.status_code == 500
    assert response.json()["type"].endswith("/custom-licence-persistence-failed")
