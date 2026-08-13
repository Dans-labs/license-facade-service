from __future__ import annotations

from datetime import datetime, timezone
import os
from pathlib import Path
import socket
import subprocess
import time
import uuid

import httpx
import psycopg
import pytest
from fastapi.testclient import TestClient

from src.license_facade_service.main import create_app
from src.license_facade_service.services.auth import AuthService, Principal
from src.license_facade_service.services.licenses import ResolvedLicense
from src.license_facade_service.services.licenses import ResolvedLicenseSource
from src.license_facade_service.services.spdx3_documents import Spdx3DocumentGenerationError, Spdx3DocumentService
from src.license_facade_service.services.spdx_validation import Spdx301StructuralValidator, SpdxStructuralValidationError

REPO_ROOT = Path(__file__).resolve().parents[1]


def _auth_header(token: str = "admin-token") -> dict[str, str]:
    return {"Authorization": f"Bearer {token}"}


def _graph_index_by_spdx_id(payload: dict[str, object]) -> dict[str, dict[str, object]]:
    graph = payload.get("@graph", [])
    assert isinstance(graph, list)
    indexed: dict[str, dict[str, object]] = {}
    for node in graph:
        assert isinstance(node, dict)
        spdx_id = node.get("spdxId")
        if isinstance(spdx_id, str):
            indexed[spdx_id] = node
    return indexed


class _RecordingValidator:
    def __init__(self) -> None:
        self.calls = 0

    def validate(self, document) -> None:
        self.calls += 1
        Spdx301StructuralValidator().validate(document)


class _FailingValidator:
    def validate(self, _document) -> None:
        raise SpdxStructuralValidationError(
            "SPDX document failed structural validation.",
            errors=[{"path": ["@graph", 2], "message": "synthetic validation failure"}],
        )


class _FailingDocumentService:
    def create_minimal_document(self, *, name: str, namespace: str):
        raise Spdx3DocumentGenerationError("synthetic service failure")

    def create_complete_license_document(self, *, resolved: ResolvedLicense):
        raise Spdx3DocumentGenerationError("synthetic service failure")


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


def _count_rows(raw_dsn: str, table: str) -> int:
    with psycopg.connect(raw_dsn) as conn:
        with conn.cursor() as cur:
            cur.execute(f"SELECT count(*) FROM {table}")
            return int(cur.fetchone()[0])


@pytest.fixture(scope="module")
def postgres_urls():
    if not _docker_available():
        pytest.skip("docker not available for PostgreSQL SPDX integration tests")
    port = _free_port()
    container_name = f"lfs-spdx3-{uuid.uuid4().hex[:8]}"
    subprocess.run(
        [
            "docker", "run", "--rm", "-d",
            "--name", container_name,
            "-e", "POSTGRES_PASSWORD=postgres",
            "-e", "POSTGRES_USER=postgres",
            "-e", "POSTGRES_DB=lfs_spdx3",
            "-p", f"{port}:5432",
            "postgres:16-alpine",
        ],
        check=True,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    dsn = f"postgresql+psycopg://postgres:postgres@127.0.0.1:{port}/lfs_spdx3"
    raw_dsn = f"postgresql://postgres:postgres@127.0.0.1:{port}/lfs_spdx3"
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
        _run_alembic(dsn, "upgrade", "head")
        yield dsn, raw_dsn
    finally:
        subprocess.run(["docker", "stop", container_name], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=False)


@pytest.fixture
def spdx_db_client(postgres_urls: tuple[str, str], monkeypatch: pytest.MonkeyPatch):
    dsn, raw_dsn = postgres_urls
    monkeypatch.setenv("LFS_ADMIN_TOKEN", "admin-token")
    monkeypatch.setenv("LFS_CURATOR_TOKEN", "curator-token")
    monkeypatch.setenv("OPENREL_ENABLED", "false")
    monkeypatch.setenv("FEDERATION_ENABLED", "false")
    monkeypatch.setenv("CUSTOM_LICENCE_REGISTRATION_DATABASE_URL", dsn)
    monkeypatch.setenv("CUSTOM_LICENCE_AUTHORITY_ID", "lfs-local-authority")
    monkeypatch.setenv("CUSTOM_LICENCE_AUTHORITY_BASE_IRI", "https://lfs.example")
    monkeypatch.setenv("CUSTOM_LICENCE_CREATOR_ORGANIZATION_NAME", "LFS Operator")
    monkeypatch.setenv("CUSTOM_LICENCE_CREATOR_ORGANIZATION_IRI", "https://lfs.example/spdx/agents/lfs-operator")
    app = create_app()
    with TestClient(app) as client:
        yield client, raw_dsn


def test_spdx3_service_is_application_scoped_and_config_specific(monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setenv("URL_BASE", "https://node-a.example/api/v1/licenses")
    app_a = create_app()
    monkeypatch.setenv("URL_BASE", "https://node-b.example/api/v1/licenses")
    app_b = create_app()

    service_a = app_a.state.spdx3_document_service
    service_b = app_b.state.spdx3_document_service
    assert service_a is not None
    assert service_b is not None
    assert service_a is not service_b
    assert service_a.complete_namespace == "https://node-a.example/api/v1/licenses/spdx3/documents"
    assert service_b.complete_namespace == "https://node-b.example/api/v1/licenses/spdx3/documents"


def test_spdx3_minimal_endpoint_returns_structurally_valid_document(app_client):
    client, *_ = app_client
    response = client.post(
        "/api/v1/licenses/spdx3/minimal",
        headers=_auth_header("curator-token"),
        json={"name": "Minimal SPDX 3.0 Document", "namespace": "https://example.org/spdx3/minimal-doc-1"},
    )
    assert response.status_code == 200

    payload = response.json()
    Spdx301StructuralValidator().validate(payload)
    assert payload["@context"] == "https://spdx.org/rdf/3.0.1/spdx-context.jsonld"

    graph = payload["@graph"]
    creation_info = next(node for node in graph if node.get("type") == "CreationInfo")
    assert creation_info["specVersion"] == "3.0.1"
    created_by = creation_info["createdBy"]
    assert isinstance(created_by, list)
    indexed = _graph_index_by_spdx_id(payload)
    for ref in created_by:
        assert ref in indexed
    document = next(node for node in graph if node.get("type") == "SpdxDocument")
    assert document["spdxId"].startswith("https://")
    assert isinstance(document["rootElement"], list)
    for ref in document["rootElement"]:
        assert ref in indexed
    for spdx_id in indexed:
        assert spdx_id.startswith("http://") or spdx_id.startswith("https://")


@pytest.mark.parametrize(
    "namespace",
    [
        "/relative",
        "https://user:pass@example.org/ns",
        "https://example.org/ns?x=1",
        "https://example.org/ns?",
        "https://example.org/ns#frag",
        "https://example.org/ns#",
        "https://example.org:bad/ns",
        "https://example.org\\bad",
        "https://example.org/\u0001bad",
    ],
)
def test_spdx3_minimal_endpoint_rejects_invalid_namespaces(app_client, namespace):
    client, *_ = app_client
    response = client.post(
        "/api/v1/licenses/spdx3/minimal",
        headers=_auth_header(),
        json={"name": "Minimal SPDX 3.0 Document", "namespace": namespace},
    )
    assert response.status_code == 422
    assert response.headers["content-type"].startswith("application/problem+json")
    body = response.json()
    assert body["title"] == "Invalid SPDX 3 Request"
    assert body["status"] == 422


def test_spdx3_minimal_endpoint_rejects_unknown_field(app_client):
    client, *_ = app_client
    response = client.post(
        "/api/v1/licenses/spdx3/minimal",
        headers=_auth_header(),
        json={"name": "x", "namespace": "https://example.org/ns", "unexpected": "value"},
    )
    assert response.status_code == 422
    assert response.headers["content-type"].startswith("application/problem+json")


def test_spdx3_minimal_endpoint_calls_validator_before_return(app_client):
    client, *_ = app_client
    validator = _RecordingValidator()
    client.app.state.spdx3_document_service = Spdx3DocumentService(
        validator=validator,
        now_provider=lambda: datetime(2026, 1, 1, 0, 0, 0, tzinfo=timezone.utc),
        complete_namespace="https://example.test/api/v1/licenses/spdx3/documents",
    )
    response = client.post(
        "/api/v1/licenses/spdx3/minimal",
        headers=_auth_header(),
        json={"name": "Minimal SPDX 3.0 Document", "namespace": "https://example.org/ns"},
    )
    assert response.status_code == 200
    assert validator.calls == 1


def test_spdx3_minimal_endpoint_validation_failure_returns_sanitized_500(app_client):
    client, *_ = app_client
    client.app.state.spdx3_document_service = Spdx3DocumentService(
        validator=_FailingValidator(),
        now_provider=lambda: datetime(2026, 1, 1, 0, 0, 0, tzinfo=timezone.utc),
        complete_namespace="https://example.test/api/v1/licenses/spdx3/documents",
    )
    response = client.post(
        "/api/v1/licenses/spdx3/minimal",
        headers=_auth_header(),
        json={"name": "Minimal SPDX 3.0 Document", "namespace": "https://example.org/ns"},
    )
    assert response.status_code == 500
    assert response.headers["content-type"].startswith("application/problem+json")
    body = response.json()
    assert body["type"] == "https://eosc-eden.eu/problems/spdx3-document-generation-invalid"
    assert body["title"] == "SPDX 3 Document Generation Failed"
    assert body["detail"] == "Generated SPDX 3.0.1 document failed structural validation."


def test_spdx3_minimal_endpoint_internal_failure_returns_sanitized_500(app_client):
    client, *_ = app_client
    client.app.state.spdx3_document_service = _FailingDocumentService()
    response = client.post(
        "/api/v1/licenses/spdx3/minimal",
        headers=_auth_header(),
        json={"name": "Minimal SPDX 3.0 Document", "namespace": "https://example.org/ns"},
    )
    assert response.status_code == 500
    assert response.headers["content-type"].startswith("application/problem+json")
    assert response.json()["detail"] == "SPDX 3 document generation is temporarily unavailable."


def test_spdx3_complete_mit_endpoint_returns_structurally_valid_listed_license_document(app_client):
    client, *_ = app_client
    response = client.post("/api/v1/licenses/spdx3/complete/MIT", headers=_auth_header("curator-token"))
    assert response.status_code == 200

    payload = response.json()
    Spdx301StructuralValidator().validate(payload)
    graph = payload["@graph"]
    license_node = next(node for node in graph if node.get("type") in {"expandedlicensing_ListedLicense", "expandedlicensing_CustomLicense"})
    assert license_node["type"] == "expandedlicensing_ListedLicense"
    assert license_node["simplelicensing_licenseText"] == "MIT text"


def test_spdx3_complete_omits_empty_template(app_client, monkeypatch):
    client, service, *_ = app_client

    async def _resolve_without_template(_identifier: str) -> ResolvedLicense:
        return ResolvedLicense(
            license_id="MIT",
            identifier="MIT",
            record={"licenseId": "MIT", "name": "MIT License", "detailsUrl": "https://spdx.org/licenses/MIT.json"},
            details={"licenseId": "MIT", "name": "MIT License", "licenseText": "MIT text"},
            uri="https://example.test/api/v1/licenses/mit",
            source=ResolvedLicenseSource.SPDX_LISTED,
        )

    monkeypatch.setattr(service, "resolve", _resolve_without_template)
    response = client.post("/api/v1/licenses/spdx3/complete/MIT", headers=_auth_header())
    assert response.status_code == 200
    license_node = next(
        node for node in response.json()["@graph"] if node.get("type") in {"expandedlicensing_ListedLicense", "expandedlicensing_CustomLicense"}
    )
    assert "expandedlicensing_standardLicenseTemplate" not in license_node


def test_spdx3_complete_unknown_license_returns_404(app_client):
    client, *_ = app_client
    response = client.post("/api/v1/licenses/spdx3/complete/does-not-exist", headers=_auth_header())
    assert response.status_code == 404
    assert response.headers["content-type"].startswith("application/problem+json")


def test_spdx3_complete_validation_failure_returns_sanitized_500(app_client):
    client, *_ = app_client
    client.app.state.spdx3_document_service = Spdx3DocumentService(
        validator=_FailingValidator(),
        now_provider=lambda: datetime(2026, 1, 1, 0, 0, 0, tzinfo=timezone.utc),
        complete_namespace="https://example.test/api/v1/licenses/spdx3/documents",
    )
    response = client.post("/api/v1/licenses/spdx3/complete/MIT", headers=_auth_header())
    assert response.status_code == 500
    assert response.headers["content-type"].startswith("application/problem+json")
    body = response.json()
    assert body["type"] == "https://eosc-eden.eu/problems/spdx3-document-generation-invalid"
    assert body["title"] == "SPDX 3 Document Generation Failed"
    assert body["detail"] == "Generated SPDX 3.0.1 document failed structural validation."


def test_spdx3_complete_internal_failure_returns_sanitized_500(app_client):
    client, *_ = app_client
    client.app.state.spdx3_document_service = _FailingDocumentService()
    response = client.post("/api/v1/licenses/spdx3/complete/MIT", headers=_auth_header())
    assert response.status_code == 500
    assert response.headers["content-type"].startswith("application/problem+json")
    assert response.json()["detail"] == "SPDX 3 document generation is temporarily unavailable."


def test_spdx3_complete_calls_validator_before_return(app_client):
    client, *_ = app_client
    validator = _RecordingValidator()
    client.app.state.spdx3_document_service = Spdx3DocumentService(
        validator=validator,
        now_provider=lambda: datetime(2026, 1, 1, 0, 0, 0, tzinfo=timezone.utc),
        complete_namespace="https://example.test/api/v1/licenses/spdx3/documents",
    )
    response = client.post("/api/v1/licenses/spdx3/complete/MIT", headers=_auth_header())
    assert response.status_code == 200
    assert validator.calls == 1


def test_spdx3_service_classification_uses_explicit_source_not_details_url():
    service = Spdx3DocumentService(
        validator=Spdx301StructuralValidator(),
        now_provider=lambda: datetime(2026, 1, 1, 12, 0, 0, tzinfo=timezone.utc),
        complete_namespace="https://example.test/api/v1/licenses/spdx3/documents",
    )
    spoofed = ResolvedLicense(
        license_id="Local-Custom-1.0",
        identifier="Local-Custom-1.0",
        record={"licenseId": "Local-Custom-1.0", "name": "Local", "detailsUrl": "https://spdx.org/licenses/MIT.json"},
        details={"licenseId": "MIT", "name": "Local", "licenseText": "Exact custom legal text", "detailsUrl": "https://spdx.org/licenses/MIT.json"},
        uri="https://example.test/api/v1/licenses/local",
        source=ResolvedLicenseSource.LOCAL_CUSTOM,
    )
    doc = service.create_complete_license_document(resolved=spoofed)
    license_node = next(node for node in doc["@graph"] if node.get("type") in {"expandedlicensing_ListedLicense", "expandedlicensing_CustomLicense"})
    assert license_node["type"] == "expandedlicensing_CustomLicense"
    assert license_node["simplelicensing_licenseText"] == "Exact custom legal text"


def test_spdx3_service_classification_treats_federated_custom_source_as_custom():
    service = Spdx3DocumentService(
        validator=Spdx301StructuralValidator(),
        now_provider=lambda: datetime(2026, 1, 1, 12, 0, 0, tzinfo=timezone.utc),
        complete_namespace="https://example.test/api/v1/licenses/spdx3/documents",
    )
    resolved = ResolvedLicense(
        license_id="Imported-Custom-1.0",
        identifier="Imported-Custom-1.0",
        record={"licenseId": "Imported-Custom-1.0", "name": "Imported Custom"},
        details={"licenseId": "Imported-Custom-1.0", "name": "Imported Custom", "licenseText": "Imported legal text"},
        uri="https://example.test/api/v1/licenses/imported-custom",
        source=ResolvedLicenseSource.FEDERATED_CUSTOM,
    )
    document = service.create_complete_license_document(resolved=resolved)
    license_node = next(node for node in document["@graph"] if node.get("type") in {"expandedlicensing_ListedLicense", "expandedlicensing_CustomLicense"})
    assert license_node["type"] == "expandedlicensing_CustomLicense"
    assert license_node["simplelicensing_licenseText"] == "Imported legal text"


def test_spdx3_endpoint_auth_boundaries(app_client, monkeypatch):
    client, *_ = app_client
    assert client.post("/api/v1/licenses/spdx3/minimal", json={"name": "x", "namespace": "https://example.org/ns"}).status_code == 401
    assert client.post("/api/v1/licenses/spdx3/minimal", headers=_auth_header("curator-token"), json={"name": "x", "namespace": "https://example.org/ns"}).status_code == 200

    class _ViewerAuth(AuthService):
        def authenticate(self, _request):
            return Principal(role="viewer")

    monkeypatch.setattr("src.license_facade_service.api.v1.licenses._auth_service", _ViewerAuth())
    forbidden = client.post(
        "/api/v1/licenses/spdx3/minimal",
        headers={"Authorization": "Bearer viewer-token"},
        json={"name": "x", "namespace": "https://example.org/ns"},
    )
    assert forbidden.status_code == 403


def test_unauthenticated_spdx_calls_invoke_neither_resolver_nor_validator(app_client, monkeypatch):
    client, service, *_ = app_client
    validator = _RecordingValidator()
    client.app.state.spdx3_document_service = Spdx3DocumentService(
        validator=validator,
        now_provider=lambda: datetime(2026, 1, 1, 0, 0, 0, tzinfo=timezone.utc),
        complete_namespace="https://example.test/api/v1/licenses/spdx3/documents",
    )
    calls = {"resolve": 0}
    original_resolve = service.resolve

    async def _recording_resolve(_identifier: str):
        calls["resolve"] += 1
        return await original_resolve("MIT")

    monkeypatch.setattr(service, "resolve", _recording_resolve)
    minimal = client.post("/api/v1/licenses/spdx3/minimal", json={"name": "x", "namespace": "https://example.org/ns"})
    complete = client.post("/api/v1/licenses/spdx3/complete/MIT")
    assert minimal.status_code == 401
    assert complete.status_code == 401
    assert calls["resolve"] == 0
    assert validator.calls == 0


def test_spdx3_endpoint_unavailable_service_returns_sanitized_500(app_client):
    client, *_ = app_client
    client.app.state.spdx3_document_service = None
    response = client.post(
        "/api/v1/licenses/spdx3/minimal",
        headers=_auth_header(),
        json={"name": "x", "namespace": "https://example.org/ns"},
    )
    assert response.status_code == 500
    assert response.headers["content-type"].startswith("application/problem+json")
    body = response.json()
    assert body["type"] == "https://eosc-eden.eu/problems/spdx3-document-generation-invalid"
    assert body["detail"] == "SPDX 3 document generation is temporarily unavailable."


def test_spdx3_endpoints_do_not_perform_external_http_calls(app_client, monkeypatch):
    client, *_ = app_client

    async def _boom(*_args, **_kwargs):
        raise AssertionError("unexpected outbound HTTP call")

    monkeypatch.setattr(httpx.AsyncClient, "get", _boom)
    minimal = client.post(
        "/api/v1/licenses/spdx3/minimal",
        headers=_auth_header(),
        json={"name": "Minimal SPDX 3.0 Document", "namespace": "https://example.org/ns"},
    )
    complete = client.post("/api/v1/licenses/spdx3/complete/MIT", headers=_auth_header())
    assert minimal.status_code == 200
    assert complete.status_code == 200


def test_spdx3_complete_does_not_resolve_registered_local_custom_licences_yet(spdx_db_client):
    client, _ = spdx_db_client
    requested = f"LOCAL-CUSTOM-{uuid.uuid4().hex[:8]}"
    register = client.post(
        "/api/v1/licenses",
        headers=_auth_header("curator-token"),
        json={
            "requestedLicenseId": requested,
            "version": "1.0",
            "name": "Local Custom License",
            "summary": "A local custom license",
            "description": "Custom terms",
            "licenseText": "Exact local custom legal text",
            "scope": "local",
            "aliases": [f"{requested}-alias"],
        },
    )
    assert register.status_code == 201
    complete = client.post(f"/api/v1/licenses/spdx3/complete/{requested}", headers=_auth_header("curator-token"))
    assert complete.status_code == 404
    assert complete.headers["content-type"].startswith("application/problem+json")


def test_spdx3_endpoints_have_no_db_or_outbox_side_effects_on_success_and_failure(spdx_db_client):
    client, raw_dsn = spdx_db_client
    tracked_tables = [
        "custom_licences",
        "custom_licence_federation_outbox",
        "federation_change_events",
        "federation_rdf_outbox_jobs",
    ]
    before = {table: _count_rows(raw_dsn, table) for table in tracked_tables}

    ok_minimal = client.post(
        "/api/v1/licenses/spdx3/minimal",
        headers=_auth_header(),
        json={"name": "Minimal SPDX 3.0 Document", "namespace": "https://example.org/ns"},
    )
    assert ok_minimal.status_code == 200
    ok_complete = client.post("/api/v1/licenses/spdx3/complete/MIT", headers=_auth_header())
    assert ok_complete.status_code == 200

    client.app.state.spdx3_document_service = Spdx3DocumentService(
        validator=_FailingValidator(),
        now_provider=lambda: datetime(2026, 1, 1, 0, 0, 0, tzinfo=timezone.utc),
        complete_namespace="https://example.test/api/v1/licenses/spdx3/documents",
    )
    fail_minimal = client.post(
        "/api/v1/licenses/spdx3/minimal",
        headers=_auth_header(),
        json={"name": "Minimal SPDX 3.0 Document", "namespace": "https://example.org/ns"},
    )
    assert fail_minimal.status_code == 500
    fail_complete = client.post("/api/v1/licenses/spdx3/complete/MIT", headers=_auth_header())
    assert fail_complete.status_code == 500

    after = {table: _count_rows(raw_dsn, table) for table in tracked_tables}
    assert before == after


def test_spdx3_service_is_deterministic_with_fixed_clock():
    fixed_now = datetime(2026, 1, 1, 12, 0, 0, tzinfo=timezone.utc)
    service = Spdx3DocumentService(
        validator=Spdx301StructuralValidator(),
        now_provider=lambda: fixed_now,
        complete_namespace="https://example.test/api/v1/licenses/spdx3/documents",
    )
    resolved = ResolvedLicense(
        license_id="MIT",
        identifier="MIT",
        record={"licenseId": "MIT", "name": "MIT License", "detailsUrl": "https://spdx.org/licenses/MIT.json"},
        details={"licenseId": "MIT", "name": "MIT License", "licenseText": "MIT text"},
        uri="https://example.test/api/v1/licenses/mit",
        source=ResolvedLicenseSource.SPDX_LISTED,
    )
    first = service.create_complete_license_document(resolved=resolved)
    second = service.create_complete_license_document(resolved=resolved)
    first_doc = next(node for node in first["@graph"] if node.get("type") == "SpdxDocument")
    second_doc = next(node for node in second["@graph"] if node.get("type") == "SpdxDocument")
    assert first_doc["spdxId"] == second_doc["spdxId"]
    first_creation = next(node for node in first["@graph"] if node.get("type") == "CreationInfo")
    assert first_creation["created"] == "2026-01-01T12:00:00Z"


def test_spdx3_service_rejects_naive_clock():
    service = Spdx3DocumentService(
        validator=Spdx301StructuralValidator(),
        now_provider=lambda: datetime(2026, 1, 1, 0, 0, 0),
        complete_namespace="https://example.test/api/v1/licenses/spdx3/documents",
    )
    with pytest.raises(ValueError, match="timezone-aware"):
        service.create_minimal_document(name="Minimal", namespace="https://example.org/ns")


def test_spdx3_openapi_contract_and_examples_validate(app_client):
    client, *_ = app_client
    openapi = client.get("/openapi.json").json()

    minimal = openapi["paths"]["/api/v1/licenses/spdx3/minimal"]["post"]
    complete = openapi["paths"]["/api/v1/licenses/spdx3/complete/{license_id}"]["post"]
    assert minimal["operationId"] == "createMinimalSpdx3Document"
    assert complete["operationId"] == "createCompleteSpdx3Document"
    assert minimal["security"] == [{"HTTPBearer": []}]
    assert complete["security"] == [{"HTTPBearer": []}]
    assert "application/json" in minimal["responses"]["200"]["content"]
    assert "application/problem+json" in minimal["responses"]["422"]["content"]
    assert "application/problem+json" in minimal["responses"]["500"]["content"]
    assert "application/problem+json" in complete["responses"]["404"]["content"]
    assert "application/problem+json" in complete["responses"]["422"]["content"]
    assert "application/problem+json" in complete["responses"]["500"]["content"]
    assert "vendored official SPDX 3.0.1 JSON Schema" in minimal["description"]
    assert "vendored official SPDX 3.0.1 JSON Schema" in complete["description"]
    assert "These endpoints do not use `spdx-tools` validation" in minimal["description"]
    assert "These endpoints do not use `spdx-tools` validation" in complete["description"]

    validator = Spdx301StructuralValidator()
    minimal_example = minimal["responses"]["200"]["content"]["application/json"]["example"]
    complete_example = complete["responses"]["200"]["content"]["application/json"]["example"]
    validator.validate(minimal_example)
    validator.validate(complete_example)
