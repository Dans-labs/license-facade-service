from __future__ import annotations

import json
from pathlib import Path
from urllib.parse import quote

import pytest

from src.license_facade_service.api.v1 import licenses as licenses_api
from src.license_facade_service.main import create_app
from src.license_facade_service.services.auth import AuthService, Principal
from src.license_facade_service.services.licenses import LicenseService, SPDXClient


def test_openapi_has_no_duplicate_operations(app_client):
    client, *_ = app_client
    openapi = client.get("/openapi.json").json()
    keys = [(path, method) for path, methods in openapi["paths"].items() for method in methods]
    assert len(keys) == len(set(keys))
    seen = set()
    for route in client.app.routes:
        methods = getattr(route, "methods", None)
        if not methods:
            continue
        for method in methods:
            if method in {"HEAD", "OPTIONS"}:
                continue
            key = (route.path, method)
            assert key not in seen
            seen.add(key)


def test_static_routes_take_precedence(app_client):
    client, *_ = app_client
    taxonomy = client.get("/api/v1/licenses/taxonomy")
    assert taxonomy.status_code == 200
    assert "Permissive" in taxonomy.json()["description"]

    alias_taxonomy = client.get("/api/v1/licences/taxonomy")
    assert alias_taxonomy.status_code == 200

    cache_status = client.get("/api/v1/licenses/cache/status")
    assert cache_status.status_code == 200
    assert cache_status.json()["cached"] is True

    spdx_minimal = client.post("/api/v1/licenses/spdx3/minimal", json={})
    assert spdx_minimal.status_code == 401

    openapi = client.get("/openapi.json").json()
    assert "/api/v1/licences/taxonomy" not in openapi["paths"]
    assert "/api/v1/licenses/taxonomy" in openapi["paths"]


def test_lookup_by_spdx_id_uuid_and_uri(app_client):
    client, _, licenses_payload, _, mit_uuid = app_client
    by_id = client.get("/api/v1/licenses/MIT/json")
    assert by_id.status_code == 200
    payload = by_id.json()
    assert payload["licenseId"] == "MIT"
    assert payload["licenseID"] == "MIT"
    assert "uri" in payload
    assert "referenceNumber" in payload
    assert "detailsURL" in payload
    assert "isDeprecatedLicenseID" in payload
    assert payload["uri"].startswith("https://example.test/api/v1/licenses/")
    assert "representations" in payload
    assert "html" in payload["representations"]

    by_uuid = client.get(f"/api/v1/licenses/{mit_uuid}/json")
    assert by_uuid.status_code == 200
    assert by_uuid.json()["licenseId"] == "MIT"

    encoded_uri = quote(licenses_payload["licenses"][0]["uri"], safe="")
    by_uri = client.get(f"/api/v1/licenses/{encoded_uri}/json")
    assert by_uri.status_code == 200
    assert by_uri.json()["licenseId"] == "MIT"


def test_invalid_and_malicious_identifiers(app_client):
    client, *_ = app_client
    case_sensitive = client.get("/api/v1/licenses/mit/json")
    assert case_sensitive.status_code == 404

    traversal = client.get("/api/v1/licenses/%2E%2E%2Fetc%2Fpasswd/json")
    assert traversal.status_code == 404


@pytest.mark.parametrize(
    ("accept", "expected_content_type"),
    [
        ("text/html", "text/html"),
        ("application/json", "application/json"),
        ("application/ld+json", "application/ld+json"),
        ("text/turtle", "text/turtle"),
        ("application/rdf+xml", "application/rdf+xml"),
    ],
)
def test_content_negotiation_supported_types(app_client, accept, expected_content_type):
    client, *_ = app_client
    response = client.get("/api/v1/licenses/MIT", headers={"Accept": accept})
    assert response.status_code == 200
    assert response.headers["content-type"].startswith(expected_content_type)
    assert response.headers["vary"] == "Accept"


def test_default_accept_is_html(app_client):
    client, *_ = app_client
    response = client.get("/api/v1/licenses/MIT")
    assert response.status_code == 200
    assert response.headers["content-type"].startswith("text/html")


def test_unsupported_accept_returns_406_problem_details(app_client):
    client, *_ = app_client
    response = client.get("/api/v1/licenses/MIT", headers={"Accept": "application/pdf"})
    assert response.status_code == 406
    assert response.headers["content-type"].startswith("application/problem+json")
    assert response.json()["status"] == 406


def test_convenience_route_equivalent_to_negotiation_json(app_client):
    client, *_ = app_client
    direct = client.get("/api/v1/licenses/MIT/json").json()
    negotiated = client.get("/api/v1/licenses/MIT", headers={"Accept": "application/json"}).json()
    assert direct == negotiated


def test_optional_original_legal_machine_representations(app_client):
    client, *_ = app_client
    original = client.get("/api/v1/licenses/MIT/original", follow_redirects=False)
    assert original.status_code == 307
    assert original.headers["location"].startswith("https://opensource.org/licenses/MIT") or original.headers["location"].startswith("https://spdx.org/licenses/MIT")

    legal = client.get("/api/v1/licenses/MIT/legal")
    assert legal.status_code == 404
    assert "availableRepresentations" in legal.json()

    machine_missing = client.get("/api/v1/licenses/MIT/machine")
    assert machine_missing.status_code == 404

    encoding_missing = client.get("/api/v1/licenses/MIT/encoding")
    assert encoding_missing.status_code == 404

    machine_available = client.get("/api/v1/licenses/Apache-2.0/machine")
    assert machine_available.status_code == 200
    assert machine_available.headers["content-type"].startswith("application/ld+json")


def test_authentication_and_authorization_for_mutations(app_client, monkeypatch):
    client, *_ = app_client
    unauthenticated = client.post("/api/v1/licenses/cache/refresh")
    assert unauthenticated.status_code == 401

    invalid = client.post(
        "/api/v1/licenses/cache/refresh",
        headers={"Authorization": "Bearer nope"},
    )
    assert invalid.status_code == 401

    allowed = client.post(
        "/api/v1/licenses/cache/refresh",
        headers={"Authorization": "Bearer curator-token"},
    )
    assert allowed.status_code == 200

    class ViewerAuth(AuthService):
        def authenticate(self, request):
            return Principal(role="viewer")

    licenses_api._auth_service = ViewerAuth()
    forbidden = client.post(
        "/api/v1/licenses/cache/refresh",
        headers={"Authorization": "Bearer viewer-token"},
    )
    assert forbidden.status_code == 403


def test_atomic_refresh_rolls_back_on_failure(tmp_path: Path):
    import asyncio

    licenses_payload = {
        "licenseListVersion": "3.26",
        "licenses": [{"licenseId": "MIT", "uri": "https://example.test/api/v1/licenses/mit"}],
    }
    details_payload = {"MIT": {"licenseId": "MIT", "licenseText": "ok"}}

    base = tmp_path
    seed = base / "resources" / "data" / "licenses" / "snapshots" / "seed"
    seed.mkdir(parents=True, exist_ok=True)
    (seed / "licenses_list.json").write_text(json.dumps(licenses_payload), encoding="utf-8")
    (seed / "version.json").write_text(json.dumps({"licenseListVersion": "3.26"}), encoding="utf-8")
    (seed / "MIT.json").write_text(json.dumps(details_payload["MIT"]), encoding="utf-8")
    current_file = base / "resources" / "data" / "licenses" / "current_snapshot.json"
    current_file.parent.mkdir(parents=True, exist_ok=True)
    current_file.write_text(json.dumps({"snapshot": "seed"}), encoding="utf-8")

    class FailingSpdx(SPDXClient):
        async def fetch_license_list(self):
            return {"licenseListVersion": "3.27", "licenses": [{"licenseId": "MIT"}, {"licenseId": "Apache-2.0"}]}

        async def fetch_license_details(self, license_id: str):
            if license_id == "Apache-2.0":
                raise RuntimeError("download failed")
            return {"licenseId": "MIT", "licenseText": "ok"}

    service = LicenseService(base_dir=base, spdx_client=FailingSpdx())
    with pytest.raises(Exception):
        asyncio.run(service.refresh_cache())

    assert json.loads(current_file.read_text(encoding="utf-8"))["snapshot"] == "seed"


def test_previous_snapshot_served_when_spdx_offline(tmp_path: Path):
    licenses_payload = {
        "licenseListVersion": "3.26",
        "licenses": [{"licenseId": "MIT", "name": "MIT", "uri": "https://example.test/api/v1/licenses/uuid"}],
    }
    details_payload = {"MIT": {"licenseId": "MIT", "licenseText": "MIT text", "crossRef": []}}
    seed = tmp_path / "resources" / "data" / "licenses" / "snapshots" / "seed"
    seed.mkdir(parents=True, exist_ok=True)
    (seed / "licenses_list.json").write_text(json.dumps(licenses_payload), encoding="utf-8")
    (seed / "version.json").write_text(json.dumps({"licenseListVersion": "3.26"}), encoding="utf-8")
    (seed / "MIT.json").write_text(json.dumps(details_payload["MIT"]), encoding="utf-8")
    current = tmp_path / "resources" / "data" / "licenses" / "current_snapshot.json"
    current.parent.mkdir(parents=True, exist_ok=True)
    current.write_text(json.dumps({"snapshot": "seed"}), encoding="utf-8")

    class OfflineSpdx(SPDXClient):
        async def fetch_license_list(self):
            raise RuntimeError("offline")

        async def fetch_license_details(self, license_id: str):
            raise RuntimeError("offline")

    service = LicenseService(base_dir=tmp_path, spdx_client=OfflineSpdx())
    import asyncio

    resolved = asyncio.run(service.resolve("MIT"))
    assert resolved.license_id == "MIT"


def test_health_and_readiness(app_client):
    client, *_ = app_client
    assert client.get("/api/v1/health").status_code == 200
    ready = client.get("/api/v1/ready")
    assert ready.status_code == 200
    assert ready.json()["status"] == "ready"


def test_application_import_and_compose_configuration():
    app = create_app()
    assert app is not None
    compose_text = Path("docker-compose.yaml").read_text(encoding="utf-8")
    assert "secoresearch/fuseki:4.10.0" in compose_text
    assert '  ports:\n      - "3030:3030"' not in compose_text
