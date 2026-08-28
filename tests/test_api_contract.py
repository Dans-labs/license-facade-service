from __future__ import annotations

import json
from pathlib import Path
from urllib.parse import quote

import pytest

from src.license_facade_service.api.v1 import licenses as licenses_api
from src.license_facade_service.main import create_app
from src.license_facade_service.services.auth import AuthService, Principal
from src.license_facade_service.services.licenses import LicenseService, SPDXClient, ResolvedLicense


def _openapi_operations(client):
    openapi = client.get("/openapi.json").json()
    operations = []
    for path, methods in openapi["paths"].items():
        for method, operation in methods.items():
            operations.append((path, method, operation))
    return openapi, operations


def test_openapi_has_no_duplicate_operations(app_client):
    client, *_ = app_client
    openapi, _ = _openapi_operations(client)
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


def test_openapi_operations_have_summary_description_tags_and_unique_operation_ids(app_client):
    client, *_ = app_client
    openapi, operations = _openapi_operations(client)
    tag_descriptions = {tag["name"]: tag.get("description") for tag in openapi.get("tags", [])}
    operation_ids = [operation["operationId"] for _, _, operation in operations]

    assert operation_ids
    assert len(operation_ids) == len(set(operation_ids))

    for path, method, operation in operations:
        assert operation.get("summary"), f"missing summary for {method.upper()} {path}"
        assert operation.get("description"), f"missing description for {method.upper()} {path}"
        assert "\n" in operation["description"], f"description should be multiline for {method.upper()} {path}"
        assert operation.get("tags"), f"missing tags for {method.upper()} {path}"
        for tag in operation["tags"]:
            assert tag in tag_descriptions, f"missing app-level tag description for {tag}"
            assert tag_descriptions[tag], f"empty app-level tag description for {tag}"


def test_openapi_security_scheme_marks_only_protected_operations(app_client):
    client, *_ = app_client
    openapi, operations = _openapi_operations(client)
    assert "HTTPBearer" in openapi["components"]["securitySchemes"]

    protected = {
        ("post", "/api/v1/licenses/cache/update"),
        ("post", "/api/v1/licenses/cache/refresh"),
        ("post", "/api/v1/licenses/spdx3/minimal"),
        ("post", "/api/v1/licenses/spdx3/complete/{license_id}"),
        ("get", "/api/v1/admin/federation/peers"),
        ("post", "/api/v1/admin/federation/peers"),
        ("get", "/api/v1/admin/federation/peers/{peer_id}"),
        ("patch", "/api/v1/admin/federation/peers/{peer_id}"),
        ("delete", "/api/v1/admin/federation/peers/{peer_id}"),
        ("get", "/api/v1/admin/federation/peers/{peer_id}/imports"),
        ("post", "/api/v1/admin/federation/peers/{peer_id}/sync"),
        ("get", "/api/v1/admin/federation/status"),
        ("post", "/api/v1/admin/federation/publish"),
        ("get", "/api/v1/admin/federation/conflicts"),
        ("get", "/api/v1/admin/federation/conflicts/{conflict_id}"),
        ("post", "/api/v1/admin/federation/conflicts/{conflict_id}/decisions"),
        ("post", "/api/v1/admin/federation/conflicts/{conflict_id}/reversals"),
        # Phase 5 Increment 2 — operational visibility endpoints
        ("get", "/api/v1/admin/federation/peers/{peer_id}/health"),
        ("get", "/api/v1/admin/federation/peers/{peer_id}/cursor"),
        ("get", "/api/v1/admin/federation/signing-keys"),
        ("get", "/api/v1/admin/federation/rdf-outbox"),
        ("get", "/api/v1/admin/federation/sync-attempts"),
        ("get", "/api/v1/admin/federation/compatibility"),
    }

    seen_protected = set()
    for path, method, operation in operations:
        key = (method, path)
        security = operation.get("security")
        if key in protected:
            seen_protected.add(key)
            assert security == [{"HTTPBearer": []}], f"missing bearer auth for {method.upper()} {path}"
        else:
            assert not security, f"unexpected auth metadata for public operation {method.upper()} {path}"
    assert seen_protected == protected


def test_openapi_problem_media_types_and_public_response_types(app_client):
    client, *_ = app_client
    openapi, _ = _openapi_operations(client)

    assert "application/problem+json" in openapi["paths"]["/api/v1/licenses/{id}"]["get"]["responses"]["406"]["content"]
    assert "application/problem+json" in openapi["paths"]["/api/v1/licenses/resolution"]["get"]["responses"]["404"]["content"]
    assert "application/problem+json" in openapi["paths"]["/api/v1/licenses/provenance"]["get"]["responses"]["409"]["content"]
    assert "application/problem+json" in openapi["paths"]["/api/v1/admin/federation/peers"]["post"]["responses"]["401"]["content"]
    assert "application/problem+json" in openapi["paths"]["/api/v1/admin/federation/conflicts/{conflict_id}/decisions"]["post"]["responses"]["409"]["content"]

    assert list(openapi["paths"]["/api/v1/licenses/{id}"]["get"]["responses"]["200"]["content"].keys()) == [
        "application/json",
        "text/html",
        "application/ld+json",
        "text/turtle",
        "application/rdf+xml",
    ]
    assert {"200", "304", "404", "503"}.issubset(openapi["paths"]["/.well-known/lfs"]["get"]["responses"].keys())
    assert "application/json" in openapi["paths"]["/.well-known/jwks.json"]["get"]["responses"]["200"]["content"]


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
    assert "/api/v1/licenses/resolution" in openapi["paths"]
    assert "/api/v1/licenses/provenance" in openapi["paths"]
    assert "/api/v1/licenses/{id}" in openapi["paths"]
    assert list(openapi["paths"]["/api/v1/licenses/{id}"]["get"]["responses"]["200"]["content"].keys()) == [
        "application/json",
        "text/html",
        "application/ld+json",
        "text/turtle",
        "application/rdf+xml",
    ]
    assert list(openapi["paths"]["/api/v1/licenses/{id}/html"]["get"]["responses"]["200"]["content"].keys()) == ["text/html"]
    assert list(openapi["paths"]["/api/v1/licenses/{id}/json-ld"]["get"]["responses"]["200"]["content"].keys()) == ["application/ld+json"]
    assert list(openapi["paths"]["/api/v1/licenses/{id}/turtle"]["get"]["responses"]["200"]["content"].keys()) == ["text/turtle"]
    assert list(openapi["paths"]["/api/v1/licenses/{id}/rdfxml"]["get"]["responses"]["200"]["content"].keys()) == ["application/rdf+xml"]
    assert "/.well-known/lfs" in openapi["paths"]
    assert "/.well-known/jwks.json" in openapi["paths"]
    assert "/api/v1/federation/catalog" in openapi["paths"]
    assert "/api/v1/federation/changes" in openapi["paths"]
    assert "/api/v1/federation/records/{encoded_id}" in openapi["paths"]


def test_default_json_and_aliases(app_client):
    client, _, _, _, _ = app_client
    default = client.get("/api/v1/licenses/MIT")
    assert default.status_code == 200
    assert default.headers["content-type"].startswith("application/json")
    payload = default.json()
    assert payload["licenseId"] == "MIT"
    assert payload["licenseID"] == "MIT"
    assert payload["detailsURL"] == "/api/v1/licenses/MIT/json"
    assert payload["spdxDetailsURL"] == "https://spdx.org/licenses/MIT.json"
    assert payload["conformance"]["conformant"] is False
    assert payload["conformance"]["requirements"]["LFS-REQ-2-04"]["missing"] == ["machine"]

    wildcard = client.get("/api/v1/licenses/MIT", headers={"Accept": "*/*"})
    assert wildcard.status_code == 200
    assert wildcard.headers["content-type"].startswith("application/json")

    alias = client.get("/api/v1/licences/MIT")
    assert alias.status_code == 200
    assert alias.json()["licenseId"] == "MIT"

    alias_json = client.get("/api/v1/licences/MIT/json")
    assert alias_json.status_code == 200
    assert alias_json.json()["licenseId"] == "MIT"

    explicit_html = client.get("/api/v1/licenses/MIT", headers={"Accept": "text/html"})
    assert explicit_html.status_code == 200
    assert explicit_html.headers["content-type"].startswith("text/html")


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
    assert "original" in payload["representations"]

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
    assert client.get("/api/v1/licenses/MIT").json() == negotiated


def test_optional_original_legal_machine_representations(app_client):
    client, *_ = app_client
    original = client.get("/api/v1/licenses/Apache-2.0/original", follow_redirects=False)
    assert original.status_code == 307
    assert original.headers["location"].startswith("https://www.apache.org/licenses/LICENSE-2.0")

    legal = client.get("/api/v1/licenses/Apache-2.0/legal")
    assert legal.status_code == 404
    assert "availableRepresentations" in legal.json()

    machine_missing = client.get("/api/v1/licenses/MIT/machine")
    assert machine_missing.status_code == 404
    assert machine_missing.json()["licenseMetadata"]["conformance"]["requirements"]["LFS-REQ-2-04"]["missing"] == ["machine"]

    encoding_missing = client.get("/api/v1/licenses/MIT/encoding")
    assert encoding_missing.status_code == 404

    machine_available = client.get("/api/v1/licenses/Apache-2.0/machine")
    assert machine_available.status_code == 200
    assert machine_available.headers["content-type"].startswith("application/ld+json")
    assert "profile" in machine_available.headers.get("link", "")

    cc_machine = client.get("/api/v1/licenses/CC-BY-4.0/machine")
    assert cc_machine.status_code == 200
    assert cc_machine.headers["content-type"].startswith("application/ld+json")

    missing_original = client.get("/api/v1/licenses/Legacy-No-Original/original")
    assert missing_original.status_code == 404
    assert missing_original.json()["licenseMetadata"]["conformance"]["requirements"]["LFS-REQ-2-04"]["missing"] == ["original"]

    bad_rel = client.get("/api/v1/licenses/Bad-REL/machine")
    assert bad_rel.status_code == 404


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


def test_table6_mappings_and_response_schema(app_client):
    client, *_ = app_client
    apache = client.get("/api/v1/licenses/Apache-2.0/json").json()
    assert apache["detailsURL"] == "/api/v1/licenses/Apache-2.0/json"
    assert apache["spdxDetailsURL"] == "https://spdx.org/licenses/Apache-2.0.json"
    assert any(ref["type"] == "original" for ref in apache["crossRef"])
    assert any(ref["type"] == "machine" for ref in apache["crossRef"])
    assert "legal" not in apache["representations"]
    assert apache["conformance"]["conformant"] is True
    assert apache["representationStatus"]["original"]["available"] is True
    assert apache["representationStatus"]["machine"]["available"] is True

    legacy = client.get("/api/v1/licenses/Legacy-No-Original/json").json()
    assert legacy["conformance"]["conformant"] is False
    assert legacy["conformance"]["requirements"]["LFS-REQ-2-04"]["missing"] == ["original"]


def test_html_escaping_and_safe_redirects(tmp_path: Path):
    from src.license_facade_service.services.licenses import LicenseService

    base = tmp_path
    licenses_root = base / "resources" / "data" / "licenses"
    licenses_root.mkdir(parents=True, exist_ok=True)
    (licenses_root / "current_snapshot.json").write_text(json.dumps({"snapshot": "seed"}), encoding="utf-8")
    seed = licenses_root / "snapshots" / "seed"
    seed.mkdir(parents=True, exist_ok=True)
    (seed / "licenses_list.json").write_text(
        json.dumps(
            {
                "licenseListVersion": "1",
                "licenses": [
                    {
                        "licenseId": "XSS",
                        "name": "<script>alert(1)</script>",
                        "isDeprecatedLicenseId": False,
                        "isOsiApproved": False,
                        "uri": "https://example.test/api/v1/licenses/xss",
                        "detailsUrl": "https://spdx.org/licenses/XSS.json",
                        "reference": "https://spdx.org/licenses/XSS.html",
                    }
                ],
            }
        ),
        encoding="utf-8",
    )
    (seed / "XSS.json").write_text(
        json.dumps(
            {
                "licenseId": "XSS",
                "name": "<script>alert(1)</script>",
                "licenseText": "x",
                "licenseTextHtml": "<img src=x onerror=alert(1)>",
                "standardLicenseTemplate": "x",
                "crossRef": [],
            }
        ),
        encoding="utf-8",
    )
    (licenses_root / "curated_representations.json").write_text(json.dumps({"XSS": {"original": {"href": "javascript:alert(1)", "relation": "original", "type": "original", "mediaType": "text/html"}}}), encoding="utf-8")
    service = LicenseService(base_dir=base)
    resolved = ResolvedLicense(
        license_id="XSS",
        identifier="XSS",
        record={
            "licenseId": "XSS",
            "name": "<script>alert(1)</script>",
            "isDeprecatedLicenseId": False,
            "isOsiApproved": False,
            "uri": "https://example.test/api/v1/licenses/xss",
            "detailsUrl": "https://spdx.org/licenses/XSS.json",
            "reference": "https://spdx.org/licenses/XSS.html",
        },
        details={
            "licenseId": "XSS",
            "name": "<script>alert(1)</script>",
            "licenseText": "x",
            "licenseTextHtml": "<img src=x onerror=alert(1)>",
            "standardLicenseTemplate": "x",
            "crossRef": [],
        },
        uri="https://example.test/api/v1/licenses/xss",
    )
    html = service._render_html(service.build_metadata(resolved))
    assert "<script>" not in html
    assert "javascript:" not in html


def test_invalid_jsonld_and_rdf_representations_are_rejected(tmp_path: Path):
    from src.license_facade_service.services.licenses import LicenseService

    base = tmp_path
    licenses_root = base / "resources" / "data" / "licenses"
    licenses_root.mkdir(parents=True, exist_ok=True)
    (licenses_root / "current_snapshot.json").write_text(json.dumps({"snapshot": "seed"}), encoding="utf-8")
    seed = licenses_root / "snapshots" / "seed"
    seed.mkdir(parents=True, exist_ok=True)
    (seed / "licenses_list.json").write_text(
        json.dumps(
            {
                "licenseListVersion": "1",
                "licenses": [
                    {
                        "licenseId": "RDF-BAD",
                        "name": "Bad RDF License",
                        "isDeprecatedLicenseId": False,
                        "isOsiApproved": False,
                        "uri": "https://example.test/api/v1/licenses/rdf-bad",
                        "detailsUrl": "https://spdx.org/licenses/RDF-BAD.json",
                        "reference": "https://spdx.org/licenses/RDF-BAD.html",
                    }
                ],
            }
        ),
        encoding="utf-8",
    )
    (seed / "RDF-BAD.json").write_text(
        json.dumps(
            {
                "licenseId": "RDF-BAD",
                "name": "Bad RDF License",
                "licenseText": "x",
                "licenseTextHtml": "<p>x</p>",
                "standardLicenseTemplate": "x",
                "crossRef": [],
            }
        ),
        encoding="utf-8",
    )
    (licenses_root / "curated_representations.json").write_text(
        json.dumps(
            {
                "RDF-BAD": {
                    "machine": {
                        "content": "@prefix odrl: <https://www.w3.org/ns/odrl/2/> . this is not turtle",
                        "mediaType": "text/turtle",
                        "profile": "https://www.w3.org/ns/odrl/2/",
                        "vocabulary": "https://www.w3.org/ns/odrl/2/",
                        "version": "1.0",
                        "digest": "sha256:bad-rdf",
                        "provenance": "curated",
                        "source": "https://example.org/curated/rdf-bad",
                    }
                }
            }
        ),
        encoding="utf-8",
    )
    service = LicenseService(base_dir=base)
    import asyncio

    resolved = asyncio.run(service.resolve("RDF-BAD"))
    assert service.get_machine_representation(resolved) is None


def test_string_crossref_booleans_do_not_crash(tmp_path: Path):
    from src.license_facade_service.services.licenses import LicenseService, ResolvedLicense

    base = tmp_path
    licenses_root = base / "resources" / "data" / "licenses"
    licenses_root.mkdir(parents=True, exist_ok=True)
    (licenses_root / "current_snapshot.json").write_text(json.dumps({"snapshot": "seed"}), encoding="utf-8")
    seed = licenses_root / "snapshots" / "seed"
    seed.mkdir(parents=True, exist_ok=True)
    (seed / "licenses_list.json").write_text(
        json.dumps(
            {
                "licenseListVersion": "1",
                "licenses": [
                    {
                        "licenseId": "X",
                        "name": "X",
                        "isDeprecatedLicenseId": False,
                        "isOsiApproved": False,
                        "uri": "https://example.test/api/v1/licenses/x",
                        "detailsUrl": "https://spdx.org/licenses/X.json",
                        "reference": "https://spdx.org/licenses/X.html",
                    }
                ],
            }
        ),
        encoding="utf-8",
    )
    (seed / "X.json").write_text(
        json.dumps(
            {
                "licenseId": "X",
                "name": "X",
                "licenseText": "x",
                "licenseTextHtml": "<p>x</p>",
                "standardLicenseTemplate": "x",
                "crossRef": [{"url": "https://example.org/x", "match": "N/A", "isValid": "maybe"}],
            }
        ),
        encoding="utf-8",
    )
    service = LicenseService(base_dir=base)
    resolved = ResolvedLicense(
        license_id="X",
        identifier="X",
        record={
            "licenseId": "X",
            "name": "X",
            "isDeprecatedLicenseId": False,
            "isOsiApproved": False,
            "uri": "https://example.test/api/v1/licenses/x",
            "detailsUrl": "https://spdx.org/licenses/X.json",
            "reference": "https://spdx.org/licenses/X.html",
        },
        details={
            "licenseId": "X",
            "name": "X",
            "licenseText": "x",
            "licenseTextHtml": "<p>x</p>",
            "standardLicenseTemplate": "x",
            "crossRef": [{"url": "https://example.org/x", "match": "N/A", "isValid": "maybe"}],
        },
        uri="https://example.test/api/v1/licenses/x",
    )
    metadata = service.build_metadata(resolved)
    assert "match" not in metadata["crossRef"][0]
    assert "isValid" not in metadata["crossRef"][0]
