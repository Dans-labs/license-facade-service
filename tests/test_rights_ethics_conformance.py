# Executable RED-phase tests for confirmed LFS Rights & Ethics requirements.
# These tests intentionally describe required behaviour that production does not yet fully implement.
# They must not fabricate licence provisions or infer legal meaning from licence prose.

from __future__ import annotations

import asyncio
import json
from pathlib import Path

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient
from rdflib import Graph

from src.license_facade_service.api.v1 import licenses as licenses_api
from src.license_facade_service.services.custom_licence_registration import build_resolving_uuid
from src.license_facade_service.services.licenses import LicenseService, ResolvedLicense, generate_license_uri
from src.license_facade_service.utils.rdf_transformer import json_to_rdf


def _seed_licenses_dir(
    tmp_path: Path,
    licenses: list[dict],
    details: dict[str, dict],
    curated: dict[str, dict] | None = None,
) -> Path:
    root = tmp_path / "resources" / "data" / "licenses"
    root.mkdir(parents=True, exist_ok=True)
    (root / "current_snapshot.json").write_text(json.dumps({"snapshot": "seed"}), encoding="utf-8")
    seed = root / "snapshots" / "seed"
    seed.mkdir(parents=True, exist_ok=True)
    (seed / "licenses_list.json").write_text(
        json.dumps({"licenseListVersion": "1", "licenses": licenses}),
        encoding="utf-8",
    )
    (seed / "version.json").write_text(json.dumps({"licenseListVersion": "1"}), encoding="utf-8")
    for license_id, payload in details.items():
        (seed / f"{license_id}.json").write_text(json.dumps(payload), encoding="utf-8")
    if curated is not None:
        (root / "curated_representations.json").write_text(json.dumps(curated), encoding="utf-8")
    return tmp_path


def _resolve(service: LicenseService, identifier: str) -> ResolvedLicense:
    return asyncio.run(service.resolve(identifier))


def _api_client(service: LicenseService) -> TestClient:
    app = FastAPI()
    app.include_router(licenses_api.router, prefix="/api/v1")
    app.dependency_overrides[licenses_api.get_license_service] = lambda: service
    return TestClient(app, raise_server_exceptions=False)


def _metadata(service: LicenseService, identifier: str) -> dict:
    return service.build_metadata(_resolve(service, identifier))


def _rdf_graph(payload: dict, serialization: str) -> Graph:
    serialized = json_to_rdf(payload, format=serialization)
    graph = Graph()
    graph.parse(
        data=serialized,
        format={
            "json-ld": "json-ld",
            "turtle": "turtle",
            "xml": "xml",
        }[serialization],
    )
    return graph


def _rdf_object_values(graph: Graph) -> set[str]:
    return {str(obj) for _, _, obj in graph}


def _rdf_semantic_values(graph: Graph) -> dict[str, set[str]]:
    values = _rdf_object_values(graph)
    return {
        "details": {value for value in values if "RDF/json" in value},
        "reference": {value for value in values if value == "https://example.org/reference"},
        "timestamp": {value for value in values if value in {"2026-09-03T00:00:00+00:00", "2026-09-03T00:00:00Z"}},
    }


def _valid_representation_descriptors() -> dict[str, dict]:
    return {
        "original": {
            "href": "https://curated.example.org/original",
            "relation": "original",
            "type": "original",
            "mediaType": "text/html",
            "provenance": "curator-reviewed",
        },
        "machine": {
            "href": "https://curated.example.org/machine",
            "relation": "machine",
            "type": "machine",
            "mediaType": "application/ld+json",
            "profile": "https://www.w3.org/ns/odrl/2/",
            "vocabulary": "https://www.w3.org/ns/odrl/2/",
            "provenance": "curator-reviewed",
        },
    }


def test_encoding_endpoint_redirects_to_curated_reference(tmp_path: Path):
    base = _seed_licenses_dir(
        tmp_path,
        [
            {
                "licenseId": "ENCODED",
                "name": "Encoded",
                "isDeprecatedLicenseId": False,
                "isOsiApproved": False,
                "uri": "https://example.test/api/v1/licenses/encoded",
                "detailsUrl": "https://spdx.org/licenses/ENCODED.json",
                "reference": "https://spdx.org/licenses/ENCODED.html",
            }
        ],
        {
            "ENCODED": {
                "licenseId": "ENCODED",
                "name": "Encoded",
                "licenseText": "x",
                "licenseTextHtml": "<p>x</p>",
                "standardLicenseTemplate": "x",
                "crossRef": [],
            }
        },
        {
            "ENCODED": {
                "encoding": {
                    "href": "https://example.org/encoding",
                    "relation": "encoding",
                    "type": "encoding",
                    "mediaType": "text/turtle",
                    "provenance": "curator-reviewed",
                }
            }
        },
    )
    service = LicenseService(base_dir=base)
    assert service.get_encoding_representation(_resolve(service, "ENCODED")) is not None
    response = _api_client(service).get("/api/v1/licenses/ENCODED/encoding", follow_redirects=False)
    assert response.status_code == 307
    assert response.headers["location"] == "https://example.org/encoding"


def test_legal_endpoint_redirects_to_curated_reference(tmp_path: Path):
    base = _seed_licenses_dir(
        tmp_path,
        [
            {
                "licenseId": "LEGAL",
                "name": "Legal",
                "isDeprecatedLicenseId": False,
                "isOsiApproved": False,
                "uri": "https://example.test/api/v1/licenses/legal",
                "detailsUrl": "https://spdx.org/licenses/LEGAL.json",
                "reference": "https://spdx.org/licenses/LEGAL.html",
            }
        ],
        {
            "LEGAL": {
                "licenseId": "LEGAL",
                "name": "Legal",
                "licenseText": "x",
                "licenseTextHtml": "<p>x</p>",
                "standardLicenseTemplate": "x",
                "crossRef": [],
            }
        },
        {
            "LEGAL": {
                "legal": {
                    "href": "https://example.org/legal",
                    "relation": "legal",
                    "type": "legal",
                    "mediaType": "text/html",
                    "provenance": "curator-reviewed",
                }
            }
        },
    )
    response = _api_client(LicenseService(base_dir=base)).get("/api/v1/licenses/LEGAL/legal", follow_redirects=False)
    assert response.status_code == 307
    assert response.headers["location"] == "https://example.org/legal"


def test_table6_maps_available_representations_to_local_endpoints(tmp_path: Path):
    base = _seed_licenses_dir(
        tmp_path,
        [
            {
                "licenseId": "TABLE6",
                "name": "Table6",
                "isDeprecatedLicenseId": False,
                "isOsiApproved": False,
                "uri": "https://example.test/api/v1/licenses/table6",
                "detailsUrl": "https://spdx.org/licenses/TABLE6.json",
                "reference": "https://spdx.org/licenses/TABLE6.html",
            }
        ],
        {
            "TABLE6": {
                "licenseId": "TABLE6",
                "name": "Table6",
                "licenseText": "x",
                "licenseTextHtml": "<p>x</p>",
                "standardLicenseTemplate": "x",
                "crossRef": [
                    {"url": "https://upstream.example.org/original", "type": "upstream"},
                    {"url": "https://upstream.example.org/machine", "type": "upstream"},
                    {"url": "https://upstream.example.org/encoding", "type": "upstream"},
                ],
            }
        },
        {
            "TABLE6": {
                "original": {
                    "href": "https://curated.example.org/original",
                    "relation": "original",
                    "type": "original",
                    "mediaType": "text/html",
                    "provenance": "curator-reviewed",
                },
                "machine": {
                    "href": "https://curated.example.org/machine",
                    "relation": "machine",
                    "type": "machine",
                    "mediaType": "application/ld+json",
                    "profile": "https://www.w3.org/ns/odrl/2/",
                    "vocabulary": "https://www.w3.org/ns/odrl/2/",
                    "provenance": "curator-reviewed",
                },
                "encoding": {
                    "href": "https://curated.example.org/encoding",
                    "relation": "encoding",
                    "type": "encoding",
                    "mediaType": "text/turtle",
                    "provenance": "curator-reviewed",
                },
            }
        },
    )
    service = LicenseService(base_dir=base)
    metadata = _metadata(service, "TABLE6")
    assert metadata["detailsURL"] == "/api/v1/licenses/TABLE6/json"
    assert metadata["representations"]["original"]["href"] == "https://curated.example.org/original"
    assert metadata["representations"]["machine"]["href"] == "https://curated.example.org/machine"
    assert metadata["representations"]["encoding"]["href"] == "https://curated.example.org/encoding"
    mappings = metadata["_links"]
    assert mappings["original"] == "/api/v1/licenses/TABLE6/original"
    assert mappings["machine"] == "/api/v1/licenses/TABLE6/machine"
    assert mappings["encoding"] == "/api/v1/licenses/TABLE6/encoding"
    generated = [ref for ref in metadata["crossRef"] if ref.get("type") != "upstream"]
    generated_by_type = {ref["type"]: ref["URL"] for ref in generated}
    assert generated_by_type == {
        "original": "/api/v1/licenses/TABLE6/original",
        "machine": "/api/v1/licenses/TABLE6/machine",
        "encoding": "/api/v1/licenses/TABLE6/encoding",
    }
    upstream = [ref for ref in metadata["crossRef"] if ref.get("type") == "upstream"]
    assert {ref["URL"] for ref in upstream} == {
        "https://upstream.example.org/original",
        "https://upstream.example.org/machine",
        "https://upstream.example.org/encoding",
    }


def test_table4_failure_is_independent_of_representation_success(tmp_path: Path):
    base = _seed_licenses_dir(
        tmp_path,
        [
            {
                "licenseId": "TABLE4",
                "name": "Table4",
                "isDeprecatedLicenseId": False,
                "isOsiApproved": False,
                "uri": "https://example.test/api/v1/licenses/table4",
                "detailsUrl": "https://spdx.org/licenses/TABLE4.json",
                "reference": "https://spdx.org/licenses/TABLE4.html",
            }
        ],
        {
            "TABLE4": {
                "licenseId": "TABLE4",
                "name": "Table4",
                "licenseText": "x",
                "standardLicenseTemplate": "x",
                "crossRef": [],
            }
        },
        {
            "TABLE4": {
                "original": {
                    "href": "https://curated.example.org/original",
                    "relation": "original",
                    "type": "original",
                    "mediaType": "text/html",
                    "provenance": "curator-reviewed",
                },
                "machine": {
                    "href": "https://curated.example.org/machine",
                    "relation": "machine",
                    "type": "machine",
                    "mediaType": "application/ld+json",
                    "profile": "https://www.w3.org/ns/odrl/2/",
                    "vocabulary": "https://www.w3.org/ns/odrl/2/",
                    "provenance": "curator-reviewed",
                },
            }
        },
    )
    service = LicenseService(base_dir=base)
    resolved = _resolve(service, "TABLE4")
    assert service.get_original_source(resolved) is not None
    assert service.get_machine_representation(resolved) is not None
    metadata = service.build_metadata(resolved)
    assert metadata["conformance"]["requirements"]["LFS-REQ-2-04"]["status"] == "passed"
    assert metadata["conformance"]["requirements"]["LFS-REQ-2-04"]["missing"] == []
    assert metadata["conformance"]["requirements"]["LFS-REQ-4-01"]["status"] == "failed"
    assert "licenseTextHtml" in metadata["conformance"]["requirements"]["LFS-REQ-4-01"]["missing"]


def test_representation_failure_is_independent_of_table4_success(tmp_path: Path):
    base = _seed_licenses_dir(
        tmp_path,
        [
            {
                "licenseId": "TABLE4B",
                "name": "Table4B",
                "isDeprecatedLicenseId": False,
                "isOsiApproved": False,
                "uri": "https://example.test/api/v1/licenses/table4b",
                "detailsUrl": "https://spdx.org/licenses/TABLE4B.json",
                "reference": "https://spdx.org/licenses/TABLE4B.html",
            }
        ],
        {
            "TABLE4B": {
                "licenseId": "TABLE4B",
                "name": "Table4B",
                "licenseText": "x",
                "licenseTextHtml": "<p>x</p>",
                "standardLicenseTemplate": "x",
                "crossRef": [],
            }
        },
        {
            "TABLE4B": {
                "original": {
                    "href": "https://curated.example.org/original",
                    "relation": "original",
                    "type": "original",
                    "mediaType": "text/html",
                    "provenance": "curator-reviewed",
                }
            }
        },
    )
    service = LicenseService(base_dir=base)
    resolved = _resolve(service, "TABLE4B")
    metadata = service.build_metadata(resolved)
    assert metadata["conformance"]["requirements"]["LFS-REQ-4-01"]["status"] == "passed"
    assert metadata["conformance"]["requirements"]["LFS-REQ-4-01"]["missing"] == []
    assert metadata["conformance"]["requirements"]["LFS-REQ-2-04"]["status"] == "failed"
    assert metadata["conformance"]["requirements"]["LFS-REQ-2-04"]["missing"] == ["machine"]


def test_table5_complete_upstream_crossref_passes_conformance(tmp_path: Path):
    base = _seed_licenses_dir(
        tmp_path,
        [
            {
                "licenseId": "TABLE5",
                "name": "Table5",
                "isDeprecatedLicenseId": False,
                "isOsiApproved": False,
                "uri": "https://example.test/api/v1/licenses/table5",
                "detailsUrl": "https://spdx.org/licenses/TABLE5.json",
                "reference": "https://spdx.org/licenses/TABLE5.html",
            }
        ],
        {
            "TABLE5": {
                "licenseId": "TABLE5",
                "name": "Table5",
                "licenseText": "x",
                "licenseTextHtml": "<p>x</p>",
                "standardLicenseTemplate": "x",
                "crossRef": [
                    {
                        "url": "https://example.org/reference",
                        "match": True,
                        "isValid": True,
                        "isLive": True,
                        "timestamp": "2026-09-03T00:00:00Z",
                        "isWayBackLink": False,
                        "order": 1,
                    }
                ],
            }
        },
        {"TABLE5": _valid_representation_descriptors()},
    )
    metadata = _metadata(LicenseService(base_dir=base), "TABLE5")
    assert "https://example.org/reference" in {ref["URL"] for ref in metadata["crossRef"]}
    assert metadata["conformance"]["requirements"]["LFS-REQ-4-01"]["status"] == "passed"
    assert metadata["conformance"]["requirements"]["LFS-REQ-4-01"]["missing"] == []
    assert metadata["conformance"]["requirements"]["LFS-REQ-4-01"].get("invalid", []) == []


def test_table5_missing_required_crossref_fields_are_reported(tmp_path: Path):
    base = _seed_licenses_dir(
        tmp_path,
        [
            {
                "licenseId": "TABLE5",
                "name": "Table5",
                "isDeprecatedLicenseId": False,
                "isOsiApproved": False,
                "uri": "https://example.test/api/v1/licenses/table5",
                "detailsUrl": "https://spdx.org/licenses/TABLE5.json",
                "reference": "https://spdx.org/licenses/TABLE5.html",
            }
        ],
        {
            "TABLE5": {
                "licenseId": "TABLE5",
                "name": "Table5",
                "licenseText": "x",
                "licenseTextHtml": "<p>x</p>",
                "standardLicenseTemplate": "x",
                "crossRef": [{"url": "https://example.org/reference"}],
            }
        },
        {"TABLE5": _valid_representation_descriptors()},
    )
    metadata = _metadata(LicenseService(base_dir=base), "TABLE5")
    requirement = metadata["conformance"]["requirements"]["LFS-REQ-4-01"]
    assert requirement["status"] == "failed"
    assert "crossRef[0].match" in requirement["missing"]
    assert "crossRef[0].isValid" in requirement["missing"]
    assert "crossRef[0].isLive" in requirement["missing"]
    assert "crossRef[0].timeStamp" in requirement["missing"]
    assert "crossRef[0].isWayBackLink" in requirement["missing"]
    assert "crossRef[0].order" in requirement["missing"]
    assert requirement.get("invalid", []) == []


@pytest.mark.parametrize(
    ("field", "value", "expected_path"),
    [
        ("match", "not-a-boolean", "crossRef[0].match"),
        ("isValid", "not-a-boolean", "crossRef[0].isValid"),
        ("isLive", "not-a-boolean", "crossRef[0].isLive"),
        ("timestamp", "not-a-timestamp", "crossRef[0].timeStamp"),
        ("isWayBackLink", "not-a-boolean", "crossRef[0].isWayBackLink"),
        ("order", "not-an-integer", "crossRef[0].order"),
        ("url", "http://insecure.example.org/reference", "crossRef[0].URL"),
    ],
)
def test_table5_invalid_crossref_field_is_reported(tmp_path: Path, field: str, value: str, expected_path: str):
    crossref = {
        "url": "https://example.org/reference",
        "match": True,
        "isValid": True,
        "isLive": True,
        "timestamp": "2026-09-03T00:00:00Z",
        "isWayBackLink": False,
        "order": 1,
    }
    crossref[field] = value
    base = _seed_licenses_dir(
        tmp_path,
        [
            {
                "licenseId": "TABLE5",
                "name": "Table5",
                "isDeprecatedLicenseId": False,
                "isOsiApproved": False,
                "uri": "https://example.test/api/v1/licenses/table5",
                "detailsUrl": "https://spdx.org/licenses/TABLE5.json",
                "reference": "https://spdx.org/licenses/TABLE5.html",
            }
        ],
        {
            "TABLE5": {
                "licenseId": "TABLE5",
                "name": "Table5",
                "licenseText": "x",
                "licenseTextHtml": "<p>x</p>",
                "standardLicenseTemplate": "x",
                "crossRef": [crossref],
            }
        },
        {"TABLE5": _valid_representation_descriptors()},
    )
    response = _api_client(LicenseService(base_dir=base)).get("/api/v1/licenses/TABLE5/json")
    assert response.status_code == 200
    requirement = response.json()["conformance"]["requirements"]["LFS-REQ-4-01"]
    assert requirement["status"] == "failed"
    assert expected_path in requirement["missing"] or expected_path in requirement.get("invalid", [])


def test_table5_crossref_without_url_is_reported_not_silently_discarded(tmp_path: Path):
    base = _seed_licenses_dir(
        tmp_path,
        [
            {
                "licenseId": "TABLE5",
                "name": "Table5",
                "isDeprecatedLicenseId": False,
                "isOsiApproved": False,
                "uri": "https://example.test/api/v1/licenses/table5",
                "detailsUrl": "https://spdx.org/licenses/TABLE5.json",
                "reference": "https://spdx.org/licenses/TABLE5.html",
            }
        ],
        {
            "TABLE5": {
                "licenseId": "TABLE5",
                "name": "Table5",
                "licenseText": "x",
                "licenseTextHtml": "<p>x</p>",
                "standardLicenseTemplate": "x",
                "crossRef": [
                    {
                        "match": True,
                        "isValid": True,
                        "isLive": True,
                        "timestamp": "2026-09-03T00:00:00Z",
                        "isWayBackLink": False,
                        "order": 1,
                    }
                ],
            }
        },
        {"TABLE5": _valid_representation_descriptors()},
    )
    response = _api_client(LicenseService(base_dir=base)).get("/api/v1/licenses/TABLE5/json")
    assert response.status_code == 200
    requirement = response.json()["conformance"]["requirements"]["LFS-REQ-4-01"]
    assert requirement["status"] == "failed"
    assert "crossRef[0].URL" in requirement["missing"]


def test_table5_conformance_paths_use_stable_crossref_indexes(tmp_path: Path):
    base = _seed_licenses_dir(
        tmp_path,
        [
            {
                "licenseId": "TABLE5",
                "name": "Table5",
                "isDeprecatedLicenseId": False,
                "isOsiApproved": False,
                "uri": "https://example.test/api/v1/licenses/table5",
                "detailsUrl": "https://spdx.org/licenses/TABLE5.json",
                "reference": "https://spdx.org/licenses/TABLE5.html",
            }
        ],
        {
            "TABLE5": {
                "licenseId": "TABLE5",
                "name": "Table5",
                "licenseText": "x",
                "licenseTextHtml": "<p>x</p>",
                "standardLicenseTemplate": "x",
                "crossRef": [
                    {
                        "url": "https://example.org/reference/0",
                        "match": True,
                        "isValid": True,
                        "isLive": True,
                        "timestamp": "2026-09-03T00:00:00Z",
                        "isWayBackLink": False,
                        "order": 1,
                    },
                    {
                        "url": "https://example.org/reference/1",
                        "match": True,
                        "isValid": True,
                        "timestamp": "2026-09-03T00:00:00Z",
                        "isWayBackLink": False,
                        "order": 1,
                    },
                    {
                        "url": "https://example.org/reference/2",
                        "match": True,
                        "isValid": True,
                        "isLive": True,
                        "timestamp": "2026-09-03T00:00:00Z",
                        "isWayBackLink": False,
                        "order": "bad",
                    },
                ],
            }
        },
        {"TABLE5": _valid_representation_descriptors()},
    )
    response = _api_client(LicenseService(base_dir=base)).get("/api/v1/licenses/TABLE5/json")
    assert response.status_code == 200
    requirement = response.json()["conformance"]["requirements"]["LFS-REQ-4-01"]
    assert "crossRef[1].isLive" in requirement["missing"]
    assert "crossRef[2].order" in requirement["missing"] or "crossRef[2].order" in requirement.get("invalid", [])


def test_pid_resolution_by_spdx_id_uuid_and_full_uri_is_stable(tmp_path: Path, monkeypatch):
    monkeypatch.setenv("URL_BASE", "https://example.test/api/v1/licenses")
    mit_uri_1 = generate_license_uri("MIT")
    mit_uri_2 = generate_license_uri("MIT")
    apache_uri = generate_license_uri("Apache-2.0")
    assert mit_uri_1 == mit_uri_2
    assert mit_uri_1 != apache_uri

    base = _seed_licenses_dir(
        tmp_path,
        [
            {
                "licenseId": "MIT",
                "name": "MIT",
                "isDeprecatedLicenseId": False,
                "isOsiApproved": True,
                "uri": mit_uri_1,
                "detailsUrl": "https://spdx.org/licenses/MIT.json",
                "reference": "https://spdx.org/licenses/MIT.html",
            },
            {
                "licenseId": "Apache-2.0",
                "name": "Apache-2.0",
                "isDeprecatedLicenseId": False,
                "isOsiApproved": True,
                "uri": apache_uri,
                "detailsUrl": "https://spdx.org/licenses/Apache-2.0.json",
                "reference": "https://spdx.org/licenses/Apache-2.0.html",
            },
        ],
        {
            "MIT": {
                "licenseId": "MIT",
                "name": "MIT",
                "licenseText": "x",
                "licenseTextHtml": "<p>x</p>",
                "standardLicenseTemplate": "x",
                "crossRef": [],
            },
            "Apache-2.0": {
                "licenseId": "Apache-2.0",
                "name": "Apache-2.0",
                "licenseText": "x",
                "licenseTextHtml": "<p>x</p>",
                "standardLicenseTemplate": "x",
                "crossRef": [],
            },
        },
        None,
    )
    service = LicenseService(base_dir=base)
    mit_uuid = mit_uri_1.rstrip("/").rsplit("/", 1)[-1]
    mit_by_id = _resolve(service, "MIT")
    mit_by_uuid = _resolve(service, mit_uuid)
    mit_by_uri = _resolve(service, mit_uri_1)
    assert mit_by_id.license_id == "MIT"
    assert mit_by_uuid.license_id == "MIT"
    assert mit_by_uri.license_id == "MIT"
    assert mit_by_id.uri == mit_uri_1
    assert mit_by_uuid.uri == mit_uri_1
    assert mit_by_uri.uri == mit_uri_1
    uuid_1 = build_resolving_uuid(authority_id="example-authority", requested_license_id="MIT", version="1.0")
    uuid_2 = build_resolving_uuid(authority_id="example-authority", requested_license_id="MIT", version="1.0")
    uuid_3 = build_resolving_uuid(authority_id="example-authority", requested_license_id="MIT", version="2.0")
    assert uuid_1 == uuid_2
    assert uuid_1 != uuid_3


@pytest.mark.parametrize("serialization", ["json-ld", "turtle", "xml"])
def test_rdf_preserves_upstream_spdx_field_names(serialization: str):
    payload = {
        "uri": "https://example.test/licenses/RDF",
        "licenseId": "RDF",
        "name": "RDF compatibility fixture",
        "detailsUrl": "https://example.test/licenses/RDF/json",
        "crossRef": [
            {
                "url": "https://example.org/reference",
                "timestamp": "2026-09-03T00:00:00Z",
                "match": True,
                "isValid": True,
                "isLive": True,
                "isWayBackLink": False,
                "order": 1,
            }
        ],
    }
    graph = _rdf_graph(payload, serialization)
    values = _rdf_semantic_values(graph)
    assert values["details"] == {"https://example.test/licenses/RDF/json"}
    assert values["reference"] == {"https://example.org/reference"}
    assert values["timestamp"] == {"2026-09-03T00:00:00+00:00"}


@pytest.mark.parametrize("serialization", ["json-ld", "turtle", "xml"])
def test_rdf_preserves_canonical_lfs_field_names(serialization: str):
    payload = {
        "uri": "https://example.test/licenses/RDF",
        "licenseId": "RDF",
        "name": "RDF compatibility fixture",
        "detailsURL": "https://example.test/licenses/RDF/json",
        "crossRef": [
            {
                "URL": "https://example.org/reference",
                "timeStamp": "2026-09-03T00:00:00Z",
                "match": True,
                "isValid": True,
                "isLive": True,
                "isWayBackLink": False,
                "order": 1,
            }
        ],
    }
    graph = _rdf_graph(payload, serialization)
    values = _rdf_semantic_values(graph)
    assert values["details"] == {"https://example.test/licenses/RDF/json"}
    assert values["reference"] == {"https://example.org/reference"}
    assert values["timestamp"] == {"2026-09-03T00:00:00+00:00"}


def test_rdf_canonical_and_upstream_names_produce_equivalent_semantic_values():
    upstream = _rdf_semantic_values(
        _rdf_graph(
            {
                "uri": "https://example.test/licenses/RDF",
                "licenseId": "RDF",
                "name": "RDF compatibility fixture",
                "detailsUrl": "https://example.test/licenses/RDF/json",
                "crossRef": [
                    {
                        "url": "https://example.org/reference",
                        "timestamp": "2026-09-03T00:00:00Z",
                        "match": True,
                        "isValid": True,
                        "isLive": True,
                        "isWayBackLink": False,
                        "order": 1,
                    }
                ],
            },
            "turtle",
        )
    )
    canonical = _rdf_semantic_values(
        _rdf_graph(
            {
                "uri": "https://example.test/licenses/RDF",
                "licenseId": "RDF",
                "name": "RDF compatibility fixture",
                "detailsURL": "https://example.test/licenses/RDF/json",
                "crossRef": [
                    {
                        "URL": "https://example.org/reference",
                        "timeStamp": "2026-09-03T00:00:00Z",
                        "match": True,
                        "isValid": True,
                        "isLive": True,
                        "isWayBackLink": False,
                        "order": 1,
                    }
                ],
            },
            "turtle",
        )
    )
    assert upstream == canonical


def test_spdx_collection_preserves_table4_fields_and_local_details_mapping(tmp_path: Path):
    base = _seed_licenses_dir(
        tmp_path,
        [
            {
                "referenceNumber": 123,
                "licenseId": "SPDX-COLLECTION",
                "name": "SPDX collection fixture",
                "detailsUrl": "https://spdx.org/licenses/SPDX-COLLECTION.json",
                "reference": "https://spdx.org/licenses/SPDX-COLLECTION.html",
                "isDeprecatedLicenseId": False,
                "seeAlso": ["https://example.org/collection"],
                "isOsiApproved": True,
                "isFsfLibre": True,
            }
        ],
        {
            "SPDX-COLLECTION": {
                "licenseId": "SPDX-COLLECTION",
                "name": "SPDX collection fixture",
                "licenseText": "x",
                "licenseTextHtml": "<p>x</p>",
                "standardLicenseTemplate": "x",
                "crossRef": [],
            }
        },
        {"SPDX-COLLECTION": _valid_representation_descriptors()},
    )
    service = LicenseService(base_dir=base)
    collection_payload = asyncio.run(service.get_all_licenses())
    assert collection_payload["licenseListVersion"] == "1"
    assert isinstance(collection_payload["licenses"], list)
    record = next(
        item
        for item in collection_payload["licenses"]
        if item["licenseId"] == "SPDX-COLLECTION"
    )
    assert record["uri"].startswith("https://")
    assert record["referenceNumber"] == 123
    assert record["licenseId"] == "SPDX-COLLECTION"
    assert record["name"] == "SPDX collection fixture"
    assert record["reference"] == "https://spdx.org/licenses/SPDX-COLLECTION.html"
    assert record["isDeprecatedLicenseId"] is False
    assert record["seeAlso"] == ["https://example.org/collection"]
    assert record["isOsiApproved"] is True
    assert record["isFsfLibre"] is True
    assert record["detailsURL"] == "/api/v1/licenses/SPDX-COLLECTION/json"
    assert record.get("spdxDetailsURL") == "https://spdx.org/licenses/SPDX-COLLECTION.json"


def test_spdx_detail_preserves_defined_spdx_fields_and_lfs_extensions(tmp_path: Path):
    base = _seed_licenses_dir(
        tmp_path,
        [
            {
                "referenceNumber": 456,
                "licenseId": "SPDX-DETAIL",
                "name": "SPDX detail fixture",
                "detailsUrl": "https://spdx.org/licenses/SPDX-DETAIL.json",
                "reference": "https://spdx.org/licenses/SPDX-DETAIL.html",
                "isDeprecatedLicenseId": False,
                "seeAlso": ["https://example.org/detail"],
                "isOsiApproved": True,
                "isFsfLibre": True,
            }
        ],
        {
            "SPDX-DETAIL": {
                "referenceNumber": 456,
                "licenseId": "SPDX-DETAIL",
                "name": "SPDX detail fixture",
                "licenseText": "Example text",
                "licenseTextHtml": "<p>Example text</p>",
                "standardLicenseTemplate": "Example template",
                "licenseComments": "Upstream SPDX comments",
                "standardLicenseHeader": "Example header",
                "standardLicenseHeaderTemplate": "Example header template",
                "isFsfLibre": True,
                "crossRef": [
                    {
                        "url": "https://example.org/reference",
                        "match": True,
                        "isValid": True,
                        "isLive": True,
                        "timestamp": "2026-09-03T00:00:00Z",
                        "isWayBackLink": False,
                        "order": 1,
                    }
                ],
            }
        },
        {"SPDX-DETAIL": _valid_representation_descriptors()},
    )
    response = _api_client(LicenseService(base_dir=base)).get("/api/v1/licenses/SPDX-DETAIL/json")
    assert response.status_code == 200
    payload = response.json()
    assert payload["referenceNumber"] == 456
    assert payload["licenseId"] == "SPDX-DETAIL"
    assert payload["name"] == "SPDX detail fixture"
    assert payload["reference"] == "https://spdx.org/licenses/SPDX-DETAIL.html"
    assert payload["isDeprecatedLicenseId"] is False
    assert payload["seeAlso"] == ["https://example.org/detail"]
    assert payload["isOsiApproved"] is True
    assert payload["licenseText"] == "Example text"
    assert payload["licenseTextHtml"] == "<p>Example text</p>"
    assert payload["standardLicenseTemplate"] == "Example template"
    assert payload["licenseComments"] == "Upstream SPDX comments"
    assert payload["standardLicenseHeader"] == "Example header"
    assert payload["standardLicenseHeaderTemplate"] == "Example header template"
    assert payload["isFsfLibre"] is True
    assert payload["crossRef"][0]["URL"] == "https://example.org/reference"
    assert payload["crossRef"][0]["match"] is True
    assert payload["crossRef"][0]["isValid"] is True
    assert payload["crossRef"][0]["isLive"] is True
    assert payload["crossRef"][0]["timeStamp"] == "2026-09-03T00:00:00+00:00"
    assert payload["crossRef"][0]["isWayBackLink"] is False
    assert payload["crossRef"][0]["order"] == 1
    assert payload["detailsURL"] == "/api/v1/licenses/SPDX-DETAIL/json"
    assert payload.get("spdxDetailsURL") == "https://spdx.org/licenses/SPDX-DETAIL.json"
    assert payload["uri"].startswith("https://")
    assert "conformance" in payload
    assert "representations" in payload
    assert "_links" in payload


def _assert_valid_jsonld_fixture(content: dict) -> None:
    graph = Graph()
    graph.parse(data=json.dumps(content), format="json-ld")
    assert len(graph) >= 1


def test_rel_valid_odrl_graph_matches_declared_vocabulary(tmp_path: Path):
    content = {
        "@context": {"odrl": "https://www.w3.org/ns/odrl/2/"},
        "@id": "https://example.org/policy/valid",
        "@type": "odrl:Policy",
        "odrl:permission": {"odrl:action": {"@id": "https://www.w3.org/ns/odrl/2/use"}},
    }
    _assert_valid_jsonld_fixture(content)
    base = _seed_licenses_dir(
        tmp_path,
        [
            {
                "licenseId": "REL-VALID",
                "name": "REL valid",
                "isDeprecatedLicenseId": False,
                "isOsiApproved": False,
                "uri": "https://example.test/api/v1/licenses/rel-valid",
                "detailsUrl": "https://spdx.org/licenses/REL-VALID.json",
                "reference": "https://spdx.org/licenses/REL-VALID.html",
            }
        ],
        {
            "REL-VALID": {
                "licenseId": "REL-VALID",
                "name": "REL valid",
                "licenseText": "x",
                "licenseTextHtml": "<p>x</p>",
                "standardLicenseTemplate": "x",
                "crossRef": [],
            }
        },
        {
            "REL-VALID": {
                "machine": {
                    "content": content,
                    "relation": "machine",
                    "type": "machine",
                    "mediaType": "application/ld+json",
                    "profile": "https://www.w3.org/ns/odrl/2/",
                    "vocabulary": "https://www.w3.org/ns/odrl/2/",
                    "provenance": "curator-reviewed",
                }
            }
        },
    )
    service = LicenseService(base_dir=base)
    resolved = _resolve(service, "REL-VALID")
    representation = service.get_machine_representation(resolved)
    assert representation is not None
    assert representation.profile == "https://www.w3.org/ns/odrl/2/"
    assert representation.vocabulary == "https://www.w3.org/ns/odrl/2/"
    assert representation.content == content


def test_rel_rejects_declared_odrl_when_graph_contains_no_odrl_terms(tmp_path: Path):
    content = {
        "@context": {"schema": "https://schema.org/"},
        "@id": "https://example.org/policy/false-declaration",
        "@type": "schema:CreativeWork",
        "schema:name": "Not an ODRL policy",
    }
    _assert_valid_jsonld_fixture(content)
    base = _seed_licenses_dir(
        tmp_path,
        [
            {
                "licenseId": "REL-FALSE",
                "name": "REL false",
                "isDeprecatedLicenseId": False,
                "isOsiApproved": False,
                "uri": "https://example.test/api/v1/licenses/rel-false",
                "detailsUrl": "https://spdx.org/licenses/REL-FALSE.json",
                "reference": "https://spdx.org/licenses/REL-FALSE.html",
            }
        ],
        {
            "REL-FALSE": {
                "licenseId": "REL-FALSE",
                "name": "REL false",
                "licenseText": "x",
                "licenseTextHtml": "<p>x</p>",
                "standardLicenseTemplate": "x",
                "crossRef": [],
            }
        },
        {
            "REL-FALSE": {
                "machine": {
                    "content": content,
                    "relation": "machine",
                    "type": "machine",
                    "mediaType": "application/ld+json",
                    "profile": "https://www.w3.org/ns/odrl/2/",
                    "vocabulary": "https://www.w3.org/ns/odrl/2/",
                    "provenance": "curator-reviewed",
                }
            }
        },
    )
    resolved = _resolve(LicenseService(base_dir=base), "REL-FALSE")
    assert LicenseService(base_dir=base).get_machine_representation(resolved) is None


def test_rel_rejects_unsupported_declared_vocabulary(tmp_path: Path):
    content = {
        "@context": {"schema": "https://schema.org/"},
        "@id": "https://example.org/policy/unsupported",
        "@type": "schema:CreativeWork",
        "schema:name": "Unsupported vocabulary",
    }
    _assert_valid_jsonld_fixture(content)
    base = _seed_licenses_dir(
        tmp_path,
        [
            {
                "licenseId": "REL-UNSUPPORTED",
                "name": "REL unsupported",
                "isDeprecatedLicenseId": False,
                "isOsiApproved": False,
                "uri": "https://example.test/api/v1/licenses/rel-unsupported",
                "detailsUrl": "https://spdx.org/licenses/REL-UNSUPPORTED.json",
                "reference": "https://spdx.org/licenses/REL-UNSUPPORTED.html",
            }
        ],
        {
            "REL-UNSUPPORTED": {
                "licenseId": "REL-UNSUPPORTED",
                "name": "REL unsupported",
                "licenseText": "x",
                "licenseTextHtml": "<p>x</p>",
                "standardLicenseTemplate": "x",
                "crossRef": [],
            }
        },
        {
            "REL-UNSUPPORTED": {
                "machine": {
                    "content": content,
                    "relation": "machine",
                    "type": "machine",
                    "mediaType": "application/ld+json",
                    "profile": "https://unsupported.example.org/rights/",
                    "vocabulary": "https://unsupported.example.org/rights/",
                    "provenance": "curator-reviewed",
                }
            }
        },
    )
    resolved = _resolve(LicenseService(base_dir=base), "REL-UNSUPPORTED")
    assert LicenseService(base_dir=base).get_machine_representation(resolved) is None


def test_rel_mapping_retains_original_profile_and_mapping_provenance(tmp_path: Path):
    content = {
        "@context": {"openrel": "https://openrel.org/ns#"},
        "@id": "https://example.org/policy/openrel",
        "@type": "openrel:Policy",
        "openrel:constraint": {"openrel:leftOperand": "openrel:purpose"},
    }
    _assert_valid_jsonld_fixture(content)
    base = _seed_licenses_dir(
        tmp_path,
        [
            {
                "licenseId": "REL-MAP",
                "name": "REL map",
                "isDeprecatedLicenseId": False,
                "isOsiApproved": False,
                "uri": "https://example.test/api/v1/licenses/rel-map",
                "detailsUrl": "https://spdx.org/licenses/REL-MAP.json",
                "reference": "https://spdx.org/licenses/REL-MAP.html",
            }
        ],
        {
            "REL-MAP": {
                "licenseId": "REL-MAP",
                "name": "REL map",
                "licenseText": "x",
                "licenseTextHtml": "<p>x</p>",
                "standardLicenseTemplate": "x",
                "crossRef": [],
            }
        },
        {
            "REL-MAP": {
                "machine": {
                    "content": content,
                    "relation": "machine",
                    "type": "machine",
                    "mediaType": "application/ld+json",
                    "profile": "https://openrel.org/ns#",
                    "vocabulary": "https://openrel.org/ns#",
                    "originalProfile": "https://www.w3.org/ns/odrl/2/",
                    "mappingProfile": "https://example.org/mappings/odrl-to-openrel/v1",
                    "mappingProvenance": "curator-reviewed",
                    "provenance": "curator-reviewed",
                }
            }
        },
    )
    metadata = _metadata(LicenseService(base_dir=base), "REL-MAP")
    machine = metadata["representations"]["machine"]
    assert machine["profile"] == "https://openrel.org/ns#"
    assert machine["vocabulary"] == "https://openrel.org/ns#"
    assert machine["originalProfile"] == "https://www.w3.org/ns/odrl/2/"
    assert machine["mappingProfile"] == "https://example.org/mappings/odrl-to-openrel/v1"
    assert machine["mappingProvenance"] == "curator-reviewed"
    assert machine["provenance"] == "curator-reviewed"
