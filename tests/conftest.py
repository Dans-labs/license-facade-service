from __future__ import annotations

import json
import sys
from pathlib import Path
from uuid import UUID

import pytest
from fastapi.testclient import TestClient

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from src.license_facade_service.api.v1 import licenses as licenses_api
from src.license_facade_service.main import create_app
from src.license_facade_service.services.auth import AuthService
from src.license_facade_service.services.licenses import LicenseService, SPDXClient, generate_license_uri


class FakeSpdxClient(SPDXClient):
    def __init__(self, licenses_payload: dict, details_payload: dict[str, dict], fail_refresh: bool = False):
        super().__init__(timeout=0.1, retries=1)
        self.licenses_payload = licenses_payload
        self.details_payload = details_payload
        self.fail_refresh = fail_refresh

    async def fetch_license_list(self) -> dict:
        if self.fail_refresh:
            raise RuntimeError("SPDX offline")
        return self.licenses_payload

    async def fetch_license_details(self, license_id: str) -> dict:
        if self.fail_refresh:
            raise RuntimeError("SPDX offline")
        payload = self.details_payload.get(license_id)
        if payload is None:
            raise RuntimeError("details missing")
        return payload


def _seed_snapshot(base_dir: Path) -> tuple[dict, dict[str, dict]]:
    licenses = {
        "licenseListVersion": "3.26",
        "licenses": [
            {
                "licenseId": "MIT",
                "name": "MIT License",
                "isDeprecatedLicenseId": False,
                "isOsiApproved": True,
                "seeAlso": ["https://opensource.org/licenses/MIT"],
                "detailsUrl": "https://spdx.org/licenses/MIT.json",
                "reference": "https://spdx.org/licenses/MIT.html",
                "uri": generate_license_uri("MIT"),
                "referenceNumber": "1",
            },
            {
                "licenseId": "Apache-2.0",
                "name": "Apache License 2.0",
                "isDeprecatedLicenseId": False,
                "isOsiApproved": True,
                "seeAlso": ["https://www.apache.org/licenses/LICENSE-2.0"],
                "detailsUrl": "https://spdx.org/licenses/Apache-2.0.json",
                "reference": "https://spdx.org/licenses/Apache-2.0.html",
                "uri": generate_license_uri("Apache-2.0"),
                "aliases": ["Apache2"],
                "referenceNumber": "2",
            },
            {
                "licenseId": "CC-BY-4.0",
                "name": "Creative Commons Attribution 4.0 International",
                "isDeprecatedLicenseId": False,
                "isOsiApproved": False,
                "seeAlso": ["https://creativecommons.org/licenses/by/4.0/"],
                "detailsUrl": "https://spdx.org/licenses/CC-BY-4.0.json",
                "reference": "https://spdx.org/licenses/CC-BY-4.0.html",
                "uri": generate_license_uri("CC-BY-4.0"),
                "referenceNumber": "3",
            },
            {
                "licenseId": "Legacy-No-Original",
                "name": "Legacy No Original License",
                "isDeprecatedLicenseId": True,
                "isOsiApproved": False,
                "seeAlso": ["https://example.org/licenses/legacy-no-original"],
                "detailsUrl": "https://spdx.org/licenses/Legacy-No-Original.json",
                "reference": "https://spdx.org/licenses/Legacy-No-Original.html",
                "uri": generate_license_uri("Legacy-No-Original"),
                "referenceNumber": "4",
            },
            {
                "licenseId": "Bad-REL",
                "name": "Bad REL License",
                "isDeprecatedLicenseId": False,
                "isOsiApproved": False,
                "seeAlso": ["https://example.org/licenses/bad-rel"],
                "detailsUrl": "https://spdx.org/licenses/Bad-REL.json",
                "reference": "https://spdx.org/licenses/Bad-REL.html",
                "uri": generate_license_uri("Bad-REL"),
                "referenceNumber": "5",
            },
        ],
    }
    details = {
        "MIT": {
            "licenseId": "MIT",
            "name": "MIT License",
            "licenseText": "MIT text",
            "licenseTextHtml": "<p>MIT text</p>",
            "standardLicenseTemplate": "MIT template",
            "crossRef": [{"url": "https://opensource.org/licenses/MIT"}],
        },
        "Apache-2.0": {
            "licenseId": "Apache-2.0",
            "name": "Apache License 2.0",
            "licenseText": "Apache text",
            "licenseTextHtml": "<p>Apache text</p>",
            "standardLicenseTemplate": "Apache template",
            "crossRef": [{"url": "https://www.apache.org/licenses/LICENSE-2.0"}],
        },
        "CC-BY-4.0": {
            "licenseId": "CC-BY-4.0",
            "name": "Creative Commons Attribution 4.0 International",
            "licenseText": "CC text",
            "licenseTextHtml": "<p>CC text</p>",
            "standardLicenseTemplate": "CC template",
            "crossRef": [{"url": "https://creativecommons.org/licenses/by/4.0/"}],
        },
        "Legacy-No-Original": {
            "licenseId": "Legacy-No-Original",
            "name": "Legacy No Original License",
            "licenseText": "Legacy text",
            "licenseTextHtml": "<p>Legacy text</p>",
            "standardLicenseTemplate": "Legacy template",
            "crossRef": [{"url": "https://example.org/licenses/legacy-no-original"}],
        },
        "Bad-REL": {
            "licenseId": "Bad-REL",
            "name": "Bad REL License",
            "licenseText": "Bad REL text",
            "licenseTextHtml": "<p>Bad REL text</p>",
            "standardLicenseTemplate": "Bad template",
            "crossRef": [{"url": "https://example.org/licenses/bad-rel"}],
        },
    }

    snapshot = base_dir / "resources" / "data" / "licenses" / "snapshots" / "seed"
    snapshot.mkdir(parents=True, exist_ok=True)
    (snapshot / "licenses_list.json").write_text(json.dumps(licenses), encoding="utf-8")
    (snapshot / "version.json").write_text(
        json.dumps(
            {
                "licenseListVersion": "3.26",
                "licenseCount": 2,
                "lastUpdated": "2026-08-03T00:00:00Z",
            }
        ),
        encoding="utf-8",
    )
    for key, payload in details.items():
        (snapshot / f"{key}.json").write_text(json.dumps(payload), encoding="utf-8")
    current = base_dir / "resources" / "data" / "licenses" / "current_snapshot.json"
    current.parent.mkdir(parents=True, exist_ok=True)
    current.write_text(json.dumps({"snapshot": "seed"}), encoding="utf-8")
    curated = {
        "MIT": {
            "original": {
                "href": "https://opensource.org/licenses/MIT",
                "relation": "original",
                "type": "original",
                "mediaType": "text/html",
                "authority": "Open Source Initiative",
                "curator": "OSI",
                "provenance": "curated",
                "source": "https://opensource.org/licenses/MIT",
            }
        },
        "Apache-2.0": {
            "original": {
                "href": "https://www.apache.org/licenses/LICENSE-2.0",
                "relation": "original",
                "type": "original",
                "mediaType": "text/html",
                "authority": "Apache Software Foundation",
                "curator": "Apache",
                "provenance": "curated",
                "source": "https://www.apache.org/licenses/LICENSE-2.0",
            },
            "machine": {
                "content": {
                    "@context": "https://www.w3.org/ns/odrl.jsonld",
                    "@type": "odrl:Policy",
                    "odrl:permission": [],
                },
                "mediaType": "application/ld+json",
                "profile": "https://www.w3.org/ns/odrl/2/",
                "vocabulary": "https://www.w3.org/ns/odrl/2/",
                "version": "1.0",
                "digest": "sha256:apache-odrl",
                "provenance": "curated",
                "source": "https://example.org/curated/apache-odrl",
            },
        },
        "CC-BY-4.0": {
            "original": {
                "href": "https://creativecommons.org/licenses/by/4.0/",
                "relation": "original",
                "type": "original",
                "mediaType": "text/html",
                "authority": "Creative Commons",
                "curator": "Creative Commons",
                "provenance": "curated",
                "source": "https://creativecommons.org/licenses/by/4.0/",
            },
            "machine": {
                "content": {
                    "@context": "http://creativecommons.org/ns#",
                    "@type": "cc:License",
                    "cc:permits": [],
                },
                "mediaType": "application/ld+json",
                "profile": "http://creativecommons.org/ns#",
                "vocabulary": "http://creativecommons.org/ns#",
                "version": "1.0",
                "digest": "sha256:ccrel",
                "provenance": "curated",
                "source": "https://example.org/curated/ccrel",
            },
        },
        "Legacy-No-Original": {
            "machine": {
                "content": {
                    "@context": "https://www.w3.org/ns/odrl.jsonld",
                    "@type": "odrl:Policy",
                },
                "mediaType": "application/ld+json",
                "profile": "https://www.w3.org/ns/odrl/2/",
                "vocabulary": "https://www.w3.org/ns/odrl/2/",
                "version": "1.0",
                "digest": "sha256:legacy",
                "provenance": "curated",
                "source": "https://example.org/curated/legacy",
            },
        },
        "Bad-REL": {
            "original": {
                "href": "https://example.org/licenses/bad-rel",
                "relation": "original",
                "type": "original",
                "mediaType": "text/html",
                "authority": "Example",
                "curator": "Example",
                "provenance": "curated",
                "source": "https://example.org/licenses/bad-rel",
            },
            "machine": {
                "content": "{not-json",
                "mediaType": "application/ld+json",
                "profile": "https://example.org/unknown-rel/",
                "vocabulary": "https://example.org/unknown-rel/",
                "version": "1.0",
                "digest": "sha256:bad",
                "provenance": "curated",
                "source": "https://example.org/curated/bad-rel",
            },
        },
    }
    (base_dir / "resources" / "data" / "licenses" / "curated_representations.json").write_text(
        json.dumps(curated),
        encoding="utf-8",
    )
    return licenses, details


@pytest.fixture
def app_client(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setenv("BASE_DIR", str(Path(__file__).resolve().parents[1]))
    monkeypatch.setenv("URL_BASE", "https://example.test/api/v1/licenses")
    monkeypatch.setenv("FUSEKI_ENABLE", "false")
    monkeypatch.setenv("CORS_ORIGINS", "https://example.org")
    monkeypatch.setenv("CORS_ALLOW_CREDENTIALS", "false")
    monkeypatch.setenv("LFS_ADMIN_TOKEN", "admin-token")
    monkeypatch.setenv("LFS_CURATOR_TOKEN", "curator-token")
    monkeypatch.setenv("RELOAD_ENABLE", "false")

    licenses_payload, details_payload = _seed_snapshot(tmp_path)
    service = LicenseService(
        base_dir=tmp_path,
        spdx_client=FakeSpdxClient(licenses_payload, details_payload),
    )

    licenses_api._license_service = service
    licenses_api._auth_service = AuthService()
    app = create_app()
    mit_uuid = str(UUID(licenses_payload["licenses"][0]["uri"].rsplit("/", 1)[-1]))
    with TestClient(app) as client:
        yield client, service, licenses_payload, details_payload, mit_uuid
