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
            "lfsRepresentations": {
                "machine": {
                    "content": {"@context": "https://www.w3.org/ns/odrl.jsonld"},
                    "mediaType": "application/ld+json",
                    "profile": "https://www.w3.org/ns/odrl/2/",
                    "vocabulary": "https://www.w3.org/ns/odrl/2/",
                }
            },
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
    client = TestClient(app)
    mit_uuid = str(UUID(licenses_payload["licenses"][0]["uri"].rsplit("/", 1)[-1]))
    return client, service, licenses_payload, details_payload, mit_uuid
