from __future__ import annotations

import json
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from src.license_facade_service.api.v1 import licenses as licenses_api
from src.license_facade_service.main import create_app
from src.license_facade_service.services.auth import AuthService
from src.license_facade_service.services.licenses import LicenseService, SPDXClient

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


@pytest.fixture
def base_app(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    _seed_snapshot(tmp_path)
    monkeypatch.setenv("BASE_DIR", str(REPO_ROOT))
    monkeypatch.setenv("URL_BASE", "https://example.test/api/v1/licenses")
    monkeypatch.setenv("FUSEKI_ENABLE", "false")
    monkeypatch.setenv("RELOAD_ENABLE", "false")
    service = LicenseService(base_dir=tmp_path, spdx_client=_StaticSpdx())
    licenses_api._license_service = service
    licenses_api._auth_service = AuthService()
    app = create_app()
    return TestClient(app)


def test_federation_disabled_mode_preserves_existing_operation(base_app: TestClient):
    ready = base_app.get("/api/v1/ready")
    assert ready.status_code == 200
    body = ready.json()
    assert body["status"] == "ready"
    assert body["federation"]["enabled"] is False
    assert base_app.get("/.well-known/jwks.json").status_code == 404


def test_federation_enabled_missing_config_fails_readiness(base_app: TestClient, monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setenv("FEDERATION_ENABLED", "true")
    app = create_app()
    with TestClient(app) as client:
        ready = client.get("/api/v1/ready")
        assert ready.status_code == 200
        payload = ready.json()
        assert payload["status"] == "not_ready"
        assert payload["federation"]["enabled"] is True
        assert any("FEDERATION_NODE_ID" in msg for msg in payload["federation"]["errors"])


def test_federation_enabled_without_signing_key_reports_readiness_error(
    base_app: TestClient, monkeypatch: pytest.MonkeyPatch
):
    monkeypatch.setenv("FEDERATION_ENABLED", "true")
    monkeypatch.setenv("FEDERATION_NODE_ID", "de305d54-75b4-431b-adb2-eb6b9e546014")
    monkeypatch.setenv("FEDERATION_PUBLIC_BASE_URL", "https://node.example.org")
    monkeypatch.setenv("FEDERATION_NODE_NAME", "EDEN Node")
    monkeypatch.setenv("FEDERATION_OPERATOR", "EDEN Operator")
    monkeypatch.setenv("FEDERATION_DATABASE_URL", "postgresql+psycopg://invalid")
    app = create_app()
    with TestClient(app) as client:
        ready = client.get("/api/v1/ready")
        assert ready.status_code == 200
        payload = ready.json()
        assert payload["status"] == "not_ready"
        assert any("SIGNING_KEY" in msg for msg in payload["federation"]["errors"])
