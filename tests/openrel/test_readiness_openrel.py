from __future__ import annotations

from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from src.license_facade_service.main import create_app
from src.license_facade_service.api.v1 import licenses as licenses_api


def _set_common_env(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("BASE_DIR", str(Path(__file__).resolve().parents[2]))
    monkeypatch.setenv("URL_BASE", "https://example.test/api/v1/licenses")
    monkeypatch.setenv("FUSEKI_ENABLE", "false")
    monkeypatch.setenv("CORS_ORIGINS", "https://example.org")
    monkeypatch.setenv("CORS_ALLOW_CREDENTIALS", "false")
    monkeypatch.setenv("RELOAD_ENABLE", "false")


def test_ready_openrel_disabled_state(monkeypatch: pytest.MonkeyPatch):
    _set_common_env(monkeypatch)
    monkeypatch.setenv("OPENREL_ENABLED", "false")
    app = create_app()
    with TestClient(app) as client:
        response = client.get("/api/v1/ready")
    assert response.status_code == 200
    payload = response.json()
    assert payload["openrel"] == {"enabled": False, "ready": None, "errors": []}


def test_ready_openrel_enabled_and_valid_configuration(monkeypatch: pytest.MonkeyPatch):
    _set_common_env(monkeypatch)
    monkeypatch.setenv("OPENREL_ENABLED", "true")
    monkeypatch.setenv("OPENREL_BASE_URL", "https://provider.example/openrel/api/v0.4")
    monkeypatch.setenv("OPENREL_ALLOWED_PORTS", "443")
    app = create_app()
    with TestClient(app) as client:
        response = client.get("/api/v1/ready")
    assert response.status_code == 200
    payload = response.json()
    assert payload["openrel"] == {"enabled": True, "ready": True, "errors": []}


def test_ready_openrel_enabled_invalid_configuration_is_sanitized(monkeypatch: pytest.MonkeyPatch):
    _set_common_env(monkeypatch)
    monkeypatch.setenv("OPENREL_ENABLED", "true")
    monkeypatch.setenv("OPENREL_BASE_URL", "https://provider.example:99999/openrel/api/v0.4")
    monkeypatch.setenv("OPENREL_ALLOWED_PORTS", "443")
    app = create_app()
    with TestClient(app) as client:
        response = client.get("/api/v1/ready")
        health = client.get("/api/v1/health")

    assert response.status_code == 200
    payload = response.json()
    assert payload["status"] == "ready"
    assert payload["openrel"] == {"enabled": True, "ready": False, "errors": ["OpenREL configuration is invalid."]}
    assert "provider.example" not in response.text
    assert health.status_code == 200
    assert health.json()["status"] == "alive"


def test_ready_core_dependencies_can_still_be_not_ready(monkeypatch: pytest.MonkeyPatch):
    _set_common_env(monkeypatch)
    monkeypatch.setenv("OPENREL_ENABLED", "true")
    monkeypatch.setenv("OPENREL_BASE_URL", "https://provider.example:99999/openrel/api/v0.4")
    monkeypatch.setenv("OPENREL_ALLOWED_PORTS", "443")

    class NotReadyLicenseService:
        async def ensure_cache_updated(self) -> None:
            return None

        def health_can_resolve(self) -> bool:
            return False

    previous = licenses_api._license_service
    licenses_api._license_service = NotReadyLicenseService()
    try:
        app = create_app()
        with TestClient(app) as client:
            response = client.get("/api/v1/ready")
    finally:
        licenses_api._license_service = previous

    assert response.status_code == 200
    payload = response.json()
    assert payload["licenses"]["ready"] is False
    assert payload["openrel"]["enabled"] is True
    assert payload["status"] == "not_ready"


def test_ready_does_not_call_openrel_dns_or_http(monkeypatch: pytest.MonkeyPatch):
    _set_common_env(monkeypatch)
    monkeypatch.setenv("OPENREL_ENABLED", "true")
    monkeypatch.setenv("OPENREL_BASE_URL", "https://provider.example/openrel/api/v0.4")
    monkeypatch.setenv("OPENREL_ALLOWED_PORTS", "443")

    class FailingOpenRelClient:
        instances: list["FailingOpenRelClient"] = []

        def __init__(self, *_args, **_kwargs):
            self.closed = False
            self.called = False
            FailingOpenRelClient.instances.append(self)

        async def aclose(self) -> None:
            self.closed = True

        async def list_resources(self, family: str, *, prefix: str | None = None):
            self.called = True
            raise AssertionError("readiness must not call OpenREL list_resources")

        async def get_resource(self, family: str, identifier: str, *, prefix: str | None = None):
            self.called = True
            raise AssertionError("readiness must not call OpenREL get_resource")

        async def list_mappings(self, *, prefix: str | None = None):
            self.called = True
            raise AssertionError("readiness must not call OpenREL list_mappings")

    monkeypatch.setattr("src.license_facade_service.main.OpenRelClient", FailingOpenRelClient)
    app = create_app()
    with TestClient(app) as client:
        response = client.get("/api/v1/ready")
        assert response.status_code == 200
        assert len(FailingOpenRelClient.instances) == 1
        assert FailingOpenRelClient.instances[0].called is False

    assert FailingOpenRelClient.instances[0].closed is True


def test_ready_openapi_schema_documents_openrel_component(app_client):
    client, *_ = app_client
    openapi = client.get("/openapi.json").json()
    ready_get = openapi["paths"]["/api/v1/ready"]["get"]
    ready_schema_ref = ready_get["responses"]["200"]["content"]["application/json"]["schema"]["$ref"]
    ready_schema_name = ready_schema_ref.rsplit("/", 1)[-1]
    ready_schema = openapi["components"]["schemas"][ready_schema_name]
    assert "openrel" in ready_schema["properties"]
    openrel_field = ready_schema["properties"]["openrel"]
    assert "configuration readiness" in openrel_field["description"].lower()
