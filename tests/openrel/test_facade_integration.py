from __future__ import annotations

import asyncio
import json
from pathlib import Path
from typing import Any
from urllib.parse import quote

import httpx
import pytest
from fastapi.testclient import TestClient

from src.license_facade_service.api import openrel as openrel_api
from src.license_facade_service.config.openrel import OpenRelSettings
from src.license_facade_service.infra.fuseki_client import FusekiClient
from src.license_facade_service.main import create_app
from src.license_facade_service.openrel.client import OpenRelClient


def _set_common_env(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("BASE_DIR", str(Path(__file__).resolve().parents[2]))
    monkeypatch.setenv("URL_BASE", "https://example.test/api/v1/licenses")
    monkeypatch.setenv("FUSEKI_ENABLE", "false")
    monkeypatch.setenv("OPENREL_ENABLED", "true")
    monkeypatch.setenv("OPENREL_BASE_URL", "https://provider.example/openrel/api/v0.4")
    monkeypatch.setenv("OPENREL_ALLOWED_PORTS", "443")
    monkeypatch.setenv("OPENREL_RETRY_ATTEMPTS", "1")
    monkeypatch.setenv("OPENREL_TOTAL_TIMEOUT_SECONDS", "5")
    monkeypatch.setenv("OPENREL_RETRY_MAX_SECONDS", "2")


def test_openrel_offline_end_to_end_with_real_client(monkeypatch: pytest.MonkeyPatch):
    _set_common_env(monkeypatch)
    requests: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        requests.append(request)
        path = request.url.path
        if path.endswith("/actions"):
            if request.url.params.get("prefix") == "odrl":
                return httpx.Response(
                    200,
                    headers={"Content-Type": "application/json"},
                    content=json.dumps([{"iri": "urn:action:use", "providerOnly": "x"}]).encode("utf-8"),
                )
            return httpx.Response(
                200,
                headers={"Content-Type": "application/json"},
                content=json.dumps([{"iri": "urn:action:read", "label": "Read", "providerOnly": "x"}]).encode("utf-8"),
            )
        if "/actions/" in path:
            return httpx.Response(
                200,
                headers={"Content-Type": "application/json"},
                content=json.dumps({"iri": "urn:action:detail", "definition": "Detail", "providerOnly": "x"}).encode("utf-8"),
            )
        if path.endswith("/mappings"):
            return httpx.Response(
                200,
                headers={"Content-Type": "application/json"},
                content=json.dumps([{"iri": "urn:mapping:one", "providerOnly": "x"}]).encode("utf-8"),
            )
        return httpx.Response(404, headers={"Content-Type": "application/json"}, content=b"{}")

    async def resolver(_hostname: str, _port: int) -> list[str]:
        return ["93.184.216.34"]

    settings = OpenRelSettings.from_env()
    transport_client = httpx.AsyncClient(transport=httpx.MockTransport(handler), follow_redirects=False)
    openrel_client = OpenRelClient(settings, http_client=transport_client, resolver=resolver)

    async def _forbid_fuseki_write(*_args: Any, **_kwargs: Any) -> bool:
        raise AssertionError("OpenREL GET must not trigger Fuseki writes")

    monkeypatch.setattr(FusekiClient, "upload_rdf", _forbid_fuseki_write)
    monkeypatch.setattr(FusekiClient, "replace_graph", _forbid_fuseki_write)
    monkeypatch.setattr(FusekiClient, "create_dataset", _forbid_fuseki_write)

    app = create_app()
    app.dependency_overrides[openrel_api.get_openrel_client] = lambda: openrel_client

    try:
        with TestClient(app) as client:
            list_response = client.get("/openrel/api/v0.4/actions")
            assert list_response.status_code == 200
            assert list_response.json() == [{"iri": "urn:action:read", "label": "Read"}]

            prefixed_response = client.get("/openrel/api/v0.4/actions", params={"prefix": "odrl"})
            assert prefixed_response.status_code == 200
            assert prefixed_response.json() == [{"iri": "urn:action:use"}]

            encoded_id = quote("urn:action:read/with space?x#y", safe="")
            detail_response = client.get(f"/openrel/api/v0.4/actions/{encoded_id}")
            assert detail_response.status_code == 200
            assert detail_response.json() == {"iri": "urn:action:detail", "definition": "Detail"}

            mappings_response = client.get("/openrel/api/v0.4/mappings")
            assert mappings_response.status_code == 200
            assert mappings_response.json() == [{"iri": "urn:mapping:one"}]

            license_response = client.get("/api/v1/licenses/MIT")
            assert license_response.status_code == 200
    finally:
        app.dependency_overrides.pop(openrel_api.get_openrel_client, None)
        asyncio.run(transport_client.aclose())

    assert any(req.url.params.get("prefix") == "odrl" for req in requests if req.url.path.endswith("/actions"))


def test_openrel_offline_end_to_end_malformed_payload_maps_to_problem(monkeypatch: pytest.MonkeyPatch):
    _set_common_env(monkeypatch)

    def malformed_handler(_request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, headers={"Content-Type": "application/json"}, content=b'{"iri":"x","iri":"y"}')

    async def resolver(_hostname: str, _port: int) -> list[str]:
        return ["93.184.216.34"]

    settings = OpenRelSettings.from_env()
    transport_client = httpx.AsyncClient(transport=httpx.MockTransport(malformed_handler), follow_redirects=False)
    openrel_client = OpenRelClient(settings, http_client=transport_client, resolver=resolver)
    app = create_app()
    app.dependency_overrides[openrel_api.get_openrel_client] = lambda: openrel_client
    try:
        with TestClient(app) as client:
            response = client.get("/openrel/api/v0.4/actions")
            assert response.status_code == 502
            assert response.headers["content-type"].startswith("application/problem+json")
            assert response.json()["title"] == "OpenREL JSON Duplicate Key"
    finally:
        app.dependency_overrides.pop(openrel_api.get_openrel_client, None)
        asyncio.run(transport_client.aclose())


def test_openrel_offline_end_to_end_provider_unavailable_maps_to_problem(monkeypatch: pytest.MonkeyPatch):
    _set_common_env(monkeypatch)

    def unavailable_handler(_request: httpx.Request) -> httpx.Response:
        return httpx.Response(503, headers={"Content-Type": "application/json"}, content=b"{}")

    async def resolver(_hostname: str, _port: int) -> list[str]:
        return ["93.184.216.34"]

    settings = OpenRelSettings.from_env()
    transport_client = httpx.AsyncClient(transport=httpx.MockTransport(unavailable_handler), follow_redirects=False)
    openrel_client = OpenRelClient(settings, http_client=transport_client, resolver=resolver)
    app = create_app()
    app.dependency_overrides[openrel_api.get_openrel_client] = lambda: openrel_client
    try:
        with TestClient(app) as client:
            response = client.get("/openrel/api/v0.4/actions")
            assert response.status_code == 503
            assert response.headers["content-type"].startswith("application/problem+json")
            assert response.json()["title"] == "OpenREL Provider Unavailable"
            assert client.get("/api/v1/licenses/MIT").status_code == 200
    finally:
        app.dependency_overrides.pop(openrel_api.get_openrel_client, None)
        asyncio.run(transport_client.aclose())
