from __future__ import annotations

import asyncio
import json
from contextlib import contextmanager
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any
from urllib.parse import quote

import pytest
from fastapi.testclient import TestClient
from starlette.requests import Request

from src.license_facade_service.api import openrel as openrel_api
from src.license_facade_service.main import create_app
from src.license_facade_service.openrel.client import OpenRelClient, OpenRelClientError, OpenRelErrorCode


EXPECTED_OPENREL_ROUTES = {
    ("get", "/openrel/api/v0.4/actions"): "openrel_list_actions",
    ("get", "/openrel/api/v0.4/actions/{id}"): "openrel_get_action",
    ("get", "/openrel/api/v0.4/constraints"): "openrel_list_constraints",
    ("get", "/openrel/api/v0.4/constraints/{id}"): "openrel_get_constraint",
    ("get", "/openrel/api/v0.4/leftoperands"): "openrel_list_left_operands",
    ("get", "/openrel/api/v0.4/leftoperands/{id}"): "openrel_get_left_operand",
    ("get", "/openrel/api/v0.4/mappings"): "openrel_list_mappings",
    ("get", "/openrel/api/v0.4/actionclasses"): "openrel_list_action_classes",
    ("get", "/openrel/api/v0.4/actionclasses/{id}"): "openrel_get_action_class",
    ("get", "/openrel/api/v0.4/assetclasses"): "openrel_list_asset_classes",
    ("get", "/openrel/api/v0.4/assetclasses/{id}"): "openrel_get_asset_class",
    ("get", "/openrel/api/v0.4/constraintclasses"): "openrel_list_constraint_classes",
    ("get", "/openrel/api/v0.4/constraintclasses/{id}"): "openrel_get_constraint_class",
    ("get", "/openrel/api/v0.4/leftoperandclasses"): "openrel_list_left_operand_classes",
    ("get", "/openrel/api/v0.4/leftoperandclasses/{id}"): "openrel_get_left_operand_class",
    ("get", "/openrel/api/v0.4/ruleclasses"): "openrel_list_rule_classes",
    ("get", "/openrel/api/v0.4/ruleclasses/{id}"): "openrel_get_rule_class",
}

PREFIX_OPERATIONS = {
    "openrel_list_actions",
    "openrel_get_action",
    "openrel_list_mappings",
    "openrel_list_action_classes",
    "openrel_get_action_class",
    "openrel_list_asset_classes",
    "openrel_get_asset_class",
    "openrel_list_constraint_classes",
    "openrel_get_constraint_class",
    "openrel_list_left_operand_classes",
    "openrel_get_left_operand_class",
    "openrel_list_rule_classes",
    "openrel_get_rule_class",
}

DETAIL_OPERATIONS = {
    "openrel_get_action",
    "openrel_get_constraint",
    "openrel_get_left_operand",
    "openrel_get_action_class",
    "openrel_get_asset_class",
    "openrel_get_constraint_class",
    "openrel_get_left_operand_class",
    "openrel_get_rule_class",
}

LIST_RESOURCE_OPERATIONS = {
    "openrel_list_actions",
    "openrel_list_constraints",
    "openrel_list_left_operands",
    "openrel_list_action_classes",
    "openrel_list_asset_classes",
    "openrel_list_constraint_classes",
    "openrel_list_left_operand_classes",
    "openrel_list_rule_classes",
}


def _openapi_and_operations(client: TestClient):
    openapi = client.get("/openapi.json").json()
    operations = []
    for path, methods in openapi["paths"].items():
        for method, operation in methods.items():
            operations.append((path, method, operation))
    return openapi, operations


@contextmanager
def _override_openrel_client(app, client):
    app.dependency_overrides[openrel_api.get_openrel_client] = lambda: client
    try:
        yield
    finally:
        app.dependency_overrides.pop(openrel_api.get_openrel_client, None)


@dataclass
class RecordingClient:
    list_values: dict[str, list[dict[str, Any]]] = field(default_factory=dict)
    detail_values: dict[str, dict[str, Any]] = field(default_factory=dict)
    mapping_values: list[dict[str, Any]] = field(default_factory=list)
    calls: list[tuple[str, str, str | None, str | None]] = field(default_factory=list)

    async def list_resources(self, family: str, *, prefix: str | None = None):
        self.calls.append(("list", family, None, prefix))
        return self.list_values.get(family, [])

    async def get_resource(self, family: str, identifier: str, *, prefix: str | None = None):
        self.calls.append(("detail", family, identifier, prefix))
        return self.detail_values[family]

    async def list_mappings(self, *, prefix: str | None = None):
        self.calls.append(("mappings", "mappings", None, prefix))
        return self.mapping_values


class RaisingClient:
    def __init__(self, error: Exception):
        self.error = error

    async def list_resources(self, family: str, *, prefix: str | None = None):
        raise self.error

    async def get_resource(self, family: str, identifier: str, *, prefix: str | None = None):
        raise self.error

    async def list_mappings(self, *, prefix: str | None = None):
        raise self.error


class NonConformingRetryAfterClient:
    def __init__(self, retry_after: Any):
        self.retry_after = retry_after

    async def list_resources(self, family: str, *, prefix: str | None = None):
        error = OpenRelClientError(OpenRelErrorCode.PROVIDER_RATE_LIMITED, "rate-limited")
        error.retry_after_seconds = self.retry_after  # type: ignore[assignment]
        raise error

    async def get_resource(self, family: str, identifier: str, *, prefix: str | None = None):
        error = OpenRelClientError(OpenRelErrorCode.PROVIDER_RATE_LIMITED, "rate-limited")
        error.retry_after_seconds = self.retry_after  # type: ignore[assignment]
        raise error

    async def list_mappings(self, *, prefix: str | None = None):
        error = OpenRelClientError(OpenRelErrorCode.PROVIDER_RATE_LIMITED, "rate-limited")
        error.retry_after_seconds = self.retry_after  # type: ignore[assignment]
        raise error


class SpyOpenRelClient(OpenRelClient):
    instances: list["SpyOpenRelClient"] = []

    def __init__(self, *args: Any, **kwargs: Any):
        super().__init__(*args, **kwargs)
        self.closed = False
        SpyOpenRelClient.instances.append(self)

    async def aclose(self) -> None:
        await super().aclose()
        self.closed = True

def _schema_by_name(schemas: dict[str, Any], name: str) -> dict[str, Any]:
    matches = [schema for key, schema in schemas.items() if key.startswith(name)]
    assert matches, f"Missing schema for {name}"
    return matches[0]


def test_openrel_route_registration_and_tag_metadata(app_client):
    client, *_ = app_client
    openapi, operations = _openapi_and_operations(client)
    openrel_ops = [(path, method, operation) for path, method, operation in operations if path.startswith("/openrel/api/v0.4")]

    assert len(openrel_ops) == 17
    assert {method for _, method, _ in openrel_ops} == {"get"}

    implemented = {(method, path): operation["operationId"] for path, method, operation in openrel_ops}
    assert implemented == EXPECTED_OPENREL_ROUTES

    all_operation_ids = [operation["operationId"] for _, _, operation in operations]
    assert len(all_operation_ids) == len(set(all_operation_ids))

    for _, _, operation in openrel_ops:
        assert operation["tags"] == ["OpenREL"]

    tag_descriptions = {tag["name"]: tag["description"] for tag in openapi["tags"]}
    assert tag_descriptions["OpenREL"] == (
        "Read-only access to vocabulary and knowledge-base resources supplied by the configured OpenREL provider. "
        "These resources are external provider data, not authoritative LFS licence or federation records. "
        "Provider availability affects only the OpenREL endpoints."
    )


def test_openrel_openapi_parameters_and_schemas(app_client):
    client, *_ = app_client
    openapi, operations = _openapi_and_operations(client)
    openrel_ops = {operation["operationId"]: operation for path, method, operation in operations if path.startswith("/openrel/api/v0.4")}

    assert len(openrel_ops) == 17
    assert "/openrel/api/v0.4/mappings/{id}" not in openapi["paths"]

    for operation_id, operation in openrel_ops.items():
        assert "requestBody" not in operation
        query_params = [p for p in operation.get("parameters", []) if p["in"] == "query"]
        has_prefix = any(p["name"] == "prefix" for p in query_params)
        assert has_prefix == (operation_id in PREFIX_OPERATIONS)
        if has_prefix:
            prefix = next(p for p in query_params if p["name"] == "prefix")
            assert prefix["required"] is False
            prefix_schema = prefix["schema"]
            if "type" in prefix_schema:
                assert prefix_schema["type"] == "string"
            else:
                assert any(item.get("type") == "string" for item in prefix_schema.get("anyOf", []))
        if operation_id in DETAIL_OPERATIONS:
            id_param = next(p for p in operation.get("parameters", []) if p["in"] == "path" and p["name"] == "id")
            assert id_param["required"] is True
            assert id_param["schema"]["type"] == "string"

        success_schema = operation["responses"]["200"]["content"]["application/json"]["schema"]
        if operation_id in LIST_RESOURCE_OPERATIONS:
            assert success_schema["type"] == "array"
            assert success_schema["items"]["$ref"].endswith("/OpenRELResource")
        elif operation_id == "openrel_list_mappings":
            assert success_schema["type"] == "array"
            assert success_schema["items"]["$ref"].endswith("/OpenRELMapping")
        else:
            assert success_schema["$ref"].endswith("/OpenRELResource")

    schemas = openapi["components"]["schemas"]
    resource_schema = _schema_by_name(schemas, "OpenRELResource")
    mapping_schema = _schema_by_name(schemas, "OpenRELMapping")

    assert resource_schema["required"] == ["iri"]
    assert mapping_schema["required"] == ["iri"]
    for schema in (resource_schema, mapping_schema):
        for optional_name in ("label", "definition"):
            field_schema = schema["properties"][optional_name]
            assert field_schema["type"] == "string"
            assert "default" not in field_schema
            assert field_schema.get("nullable") is None

    dumped = json.dumps(openapi)
    assert "PydanticUndefined" not in dumped
    assert "__pydantic" not in dumped


def test_openrel_success_proxy_behavior_with_injected_client(app_client):
    client, *_ = app_client
    fake = RecordingClient(
        list_values={
            "actions": [
                {"iri": "urn:action:first", "providerExtra": "drop"},
                {"iri": "urn:action:second", "label": "Second", "definition": "Def", "providerExtra": "drop"},
            ],
            "constraints": [{"iri": "urn:constraint:one", "providerExtra": "drop"}],
        },
        detail_values={
            "actions": {"iri": "urn:action:detail", "label": "Detail", "providerExtra": "drop"},
        },
        mapping_values=[
            {"iri": "urn:mapping:one", "providerExtra": "drop"},
            {"iri": "urn:mapping:two", "definition": "Def", "providerExtra": "drop"},
        ],
    )

    with _override_openrel_client(client.app, fake):
        actions = client.get("/openrel/api/v0.4/actions", params={"prefix": "odrl"})
        assert actions.status_code == 200
        assert actions.json() == [
            {"iri": "urn:action:first"},
            {"iri": "urn:action:second", "label": "Second", "definition": "Def"},
        ]

        constraints = client.get("/openrel/api/v0.4/constraints", params={"prefix": "ignored"})
        assert constraints.status_code == 200
        assert constraints.json() == [{"iri": "urn:constraint:one"}]

        encoded_id = quote("urn:example:action/read#frag?query", safe="")
        detail = client.get(f"/openrel/api/v0.4/actions/{encoded_id}", params={"prefix": "odrl"})
        assert detail.status_code == 200
        assert detail.json() == {"iri": "urn:action:detail", "label": "Detail"}

        mappings = client.get("/openrel/api/v0.4/mappings", params={"prefix": "odrl"})
        assert mappings.status_code == 200
        assert mappings.json() == [
            {"iri": "urn:mapping:one"},
            {"iri": "urn:mapping:two", "definition": "Def"},
        ]

    assert fake.calls == [
        ("list", "actions", None, "odrl"),
        ("list", "constraints", None, None),
        ("detail", "actions", "urn:example:action/read#frag?query", "odrl"),
        ("mappings", "mappings", None, "odrl"),
    ]


@pytest.mark.parametrize(
    ("code", "status", "title", "type_slug", "path", "retry_after"),
    [
        (OpenRelErrorCode.DISABLED, 503, "OpenREL Disabled", "openrel-disabled", "/openrel/api/v0.4/actions", None),
        (
            OpenRelErrorCode.INVALID_CONFIGURATION,
            503,
            "OpenREL Configuration Unavailable",
            "openrel-configuration-unavailable",
            "/openrel/api/v0.4/actions",
            None,
        ),
        (OpenRelErrorCode.INVALID_ID, 400, "Invalid OpenREL Identifier", "openrel-invalid-identifier", "/openrel/api/v0.4/actions/id", None),
        (OpenRelErrorCode.INVALID_PREFIX, 400, "Invalid OpenREL Prefix", "openrel-invalid-prefix", "/openrel/api/v0.4/actions", None),
        (
            OpenRelErrorCode.FORBIDDEN_DESTINATION,
            502,
            "OpenREL Upstream Destination Rejected",
            "openrel-upstream-destination-rejected",
            "/openrel/api/v0.4/actions",
            None,
        ),
        (OpenRelErrorCode.DNS_FAILURE, 503, "OpenREL Provider Unreachable", "openrel-provider-unreachable", "/openrel/api/v0.4/actions", None),
        (
            OpenRelErrorCode.CONNECTION_FAILURE,
            503,
            "OpenREL Provider Unreachable",
            "openrel-provider-unreachable",
            "/openrel/api/v0.4/actions",
            None,
        ),
        (OpenRelErrorCode.TIMEOUT, 504, "OpenREL Provider Timeout", "openrel-provider-timeout", "/openrel/api/v0.4/actions", None),
        (
            OpenRelErrorCode.PROVIDER_NOT_FOUND,
            404,
            "OpenREL Resource Not Found",
            "openrel-resource-not-found",
            "/openrel/api/v0.4/actions/id",
            None,
        ),
        (
            OpenRelErrorCode.PROVIDER_BAD_REQUEST,
            502,
            "OpenREL Provider Protocol Error",
            "openrel-provider-protocol-error",
            "/openrel/api/v0.4/actions",
            None,
        ),
        (
            OpenRelErrorCode.PROVIDER_AUTH_FAILURE,
            502,
            "OpenREL Provider Authentication Failure",
            "openrel-provider-authentication-failure",
            "/openrel/api/v0.4/actions",
            None,
        ),
        (
            OpenRelErrorCode.PROVIDER_RATE_LIMITED,
            503,
            "OpenREL Provider Rate Limited",
            "openrel-provider-rate-limited",
            "/openrel/api/v0.4/actions",
            4,
        ),
        (
            OpenRelErrorCode.PROVIDER_UNAVAILABLE,
            503,
            "OpenREL Provider Unavailable",
            "openrel-provider-unavailable",
            "/openrel/api/v0.4/actions",
            None,
        ),
        (OpenRelErrorCode.PROVIDER_ERROR, 502, "OpenREL Provider Error", "openrel-provider-error", "/openrel/api/v0.4/actions", None),
        (OpenRelErrorCode.REDIRECT, 502, "OpenREL Redirect Not Allowed", "openrel-redirect-not-allowed", "/openrel/api/v0.4/actions", None),
        (
            OpenRelErrorCode.INVALID_CONTENT_TYPE,
            502,
            "OpenREL Content Type Invalid",
            "openrel-content-type-invalid",
            "/openrel/api/v0.4/actions",
            None,
        ),
        (OpenRelErrorCode.MALFORMED_JSON, 502, "OpenREL JSON Invalid", "openrel-json-invalid", "/openrel/api/v0.4/actions", None),
        (
            OpenRelErrorCode.DUPLICATE_JSON_KEY,
            502,
            "OpenREL JSON Duplicate Key",
            "openrel-json-duplicate-key",
            "/openrel/api/v0.4/actions",
            None,
        ),
        (
            OpenRelErrorCode.OVERSIZED_RESPONSE,
            502,
            "OpenREL Response Too Large",
            "openrel-response-too-large",
            "/openrel/api/v0.4/actions",
            None,
        ),
        (
            OpenRelErrorCode.INVALID_RESPONSE_SHAPE,
            502,
            "OpenREL Response Shape Invalid",
            "openrel-response-shape-invalid",
            "/openrel/api/v0.4/actions",
            None,
        ),
        (
            OpenRelErrorCode.INVALID_RESPONSE_SCHEMA,
            502,
            "OpenREL Response Schema Invalid",
            "openrel-response-schema-invalid",
            "/openrel/api/v0.4/actions",
            None,
        ),
        (
            OpenRelErrorCode.INTERNAL_ERROR,
            500,
            "OpenREL Facade Internal Error",
            "openrel-facade-internal-error",
            "/openrel/api/v0.4/actions",
            None,
        ),
    ],
)
def test_openrel_error_mapping_covers_all_client_codes(app_client, code, status, title, type_slug, path, retry_after):
    client, *_ = app_client
    error = OpenRelClientError(
        code,
        "traceback provider.example 10.0.0.9 should-not-leak",
        retry_after_seconds=retry_after,
    )
    with _override_openrel_client(client.app, RaisingClient(error)):
        response = client.get(path)

    assert response.status_code == status
    assert response.headers["content-type"].startswith("application/problem+json")
    body = response.json()
    assert body["status"] == status
    assert body["title"] == title
    assert body["type"] == f"https://eosc-eden.eu/problems/{type_slug}"
    assert "traceback" not in response.text
    assert "provider.example" not in response.text
    assert "10.0.0.9" not in response.text

    if code == OpenRelErrorCode.PROVIDER_RATE_LIMITED:
        assert response.headers["Retry-After"] == "2"
    else:
        assert "Retry-After" not in response.headers


def test_openrel_rate_limit_without_retry_after_does_not_set_header(app_client):
    client, *_ = app_client
    error = OpenRelClientError(OpenRelErrorCode.PROVIDER_RATE_LIMITED, "rate-limited", retry_after_seconds=None)
    with _override_openrel_client(client.app, RaisingClient(error)):
        response = client.get("/openrel/api/v0.4/actions")
    assert response.status_code == 503
    assert "Retry-After" not in response.headers


def test_openrel_rate_limit_retry_after_zero_is_preserved(app_client):
    client, *_ = app_client
    error = OpenRelClientError(OpenRelErrorCode.PROVIDER_RATE_LIMITED, "rate-limited", retry_after_seconds=0)
    with _override_openrel_client(client.app, RaisingClient(error)):
        response = client.get("/openrel/api/v0.4/actions")
    assert response.status_code == 503
    assert response.headers["Retry-After"] == "0"


def test_openrel_rate_limit_retry_after_negative_is_omitted(app_client):
    client, *_ = app_client
    error = OpenRelClientError(OpenRelErrorCode.PROVIDER_RATE_LIMITED, "rate-limited", retry_after_seconds=-1)
    with _override_openrel_client(client.app, RaisingClient(error)):
        response = client.get("/openrel/api/v0.4/actions")
    assert response.status_code == 503
    assert "Retry-After" not in response.headers


def test_openrel_rate_limit_retry_after_extreme_value_is_clamped(app_client):
    client, *_ = app_client
    error = OpenRelClientError(OpenRelErrorCode.PROVIDER_RATE_LIMITED, "rate-limited", retry_after_seconds=10_000)
    with _override_openrel_client(client.app, RaisingClient(error)):
        response = client.get("/openrel/api/v0.4/actions")
    assert response.status_code == 503
    assert response.headers["Retry-After"] == "2"


@pytest.mark.parametrize("bad_retry_after", ["nan", "inf", "abc", "5.5", object()])
def test_openrel_rate_limit_malformed_retry_after_is_omitted(app_client, bad_retry_after: Any):
    client, *_ = app_client
    with _override_openrel_client(client.app, NonConformingRetryAfterClient(bad_retry_after)):
        response = client.get("/openrel/api/v0.4/actions")
    assert response.status_code == 503
    assert "Retry-After" not in response.headers


def test_openrel_unexpected_exception_maps_to_internal_problem(app_client):
    client, *_ = app_client
    with _override_openrel_client(client.app, RaisingClient(RuntimeError("boom"))):
        response = client.get("/openrel/api/v0.4/actions")
    assert response.status_code == 500
    assert response.headers["content-type"].startswith("application/problem+json")
    assert response.json()["title"] == "OpenREL Facade Internal Error"


def test_openrel_disabled_does_not_break_other_routes(app_client):
    client, *_ = app_client
    openrel_response = client.get("/openrel/api/v0.4/actions")
    assert openrel_response.status_code == 503
    assert openrel_response.json()["title"] == "OpenREL Disabled"

    license_response = client.get("/api/v1/licenses/MIT")
    assert license_response.status_code == 200


def test_openrel_invalid_configuration_does_not_prevent_startup(monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setenv("BASE_DIR", str(Path(__file__).resolve().parents[2]))
    monkeypatch.setenv("OPENREL_ENABLED", "true")
    monkeypatch.setenv("OPENREL_BASE_URL", "https://example.com:99999/openrel/api/v0.4")
    monkeypatch.setenv("OPENREL_ALLOWED_PORTS", "443")

    app = create_app()
    with TestClient(app) as client:
        health = client.get("/api/v1/health")
        license_response = client.get("/api/v1/licenses/MIT")
        openrel_response = client.get("/openrel/api/v0.4/actions")

    assert health.status_code == 200
    assert license_response.status_code == 200
    assert openrel_response.status_code == 503
    assert openrel_response.json()["title"] == "OpenREL Configuration Unavailable"


def test_create_app_does_not_allocate_openrel_client():
    app = create_app()
    assert app.state.openrel_settings is not None
    assert app.state.openrel_client is None


def test_openrel_dependency_outside_lifespan_returns_configuration_unavailable():
    app = create_app()
    request = Request({"type": "http", "method": "GET", "path": "/", "headers": [], "app": app})
    dependency_client = openrel_api.get_openrel_client(request)
    with pytest.raises(OpenRelClientError) as exc:
        asyncio.run(dependency_client.list_resources("actions"))
    assert exc.value.code == OpenRelErrorCode.INVALID_CONFIGURATION


def test_lifespan_creates_and_closes_openrel_client(monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setattr("src.license_facade_service.main.OpenRelClient", SpyOpenRelClient)
    SpyOpenRelClient.instances.clear()
    app = create_app()

    with TestClient(app):
        assert len(SpyOpenRelClient.instances) == 1
        created = SpyOpenRelClient.instances[0]
        assert app.state.openrel_client is created
        assert not created.closed

    assert created.closed
    assert app.state.openrel_client is None


def test_lifespan_reentry_creates_fresh_openrel_client(monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setattr("src.license_facade_service.main.OpenRelClient", SpyOpenRelClient)
    SpyOpenRelClient.instances.clear()
    app = create_app()

    with TestClient(app):
        first = app.state.openrel_client
    assert first is not None

    with TestClient(app):
        second = app.state.openrel_client
        assert second is not None
        assert second is not first

    assert first.closed
    assert second.closed
    assert app.state.openrel_client is None


def test_lifespan_startup_failure_still_closes_openrel_client(monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setattr("src.license_facade_service.main.OpenRelClient", SpyOpenRelClient)
    SpyOpenRelClient.instances.clear()
    app = create_app()

    class FailingRuntime:
        def initialize(self):
            raise RuntimeError("startup-failure")

    app.state.federation_runtime = FailingRuntime()
    with pytest.raises(RuntimeError, match="startup-failure"):
        with TestClient(app):
            pass

    assert len(SpyOpenRelClient.instances) == 1
    assert SpyOpenRelClient.instances[0].closed is True
    assert app.state.openrel_client is None


def test_lifespan_shutdown_close_failure_still_clears_openrel_client(monkeypatch: pytest.MonkeyPatch):
    class FailingCloseClient(OpenRelClient):
        instances: list["FailingCloseClient"] = []

        def __init__(self, *args: Any, **kwargs: Any):
            super().__init__(*args, **kwargs)
            self.close_called = False
            FailingCloseClient.instances.append(self)

        async def aclose(self) -> None:
            self.close_called = True
            raise RuntimeError("openrel-close-failure")

    monkeypatch.setattr("src.license_facade_service.main.OpenRelClient", FailingCloseClient)
    app = create_app()

    with pytest.raises(RuntimeError, match="openrel-close-failure"):
        with TestClient(app):
            pass

    assert len(FailingCloseClient.instances) == 1
    assert FailingCloseClient.instances[0].close_called is True
    assert app.state.openrel_client is None


def test_openrel_dependency_override_prevents_real_network_use(app_client):
    client, *_ = app_client
    fake = RecordingClient(list_values={"actions": [{"iri": "urn:override"}]})
    with _override_openrel_client(client.app, fake):
        response = client.get("/openrel/api/v0.4/actions")
    assert response.status_code == 200
    assert response.json() == [{"iri": "urn:override"}]
    assert fake.calls == [("list", "actions", None, None)]


def test_no_openrel_request_during_startup_with_disabled_configuration(monkeypatch: pytest.MonkeyPatch):
    class FailingStartupClient:
        def __init__(self, *args: Any, **kwargs: Any):
            pass

        async def aclose(self) -> None:
            return None

        async def list_resources(self, family: str, *, prefix: str | None = None):
            raise AssertionError("startup should not call list_resources")

        async def get_resource(self, family: str, identifier: str, *, prefix: str | None = None):
            raise AssertionError("startup should not call get_resource")

        async def list_mappings(self, *, prefix: str | None = None):
            raise AssertionError("startup should not call list_mappings")

    monkeypatch.setattr("src.license_facade_service.main.OpenRelClient", FailingStartupClient)
    app = create_app()
    with TestClient(app) as client:
        health = client.get("/api/v1/health")
        assert health.status_code == 200
