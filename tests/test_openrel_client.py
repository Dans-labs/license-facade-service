from __future__ import annotations

import json
from datetime import date

import httpx
import pytest

from src.license_facade_service.services.openrel_client import (
    OpenRelClient,
    OpenRelClientConfigurationError,
    OpenRelInvalidContentTypeError,
    OpenRelMalformedJsonError,
    OpenRelNetworkError,
    OpenRelNotFoundError,
    OpenRelResponseSchemaError,
    OpenRelResponseTooLargeError,
    OpenRelUnexpectedStatusError,
    OpenRelUnsafeDestinationError,
    OpenRelUnsupportedResourceError,
)
from src.license_facade_service.services.openrel_policy import OpenRelPolicyMode, OpenRelPolicySettings


def _settings(**overrides) -> OpenRelPolicySettings:
    values = dict(
        enabled=True,
        mode=OpenRelPolicyMode.active,
        base_url="https://kb.example/openrel/api/v0.4",
        approved_profile="https://openrel.org/ns#",
        approved_version="0.4",
        effective_date=date(2026, 9, 4),
        cache_ttl_seconds=5,
        timeout_seconds=1.0,
        max_response_bytes=256,
    )
    values.update(overrides)
    return OpenRelPolicySettings(**values)


def _resolver(*addresses: str):
    calls: list[tuple[str, int]] = []

    def resolve(hostname: str, port: int):
        calls.append((hostname, port))
        rows = []
        for address in addresses:
            family = __import__("socket").AF_INET6 if ":" in address else __import__("socket").AF_INET
            rows.append((family, 1, 6, "", (address, port, 0, 0) if family == __import__("socket").AF_INET6 else (address, port)))
        return rows

    resolve.calls = calls
    return resolve


def _client(handler, **kwargs) -> OpenRelClient:
    transport = httpx.MockTransport(handler)
    http_client = httpx.Client(transport=transport, follow_redirects=False, trust_env=False)
    return OpenRelClient(_settings(**kwargs.pop("settings_overrides", {})), http_client=http_client, **kwargs)


@pytest.mark.parametrize(
    ("resource", "expected_path", "prefix"),
    [
        ("actions", "/openrel/api/v0.4/actions", "odrl:"),
        ("constraints", "/openrel/api/v0.4/constraints", None),
        ("leftoperands", "/openrel/api/v0.4/leftoperands", None),
        ("mappings", "/openrel/api/v0.4/mappings", "odrl:"),
        ("actionclasses", "/openrel/api/v0.4/actionclasses", "odrl:"),
        ("assetclasses", "/openrel/api/v0.4/assetclasses", "odrl:"),
        ("constraintclasses", "/openrel/api/v0.4/constraintclasses", "odrl:"),
        ("leftoperandclasses", "/openrel/api/v0.4/leftoperandclasses", "odrl:"),
        ("ruleclasses", "/openrel/api/v0.4/ruleclasses", "odrl:"),
    ],
)
def test_list_resource_paths(resource, expected_path, prefix):
    seen = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append((request.method, request.url.path, request.url.query.decode()))
        return httpx.Response(200, headers={"content-type": "application/json"}, json=[{"iri": "https://openrel.org/ns#x"}])

    client = _client(handler, resolver=_resolver("8.8.8.8"))
    try:
        items = client.list_resources(resource, prefix=prefix)
    finally:
        client.close()
    assert len(items) == 1
    expected_query = f"prefix={prefix.replace(':', '%3A')}" if prefix is not None else ""
    assert seen == [("GET", expected_path, expected_query)]


@pytest.mark.parametrize(
    ("resource", "resource_id", "prefix", "expected_path"),
    [
        ("actions", "odrl:use", "odrl:", "/openrel/api/v0.4/actions/odrl%3Ause"),
        ("constraints", "leftOperand", None, "/openrel/api/v0.4/constraints/leftOperand"),
        ("leftoperands", "purpose", None, "/openrel/api/v0.4/leftoperands/purpose"),
        ("actionclasses", "odrl:Action", "odrl:", "/openrel/api/v0.4/actionclasses/odrl%3AAction"),
        ("assetclasses", "odrl:Asset", "odrl:", "/openrel/api/v0.4/assetclasses/odrl%3AAsset"),
        ("constraintclasses", "odrl:Constraint", "odrl:", "/openrel/api/v0.4/constraintclasses/odrl%3AConstraint"),
        ("leftoperandclasses", "odrl:LeftOperand", "odrl:", "/openrel/api/v0.4/leftoperandclasses/odrl%3ALeftOperand"),
        ("ruleclasses", "odrl:Rule", "odrl:", "/openrel/api/v0.4/ruleclasses/odrl%3ARule"),
    ],
)
def test_detail_paths(resource, resource_id, prefix, expected_path):
    seen = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append((request.method, request.url.path, request.url.query.decode()))
        return httpx.Response(200, headers={"content-type": "application/json"}, json={"iri": "https://openrel.org/ns#x"})

    client = _client(handler, resolver=_resolver("8.8.8.8"))
    try:
        item = client.get_resource(resource, resource_id, prefix=prefix)
    finally:
        client.close()
    assert item.iri == "https://openrel.org/ns#x"
    expected_query = f"prefix={prefix.replace(':', '%3A')}" if prefix is not None else ""
    assert seen == [("GET", expected_path.replace("%3A", ":"), expected_query)]


def test_compact_identifier_odrl_use_is_accepted():
    seen = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append((request.url.path, request.url.query.decode(), request.url.fragment))
        return httpx.Response(200, headers={"content-type": "application/json"}, json={"iri": "https://openrel.org/ns#use"})

    client = _client(handler, resolver=_resolver("8.8.8.8"))
    try:
        item = client.get_resource("actions", " odrl:use ")
    finally:
        client.close()
    assert item.iri == "https://openrel.org/ns#use"
    assert seen == [("/openrel/api/v0.4/actions/odrl:use", "", "")]


def test_simple_identifier_is_accepted():
    seen = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(request.url.path)
        return httpx.Response(200, headers={"content-type": "application/json"}, json={"iri": "https://openrel.org/ns#simple"})

    client = _client(handler, resolver=_resolver("8.8.8.8"))
    try:
        client.get_resource("constraints", "simple-id")
    finally:
        client.close()
    assert seen == ["/openrel/api/v0.4/constraints/simple-id"]


def test_full_https_iri_is_accepted_and_encoded_as_one_path_segment():
    seen = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append((str(request.url), request.url.path))
        return httpx.Response(200, headers={"content-type": "application/json"}, json={"iri": "https://openrel.org/ns#use"})

    client = _client(handler, resolver=_resolver("8.8.8.8"))
    try:
        client.get_resource("actions", "https://www.w3.org/ns/odrl/2/use")
    finally:
        client.close()
    assert seen == [("https://kb.example/openrel/api/v0.4/actions/https%3A%2F%2Fwww.w3.org%2Fns%2Fodrl%2F2%2Fuse", "/openrel/api/v0.4/actions/https://www.w3.org/ns/odrl/2/use")]


def test_full_http_iri_is_accepted_as_identifier_data():
    seen = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(str(request.url))
        return httpx.Response(200, headers={"content-type": "application/json"}, json={"iri": "https://openrel.org/ns#use"})

    client = _client(handler, resolver=_resolver("8.8.8.8"))
    try:
        client.get_resource("actions", "http://example.org/item")
    finally:
        client.close()
    assert seen == ["https://kb.example/openrel/api/v0.4/actions/http%3A%2F%2Fexample.org%2Fitem"]


def test_iri_query_and_fragment_remain_identifier_data():
    seen = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append((str(request.url), request.url.query.decode(), request.url.fragment))
        return httpx.Response(200, headers={"content-type": "application/json"}, json={"iri": "https://openrel.org/ns#use"})

    client = _client(handler, resolver=_resolver("8.8.8.8"))
    try:
        client.get_resource("actions", "https://example.org/item?id=1#term")
    finally:
        client.close()
    assert seen == [("https://kb.example/openrel/api/v0.4/actions/https%3A%2F%2Fexample.org%2Fitem%3Fid%3D1%23term", "", "")]


def test_full_iri_cannot_override_configured_host_or_api_root():
    seen = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append((request.url.host, request.url.path))
        return httpx.Response(200, headers={"content-type": "application/json"}, json={"iri": "https://openrel.org/ns#use"})

    client = _client(handler, resolver=_resolver("8.8.8.8"))
    try:
        client.get_resource("actions", "https://evil.example/other/root")
    finally:
        client.close()
    assert seen == [("kb.example", "/openrel/api/v0.4/actions/https://evil.example/other/root")]


def test_full_iri_cache_hit_uses_normalized_decoded_id():
    seen = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(request.url.path)
        return httpx.Response(200, headers={"content-type": "application/json"}, json={"iri": "https://openrel.org/ns#use"})

    client = _client(handler, resolver=_resolver("8.8.8.8"), monotonic=iter([0.0, 1.0, 2.0]).__next__)
    try:
        first = client.get_resource("actions", " https://www.w3.org/ns/odrl/2/use ")
        second = client.get_resource("actions", "https://www.w3.org/ns/odrl/2/use")
    finally:
        client.close()
    assert first == second
    assert seen == ["/openrel/api/v0.4/actions/https://www.w3.org/ns/odrl/2/use"]


def test_mappings_detail_rejected_without_network_call():
    resolver = _resolver("8.8.8.8")
    calls = []

    def handler(request: httpx.Request) -> httpx.Response:
        calls.append(request)
        return httpx.Response(200, headers={"content-type": "application/json"}, json={})

    client = _client(handler, resolver=resolver)
    try:
        with pytest.raises(OpenRelUnsupportedResourceError):
            client.get_resource("mappings", "x")
    finally:
        client.close()
    assert resolver.calls == []
    assert calls == []


def test_prefix_rejected_when_contract_does_not_support_it():
    client = _client(lambda request: httpx.Response(200, json=[]), resolver=_resolver("8.8.8.8"))
    try:
        with pytest.raises(OpenRelClientConfigurationError):
            client.list_resources("constraints", prefix="odrl:")
    finally:
        client.close()


def test_placeholder_base_url_is_complete_versioned_root():
    assert OpenRelPolicySettings.placeholder().base_url == "https://openrel.example.invalid/openrel/api/v0.4"


def test_no_duplicate_api_prefix_in_built_urls():
    seen = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(str(request.url))
        return httpx.Response(200, headers={"content-type": "application/json"}, json=[{"iri": "https://openrel.org/ns#a"}])

    client = _client(handler, resolver=_resolver("8.8.8.8"), settings_overrides={"base_url": "https://kb.example/openrel/api/v0.4"})
    try:
        client.list_resources("actions")
    finally:
        client.close()
    assert seen == ["https://kb.example/openrel/api/v0.4/actions"]


def test_placeholder_availability_uses_no_network():
    resolver = _resolver("8.8.8.8")
    transport_calls = []

    def handler(request: httpx.Request) -> httpx.Response:
        transport_calls.append(request)
        return httpx.Response(200, headers={"content-type": "application/json"}, json=[{"iri": "https://openrel.org/ns#a"}])

    settings = _settings(base_url="https://openrel.example.invalid/openrel/api/v0.4")
    client = OpenRelClient(settings, http_client=httpx.Client(transport=httpx.MockTransport(handler), follow_redirects=False, trust_env=False), resolver=resolver)
    try:
        assert client.check_availability() is False
    finally:
        client.close()
    assert resolver.calls == []
    assert transport_calls == []


@pytest.mark.parametrize("resource_id", ["../evil", "a/b", "a\\b", "//evil", "%2f", "%5c", "%2e%2e", "ftp://evil.example/x", "mailto:test@example.com", "https://user:pass@example.com/x"])
def test_id_injection_is_rejected(resource_id):
    client = _client(lambda request: httpx.Response(200, json={}), resolver=_resolver("8.8.8.8"))
    try:
        with pytest.raises(OpenRelClientConfigurationError):
            client.get_resource("actions", resource_id)
    finally:
        client.close()


def test_no_query_or_fragment_is_introduced_into_actual_request_url():
    seen = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append((request.url.path, request.url.query.decode(), request.url.fragment))
        return httpx.Response(200, headers={"content-type": "application/json"}, json={"iri": "https://openrel.org/ns#use"})

    client = _client(handler, resolver=_resolver("8.8.8.8"))
    try:
        client.get_resource("actions", "https://example.org/item?id=1#term", prefix="odrl:")
    finally:
        client.close()
    assert seen == [("/openrel/api/v0.4/actions/https://example.org/item?id=1#term", "prefix=odrl%3A", "")]


def test_http_requires_demo_flag():
    with pytest.raises(OpenRelClientConfigurationError):
        OpenRelClient(_settings(base_url="http://kb.example/openrel/api/v0.4"))


def test_http_allowed_with_demo_flag():
    client = OpenRelClient(_settings(base_url="http://kb.example/openrel/api/v0.4", allow_http_for_demo=True), http_client=httpx.Client(transport=httpx.MockTransport(lambda request: httpx.Response(200, headers={"content-type": "application/json"}, json=[{"iri": "http://openrel.org/ns#a"}])), follow_redirects=False, trust_env=False), resolver=_resolver("8.8.8.8"))
    try:
        assert len(client.list_resources("actions")) == 1
    finally:
        client.close()


@pytest.mark.parametrize(
    "base_url",
    [
        "https://user:pass@kb.example/openrel/api/v0.4",
        "https://kb.example/openrel/api/v0.4?x=1",
        "https://kb.example/openrel/api/v0.4#frag",
    ],
)
def test_base_url_rejects_credentials_query_and_fragment(base_url):
    with pytest.raises(OpenRelClientConfigurationError):
        OpenRelClient(_settings(base_url=base_url))


@pytest.mark.parametrize("address", ["127.0.0.1", "::1", "10.0.0.5", "169.254.1.10", "224.0.0.1", "0.0.0.0", "240.0.0.1", "169.254.169.254", "100.100.100.200"])
def test_unsafe_dns_destinations_are_rejected(address):
    client = _client(lambda request: httpx.Response(200, json=[]), resolver=_resolver(address))
    try:
        with pytest.raises(OpenRelUnsafeDestinationError):
            client.list_resources("actions")
    finally:
        client.close()


def test_ipv4_mapped_ipv6_rejected():
    client = _client(lambda request: httpx.Response(200, json=[]), resolver=_resolver("::ffff:10.0.0.5"))
    try:
        with pytest.raises(OpenRelUnsafeDestinationError):
            client.list_resources("actions")
    finally:
        client.close()


def test_mixed_dns_answers_rejected():
    client = _client(lambda request: httpx.Response(200, json=[]), resolver=_resolver("8.8.8.8", "127.0.0.1"))
    try:
        with pytest.raises(OpenRelUnsafeDestinationError):
            client.list_resources("actions")
    finally:
        client.close()


def test_dns_resolution_occurs_for_every_uncached_request():
    resolver = _resolver("8.8.8.8")
    clock = iter([0.0, 10.0, 20.0]).__next__
    client = _client(lambda request: httpx.Response(200, headers={"content-type": "application/json"}, json=[{"iri": "https://openrel.org/ns#a"}]), resolver=resolver, monotonic=clock, settings_overrides={"cache_ttl_seconds": 1})
    try:
        client.list_resources("actions")
        client.list_resources("constraints")
    finally:
        client.close()
    assert resolver.calls == [("kb.example", 443), ("kb.example", 443)]


def test_redirects_rejected():
    client = _client(lambda request: httpx.Response(302, headers={"location": "https://evil.example", "content-type": "application/json"}), resolver=_resolver("8.8.8.8"))
    try:
        with pytest.raises(OpenRelUnexpectedStatusError):
            client.list_resources("actions")
    finally:
        client.close()


def test_timeout_maps_to_network_error():
    def handler(request: httpx.Request) -> httpx.Response:
        raise httpx.ReadTimeout("timeout")

    client = _client(handler, resolver=_resolver("8.8.8.8"))
    try:
        with pytest.raises(OpenRelNetworkError):
            client.list_resources("actions")
    finally:
        client.close()


def test_non_2xx_maps_to_unexpected_status():
    client = _client(lambda request: httpx.Response(500, headers={"content-type": "application/json"}, json={"error": True}), resolver=_resolver("8.8.8.8"))
    try:
        with pytest.raises(OpenRelUnexpectedStatusError):
            client.list_resources("actions")
    finally:
        client.close()


def test_404_maps_to_not_found():
    client = _client(lambda request: httpx.Response(404, headers={"content-type": "application/json"}, json={"error": True}), resolver=_resolver("8.8.8.8"))
    try:
        with pytest.raises(OpenRelNotFoundError):
            client.get_resource("actions", "odrl:use")
    finally:
        client.close()


def test_content_type_enforced():
    client = _client(lambda request: httpx.Response(200, headers={"content-type": "text/plain"}, text="x"), resolver=_resolver("8.8.8.8"))
    try:
        with pytest.raises(OpenRelInvalidContentTypeError):
            client.list_resources("actions")
    finally:
        client.close()


def test_oversized_response_rejected():
    body = json.dumps([{"iri": "https://openrel.org/ns#a", "definition": "x" * 500}]).encode()
    client = _client(lambda request: httpx.Response(200, headers={"content-type": "application/json"}, stream=httpx.ByteStream(body)), resolver=_resolver("8.8.8.8"), settings_overrides={"max_response_bytes": 64})
    try:
        with pytest.raises(OpenRelResponseTooLargeError):
            client.list_resources("actions")
    finally:
        client.close()


def test_malformed_json_rejected():
    client = _client(lambda request: httpx.Response(200, headers={"content-type": "application/json"}, content=b"{"), resolver=_resolver("8.8.8.8"))
    try:
        with pytest.raises(OpenRelMalformedJsonError):
            client.list_resources("actions")
    finally:
        client.close()


def test_list_and_detail_shape_enforced():
    client = _client(lambda request: httpx.Response(200, headers={"content-type": "application/json"}, json={"iri": "https://openrel.org/ns#a"}), resolver=_resolver("8.8.8.8"))
    try:
        with pytest.raises(OpenRelResponseSchemaError):
            client.list_resources("actions")
    finally:
        client.close()

    client = _client(lambda request: httpx.Response(200, headers={"content-type": "application/json"}, json=[{"iri": "https://openrel.org/ns#a"}]), resolver=_resolver("8.8.8.8"))
    try:
        with pytest.raises(OpenRelResponseSchemaError):
            client.get_resource("actions", "odrl:use")
    finally:
        client.close()


def test_optional_label_and_definition_are_allowed():
    client = _client(lambda request: httpx.Response(200, headers={"content-type": "application/json"}, json=[{"iri": "https://openrel.org/ns#α", "label": None, "definition": "δοκιμή"}]), resolver=_resolver("8.8.8.8"))
    try:
        items = client.list_resources("actions")
    finally:
        client.close()
    assert items[0].label is None
    assert items[0].definition == "δοκιμή"


@pytest.mark.parametrize("payload", [[{"label": "x"}], [{"iri": ""}], [{"iri": "mailto:test@example.com"}], [{"iri": "https://user:pass@example.com/x"}], [{"iri": "https://openrel.org/ns#x", "extra": "bad"}]])
def test_invalid_or_missing_iri_and_schema_violations_are_rejected(payload):
    client = _client(lambda request: httpx.Response(200, headers={"content-type": "application/json"}, json=payload), resolver=_resolver("8.8.8.8"))
    try:
        with pytest.raises(OpenRelResponseSchemaError):
            client.list_resources("actions")
    finally:
        client.close()


def test_cache_hit_avoids_second_transport_request():
    seen = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(request.url.path)
        return httpx.Response(200, headers={"content-type": "application/json"}, json=[{"iri": "https://openrel.org/ns#a"}])

    client = _client(handler, resolver=_resolver("8.8.8.8"), monotonic=iter([0.0, 1.0, 2.0]).__next__)
    try:
        first = client.list_resources("actions")
        second = client.list_resources("actions")
    finally:
        client.close()
    assert first == second
    assert seen == ["/openrel/api/v0.4/actions"]


def test_cache_expires_with_monotonic_clock():
    seen = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(request.url.path)
        return httpx.Response(200, headers={"content-type": "application/json"}, json=[{"iri": "https://openrel.org/ns#a"}])

    client = _client(handler, resolver=_resolver("8.8.8.8"), monotonic=iter([0.0, 2.0, 2.0, 4.0]).__next__, settings_overrides={"cache_ttl_seconds": 1})
    try:
        client.list_resources("actions")
        client.list_resources("actions")
    finally:
        client.close()
    assert seen == ["/openrel/api/v0.4/actions", "/openrel/api/v0.4/actions"]


def test_errors_are_not_cached_and_clear_cache_works():
    count = {"value": 0}

    def handler(request: httpx.Request) -> httpx.Response:
        count["value"] += 1
        if count["value"] == 1:
            return httpx.Response(500, headers={"content-type": "application/json"}, json={"error": True})
        return httpx.Response(200, headers={"content-type": "application/json"}, json=[{"iri": "https://openrel.org/ns#a"}])

    client = _client(handler, resolver=_resolver("8.8.8.8"), monotonic=iter([0.0, 1.0, 2.0, 3.0]).__next__)
    try:
        with pytest.raises(OpenRelUnexpectedStatusError):
            client.list_resources("actions")
        client.list_resources("actions")
        client.clear_cache()
        client.list_resources("actions")
    finally:
        client.close()
    assert count["value"] == 3


def test_availability_requires_validated_response():
    client = _client(lambda request: httpx.Response(200, headers={"content-type": "application/json"}, json=[{"iri": "https://openrel.org/ns#a"}]), resolver=_resolver("8.8.8.8"))
    try:
        assert client.check_availability() is True
    finally:
        client.close()


def test_client_only_uses_get():
    methods = []

    def handler(request: httpx.Request) -> httpx.Response:
        methods.append(request.method)
        return httpx.Response(200, headers={"content-type": "application/json"}, json=[{"iri": "https://openrel.org/ns#a"}])

    client = _client(handler, resolver=_resolver("8.8.8.8"))
    try:
        client.list_resources("actions")
    finally:
        client.close()
    assert methods == ["GET"]
