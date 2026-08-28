from __future__ import annotations

import asyncio
from dataclasses import replace
from datetime import datetime, timedelta, timezone
from email.utils import format_datetime
from typing import Any

import httpx
import pytest

from src.license_facade_service.config.openrel import OpenRelSettings
from src.license_facade_service.openrel.client import (
    OpenRelClient,
    OpenRelClientError,
    OpenRelErrorCode,
)


def _settings(**overrides: Any) -> OpenRelSettings:
    base = OpenRelSettings(
        enabled=True,
        base_url="https://provider.example/openrel/api/v0.4",
        base_scheme="https",
        base_hostname="provider.example",
        base_port=443,
        allow_http_for_demo=False,
        connect_timeout_seconds=5.0,
        read_timeout_seconds=15.0,
        write_timeout_seconds=10.0,
        pool_timeout_seconds=5.0,
        total_timeout_seconds=20.0,
        retry_attempts=3,
        retry_base_seconds=0.2,
        retry_max_seconds=2.0,
        max_list_response_bytes=2_000_000,
        max_detail_response_bytes=512_000,
        max_id_length=2048,
        max_prefix_length=128,
        allowed_ports=(443,),
        allowed_hostnames=(),
        allowed_cidrs=(),
        validation_errors=(),
    )
    return replace(base, **overrides)


def _run(coro):
    return asyncio.run(coro)


async def _resolver_public(_hostname: str, _port: int) -> list[str]:
    return ["8.8.8.8"]


def _json_array_handler(payload: list[dict[str, Any]] | None = None):
    data = payload if payload is not None else []

    def handler(_request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, headers={"content-type": "application/json"}, json=data)

    return handler


def test_disabled_and_invalid_configuration_fail_fast():
    client_disabled = OpenRelClient(_settings(enabled=False), resolver=_resolver_public)
    with pytest.raises(OpenRelClientError) as disabled:
        _run(client_disabled.list_resources("actions"))
    assert disabled.value.code == OpenRelErrorCode.DISABLED
    _run(client_disabled.aclose())

    client_invalid = OpenRelClient(_settings(validation_errors=("bad",)), resolver=_resolver_public)
    with pytest.raises(OpenRelClientError) as invalid:
        _run(client_invalid.list_resources("actions"))
    assert invalid.value.code == OpenRelErrorCode.INVALID_CONFIGURATION
    _run(client_invalid.aclose())


def test_dns_resolution_async_timeout_is_bounded():
    async def stalled_resolver(_h: str, _p: int) -> list[str]:
        await asyncio.sleep(3600)
        return ["8.8.8.8"]

    client = OpenRelClient(
        _settings(total_timeout_seconds=0.05),
        resolver=stalled_resolver,
        http_client=httpx.AsyncClient(transport=httpx.MockTransport(_json_array_handler()), follow_redirects=False),
    )
    with pytest.raises(OpenRelClientError) as exc:
        _run(client.list_resources("actions"))
    assert exc.value.code == OpenRelErrorCode.TIMEOUT
    _run(client.aclose())


def test_dns_failures_and_malformed_answers_are_typed():
    async def failing_resolver(_h: str, _p: int) -> list[str]:
        raise RuntimeError("boom")

    client_fail = OpenRelClient(_settings(), resolver=failing_resolver)
    with pytest.raises(OpenRelClientError) as exc_fail:
        _run(client_fail.list_resources("actions"))
    assert exc_fail.value.code == OpenRelErrorCode.DNS_FAILURE
    _run(client_fail.aclose())

    async def malformed_resolver(_h: str, _p: int):
        return ["not-an-ip"]

    client_malformed = OpenRelClient(_settings(), resolver=malformed_resolver)
    with pytest.raises(OpenRelClientError) as exc_malformed:
        _run(client_malformed.list_resources("actions"))
    assert exc_malformed.value.code == OpenRelErrorCode.DNS_FAILURE
    _run(client_malformed.aclose())

    async def empty_resolver(_h: str, _p: int):
        return []

    client_empty = OpenRelClient(_settings(), resolver=empty_resolver)
    with pytest.raises(OpenRelClientError) as exc_empty:
        _run(client_empty.list_resources("actions"))
    assert exc_empty.value.code == OpenRelErrorCode.DNS_FAILURE
    _run(client_empty.aclose())


def test_dns_policy_blocks_ipv4_mapped_ipv6_and_unsafe_ipv6():
    async def mapped_resolver(_h: str, _p: int):
        return ["::ffff:10.0.0.5"]

    client_mapped = OpenRelClient(_settings(), resolver=mapped_resolver)
    with pytest.raises(OpenRelClientError) as exc_mapped:
        _run(client_mapped.list_resources("actions"))
    assert exc_mapped.value.code == OpenRelErrorCode.FORBIDDEN_DESTINATION
    _run(client_mapped.aclose())

    async def link_local_resolver(_h: str, _p: int):
        return ["fe80::1"]

    client_link = OpenRelClient(_settings(), resolver=link_local_resolver)
    with pytest.raises(OpenRelClientError) as exc_link:
        _run(client_link.list_resources("actions"))
    assert exc_link.value.code == OpenRelErrorCode.FORBIDDEN_DESTINATION
    _run(client_link.aclose())


def test_private_destination_requires_hostname_and_cidr_and_rejects_mixed_sets():
    async def private_resolver(_h: str, _p: int):
        return ["10.0.0.7"]

    client_denied = OpenRelClient(_settings(), resolver=private_resolver)
    with pytest.raises(OpenRelClientError) as denied:
        _run(client_denied.list_resources("actions"))
    assert denied.value.code == OpenRelErrorCode.FORBIDDEN_DESTINATION
    _run(client_denied.aclose())

    client_allowed = OpenRelClient(
        _settings(
            base_url="http://provider.example:8443/openrel/api/v0.4",
            base_scheme="http",
            base_port=8443,
            allow_http_for_demo=True,
            allowed_ports=(443, 8443),
            allowed_hostnames=("provider.example",),
            allowed_cidrs=("10.0.0.0/24",),
        ),
        resolver=private_resolver,
        http_client=httpx.AsyncClient(transport=httpx.MockTransport(_json_array_handler()), follow_redirects=False),
    )
    assert _run(client_allowed.list_resources("actions")) == []
    _run(client_allowed.aclose())

    async def mixed_public_private(_h: str, _p: int):
        return ["8.8.8.8", "10.0.0.7"]

    client_mixed = OpenRelClient(
        _settings(allowed_hostnames=("provider.example",), allowed_cidrs=("10.0.0.0/24",)),
        resolver=mixed_public_private,
    )
    with pytest.raises(OpenRelClientError) as mixed:
        _run(client_mixed.list_resources("actions"))
    assert mixed.value.code == OpenRelErrorCode.FORBIDDEN_DESTINATION
    _run(client_mixed.aclose())

    async def mixed_private_allowed_disallowed(_h: str, _p: int):
        return ["10.0.0.7", "10.1.0.7"]

    client_mixed_private = OpenRelClient(
        _settings(allowed_hostnames=("provider.example",), allowed_cidrs=("10.0.0.0/24",)),
        resolver=mixed_private_allowed_disallowed,
    )
    with pytest.raises(OpenRelClientError) as mixed_private:
        _run(client_mixed_private.list_resources("actions"))
    assert mixed_private.value.code == OpenRelErrorCode.FORBIDDEN_DESTINATION
    _run(client_mixed_private.aclose())


def test_fixed_route_families_and_mapping_detail_restriction():
    client = OpenRelClient(_settings(), resolver=_resolver_public)
    with pytest.raises(OpenRelClientError):
        _run(client.list_resources("mappings"))  # must use dedicated method
    with pytest.raises(OpenRelClientError):
        _run(client.get_resource("mappings", "x"))  # type: ignore[arg-type]
    _run(client.aclose())


def test_headers_and_no_auth_cookie_forwarding():
    captured = {}

    def handler(request: httpx.Request) -> httpx.Response:
        captured["headers"] = dict(request.headers)
        return httpx.Response(200, headers={"content-type": "application/json"}, json=[])

    http_client = httpx.AsyncClient(transport=httpx.MockTransport(handler), follow_redirects=False)
    client = OpenRelClient(_settings(), http_client=http_client, resolver=_resolver_public)
    _run(client.list_resources("actions"))
    headers = captured["headers"]
    assert headers.get("accept") == "application/json"
    assert headers.get("accept-encoding") == "identity"
    assert headers.get("user-agent") == "license-facade-service/openrel-client"
    assert "authorization" not in headers
    assert "cookie" not in headers
    _run(client.aclose())


@pytest.mark.parametrize(
    ("identifier", "expected_path_suffix"),
    [
        ("MIT", "/openrel/api/v0.4/actions/MIT"),
        ("with space", "/openrel/api/v0.4/actions/with%20space"),
        ("Å", "/openrel/api/v0.4/actions/%C3%85"),
        ("odrl:use", "/openrel/api/v0.4/actions/odrl%3Ause"),
        ("a/b", "/openrel/api/v0.4/actions/a%2Fb"),
        ("a%b", "/openrel/api/v0.4/actions/a%25b"),
        ("a%2Fb", "/openrel/api/v0.4/actions/a%252Fb"),
        ("a#b", "/openrel/api/v0.4/actions/a%23b"),
        ("a?b", "/openrel/api/v0.4/actions/a%3Fb"),
        ("http://example.org/a/b#c?d", "/openrel/api/v0.4/actions/http%3A%2F%2Fexample.org%2Fa%2Fb%23c%3Fd"),
    ],
)
def test_identifier_encoding(identifier: str, expected_path_suffix: str):
    captured = {}

    def handler(request: httpx.Request) -> httpx.Response:
        captured["raw_path"] = request.url.raw_path.decode("latin1")
        return httpx.Response(200, headers={"content-type": "application/json"}, json={"iri": "https://x"})

    http_client = httpx.AsyncClient(transport=httpx.MockTransport(handler), follow_redirects=False)
    client = OpenRelClient(_settings(), http_client=http_client, resolver=_resolver_public)
    _run(client.get_resource("actions", identifier))
    assert captured["raw_path"].startswith(expected_path_suffix)
    _run(client.aclose())


@pytest.mark.parametrize("identifier", ["", ".", "..", "a/../b", "\x00x", "x\x1f"])
def test_identifier_validation_rejects_forbidden_values(identifier: str):
    client = OpenRelClient(_settings(), resolver=_resolver_public)
    with pytest.raises(OpenRelClientError) as exc:
        _run(client.get_resource("actions", identifier))
    assert exc.value.code == OpenRelErrorCode.INVALID_ID
    _run(client.aclose())


def test_prefix_validation_and_encoding():
    captured = {}

    def handler(request: httpx.Request) -> httpx.Response:
        captured["query"] = request.url.query.decode("latin1")
        return httpx.Response(200, headers={"content-type": "application/json"}, json=[])

    http_client = httpx.AsyncClient(transport=httpx.MockTransport(handler), follow_redirects=False)
    client = OpenRelClient(_settings(), http_client=http_client, resolver=_resolver_public)
    _run(client.list_resources("actions", prefix="odrl:"))
    assert captured["query"] == "prefix=odrl%3A"
    _run(client.list_resources("actions", prefix=""))
    assert captured["query"] == ""
    with pytest.raises(OpenRelClientError):
        _run(client.list_resources("actions", prefix="\x00bad"))
    _run(client.aclose())


def test_retry_after_parsing_and_sanitization():
    def make_client_with_429(header_value: str | None, *, wall_now: float = 1_700_000_000.0):
        def handler(_request: httpx.Request) -> httpx.Response:
            headers = {}
            if header_value is not None:
                headers["retry-after"] = header_value
            return httpx.Response(429, headers=headers)

        return OpenRelClient(
            _settings(total_timeout_seconds=20.0, retry_max_seconds=2.0),
            resolver=_resolver_public,
            wall_time_fn=lambda: wall_now,
            http_client=httpx.AsyncClient(transport=httpx.MockTransport(handler), follow_redirects=False),
        )

    c1 = make_client_with_429("5")
    with pytest.raises(OpenRelClientError) as e1:
        _run(c1.list_resources("actions"))
    assert e1.value.code == OpenRelErrorCode.PROVIDER_RATE_LIMITED
    assert e1.value.retry_after_seconds == 2
    _run(c1.aclose())

    future_date = format_datetime(datetime.fromtimestamp(1_700_000_000.0, tz=timezone.utc) + timedelta(seconds=30))
    c2 = make_client_with_429(future_date)
    with pytest.raises(OpenRelClientError) as e2:
        _run(c2.list_resources("actions"))
    assert e2.value.retry_after_seconds == 2
    _run(c2.aclose())

    expired_date = format_datetime(datetime.fromtimestamp(1_700_000_000.0, tz=timezone.utc) - timedelta(seconds=10))
    c3 = make_client_with_429(expired_date)
    with pytest.raises(OpenRelClientError) as e3:
        _run(c3.list_resources("actions"))
    assert e3.value.retry_after_seconds == 0
    _run(c3.aclose())

    c4 = make_client_with_429("not-a-date")
    with pytest.raises(OpenRelClientError) as e4:
        _run(c4.list_resources("actions"))
    assert e4.value.retry_after_seconds is None
    _run(c4.aclose())

    c5 = make_client_with_429("999999")
    with pytest.raises(OpenRelClientError) as e5:
        _run(c5.list_resources("actions"))
    assert e5.value.retry_after_seconds == 2
    _run(c5.aclose())


def test_retries_only_for_transient_failures():
    state = {"count": 0}
    sleeps: list[float] = []

    async def fake_sleep(seconds: float):
        sleeps.append(seconds)

    def transient_handler(_request: httpx.Request) -> httpx.Response:
        state["count"] += 1
        if state["count"] < 3:
            return httpx.Response(503, headers={"retry-after": "5"})
        return httpx.Response(200, headers={"content-type": "application/json"}, json=[])

    client = OpenRelClient(
        _settings(retry_attempts=3),
        resolver=_resolver_public,
        sleep_fn=fake_sleep,
        random_fn=lambda: 0.0,
        http_client=httpx.AsyncClient(transport=httpx.MockTransport(transient_handler), follow_redirects=False),
    )
    assert _run(client.list_resources("actions")) == []
    assert state["count"] == 3
    assert len(sleeps) == 2
    _run(client.aclose())

    state_429 = {"count": 0}

    def rate_limit_handler(_request: httpx.Request) -> httpx.Response:
        state_429["count"] += 1
        return httpx.Response(429, headers={"retry-after": "5"})

    client_429 = OpenRelClient(
        _settings(retry_attempts=5),
        resolver=_resolver_public,
        http_client=httpx.AsyncClient(transport=httpx.MockTransport(rate_limit_handler), follow_redirects=False),
    )
    with pytest.raises(OpenRelClientError) as exc_429:
        _run(client_429.list_resources("actions"))
    assert exc_429.value.code == OpenRelErrorCode.PROVIDER_RATE_LIMITED
    assert state_429["count"] == 1
    _run(client_429.aclose())


def test_total_budget_limits_retry_sleep():
    state = {"count": 0, "now": 0.0}

    async def fake_sleep(seconds: float):
        state["now"] += seconds

    def fake_monotonic() -> float:
        return state["now"]

    def handler(_request: httpx.Request) -> httpx.Response:
        state["count"] += 1
        return httpx.Response(503)

    client = OpenRelClient(
        _settings(total_timeout_seconds=0.3, retry_base_seconds=0.2, retry_max_seconds=2.0, retry_attempts=5),
        resolver=_resolver_public,
        sleep_fn=fake_sleep,
        monotonic_fn=fake_monotonic,
        random_fn=lambda: 0.0,
        http_client=httpx.AsyncClient(transport=httpx.MockTransport(handler), follow_redirects=False),
    )
    with pytest.raises(OpenRelClientError) as exc:
        _run(client.list_resources("actions"))
    assert exc.value.code == OpenRelErrorCode.TIMEOUT
    assert state["count"] <= 5
    _run(client.aclose())


class _FlagStream(httpx.AsyncByteStream):
    def __init__(self, chunks: list[bytes]) -> None:
        self._chunks = chunks
        self.closed = False

    async def __aiter__(self):
        for chunk in self._chunks:
            yield chunk

    async def aclose(self) -> None:
        self.closed = True


def test_response_size_limits_and_response_closure():
    stream = _FlagStream([b'{"abc":', b'"def"}'])

    def handler(_request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            200,
            headers={"content-type": "application/json", "content-length": "3"},
            stream=stream,
        )

    client = OpenRelClient(
        _settings(max_list_response_bytes=100),
        resolver=_resolver_public,
        http_client=httpx.AsyncClient(transport=httpx.MockTransport(handler), follow_redirects=False),
    )
    with pytest.raises(OpenRelClientError) as exc:
        _run(client.list_resources("actions"))
    assert exc.value.code == OpenRelErrorCode.OVERSIZED_RESPONSE
    assert stream.closed is True
    _run(client.aclose())


@pytest.mark.parametrize(
    ("content_type", "accepted"),
    [
        ("application/json", True),
        ("Application/JSON", True),
        ("application/json; charset=utf-8", True),
        ("application/ld+json", True),
        ("application/problem+json", True),
        ("application/+json", False),
        (None, False),
        ("text/json", False),
        ("text/html", False),
    ],
)
def test_content_type_rules(content_type: str | None, accepted: bool):
    def handler(_request: httpx.Request) -> httpx.Response:
        headers: dict[str, str] = {}
        if content_type is not None:
            headers["content-type"] = content_type
            return httpx.Response(200, headers=headers, json=[])
        return httpx.Response(200, headers=headers, content=b"[]")

    client = OpenRelClient(
        _settings(),
        resolver=_resolver_public,
        http_client=httpx.AsyncClient(transport=httpx.MockTransport(handler), follow_redirects=False),
    )
    if accepted:
        assert _run(client.list_resources("actions")) == []
    else:
        with pytest.raises(OpenRelClientError) as exc:
            _run(client.list_resources("actions"))
        assert exc.value.code == OpenRelErrorCode.INVALID_CONTENT_TYPE
    _run(client.aclose())


def test_json_errors_and_shape_validation():
    def malformed_handler(_request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, headers={"content-type": "application/json"}, content=b'{"a":')

    client_malformed = OpenRelClient(
        _settings(),
        resolver=_resolver_public,
        http_client=httpx.AsyncClient(transport=httpx.MockTransport(malformed_handler), follow_redirects=False),
    )
    with pytest.raises(OpenRelClientError) as malformed_err:
        _run(client_malformed.list_resources("actions"))
    assert malformed_err.value.code == OpenRelErrorCode.MALFORMED_JSON
    _run(client_malformed.aclose())

    def duplicate_handler(_request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, headers={"content-type": "application/json"}, content=b'{"iri":"x","iri":"y"}')

    client_dup = OpenRelClient(
        _settings(),
        resolver=_resolver_public,
        http_client=httpx.AsyncClient(transport=httpx.MockTransport(duplicate_handler), follow_redirects=False),
    )
    with pytest.raises(OpenRelClientError) as duplicate_err:
        _run(client_dup.get_resource("actions", "x"))
    assert duplicate_err.value.code == OpenRelErrorCode.DUPLICATE_JSON_KEY
    _run(client_dup.aclose())

    def list_not_array(_request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, headers={"content-type": "application/json"}, json={"not": "array"})

    client_list_shape = OpenRelClient(
        _settings(),
        resolver=_resolver_public,
        http_client=httpx.AsyncClient(transport=httpx.MockTransport(list_not_array), follow_redirects=False),
    )
    with pytest.raises(OpenRelClientError) as list_shape_err:
        _run(client_list_shape.list_resources("actions"))
    assert list_shape_err.value.code == OpenRelErrorCode.INVALID_RESPONSE_SHAPE
    _run(client_list_shape.aclose())

    def detail_not_object(_request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, headers={"content-type": "application/json"}, json=[])

    client_detail_shape = OpenRelClient(
        _settings(),
        resolver=_resolver_public,
        http_client=httpx.AsyncClient(transport=httpx.MockTransport(detail_not_object), follow_redirects=False),
    )
    with pytest.raises(OpenRelClientError) as detail_shape_err:
        _run(client_detail_shape.get_resource("actions", "x"))
    assert detail_shape_err.value.code == OpenRelErrorCode.INVALID_RESPONSE_SHAPE
    _run(client_detail_shape.aclose())

    def invalid_object(_request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, headers={"content-type": "application/json"}, json=[{"label": "missing iri"}])

    client_invalid_schema = OpenRelClient(
        _settings(),
        resolver=_resolver_public,
        http_client=httpx.AsyncClient(transport=httpx.MockTransport(invalid_object), follow_redirects=False),
    )
    with pytest.raises(OpenRelClientError) as schema_err:
        _run(client_invalid_schema.list_resources("actions"))
    assert schema_err.value.code == OpenRelErrorCode.INVALID_RESPONSE_SCHEMA
    _run(client_invalid_schema.aclose())


def test_mappings_validation_uses_distinct_mapping_contract():
    def mappings_ok(_request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, headers={"content-type": "application/json"}, json=[{"iri": "x", "extra": "ignored"}])

    client = OpenRelClient(
        _settings(),
        resolver=_resolver_public,
        http_client=httpx.AsyncClient(transport=httpx.MockTransport(mappings_ok), follow_redirects=False),
    )
    assert _run(client.list_mappings()) == [{"iri": "x"}]
    _run(client.aclose())


def test_injected_http_client_is_not_closed_by_default():
    shared = httpx.AsyncClient(transport=httpx.MockTransport(_json_array_handler()), follow_redirects=False)
    client = OpenRelClient(_settings(), resolver=_resolver_public, http_client=shared)
    _run(client.list_resources("actions"))
    _run(client.aclose())
    assert shared.is_closed is False
    _run(shared.aclose())
