from __future__ import annotations

import pytest

from src.license_facade_service.config.openrel import OpenRelSettings


OPENREL_ENV_KEYS = [
    "OPENREL_ENABLED",
    "OPENREL_BASE_URL",
    "OPENREL_ALLOW_HTTP_FOR_DEMO",
    "OPENREL_CONNECT_TIMEOUT_SECONDS",
    "OPENREL_READ_TIMEOUT_SECONDS",
    "OPENREL_WRITE_TIMEOUT_SECONDS",
    "OPENREL_POOL_TIMEOUT_SECONDS",
    "OPENREL_TOTAL_TIMEOUT_SECONDS",
    "OPENREL_RETRY_ATTEMPTS",
    "OPENREL_RETRY_BASE_SECONDS",
    "OPENREL_RETRY_MAX_SECONDS",
    "OPENREL_MAX_LIST_RESPONSE_BYTES",
    "OPENREL_MAX_DETAIL_RESPONSE_BYTES",
    "OPENREL_MAX_ID_LENGTH",
    "OPENREL_MAX_PREFIX_LENGTH",
    "OPENREL_ALLOWED_PORTS",
    "OPENREL_ALLOWED_HOSTNAMES",
    "OPENREL_ALLOWED_CIDRS",
]


@pytest.fixture(autouse=True)
def clear_openrel_env(monkeypatch: pytest.MonkeyPatch):
    for key in OPENREL_ENV_KEYS:
        monkeypatch.delenv(key, raising=False)


def test_openrel_defaults_disabled():
    settings = OpenRelSettings.from_env()
    assert settings.enabled is False
    assert settings.base_url is None
    assert settings.allow_http_for_demo is False
    assert settings.connect_timeout_seconds == 5.0
    assert settings.read_timeout_seconds == 15.0
    assert settings.write_timeout_seconds == 10.0
    assert settings.pool_timeout_seconds == 5.0
    assert settings.total_timeout_seconds == 20.0
    assert settings.retry_attempts == 3
    assert settings.retry_base_seconds == 0.2
    assert settings.retry_max_seconds == 2.0
    assert settings.max_list_response_bytes == 2_000_000
    assert settings.max_detail_response_bytes == 512_000
    assert settings.max_id_length == 2048
    assert settings.max_prefix_length == 128
    assert settings.allowed_ports == (443,)
    assert settings.allowed_hostnames == ()
    assert settings.allowed_cidrs == ()
    assert settings.validation_errors == ()


def test_openrel_enabled_requires_base_url(monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setenv("OPENREL_ENABLED", "true")
    settings = OpenRelSettings.from_env()
    assert settings.enabled is True
    assert "OPENREL_BASE_URL is required when OPENREL_ENABLED=true" in settings.validation_errors


def test_openrel_https_base_url_normalization(monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setenv("OPENREL_ENABLED", "true")
    monkeypatch.setenv("OPENREL_BASE_URL", "https://ExAmple.Org/openrel/api/v0.4/")
    settings = OpenRelSettings.from_env()
    assert settings.validation_errors == ()
    assert settings.base_hostname == "example.org"
    assert settings.base_port == 443
    assert settings.base_url == "https://example.org/openrel/api/v0.4"


def test_openrel_http_requires_demo_flag(monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setenv("OPENREL_ENABLED", "true")
    monkeypatch.setenv("OPENREL_BASE_URL", "http://example.org/openrel/api/v0.4")
    settings = OpenRelSettings.from_env()
    assert any("must use https" in err for err in settings.validation_errors)

    monkeypatch.setenv("OPENREL_ALLOW_HTTP_FOR_DEMO", "true")
    monkeypatch.setenv("OPENREL_ALLOWED_PORTS", "80,443")
    demo_settings = OpenRelSettings.from_env()
    assert demo_settings.validation_errors == ()
    assert demo_settings.base_url == "http://example.org/openrel/api/v0.4"


def test_openrel_base_url_rejects_credentials_query_fragment(monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setenv("OPENREL_ENABLED", "true")
    monkeypatch.setenv("OPENREL_BASE_URL", "https://user:pass@example.org/openrel/api/v0.4?x=1#f")
    settings = OpenRelSettings.from_env()
    errors = "\n".join(settings.validation_errors)
    assert "must not include URL credentials" in errors
    assert "must not include URL query parameters" in errors
    assert "must not include URL fragments" in errors


@pytest.mark.parametrize(
    "url",
    [
        "https://example.org:bad/openrel/api/v0.4",
        "https://example.org:70000/openrel/api/v0.4",
        "https://[2001:db8::zz]/openrel/api/v0.4",
        "https:///openrel/api/v0.4",
        "https://exa mple.org/openrel/api/v0.4",
        "ftp://example.org/openrel/api/v0.4",
    ],
)
def test_openrel_base_url_invalid_forms_are_captured(monkeypatch: pytest.MonkeyPatch, url: str):
    monkeypatch.setenv("OPENREL_ENABLED", "true")
    monkeypatch.setenv("OPENREL_BASE_URL", url)
    settings = OpenRelSettings.from_env()
    assert settings.validation_errors


def test_openrel_base_url_ipv6_literal_is_normalized_with_brackets(monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setenv("OPENREL_ENABLED", "true")
    monkeypatch.setenv("OPENREL_BASE_URL", "https://[2001:db8::1]/openrel/api/v0.4")
    settings = OpenRelSettings.from_env()
    assert settings.validation_errors == ()
    assert settings.base_hostname == "2001:db8::1"
    assert settings.base_url == "https://[2001:db8::1]/openrel/api/v0.4"


def test_openrel_base_url_dot_segments_rejected(monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setenv("OPENREL_ENABLED", "true")
    monkeypatch.setenv("OPENREL_BASE_URL", "https://example.org/openrel/api/v0.4/../admin")
    settings = OpenRelSettings.from_env()
    assert "OPENREL_BASE_URL path must not contain dot-segments" in settings.validation_errors

    monkeypatch.setenv("OPENREL_BASE_URL", "https://example.org/openrel/api/v0.4/%2e%2e/admin")
    settings_encoded = OpenRelSettings.from_env()
    assert "OPENREL_BASE_URL path must not contain dot-segments" in settings_encoded.validation_errors


def test_openrel_port_must_be_allowlisted(monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setenv("OPENREL_ENABLED", "true")
    monkeypatch.setenv("OPENREL_BASE_URL", "https://example.org:8443/openrel/api/v0.4")
    settings = OpenRelSettings.from_env()
    assert "OPENREL_BASE_URL port must be listed in OPENREL_ALLOWED_PORTS" in settings.validation_errors

    monkeypatch.setenv("OPENREL_ALLOWED_PORTS", "443,8443")
    settings_allowed = OpenRelSettings.from_env()
    assert settings_allowed.validation_errors == ()
    assert settings_allowed.base_url == "https://example.org:8443/openrel/api/v0.4"


@pytest.mark.parametrize(
    ("name", "value"),
    [
        ("OPENREL_CONNECT_TIMEOUT_SECONDS", "nan"),
        ("OPENREL_READ_TIMEOUT_SECONDS", "inf"),
        ("OPENREL_WRITE_TIMEOUT_SECONDS", "-1"),
        ("OPENREL_POOL_TIMEOUT_SECONDS", "0"),
        ("OPENREL_TOTAL_TIMEOUT_SECONDS", "61"),
        ("OPENREL_RETRY_BASE_SECONDS", "nan"),
        ("OPENREL_RETRY_MAX_SECONDS", "0"),
    ],
)
def test_openrel_float_boundaries(monkeypatch: pytest.MonkeyPatch, name: str, value: str):
    monkeypatch.setenv("OPENREL_ENABLED", "true")
    monkeypatch.setenv("OPENREL_BASE_URL", "https://example.org/openrel/api/v0.4")
    monkeypatch.setenv(name, value)
    settings = OpenRelSettings.from_env()
    assert settings.validation_errors


@pytest.mark.parametrize(
    ("name", "value"),
    [
        ("OPENREL_RETRY_ATTEMPTS", "0"),
        ("OPENREL_RETRY_ATTEMPTS", "6"),
        ("OPENREL_MAX_LIST_RESPONSE_BYTES", "0"),
        ("OPENREL_MAX_DETAIL_RESPONSE_BYTES", "-1"),
        ("OPENREL_MAX_ID_LENGTH", "0"),
        ("OPENREL_MAX_PREFIX_LENGTH", "0"),
    ],
)
def test_openrel_int_boundaries(monkeypatch: pytest.MonkeyPatch, name: str, value: str):
    monkeypatch.setenv("OPENREL_ENABLED", "true")
    monkeypatch.setenv("OPENREL_BASE_URL", "https://example.org/openrel/api/v0.4")
    monkeypatch.setenv(name, value)
    settings = OpenRelSettings.from_env()
    assert settings.validation_errors


def test_openrel_retry_max_must_not_be_lower_than_base(monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setenv("OPENREL_ENABLED", "true")
    monkeypatch.setenv("OPENREL_BASE_URL", "https://example.org/openrel/api/v0.4")
    monkeypatch.setenv("OPENREL_RETRY_BASE_SECONDS", "2")
    monkeypatch.setenv("OPENREL_RETRY_MAX_SECONDS", "1")
    settings = OpenRelSettings.from_env()
    assert "OPENREL_RETRY_MAX_SECONDS must be >= OPENREL_RETRY_BASE_SECONDS" in settings.validation_errors


def test_openrel_allowed_ports_unique_and_valid(monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setenv("OPENREL_ALLOWED_PORTS", "443,443,8443")
    settings = OpenRelSettings.from_env()
    assert settings.allowed_ports == (443, 8443)

    monkeypatch.setenv("OPENREL_ALLOWED_PORTS", "443,0")
    bad = OpenRelSettings.from_env()
    assert bad.validation_errors


def test_openrel_allowed_hostnames_and_cidrs(monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setenv("OPENREL_ALLOWED_HOSTNAMES", "Ä.example.org, example.org")
    monkeypatch.setenv("OPENREL_ALLOWED_CIDRS", "10.0.0.0/24,2001:db8::/32")
    settings = OpenRelSettings.from_env()
    assert "xn--4ca.example.org" in settings.allowed_hostnames
    assert "example.org" in settings.allowed_hostnames
    assert "10.0.0.0/24" in settings.allowed_cidrs
    assert "2001:db8::/32" in settings.allowed_cidrs

    monkeypatch.setenv("OPENREL_ALLOWED_CIDRS", "not-a-cidr")
    bad_cidr = OpenRelSettings.from_env()
    assert bad_cidr.validation_errors

    monkeypatch.setenv("OPENREL_ALLOWED_HOSTNAMES", "bad host")
    bad_host = OpenRelSettings.from_env()
    assert bad_host.validation_errors


def test_openrel_strict_boolean_values(monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setenv("OPENREL_ENABLED", "maybe")
    settings = OpenRelSettings.from_env()
    assert "OPENREL_ENABLED must be a supported boolean value" in settings.validation_errors

    monkeypatch.setenv("OPENREL_ENABLED", "true")
    monkeypatch.setenv("OPENREL_ALLOW_HTTP_FOR_DEMO", "2")
    settings2 = OpenRelSettings.from_env()
    assert "OPENREL_ALLOW_HTTP_FOR_DEMO must be a supported boolean value" in settings2.validation_errors
