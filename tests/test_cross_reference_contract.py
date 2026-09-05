from pydantic import ValidationError

from src.license_facade_service.services.contract import CrossReference


def test_cross_reference_accepts_local_representation_path():
    item = CrossReference(type="encoding", relation="encoding", URL="/api/v1/licenses/TABLE6/encoding")
    assert item.URL == "/api/v1/licenses/TABLE6/encoding"


def test_cross_reference_accepts_upstream_https_url():
    item = CrossReference(type="upstream", URL="https://upstream.example.org/reference")
    assert item.URL == "https://upstream.example.org/reference"


def test_cross_reference_rejects_upstream_https_missing_host():
    try:
        CrossReference(type="upstream", URL="https:///missing-host")
    except ValidationError as exc:
        assert "must include a host" in str(exc)
    else:
        raise AssertionError("Expected ValidationError for missing-host upstream URL")


def test_cross_reference_rejects_upstream_relative_path():
    try:
        CrossReference(type="upstream", URL="/api/v1/licenses/TABLE6/original")
    except ValidationError as exc:
        assert "Only https URLs are permitted for public representation targets" in str(exc)
    else:
        raise AssertionError("Expected ValidationError for upstream relative path")


def test_cross_reference_rejects_http_url():
    try:
        CrossReference(type="upstream", URL="http://upstream.example.org/reference")
    except ValidationError as exc:
        assert "Only https URLs are permitted for public representation targets" in str(exc)
    else:
        raise AssertionError("Expected ValidationError for insecure upstream URL")


def test_cross_reference_rejects_scheme_relative_local_url():
    try:
        CrossReference(type="legal", relation="legal", URL="//host/path")
    except ValidationError as exc:
        assert "must not include scheme or authority" in str(exc)
    else:
        raise AssertionError("Expected ValidationError for scheme-relative local URL")


def test_cross_reference_rejects_traversal_and_backslash_local_path():
    try:
        CrossReference(type="machine", relation="machine", URL="/api/v1/licenses/../secret")
    except ValidationError as exc:
        assert "must not contain traversal segments" in str(exc)
    else:
        raise AssertionError("Expected ValidationError for traversal local path")

    try:
        CrossReference(type="machine", relation="machine", URL="/api/v1/licenses\\TABLE6\\encoding")
    except ValidationError as exc:
        assert "must not contain backslashes" in str(exc)
    else:
        raise AssertionError("Expected ValidationError for backslash local path")


def test_cross_reference_rejects_unrelated_local_path():
    try:
        CrossReference(type="original", relation="original", URL="/internal/admin")
    except ValidationError as exc:
        assert "must start with /api/v1/licenses/" in str(exc)
    else:
        raise AssertionError("Expected ValidationError for unrelated local path")
