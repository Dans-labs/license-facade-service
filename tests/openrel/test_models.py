from __future__ import annotations

import pytest
from pydantic import ValidationError

from src.license_facade_service.openrel.models import (
    openrel_mapping_json_schema,
    openrel_resource_json_schema,
    validate_openrel_mapping_list,
    validate_openrel_resource,
    validate_openrel_resource_list,
)


def test_missing_iri_is_rejected():
    with pytest.raises(ValidationError):
        validate_openrel_resource({"label": "x"})


def test_null_and_blank_iri_rejected():
    with pytest.raises(ValidationError):
        validate_openrel_resource({"iri": None})
    with pytest.raises(ValidationError):
        validate_openrel_resource({"iri": "   "})


def test_optional_fields_may_be_omitted_but_not_null():
    item = validate_openrel_resource({"iri": "https://example.org/a"})
    assert item == {"iri": "https://example.org/a"}

    with pytest.raises(ValidationError):
        validate_openrel_resource({"iri": "https://example.org/a", "label": None})
    with pytest.raises(ValidationError):
        validate_openrel_resource({"iri": "https://example.org/a", "definition": None})


def test_unknown_fields_are_accepted_and_omitted_from_output():
    item = validate_openrel_resource(
        {
            "iri": "https://example.org/a",
            "label": "Alpha",
            "definition": "desc",
            "unknown": "x",
        }
    )
    assert item == {
        "iri": "https://example.org/a",
        "label": "Alpha",
        "definition": "desc",
    }
    assert "unknown" not in item


def test_omitted_fields_stay_omitted_after_validation():
    item = validate_openrel_resource({"iri": "https://example.org/a"})
    assert "label" not in item
    assert "definition" not in item


def test_json_schema_required_and_non_nullable_shape():
    schema = openrel_resource_json_schema()
    assert schema["type"] == "object"
    assert schema["required"] == ["iri"]
    assert schema["properties"]["iri"]["type"] == "string"
    assert schema["properties"]["label"]["type"] == "string"
    assert schema["properties"]["definition"]["type"] == "string"
    assert "anyOf" not in schema["properties"]["label"]
    assert "anyOf" not in schema["properties"]["definition"]


def test_resource_list_order_preserved_and_invalid_item_fails_whole_response():
    payload = [
        {"iri": "https://example.org/1", "label": "1"},
        {"iri": "https://example.org/2", "definition": "2"},
    ]
    validated = validate_openrel_resource_list(payload)
    assert [item["iri"] for item in validated] == ["https://example.org/1", "https://example.org/2"]

    with pytest.raises(ValidationError):
        validate_openrel_resource_list([{"iri": "https://example.org/1"}, {"label": "missing iri"}])


def test_mapping_list_validation_uses_distinct_mapping_contract():
    payload = [
        {"iri": "https://example.org/m1", "label": "m1"},
        {"iri": "https://example.org/m2", "definition": "m2"},
    ]
    mappings = validate_openrel_mapping_list(payload)
    assert len(mappings) == 2
    assert mappings[0]["iri"] == "https://example.org/m1"

    schema = openrel_mapping_json_schema()
    assert schema["required"] == ["iri"]
