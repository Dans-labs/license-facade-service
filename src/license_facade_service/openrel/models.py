from __future__ import annotations

from typing import Any, Required, NotRequired

from pydantic import TypeAdapter, ValidationError
from pydantic.config import ConfigDict
from typing_extensions import TypedDict


class OpenRELResource(TypedDict):
    __pydantic_config__ = ConfigDict(extra="ignore")

    iri: Required[str]
    label: NotRequired[str]
    definition: NotRequired[str]


class OpenRELMapping(TypedDict):
    __pydantic_config__ = ConfigDict(extra="ignore")

    iri: Required[str]
    label: NotRequired[str]
    definition: NotRequired[str]


_resource_adapter = TypeAdapter(OpenRELResource)
_resource_list_adapter = TypeAdapter(list[OpenRELResource])
_mapping_adapter = TypeAdapter(OpenRELMapping)
_mapping_list_adapter = TypeAdapter(list[OpenRELMapping])


def _validate_iri(value: str) -> None:
    if value.strip() == "":
        raise ValidationError.from_exception_data(
            title="OpenRELResource",
            line_errors=[
                {
                    "type": "value_error",
                    "loc": ("iri",),
                    "msg": "iri must not be empty or whitespace-only",
                    "input": value,
                    "ctx": {"error": ValueError("iri must not be empty or whitespace-only")},
                }
            ],
        )


def validate_openrel_resource(payload: Any) -> OpenRELResource:
    item = _resource_adapter.validate_python(payload)
    _validate_iri(item["iri"])
    return item


def validate_openrel_resource_list(payload: Any) -> list[OpenRELResource]:
    items = _resource_list_adapter.validate_python(payload)
    for item in items:
        _validate_iri(item["iri"])
    return items


def validate_openrel_mapping(payload: Any) -> OpenRELMapping:
    item = _mapping_adapter.validate_python(payload)
    _validate_iri(item["iri"])
    return item


def validate_openrel_mapping_list(payload: Any) -> list[OpenRELMapping]:
    items = _mapping_list_adapter.validate_python(payload)
    for item in items:
        _validate_iri(item["iri"])
    return items


def openrel_resource_json_schema() -> dict[str, Any]:
    return _resource_adapter.json_schema()


def openrel_mapping_json_schema() -> dict[str, Any]:
    return _mapping_adapter.json_schema()
