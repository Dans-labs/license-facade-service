from __future__ import annotations

import json
from dataclasses import dataclass
from html import escape
from typing import Any, Literal
from urllib.parse import urlparse

from pydantic import BaseModel, ConfigDict, Field, HttpUrl, field_validator
from rdflib import Graph


SAFE_SCHEMES = {"https"}
SUPPORTED_RDF_SERIALIZATIONS = {"text/turtle": "turtle", "application/rdf+xml": "xml"}
SUPPORTED_JSON_MEDIA_TYPES = {"application/json", "application/ld+json"}


class CrossReference(BaseModel):
    type: str = Field(..., description="original, machine, legal, or upstream")
    URL: str
    match: bool | None = None
    isValid: bool | None = None
    isLive: bool | None = None
    timeStamp: str | None = None
    isWayBackLink: bool | None = None
    order: int | None = None
    authority: str | None = None
    curator: str | None = None
    provenance: str | None = None
    source: str | None = None
    relation: str | None = None

    @field_validator("URL")
    @classmethod
    def _validate_url(cls, value: str) -> str:
        parsed = urlparse(value)
        if parsed.scheme not in SAFE_SCHEMES:
            raise ValueError("Only https URLs are permitted for public representation targets")
        return value


class RepresentationDescriptor(BaseModel):
    href: str | None = None
    relation: str | None = None
    type: str | None = None
    mediaType: str
    authority: str | None = None
    curator: str | None = None
    provenance: str | None = None
    source: str | None = None
    profile: str | None = None
    vocabulary: str | None = None
    version: str | None = None
    digest: str | None = None
    content: str | dict[str, Any] | None = None

    @field_validator("href")
    @classmethod
    def _validate_href(cls, value: str | None) -> str | None:
        if value is None:
            return value
        parsed = urlparse(value)
        if parsed.scheme not in SAFE_SCHEMES:
            raise ValueError("Only https URLs are permitted for public representation targets")
        return value

    @field_validator("content")
    @classmethod
    def _validate_content(cls, value: str | dict[str, Any] | None) -> str | dict[str, Any] | None:
        if value is None:
            return value
        if isinstance(value, dict):
            return value
        if not isinstance(value, str):
            raise ValueError("content must be JSON text or a JSON object")
        return value


class MachineRepresentation(RepresentationDescriptor):
    profile: str | None = None
    vocabulary: str | None = None
    content: str | dict[str, Any] | None = None


class OriginalRepresentation(RepresentationDescriptor):
    relation: Literal["original"] = "original"


class LegalRepresentation(RepresentationDescriptor):
    relation: Literal["legal"] = "legal"


class EncodingRepresentation(RepresentationDescriptor):
    relation: Literal["encoding"] = "encoding"


class ConformanceRequirement(BaseModel):
    status: Literal["passed", "failed", "unknown"]
    missing: list[str] = Field(default_factory=list)
    note: str | None = None


class ConformanceStatus(BaseModel):
    conformant: bool
    specification: str
    requirements: dict[str, ConformanceRequirement] = Field(default_factory=dict)


class LicenseDetail(BaseModel):
    model_config = ConfigDict(populate_by_name=True)

    uri: str
    referenceNumber: str | None = None
    licenseId: str
    licenseID: str | None = None
    licenceID: str | None = None
    name: str
    detailsURL: str
    spdxDetailsURL: str | None = None
    reference: str | None = None
    isDeprecatedLicenseId: bool
    isDeprecatedLicenseID: bool | None = None
    seeAlso: list[str] = Field(default_factory=list)
    isOsiApproved: bool
    licenseText: str | None = None
    standardLicenseTemplate: str | None = None
    licenseTextHtml: str | None = None
    crossRef: list[CrossReference] = Field(default_factory=list)
    representations: dict[str, RepresentationDescriptor] = Field(default_factory=dict)
    conformance: ConformanceStatus
    links: dict[str, str] = Field(default_factory=dict, alias="_links")


class LicenseInventoryItem(BaseModel):
    uri: str
    licenseId: str
    name: str
    isDeprecatedLicenseId: bool
    isOsiApproved: bool
    seeAlso: list[str] = Field(default_factory=list)
    detailsURL: str | None = None
    reference: str | None = None


class LicenseInventoryResponse(BaseModel):
    licenseListVersion: str | None = None
    licenses: list[LicenseInventoryItem] = Field(default_factory=list)


def safe_escape_text(value: Any) -> str:
    return escape("" if value is None else str(value))


def is_valid_json_document(value: str | dict[str, Any]) -> bool:
    try:
        if isinstance(value, str):
            json.loads(value)
        else:
            json.dumps(value)
        return True
    except ValueError:
        return False


def parse_rdf(value: str, media_type: str) -> Graph:
    graph = Graph()
    graph.parse(data=value, format=SUPPORTED_RDF_SERIALIZATIONS[media_type])
    return graph
