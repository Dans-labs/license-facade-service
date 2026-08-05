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
    URL: str = Field(description="Curated HTTPS target for the related representation or upstream reference.")
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
    href: str | None = Field(default=None, description="Curated external URL for the representation, when the service links out instead of embedding content.")
    relation: str | None = Field(default=None, description="Relationship of the representation to the licence, such as original, legal, or encoding.")
    type: str | None = Field(default=None, description="Application-specific representation classification.")
    mediaType: str = Field(description="Media type for the representation content or linked resource.")
    authority: str | None = Field(default=None, description="Authority responsible for the representation, when known.")
    curator: str | None = Field(default=None, description="Curator responsible for the representation metadata, when known.")
    provenance: str | None = Field(default=None, description="Provenance note describing how the representation was curated.")
    source: str | None = Field(default=None, description="Source URL from which the representation metadata was curated.")
    profile: str | None = Field(default=None, description="Optional profile URI describing the representation semantics.")
    vocabulary: str | None = Field(default=None, description="Optional vocabulary URI used by the representation.")
    version: str | None = Field(default=None, description="Optional representation version label.")
    digest: str | None = Field(default=None, description="Optional digest of the representation content.")
    content: str | dict[str, Any] | None = Field(default=None, description="Embedded representation content when the service returns it directly.")

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
    status: Literal["passed", "failed", "unknown"] = Field(description="Conformance result for a single requirement.")
    missing: list[str] = Field(default_factory=list, description="Representation names or fields still missing for this requirement.")
    note: str | None = Field(default=None, description="Additional conformance note for this requirement.")


class ConformanceStatus(BaseModel):
    conformant: bool = Field(description="Whether the current metadata set satisfies the documented LFS conformance checks.")
    specification: str = Field(description="Specification or profile name used for conformance evaluation.")
    requirements: dict[str, ConformanceRequirement] = Field(default_factory=dict, description="Per-requirement conformance results.")


class LicenseDetail(BaseModel):
    model_config = ConfigDict(populate_by_name=True)

    uri: str = Field(description="Canonical public URI for the licence record.")
    referenceNumber: str | None = None
    licenseId: str = Field(description="Primary SPDX licence ID or equivalent local identifier.")
    licenseID: str | None = None
    licenceID: str | None = None
    name: str = Field(description="Human-readable licence name.")
    detailsURL: str = Field(description="Convenience JSON metadata endpoint for this licence.")
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
    representations: dict[str, RepresentationDescriptor] = Field(default_factory=dict, description="Curated available representations keyed by representation name.")
    conformance: ConformanceStatus = Field(description="Conformance summary for this licence metadata record.")
    links: dict[str, str] = Field(default_factory=dict, alias="_links")


class LicenseInventoryItem(BaseModel):
    uri: str = Field(description="Canonical public URI for the licence record.")
    licenseId: str = Field(description="Primary SPDX licence ID or equivalent local identifier.")
    name: str = Field(description="Human-readable licence name.")
    isDeprecatedLicenseId: bool = Field(description="Whether the identifier is deprecated in SPDX data.")
    isOsiApproved: bool = Field(description="Whether SPDX marks the licence as OSI-approved.")
    seeAlso: list[str] = Field(default_factory=list)
    detailsURL: str | None = None
    reference: str | None = None


class LicenseInventoryResponse(BaseModel):
    licenseListVersion: str | None = Field(default=None, description="SPDX licence list version represented by the local cache snapshot.")
    licenses: list[LicenseInventoryItem] = Field(default_factory=list, description="Licence inventory items available from the local cache snapshot.")


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
