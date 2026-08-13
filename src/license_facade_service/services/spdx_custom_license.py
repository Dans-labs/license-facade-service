from __future__ import annotations

import ipaddress
import re
from copy import deepcopy
from dataclasses import dataclass
from datetime import datetime, timezone
from urllib.parse import quote, unquote, urlsplit, urlunsplit

from src.license_facade_service.services.spdx_validation import Spdx301StructuralValidator, SpdxStructuralValidationError

_HOSTNAME_RE = re.compile(
    r"^(?=.{1,253}$)(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?)(?:\.(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?))*$|^localhost$"
)


def validate_http_iri(value: str, field_name: str) -> str:
    if not isinstance(value, str):
        raise ValueError(f"{field_name} must be a string.")
    candidate = value.strip()
    if not candidate:
        raise ValueError(f"{field_name} must be a non-empty absolute HTTP(S) IRI.")
    if any(ord(ch) < 32 or ord(ch) == 127 for ch in candidate):
        raise ValueError(f"{field_name} must not contain control characters.")
    if "\\" in candidate:
        raise ValueError(f"{field_name} must not contain backslashes.")
    if "?" in candidate or "#" in candidate:
        raise ValueError(f"{field_name} must not include a query string or fragment.")

    parsed = urlsplit(candidate)
    if parsed.scheme not in {"http", "https"}:
        raise ValueError(f"{field_name} must be an absolute HTTP(S) IRI.")
    if parsed.username is not None or parsed.password is not None:
        raise ValueError(f"{field_name} must not contain credentials.")
    if parsed.query or parsed.fragment:
        raise ValueError(f"{field_name} must not include a query string or fragment.")
    if not parsed.hostname:
        raise ValueError(f"{field_name} must include a hostname.")

    try:
        port = parsed.port
    except ValueError as exc:
        raise ValueError(f"{field_name} contains an invalid port.") from exc
    if port is not None and not 1 <= port <= 65535:
        raise ValueError(f"{field_name} contains a malformed port.")

    hostname = parsed.hostname
    if not hostname:
        raise ValueError(f"{field_name} must include a hostname.")
    if hostname.startswith(".") or hostname.endswith("."):
        raise ValueError(f"{field_name} has an invalid hostname.")
    try:
        ipaddress.ip_address(hostname)
    except ValueError:
        if not _HOSTNAME_RE.fullmatch(hostname):
            raise ValueError(f"{field_name} has a malformed hostname.")

    return urlunsplit((parsed.scheme, parsed.netloc, parsed.path.rstrip("/") or "", "", ""))


def validate_custom_license_identifier(value: str) -> str:
    if not isinstance(value, str):
        raise TypeError("custom_license_id must be a string.")
    candidate = value.strip()
    if not candidate:
        raise ValueError("custom_license_id must be non-empty after trimming.")
    if any(ord(ch) < 32 or ord(ch) == 127 for ch in candidate):
        raise ValueError("custom_license_id contains control characters.")
    if "%" in candidate:
        raise ValueError("custom_license_id must be a raw identifier and cannot contain percent-encoding.")
    if any(ch in candidate for ch in ("/", "\\", "?", "#")):
        raise ValueError("custom_license_id cannot include path separators or URL fragments.")
    decoded = unquote(candidate)
    lowered = decoded.lower()
    if "//" in decoded or lowered.startswith("http://") or lowered.startswith("https://"):
        raise ValueError("custom_license_id must not be an absolute URL.")
    if re.match(r"^[A-Za-z][A-Za-z0-9+.-]*:", decoded):
        raise ValueError("custom_license_id must not look like a URI scheme.")
    if any(segment in {"", ".", ".."} for segment in decoded.split("/")):
        raise ValueError("custom_license_id cannot contain dot-segments or empty path segments.")
    if "%2f" in candidate.lower() or "%2e" in candidate.lower():
        raise ValueError("custom_license_id must not contain encoded path separators or dot-segments.")
    return candidate


@dataclass(frozen=True)
class SpdxCustomLicenseBuilderInput:
    authority_base_iri: str
    creator_organization_name: str
    creator_organization_iri: str | None = None
    custom_license_id: str = "DANS-Custom-1.0"
    name: str = "DANS Custom License v1.0"
    summary: str | None = None
    description: str | None = None
    license_text: str = ""
    created_at: datetime | None = None


class SpdxCustomLicenseBuilder:
    def __init__(self, *, validator: Spdx301StructuralValidator | None = None) -> None:
        self.validator = validator or Spdx301StructuralValidator()

    def build(self, input_data: SpdxCustomLicenseBuilderInput) -> dict[str, object]:
        authority_base = validate_http_iri(input_data.authority_base_iri, "authority_base_iri")
        creator_name = input_data.creator_organization_name.strip()
        if not creator_name:
            raise ValueError("creator_organization_name must be non-empty after trimming.")

        license_name = input_data.name.strip()
        if not license_name:
            raise ValueError("name must be non-empty after trimming.")

        if not isinstance(input_data.license_text, str) or not input_data.license_text.strip():
            raise ValueError("license_text is required.")
        # Preserve authoritative legal text exactly as submitted; digest normalization is separate.
        license_text = input_data.license_text

        if input_data.created_at is not None and input_data.created_at.tzinfo is None:
            raise ValueError("created_at must be timezone-aware.")

        created_at = (input_data.created_at or datetime.now(timezone.utc)).astimezone(timezone.utc)
        created_text = created_at.strftime("%Y-%m-%dT%H:%M:%SZ")

        creator_iri = input_data.creator_organization_iri
        if creator_iri is not None:
            creator_iri = validate_http_iri(creator_iri, "creator_organization_iri")
        else:
            creator_iri = authority_base.rstrip("/") + "/spdx/agents/lfs-operator"

        custom_id = validate_custom_license_identifier(input_data.custom_license_id)
        encoded_id = quote(custom_id, safe="")
        base_path = urlsplit(authority_base).path.rstrip("/")
        spdx_id = urlunsplit(
            (
                urlsplit(authority_base).scheme,
                urlsplit(authority_base).netloc,
                f"{base_path}/licenses/{encoded_id}" if base_path else f"/licenses/{encoded_id}",
                "",
                "",
            )
        )
        if not spdx_id.startswith(authority_base.rstrip("/")):
            raise ValueError("generated licence IRI escapes the configured authority base.")

        document: dict[str, object] = {
            "@context": "https://spdx.org/rdf/3.0.1/spdx-context.jsonld",
            "@graph": [
                {
                    "type": "Organization",
                    "spdxId": creator_iri,
                    "name": creator_name,
                    "creationInfo": "_:creation-info",
                },
                {
                    "@id": "_:creation-info",
                    "type": "CreationInfo",
                    "specVersion": "3.0.1",
                    "created": created_text,
                    "createdBy": [creator_iri],
                },
                {
                    "type": "expandedlicensing_CustomLicense",
                    "spdxId": spdx_id,
                    "creationInfo": "_:creation-info",
                    "name": license_name,
                    "simplelicensing_licenseText": license_text,
                },
            ],
        }

        if input_data.summary is not None:
            summary = input_data.summary.strip()
            if summary:
                document["@graph"][2]["summary"] = summary
        if input_data.description is not None:
            description = input_data.description.strip()
            if description:
                document["@graph"][2]["description"] = description

        try:
            self.validator.validate(document)
        except SpdxStructuralValidationError as exc:
            raise SpdxStructuralValidationError(f"Generated SPDX custom license is invalid: {exc}") from exc
        return deepcopy(document)


__all__ = [
    "SpdxCustomLicenseBuilder",
    "SpdxCustomLicenseBuilderInput",
    "validate_custom_license_identifier",
    "validate_http_iri",
]
