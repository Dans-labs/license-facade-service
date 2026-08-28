from __future__ import annotations

from copy import deepcopy
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Callable
from urllib.parse import quote

from src.license_facade_service.services.licenses import ResolvedLicense
from src.license_facade_service.services.licenses import ResolvedLicenseSource
from src.license_facade_service.services.spdx_custom_license import validate_http_iri
from src.license_facade_service.services.spdx_validation import Spdx301StructuralValidator


def _utc_now() -> datetime:
    return datetime.now(timezone.utc)


class Spdx3DocumentGenerationError(RuntimeError):
    """Raised when SPDX 3 document generation cannot proceed safely."""


@dataclass(frozen=True)
class Spdx3DocumentService:
    validator: Spdx301StructuralValidator
    now_provider: Callable[[], datetime]
    complete_namespace: str
    creator_name: str

    def __init__(
        self,
        *,
        validator: Spdx301StructuralValidator | None = None,
        now_provider: Callable[[], datetime] | None = None,
        complete_namespace: str = "https://spdx.org/spdxdocs/lfs",
        creator_name: str = "License Facade Service",
    ) -> None:
        object.__setattr__(self, "validator", validator or Spdx301StructuralValidator())
        object.__setattr__(self, "now_provider", now_provider or _utc_now)
        object.__setattr__(self, "complete_namespace", validate_http_iri(complete_namespace, "complete_namespace"))
        object.__setattr__(self, "creator_name", creator_name.strip() or "License Facade Service")

    def _now_z(self) -> str:
        now = self.now_provider()
        if now.tzinfo is None:
            raise ValueError("now_provider must return a timezone-aware datetime.")
        return now.astimezone(timezone.utc).replace(microsecond=0).strftime("%Y-%m-%dT%H:%M:%SZ")

    @staticmethod
    def _iri(base: str, *segments: str) -> str:
        cleaned = [quote(segment, safe="") for segment in segments]
        return f"{base.rstrip('/')}/{'/'.join(cleaned)}"

    @staticmethod
    def _license_type_for_source(source: ResolvedLicenseSource) -> str:
        if source == ResolvedLicenseSource.SPDX_LISTED:
            return "expandedlicensing_ListedLicense"
        if source in {ResolvedLicenseSource.LOCAL_CUSTOM, ResolvedLicenseSource.FEDERATED_CUSTOM}:
            return "expandedlicensing_CustomLicense"
        raise Spdx3DocumentGenerationError("Unsupported resolved license source.")

    def create_minimal_document(self, *, name: str, namespace: str) -> dict[str, object]:
        validated_namespace = validate_http_iri(namespace, "namespace")
        cleaned_name = name.strip()
        if not cleaned_name:
            raise ValueError("name must be non-blank.")

        created = self._now_z()
        creation_info_id = "_:creation-info"
        creator_id = self._iri(validated_namespace, "actors", "lfs-operator")
        document_id = self._iri(validated_namespace, "documents", "minimal")

        document: dict[str, object] = {
            "@context": "https://spdx.org/rdf/3.0.1/spdx-context.jsonld",
            "@graph": [
                {
                    "@id": creation_info_id,
                    "type": "CreationInfo",
                    "specVersion": "3.0.1",
                    "created": created,
                    "createdBy": [creator_id],
                },
                {
                    "type": "Organization",
                    "spdxId": creator_id,
                    "name": self.creator_name,
                    "creationInfo": creation_info_id,
                },
                {
                    "type": "SpdxDocument",
                    "spdxId": document_id,
                    "name": cleaned_name,
                    "creationInfo": creation_info_id,
                    "rootElement": [creator_id],
                },
            ],
        }
        self.validator.validate(document)
        return deepcopy(document)

    def create_complete_license_document(self, *, resolved: ResolvedLicense) -> dict[str, object]:
        created = self._now_z()
        creation_info_id = "_:creation-info"
        creator_id = self._iri(self.complete_namespace, "actors", "lfs-operator")
        license_component = resolved.license_id
        document_id = self._iri(self.complete_namespace, license_component)
        license_id = self._iri(self.complete_namespace, "licenses", license_component)

        name = resolved.details.get("name") or resolved.record.get("name") or resolved.license_id
        if not isinstance(name, str):
            name = resolved.license_id
        license_text = resolved.details.get("licenseText")
        if not isinstance(license_text, str):
            raise Spdx3DocumentGenerationError("Resolved licence is missing an authoritative licenseText string.")

        license_type = self._license_type_for_source(resolved.source)
        license_node: dict[str, Any] = {
            "type": license_type,
            "spdxId": license_id,
            "creationInfo": creation_info_id,
            "name": name,
            "simplelicensing_licenseText": license_text,
        }
        template = resolved.details.get("standardLicenseTemplate")
        if isinstance(template, str) and template != "":
            license_node["expandedlicensing_standardLicenseTemplate"] = template

        document: dict[str, object] = {
            "@context": "https://spdx.org/rdf/3.0.1/spdx-context.jsonld",
            "@graph": [
                {
                    "@id": creation_info_id,
                    "type": "CreationInfo",
                    "specVersion": "3.0.1",
                    "created": created,
                    "createdBy": [creator_id],
                },
                {
                    "type": "Organization",
                    "spdxId": creator_id,
                    "name": self.creator_name,
                    "creationInfo": creation_info_id,
                },
                {
                    "type": "SpdxDocument",
                    "spdxId": document_id,
                    "rootElement": [license_id],
                    "name": f"SPDX Document for {resolved.license_id}",
                    "creationInfo": creation_info_id,
                },
                license_node,
            ],
        }
        self.validator.validate(document)
        return deepcopy(document)
