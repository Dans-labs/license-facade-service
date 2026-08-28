from __future__ import annotations

import os
from dataclasses import dataclass, field

from src.license_facade_service.services.spdx_custom_license import validate_http_iri


@dataclass(frozen=True)
class CustomLicenceRegistrationSettings:
    database_url: str | None
    authority_id: str | None
    authority_base_iri: str | None
    creator_organization_name: str | None
    creator_organization_iri: str | None
    validation_errors: tuple[str, ...] = field(default_factory=tuple)

    @classmethod
    def from_env(cls) -> "CustomLicenceRegistrationSettings":
        database_url = os.getenv("CUSTOM_LICENCE_REGISTRATION_DATABASE_URL", "").strip() or None
        authority_id = os.getenv("CUSTOM_LICENCE_AUTHORITY_ID", "").strip() or None
        authority_base_iri = os.getenv("CUSTOM_LICENCE_AUTHORITY_BASE_IRI", "").strip() or None
        creator_organization_name = os.getenv("CUSTOM_LICENCE_CREATOR_ORGANIZATION_NAME", "").strip() or None
        creator_organization_iri = os.getenv("CUSTOM_LICENCE_CREATOR_ORGANIZATION_IRI", "").strip() or None

        errors: list[str] = []

        if database_url is None:
            errors.append("CUSTOM_LICENCE_REGISTRATION_DATABASE_URL is required for custom licence registration")
        if authority_id is None:
            errors.append("CUSTOM_LICENCE_AUTHORITY_ID is required for custom licence registration")
        elif len(authority_id) > 128:
            errors.append("CUSTOM_LICENCE_AUTHORITY_ID must be <= 128 characters")
        elif any(ord(ch) < 32 or ord(ch) == 127 for ch in authority_id):
            errors.append("CUSTOM_LICENCE_AUTHORITY_ID must not contain control characters")

        if authority_base_iri is None:
            errors.append("CUSTOM_LICENCE_AUTHORITY_BASE_IRI is required for custom licence registration")
        else:
            try:
                authority_base_iri = validate_http_iri(authority_base_iri, "CUSTOM_LICENCE_AUTHORITY_BASE_IRI")
            except ValueError as exc:
                errors.append(str(exc))

        if creator_organization_name is None:
            errors.append("CUSTOM_LICENCE_CREATOR_ORGANIZATION_NAME is required for custom licence registration")
        elif len(creator_organization_name) > 256:
            errors.append("CUSTOM_LICENCE_CREATOR_ORGANIZATION_NAME must be <= 256 characters")
        elif any(ord(ch) < 32 or ord(ch) == 127 for ch in creator_organization_name):
            errors.append("CUSTOM_LICENCE_CREATOR_ORGANIZATION_NAME must not contain control characters")

        if creator_organization_iri is not None:
            try:
                creator_organization_iri = validate_http_iri(
                    creator_organization_iri, "CUSTOM_LICENCE_CREATOR_ORGANIZATION_IRI"
                )
            except ValueError as exc:
                errors.append(str(exc))

        return cls(
            database_url=database_url,
            authority_id=authority_id,
            authority_base_iri=authority_base_iri,
            creator_organization_name=creator_organization_name,
            creator_organization_iri=creator_organization_iri,
            validation_errors=tuple(errors),
        )
