from __future__ import annotations

import os
from dataclasses import dataclass, field
from urllib.parse import urlparse
from uuid import UUID


def _as_bool(name: str, default: bool = False) -> bool:
    raw = os.getenv(name)
    if raw is None:
        return default
    return raw.strip().lower() in {"1", "true", "yes", "y", "on"}


@dataclass(frozen=True)
class FederationSettings:
    enabled: bool
    node_id: str | None
    public_base_url: str | None
    node_name: str | None
    operator_name: str | None
    database_url: str | None
    signing_key_path: str | None
    signing_key_secret_path: str | None
    active_kid: str | None
    jwks_enabled: bool
    validation_errors: tuple[str, ...] = field(default_factory=tuple)

    @classmethod
    def from_env(cls) -> "FederationSettings":
        enabled = _as_bool("FEDERATION_ENABLED", default=False)
        node_id_raw = os.getenv("FEDERATION_NODE_ID", "").strip() or None
        public_base_url = (os.getenv("FEDERATION_PUBLIC_BASE_URL", "").strip() or None)
        if public_base_url:
            public_base_url = public_base_url.rstrip("/")
        node_name = os.getenv("FEDERATION_NODE_NAME", "").strip() or None
        operator_name = os.getenv("FEDERATION_OPERATOR", "").strip() or None
        database_url = os.getenv("FEDERATION_DATABASE_URL", "").strip() or None
        active_kid = os.getenv("FEDERATION_ACTIVE_KID", "").strip() or None
        signing_key_path = os.getenv("FEDERATION_SIGNING_KEY_PATH", "").strip() or None
        signing_key_secret_path = os.getenv("FEDERATION_SIGNING_KEY_SECRET_PATH", "").strip() or None
        errors: list[str] = []

        parsed_node_id: str | None = None
        if node_id_raw:
            try:
                parsed_node_id = str(UUID(node_id_raw))
            except ValueError:
                errors.append("FEDERATION_NODE_ID must be a valid UUID string")

        if enabled:
            if not node_id_raw:
                errors.append("FEDERATION_NODE_ID is required when FEDERATION_ENABLED=true")
            if not public_base_url:
                errors.append("FEDERATION_PUBLIC_BASE_URL is required when FEDERATION_ENABLED=true")
            if not node_name:
                errors.append("FEDERATION_NODE_NAME is required when FEDERATION_ENABLED=true")
            if not operator_name:
                errors.append("FEDERATION_OPERATOR is required when FEDERATION_ENABLED=true")
            if not database_url:
                errors.append("FEDERATION_DATABASE_URL is required when FEDERATION_ENABLED=true")
            if not active_kid:
                errors.append("FEDERATION_ACTIVE_KID is required when FEDERATION_ENABLED=true")
            if not signing_key_path and not signing_key_secret_path:
                errors.append(
                    "FEDERATION_SIGNING_KEY_PATH or FEDERATION_SIGNING_KEY_SECRET_PATH is required when "
                    "FEDERATION_ENABLED=true"
                )
            if public_base_url:
                parsed = urlparse(public_base_url)
                if parsed.scheme != "https" or not parsed.netloc:
                    errors.append("FEDERATION_PUBLIC_BASE_URL must be an absolute https URL")

        return cls(
            enabled=enabled,
            node_id=parsed_node_id,
            public_base_url=public_base_url,
            node_name=node_name,
            operator_name=operator_name,
            database_url=database_url,
            signing_key_path=signing_key_path,
            signing_key_secret_path=signing_key_secret_path,
            active_kid=active_kid,
            jwks_enabled=_as_bool("FEDERATION_JWKS_ENABLED", default=True if enabled else False),
            validation_errors=tuple(errors),
        )
