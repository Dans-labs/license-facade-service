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


def _as_int(name: str, default: int) -> int:
    raw = os.getenv(name)
    if raw is None or not raw.strip():
        return default
    return int(raw.strip())


def _as_csv(name: str) -> tuple[str, ...]:
    raw = os.getenv(name, "").strip()
    if not raw:
        return ()
    return tuple(item.strip() for item in raw.split(",") if item.strip())


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
    inbound_enabled: bool
    admin_sync_timeout_seconds: int
    worker_interval_seconds: int
    worker_max_sync_seconds: int
    sync_connect_timeout_seconds: float
    sync_read_timeout_seconds: float
    sync_write_timeout_seconds: float
    sync_pool_timeout_seconds: float
    sync_retry_attempts: int
    sync_retry_base_seconds: float
    sync_retry_max_seconds: float
    sync_max_discovery_bytes: int
    sync_max_jwks_bytes: int
    sync_max_changes_bytes: int
    sync_max_record_bytes: int
    sync_max_embedded_payload_bytes: int
    sync_max_jwks_keys: int
    sync_max_events_per_page: int
    sync_max_future_seconds: int
    sync_allowed_ports: tuple[int, ...]
    sync_allowed_hostnames: tuple[str, ...]
    sync_allowed_cidrs: tuple[str, ...]
    allow_private_network: bool
    allow_http_for_demo: bool
    demo_tofu_unsafe_enabled: bool
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
        inbound_enabled = _as_bool("FEDERATION_INBOUND_ENABLED", default=enabled)
        allow_private_network = _as_bool("FEDERATION_ALLOW_PRIVATE_NETWORK", default=False)
        allow_http_for_demo = _as_bool("FEDERATION_ALLOW_HTTP_FOR_DEMO", default=False)
        demo_tofu_unsafe_enabled = _as_bool("FEDERATION_DEMO_TOFU_UNSAFE", default=False)
        allowed_ports = tuple(
            int(value.strip()) for value in os.getenv("FEDERATION_SYNC_ALLOWED_PORTS", "443").split(",") if value.strip()
        )
        if not allowed_ports:
            allowed_ports = (443,)
        max_discovery_bytes = _as_int("FEDERATION_SYNC_MAX_DISCOVERY_BYTES", 64_000)
        max_jwks_bytes = _as_int("FEDERATION_SYNC_MAX_JWKS_BYTES", 256_000)
        max_changes_bytes = _as_int("FEDERATION_SYNC_MAX_CHANGES_BYTES", 2_000_000)
        max_record_bytes = _as_int("FEDERATION_SYNC_MAX_RECORD_BYTES", 1_000_000)
        max_embedded_payload_bytes = _as_int("FEDERATION_SYNC_MAX_EMBEDDED_PAYLOAD_BYTES", 512_000)
        max_jwks_keys = _as_int("FEDERATION_SYNC_MAX_JWKS_KEYS", 32)
        max_events_per_page = _as_int("FEDERATION_SYNC_MAX_EVENTS_PER_PAGE", 200)
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
                if not parsed.netloc:
                    errors.append("FEDERATION_PUBLIC_BASE_URL must be an absolute URL")
                elif parsed.scheme != "https" and not (allow_http_for_demo and parsed.scheme == "http"):
                    errors.append("FEDERATION_PUBLIC_BASE_URL must be an absolute https URL")
            if inbound_enabled and max_events_per_page <= 0:
                errors.append("FEDERATION_SYNC_MAX_EVENTS_PER_PAGE must be positive")
            if any(port <= 0 or port > 65535 for port in allowed_ports):
                errors.append("FEDERATION_SYNC_ALLOWED_PORTS must contain valid TCP ports")

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
            inbound_enabled=inbound_enabled,
            admin_sync_timeout_seconds=_as_int("FEDERATION_ADMIN_SYNC_TIMEOUT_SECONDS", 60),
            worker_interval_seconds=_as_int("FEDERATION_WORKER_INTERVAL_SECONDS", 60),
            worker_max_sync_seconds=_as_int("FEDERATION_WORKER_MAX_SYNC_SECONDS", 120),
            sync_connect_timeout_seconds=float(os.getenv("FEDERATION_SYNC_CONNECT_TIMEOUT_SECONDS", "5")),
            sync_read_timeout_seconds=float(os.getenv("FEDERATION_SYNC_READ_TIMEOUT_SECONDS", "10")),
            sync_write_timeout_seconds=float(os.getenv("FEDERATION_SYNC_WRITE_TIMEOUT_SECONDS", "10")),
            sync_pool_timeout_seconds=float(os.getenv("FEDERATION_SYNC_POOL_TIMEOUT_SECONDS", "5")),
            sync_retry_attempts=_as_int("FEDERATION_SYNC_RETRY_ATTEMPTS", 3),
            sync_retry_base_seconds=float(os.getenv("FEDERATION_SYNC_RETRY_BASE_SECONDS", "0.2")),
            sync_retry_max_seconds=float(os.getenv("FEDERATION_SYNC_RETRY_MAX_SECONDS", "2.0")),
            sync_max_discovery_bytes=max_discovery_bytes,
            sync_max_jwks_bytes=max_jwks_bytes,
            sync_max_changes_bytes=max_changes_bytes,
            sync_max_record_bytes=max_record_bytes,
            sync_max_embedded_payload_bytes=max_embedded_payload_bytes,
            sync_max_jwks_keys=max_jwks_keys,
            sync_max_events_per_page=max_events_per_page,
            sync_max_future_seconds=_as_int("FEDERATION_SYNC_MAX_FUTURE_SECONDS", 300),
            sync_allowed_ports=allowed_ports,
            sync_allowed_hostnames=_as_csv("FEDERATION_SYNC_ALLOWED_HOSTNAMES"),
            sync_allowed_cidrs=_as_csv("FEDERATION_SYNC_ALLOWED_CIDRS"),
            allow_private_network=allow_private_network,
            allow_http_for_demo=allow_http_for_demo,
            demo_tofu_unsafe_enabled=demo_tofu_unsafe_enabled,
            validation_errors=tuple(errors),
        )
