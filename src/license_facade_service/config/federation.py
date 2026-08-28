from __future__ import annotations

import os
import secrets
import warnings
from dataclasses import dataclass, field
from pathlib import Path
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

# Keep these bounds aligned with federation/lease.py duration validation.
_SYNC_LEASE_MIN_SECONDS = 10
_SYNC_LEASE_MAX_SECONDS = 3_600


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
    sync_max_duration_seconds: int
    sync_lease_duration_seconds: int
    sync_lease_renewal_seconds: int
    sync_probe_timeout_seconds: int
    circuit_open_threshold: int
    circuit_base_open_seconds: int
    circuit_max_open_seconds: int
    circuit_half_open_probe_limit: int
    sync_allowed_ports: tuple[int, ...]
    sync_allowed_hostnames: tuple[str, ...]
    sync_allowed_cidrs: tuple[str, ...]
    allow_private_network: bool
    allow_http_for_demo: bool
    demo_tofu_unsafe_enabled: bool
    rdf_fuseki_timeout_seconds: float
    rdf_outbox_lease_seconds: int
    rdf_outbox_retry_attempts: int
    rdf_outbox_retry_base_seconds: float
    rdf_outbox_retry_max_seconds: float
    rdf_outbox_batch_size: int
    admin_cursor_secret: str | None = field(default=None, repr=False, compare=False)
    admin_cursor_secret_allow_ephemeral: bool = False
    admin_cursor_secret_generated: bool = False
    admin_cursor_secret_source: str | None = None
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
        cursor_secret = (os.getenv("FEDERATION_ADMIN_CURSOR_SECRET", "").strip() or None)
        cursor_secret_file = (os.getenv("FEDERATION_ADMIN_CURSOR_SECRET_FILE", "").strip() or None)
        cursor_secret_allow_ephemeral = _as_bool("FEDERATION_ADMIN_CURSOR_SECRET_ALLOW_EPHEMERAL", default=False)
        cursor_secret_source: str | None = "inline" if cursor_secret else None
        cursor_secret_generated = False
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
        sync_max_duration_seconds = _as_int("FEDERATION_SYNC_MAX_DURATION_SECONDS", 300)
        sync_lease_duration_seconds = _as_int("FEDERATION_SYNC_LEASE_DURATION_SECONDS", 120)
        sync_lease_renewal_seconds = _as_int("FEDERATION_SYNC_LEASE_RENEWAL_SECONDS", 60)
        sync_probe_timeout_seconds = _as_int("FEDERATION_SYNC_PROBE_TIMEOUT_SECONDS", 10)
        circuit_open_threshold = _as_int("FEDERATION_SYNC_CIRCUIT_OPEN_THRESHOLD", 3)
        circuit_base_open_seconds = _as_int("FEDERATION_SYNC_CIRCUIT_BASE_OPEN_SECONDS", 30)
        circuit_max_open_seconds = _as_int("FEDERATION_SYNC_CIRCUIT_MAX_OPEN_SECONDS", 900)
        circuit_half_open_probe_limit = _as_int("FEDERATION_SYNC_CIRCUIT_HALF_OPEN_PROBE_LIMIT", 1)
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
            if cursor_secret_file:
                cursor_secret_path = Path(cursor_secret_file)
                if not cursor_secret_path.is_file():
                    errors.append("FEDERATION_ADMIN_CURSOR_SECRET_FILE must point to a readable regular file when set")
                else:
                    try:
                        file_secret = cursor_secret_path.read_text(encoding="utf-8").strip()
                    except OSError:
                        errors.append("FEDERATION_ADMIN_CURSOR_SECRET_FILE must point to a readable regular file when set")
                    else:
                        if not file_secret:
                            errors.append("FEDERATION_ADMIN_CURSOR_SECRET_FILE must not be empty")
                        else:
                            cursor_secret = file_secret
                            cursor_secret_source = "file"
            if not cursor_secret:
                if cursor_secret_allow_ephemeral:
                    cursor_secret = secrets.token_hex(32)
                    cursor_secret_generated = True
                    cursor_secret_source = "generated"
                    warnings.warn(
                        "FEDERATION_ADMIN_CURSOR_SECRET was not configured; using an ephemeral in-memory cursor secret. "
                        "Pagination cursors will not survive process restart or replica changes.",
                        RuntimeWarning,
                        stacklevel=2,
                    )
                else:
                    errors.append(
                        "FEDERATION_ADMIN_CURSOR_SECRET or FEDERATION_ADMIN_CURSOR_SECRET_FILE is required when "
                        "FEDERATION_ENABLED=true"
                    )
            if cursor_secret and len(cursor_secret) < 32:
                errors.append("FEDERATION_ADMIN_CURSOR_SECRET must be at least 32 characters long")
            if inbound_enabled and max_events_per_page <= 0:
                errors.append("FEDERATION_SYNC_MAX_EVENTS_PER_PAGE must be positive")
            if any(port <= 0 or port > 65535 for port in allowed_ports):
                errors.append("FEDERATION_SYNC_ALLOWED_PORTS must contain valid TCP ports")
            if sync_max_duration_seconds <= 0:
                errors.append("FEDERATION_SYNC_MAX_DURATION_SECONDS must be positive")
            if sync_lease_duration_seconds <= 0:
                errors.append("FEDERATION_SYNC_LEASE_DURATION_SECONDS must be positive")
            if sync_lease_duration_seconds < _SYNC_LEASE_MIN_SECONDS or sync_lease_duration_seconds > _SYNC_LEASE_MAX_SECONDS:
                errors.append(
                    "FEDERATION_SYNC_LEASE_DURATION_SECONDS must be between "
                    f"{_SYNC_LEASE_MIN_SECONDS} and {_SYNC_LEASE_MAX_SECONDS}"
                )
            if sync_lease_renewal_seconds <= 0:
                errors.append("FEDERATION_SYNC_LEASE_RENEWAL_SECONDS must be positive")
            if sync_lease_renewal_seconds < _SYNC_LEASE_MIN_SECONDS or sync_lease_renewal_seconds > _SYNC_LEASE_MAX_SECONDS:
                errors.append(
                    "FEDERATION_SYNC_LEASE_RENEWAL_SECONDS must be between "
                    f"{_SYNC_LEASE_MIN_SECONDS} and {_SYNC_LEASE_MAX_SECONDS}"
                )
            if sync_probe_timeout_seconds <= 0:
                errors.append("FEDERATION_SYNC_PROBE_TIMEOUT_SECONDS must be positive")
            if circuit_open_threshold <= 0 or circuit_open_threshold > 100:
                errors.append("FEDERATION_SYNC_CIRCUIT_OPEN_THRESHOLD must be between 1 and 100")
            if circuit_base_open_seconds <= 0:
                errors.append("FEDERATION_SYNC_CIRCUIT_BASE_OPEN_SECONDS must be positive")
            if circuit_max_open_seconds <= 0:
                errors.append("FEDERATION_SYNC_CIRCUIT_MAX_OPEN_SECONDS must be positive")
            if circuit_base_open_seconds > circuit_max_open_seconds:
                errors.append("FEDERATION_SYNC_CIRCUIT_BASE_OPEN_SECONDS must be <= FEDERATION_SYNC_CIRCUIT_MAX_OPEN_SECONDS")
            if circuit_half_open_probe_limit <= 0 or circuit_half_open_probe_limit > 20:
                errors.append("FEDERATION_SYNC_CIRCUIT_HALF_OPEN_PROBE_LIMIT must be between 1 and 20")
            if sync_lease_renewal_seconds > sync_lease_duration_seconds:
                errors.append("FEDERATION_SYNC_LEASE_RENEWAL_SECONDS must be <= FEDERATION_SYNC_LEASE_DURATION_SECONDS")
            if sync_max_duration_seconds < sync_lease_renewal_seconds:
                errors.append("FEDERATION_SYNC_MAX_DURATION_SECONDS must be >= FEDERATION_SYNC_LEASE_RENEWAL_SECONDS")

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
            sync_max_duration_seconds=sync_max_duration_seconds,
            sync_lease_duration_seconds=sync_lease_duration_seconds,
            sync_lease_renewal_seconds=sync_lease_renewal_seconds,
            sync_probe_timeout_seconds=sync_probe_timeout_seconds,
            circuit_open_threshold=circuit_open_threshold,
            circuit_base_open_seconds=circuit_base_open_seconds,
            circuit_max_open_seconds=circuit_max_open_seconds,
            circuit_half_open_probe_limit=circuit_half_open_probe_limit,
            sync_allowed_ports=allowed_ports,
            sync_allowed_hostnames=_as_csv("FEDERATION_SYNC_ALLOWED_HOSTNAMES"),
            sync_allowed_cidrs=_as_csv("FEDERATION_SYNC_ALLOWED_CIDRS"),
            allow_private_network=allow_private_network,
            allow_http_for_demo=allow_http_for_demo,
            demo_tofu_unsafe_enabled=demo_tofu_unsafe_enabled,
            rdf_fuseki_timeout_seconds=float(os.getenv("FEDERATION_RDF_FUSEKI_TIMEOUT_SECONDS", "10")),
            rdf_outbox_lease_seconds=_as_int("FEDERATION_RDF_OUTBOX_LEASE_SECONDS", 300),
            rdf_outbox_retry_attempts=_as_int("FEDERATION_RDF_OUTBOX_RETRY_ATTEMPTS", 5),
            rdf_outbox_retry_base_seconds=float(os.getenv("FEDERATION_RDF_OUTBOX_RETRY_BASE_SECONDS", "2")),
            rdf_outbox_retry_max_seconds=float(os.getenv("FEDERATION_RDF_OUTBOX_RETRY_MAX_SECONDS", "30")),
            rdf_outbox_batch_size=_as_int("FEDERATION_RDF_OUTBOX_BATCH_SIZE", 25),
            admin_cursor_secret=cursor_secret,
            admin_cursor_secret_allow_ephemeral=cursor_secret_allow_ephemeral,
            admin_cursor_secret_generated=cursor_secret_generated,
            admin_cursor_secret_source=cursor_secret_source,
            validation_errors=tuple(errors),
        )
