from __future__ import annotations

import ipaddress
import math
import os
from dataclasses import dataclass, field
from urllib.parse import unquote, urlsplit

_TRUE_VALUES = {"1", "true", "yes", "y", "on"}
_FALSE_VALUES = {"0", "false", "no", "n", "off"}


def _parse_bool(name: str, default: bool, errors: list[str]) -> bool:
    raw = os.getenv(name)
    if raw is None:
        return default
    normalized = raw.strip().lower()
    if normalized in _TRUE_VALUES:
        return True
    if normalized in _FALSE_VALUES:
        return False
    errors.append(f"{name} must be a supported boolean value")
    return default


def _parse_int(
    name: str,
    default: int,
    errors: list[str],
    *,
    min_value: int | None = None,
    max_value: int | None = None,
) -> int:
    raw = os.getenv(name)
    if raw is None or not raw.strip():
        value = default
    else:
        try:
            value = int(raw.strip())
        except ValueError:
            errors.append(f"{name} must be an integer")
            return default
    if min_value is not None and value < min_value:
        errors.append(f"{name} must be >= {min_value}")
    if max_value is not None and value > max_value:
        errors.append(f"{name} must be <= {max_value}")
    return value


def _parse_float(
    name: str,
    default: float,
    errors: list[str],
    *,
    min_exclusive: float | None = None,
    max_inclusive: float | None = None,
) -> float:
    raw = os.getenv(name)
    if raw is None or not raw.strip():
        value = default
    else:
        try:
            value = float(raw.strip())
        except ValueError:
            errors.append(f"{name} must be a finite number")
            return default
    if not math.isfinite(value):
        errors.append(f"{name} must be a finite number")
        return default
    if min_exclusive is not None and value <= min_exclusive:
        errors.append(f"{name} must be > {min_exclusive}")
    if max_inclusive is not None and value > max_inclusive:
        errors.append(f"{name} must be <= {max_inclusive}")
    return value


def _parse_allowed_ports(name: str, default: tuple[int, ...], errors: list[str]) -> tuple[int, ...]:
    raw = os.getenv(name)
    if raw is None or not raw.strip():
        return default
    parsed: list[int] = []
    seen: set[int] = set()
    for item in raw.split(","):
        token = item.strip()
        if not token:
            continue
        try:
            value = int(token)
        except ValueError:
            errors.append(f"{name} must contain valid TCP ports")
            return default
        if value < 1 or value > 65535:
            errors.append(f"{name} must contain valid TCP ports")
            return default
        if value not in seen:
            seen.add(value)
            parsed.append(value)
    if not parsed:
        errors.append(f"{name} must contain at least one TCP port")
        return default
    return tuple(parsed)


def _normalize_hostname(value: str) -> str:
    host = value.strip().rstrip(".").lower()
    if not host:
        raise ValueError("hostname is empty")
    if any(ch.isspace() for ch in host):
        raise ValueError("hostname contains whitespace")
    return host.encode("idna").decode("ascii")


def _parse_hostnames(name: str, errors: list[str]) -> tuple[str, ...]:
    raw = os.getenv(name, "").strip()
    if not raw:
        return ()
    parsed: list[str] = []
    seen: set[str] = set()
    for item in raw.split(","):
        token = item.strip()
        if not token:
            continue
        try:
            hostname = _normalize_hostname(token)
        except Exception:
            errors.append(f"{name} must contain valid hostnames")
            return ()
        if hostname not in seen:
            seen.add(hostname)
            parsed.append(hostname)
    return tuple(parsed)


def _parse_cidrs(name: str, errors: list[str]) -> tuple[str, ...]:
    raw = os.getenv(name, "").strip()
    if not raw:
        return ()
    parsed: list[str] = []
    seen: set[str] = set()
    for item in raw.split(","):
        token = item.strip()
        if not token:
            continue
        try:
            network = str(ipaddress.ip_network(token, strict=False))
        except ValueError:
            errors.append(f"{name} must contain valid IPv4/IPv6 CIDRs")
            return ()
        if network not in seen:
            seen.add(network)
            parsed.append(network)
    return tuple(parsed)


@dataclass(frozen=True)
class OpenRelSettings:
    enabled: bool
    base_url: str | None
    base_scheme: str | None
    base_hostname: str | None
    base_port: int | None
    allow_http_for_demo: bool
    connect_timeout_seconds: float
    read_timeout_seconds: float
    write_timeout_seconds: float
    pool_timeout_seconds: float
    total_timeout_seconds: float
    retry_attempts: int
    retry_base_seconds: float
    retry_max_seconds: float
    max_list_response_bytes: int
    max_detail_response_bytes: int
    max_id_length: int
    max_prefix_length: int
    allowed_ports: tuple[int, ...]
    allowed_hostnames: tuple[str, ...]
    allowed_cidrs: tuple[str, ...]
    validation_errors: tuple[str, ...] = field(default_factory=tuple)

    @classmethod
    def from_env(cls) -> OpenRelSettings:
        errors: list[str] = []
        enabled = _parse_bool("OPENREL_ENABLED", default=False, errors=errors)
        allow_http_for_demo = _parse_bool("OPENREL_ALLOW_HTTP_FOR_DEMO", default=False, errors=errors)

        allowed_ports = _parse_allowed_ports("OPENREL_ALLOWED_PORTS", default=(443,), errors=errors)
        connect_timeout = _parse_float("OPENREL_CONNECT_TIMEOUT_SECONDS", 5.0, errors, min_exclusive=0)
        read_timeout = _parse_float("OPENREL_READ_TIMEOUT_SECONDS", 15.0, errors, min_exclusive=0)
        write_timeout = _parse_float("OPENREL_WRITE_TIMEOUT_SECONDS", 10.0, errors, min_exclusive=0)
        pool_timeout = _parse_float("OPENREL_POOL_TIMEOUT_SECONDS", 5.0, errors, min_exclusive=0)
        total_timeout = _parse_float("OPENREL_TOTAL_TIMEOUT_SECONDS", 20.0, errors, min_exclusive=0, max_inclusive=60)
        retry_attempts = _parse_int("OPENREL_RETRY_ATTEMPTS", 3, errors, min_value=1, max_value=5)
        retry_base_seconds = _parse_float("OPENREL_RETRY_BASE_SECONDS", 0.2, errors, min_exclusive=0)
        retry_max_seconds = _parse_float("OPENREL_RETRY_MAX_SECONDS", 2.0, errors, min_exclusive=0)
        if retry_max_seconds < retry_base_seconds:
            errors.append("OPENREL_RETRY_MAX_SECONDS must be >= OPENREL_RETRY_BASE_SECONDS")
        max_list_response_bytes = _parse_int("OPENREL_MAX_LIST_RESPONSE_BYTES", 2_000_000, errors, min_value=1)
        max_detail_response_bytes = _parse_int("OPENREL_MAX_DETAIL_RESPONSE_BYTES", 512_000, errors, min_value=1)
        max_id_length = _parse_int("OPENREL_MAX_ID_LENGTH", 2048, errors, min_value=1)
        max_prefix_length = _parse_int("OPENREL_MAX_PREFIX_LENGTH", 128, errors, min_value=1)
        allowed_hostnames = _parse_hostnames("OPENREL_ALLOWED_HOSTNAMES", errors)
        allowed_cidrs = _parse_cidrs("OPENREL_ALLOWED_CIDRS", errors)

        raw_base_url = os.getenv("OPENREL_BASE_URL", "").strip() or None
        base_url: str | None = None
        base_scheme: str | None = None
        base_hostname: str | None = None
        base_port: int | None = None
        if enabled and not raw_base_url:
            errors.append("OPENREL_BASE_URL is required when OPENREL_ENABLED=true")

        if raw_base_url:
            try:
                parsed = urlsplit(raw_base_url)
            except ValueError:
                parsed = None
                errors.append("OPENREL_BASE_URL must be an absolute URL")
            if parsed is not None:
                parsed_scheme = parsed.scheme.lower()
                try:
                    parsed_hostname = parsed.hostname
                except ValueError:
                    parsed_hostname = None
                    errors.append("OPENREL_BASE_URL hostname is invalid")
                if not parsed_scheme or not parsed_hostname:
                    errors.append("OPENREL_BASE_URL must be an absolute URL with hostname")
                elif parsed_scheme not in {"https", "http"}:
                    errors.append("OPENREL_BASE_URL scheme must be https (or http when demo override is enabled)")
                elif parsed_scheme == "http" and not allow_http_for_demo:
                    errors.append("OPENREL_BASE_URL must use https unless OPENREL_ALLOW_HTTP_FOR_DEMO=true")
                if parsed.username or parsed.password:
                    errors.append("OPENREL_BASE_URL must not include URL credentials")
                if parsed.query:
                    errors.append("OPENREL_BASE_URL must not include URL query parameters")
                if parsed.fragment:
                    errors.append("OPENREL_BASE_URL must not include URL fragments")
                if parsed_hostname:
                    try:
                        base_hostname = _normalize_hostname(parsed_hostname)
                    except Exception:
                        errors.append("OPENREL_BASE_URL hostname is invalid")
                if parsed_scheme in {"https", "http"}:
                    default_port = 443 if parsed_scheme == "https" else 80
                    try:
                        parsed_port = parsed.port
                    except ValueError:
                        parsed_port = None
                        errors.append("OPENREL_BASE_URL port is invalid")
                    base_port = parsed_port or default_port
                    if base_port not in allowed_ports:
                        errors.append("OPENREL_BASE_URL port must be listed in OPENREL_ALLOWED_PORTS")
                    base_scheme = parsed_scheme
                decoded_segments = [unquote(seg) for seg in parsed.path.split("/") if seg]
                if any(seg in {".", ".."} for seg in decoded_segments):
                    errors.append("OPENREL_BASE_URL path must not contain dot-segments")
                if base_hostname and base_scheme and base_port:
                    normalized_path = parsed.path.rstrip("/")
                    host = base_hostname
                    try:
                        parsed_ip = ipaddress.ip_address(base_hostname)
                    except ValueError:
                        parsed_ip = None
                    if isinstance(parsed_ip, ipaddress.IPv6Address):
                        host = f"[{base_hostname}]"
                    if (base_scheme == "https" and base_port != 443) or (base_scheme == "http" and base_port != 80):
                        host = f"{base_hostname}:{base_port}"
                        if isinstance(parsed_ip, ipaddress.IPv6Address):
                            host = f"[{base_hostname}]:{base_port}"
                    base_url = f"{base_scheme}://{host}{normalized_path}"

        return cls(
            enabled=enabled,
            base_url=base_url,
            base_scheme=base_scheme,
            base_hostname=base_hostname,
            base_port=base_port,
            allow_http_for_demo=allow_http_for_demo,
            connect_timeout_seconds=connect_timeout,
            read_timeout_seconds=read_timeout,
            write_timeout_seconds=write_timeout,
            pool_timeout_seconds=pool_timeout,
            total_timeout_seconds=total_timeout,
            retry_attempts=retry_attempts,
            retry_base_seconds=retry_base_seconds,
            retry_max_seconds=retry_max_seconds,
            max_list_response_bytes=max_list_response_bytes,
            max_detail_response_bytes=max_detail_response_bytes,
            max_id_length=max_id_length,
            max_prefix_length=max_prefix_length,
            allowed_ports=allowed_ports,
            allowed_hostnames=allowed_hostnames,
            allowed_cidrs=allowed_cidrs,
            validation_errors=tuple(errors),
        )
