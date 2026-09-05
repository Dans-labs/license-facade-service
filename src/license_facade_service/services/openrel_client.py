from __future__ import annotations

import copy
import ipaddress
import socket
import time
from dataclasses import dataclass
from enum import Enum
from typing import Any, Callable
from urllib.parse import quote, urlencode, urlsplit

import httpx

from src.license_facade_service.federation.json_strict import DuplicateJsonKeyError, loads_json_no_duplicates
from src.license_facade_service.federation.security import METADATA_IPS
from src.license_facade_service.services.openrel_policy import OpenRelPolicySettings


class OpenRelClientError(ValueError):
    pass


class OpenRelClientConfigurationError(OpenRelClientError):
    pass


class OpenRelUnsupportedResourceError(OpenRelClientError):
    pass


class OpenRelUnsafeDestinationError(OpenRelClientError):
    pass


class OpenRelNetworkError(OpenRelClientError):
    pass


class OpenRelUnexpectedStatusError(OpenRelClientError):
    pass


class OpenRelNotFoundError(OpenRelUnexpectedStatusError):
    pass


class OpenRelInvalidContentTypeError(OpenRelClientError):
    pass


class OpenRelResponseTooLargeError(OpenRelClientError):
    pass


class OpenRelMalformedJsonError(OpenRelClientError):
    pass


class OpenRelResponseSchemaError(OpenRelClientError):
    pass


class OpenRelResourceType(str, Enum):
    actions = "actions"
    constraints = "constraints"
    leftoperands = "leftoperands"
    mappings = "mappings"
    actionclasses = "actionclasses"
    assetclasses = "assetclasses"
    constraintclasses = "constraintclasses"
    leftoperandclasses = "leftoperandclasses"
    ruleclasses = "ruleclasses"


@dataclass(frozen=True)
class OpenRelLookupItem:
    iri: str
    label: str | None
    definition: str | None


@dataclass(frozen=True)
class _ResourceSpec:
    path: str
    supports_detail: bool
    supports_prefix: bool


@dataclass(frozen=True)
class _ResolvedHost:
    hostname: str
    port: int
    addresses: tuple[str, ...]


_RESOURCE_SPECS: dict[OpenRelResourceType, _ResourceSpec] = {
    OpenRelResourceType.actions: _ResourceSpec("/actions", True, True),
    OpenRelResourceType.constraints: _ResourceSpec("/constraints", True, False),
    OpenRelResourceType.leftoperands: _ResourceSpec("/leftoperands", True, False),
    OpenRelResourceType.mappings: _ResourceSpec("/mappings", False, True),
    OpenRelResourceType.actionclasses: _ResourceSpec("/actionclasses", True, True),
    OpenRelResourceType.assetclasses: _ResourceSpec("/assetclasses", True, True),
    OpenRelResourceType.constraintclasses: _ResourceSpec("/constraintclasses", True, True),
    OpenRelResourceType.leftoperandclasses: _ResourceSpec("/leftoperandclasses", True, True),
    OpenRelResourceType.ruleclasses: _ResourceSpec("/ruleclasses", True, True),
}

_MAX_CACHE_ENTRIES = 128


def _default_resolver(hostname: str, port: int) -> list[tuple[Any, ...]]:
    return socket.getaddrinfo(hostname, port, type=socket.SOCK_STREAM)


class OpenRelClient:
    def __init__(
        self,
        settings: OpenRelPolicySettings,
        *,
        http_client: httpx.Client | None = None,
        resolver: Callable[[str, int], list[tuple[Any, ...]]] | None = None,
        monotonic: Callable[[], float] | None = None,
        allowed_hostnames: tuple[str, ...] = (),
        allowed_cidrs: tuple[str, ...] = (),
    ) -> None:
        self.settings = settings
        self._resolver = resolver or _default_resolver
        self._monotonic = monotonic or time.monotonic
        self._allowed_hostnames = self._normalize_hostnames(allowed_hostnames)
        self._allowed_cidrs = allowed_cidrs
        self._cache: dict[tuple[str, str | None, str | None], tuple[float, Any]] = {}
        self._owns_client = http_client is None
        self._http_client = http_client or httpx.Client(
            timeout=httpx.Timeout(
                connect=settings.timeout_seconds,
                read=settings.timeout_seconds,
                write=settings.timeout_seconds,
                pool=settings.timeout_seconds,
            ),
            follow_redirects=False,
            trust_env=False,
        )
        self._base_url = self._validate_base_url(settings)

    def close(self) -> None:
        if self._owns_client:
            self._http_client.close()

    def clear_cache(self) -> None:
        self._cache.clear()

    def list_resources(self, resource_type: str | OpenRelResourceType, *, prefix: str | None = None) -> tuple[OpenRelLookupItem, ...]:
        resource = self._normalize_resource_type(resource_type)
        spec = _RESOURCE_SPECS[resource]
        cache_key = (resource.value, None, prefix)
        cached = self._cache_get(cache_key)
        if cached is not None:
            return cached
        items = self._fetch_list(resource=resource, spec=spec, prefix=prefix)
        self._cache_set(cache_key, items)
        return items

    def get_resource(self, resource_type: str | OpenRelResourceType, resource_id: str, *, prefix: str | None = None) -> OpenRelLookupItem:
        resource = self._normalize_resource_type(resource_type)
        spec = _RESOURCE_SPECS[resource]
        if not spec.supports_detail:
            raise OpenRelUnsupportedResourceError(f"detail lookup is not supported for resource type: {resource.value}")
        normalized_id = self._normalize_resource_id(resource_id)
        cache_key = (resource.value, normalized_id, prefix)
        cached = self._cache_get(cache_key)
        if cached is not None:
            return cached
        item = self._fetch_detail(resource=resource, spec=spec, resource_id=normalized_id, prefix=prefix)
        self._cache_set(cache_key, item)
        return item

    def check_availability(self) -> bool:
        if not self.settings.enabled or self.settings.validation_errors:
            return False
        parsed = urlsplit(self._base_url)
        if parsed.hostname and parsed.hostname.endswith(".invalid"):
            return False
        try:
            items = self._fetch_list(resource=OpenRelResourceType.actions, spec=_RESOURCE_SPECS[OpenRelResourceType.actions], prefix=None)
        except OpenRelClientError:
            return False
        return len(items) >= 0

    def _fetch_list(self, *, resource: OpenRelResourceType, spec: _ResourceSpec, prefix: str | None) -> tuple[OpenRelLookupItem, ...]:
        self._validate_prefix(prefix, spec)
        url = self._build_url(spec.path)
        payload = self._request_json(url, prefix=prefix if spec.supports_prefix else None)
        if not isinstance(payload, list):
            raise OpenRelResponseSchemaError("OpenREL list endpoint must return a JSON array.")
        return tuple(self._parse_item(item) for item in payload)

    def _fetch_detail(self, *, resource: OpenRelResourceType, spec: _ResourceSpec, resource_id: str, prefix: str | None) -> OpenRelLookupItem:
        self._validate_prefix(prefix, spec)
        encoded_id = quote(resource_id, safe="")
        url = self._build_url(f"{spec.path}/{encoded_id}")
        payload = self._request_json(url, prefix=prefix if spec.supports_prefix else None)
        if not isinstance(payload, dict):
            raise OpenRelResponseSchemaError("OpenREL detail endpoint must return one JSON object.")
        return self._parse_item(payload)

    def _request_json(self, url: str, *, prefix: str | None) -> Any:
        self._validate_and_resolve(url)
        headers = {"Accept": "application/json"}
        params = {"prefix": prefix} if prefix is not None else None
        try:
            with self._http_client.stream("GET", url, headers=headers, params=params, follow_redirects=False) as response:
                if 300 <= response.status_code <= 399:
                    raise OpenRelUnexpectedStatusError("OpenREL redirects are not allowed.")
                if response.status_code == 404:
                    raise OpenRelNotFoundError("OpenREL resource was not found.")
                if response.status_code < 200 or response.status_code >= 300:
                    raise OpenRelUnexpectedStatusError(f"OpenREL endpoint returned HTTP {response.status_code}.")
                content_type = response.headers.get("content-type", "").split(";")[0].strip().lower()
                if content_type != "application/json":
                    raise OpenRelInvalidContentTypeError("OpenREL endpoint returned a non-JSON content type.")
                body = bytearray()
                for chunk in response.iter_bytes():
                    body.extend(chunk)
                    if len(body) > self.settings.max_response_bytes:
                        raise OpenRelResponseTooLargeError("OpenREL response exceeded the configured size limit.")
                try:
                    return loads_json_no_duplicates(bytes(body))
                except DuplicateJsonKeyError as exc:
                    raise OpenRelMalformedJsonError("OpenREL JSON contains duplicate object keys.") from exc
                except ValueError as exc:
                    raise OpenRelMalformedJsonError("OpenREL JSON payload is malformed.") from exc
        except httpx.TimeoutException as exc:
            raise OpenRelNetworkError("OpenREL request timed out.") from exc
        except httpx.TransportError as exc:
            raise OpenRelNetworkError("OpenREL request failed.") from exc

    def _parse_item(self, payload: Any) -> OpenRelLookupItem:
        if not isinstance(payload, dict):
            raise OpenRelResponseSchemaError("OpenREL response items must be JSON objects.")
        allowed = {"iri", "label", "definition"}
        unknown = set(payload) - allowed
        if unknown:
            raise OpenRelResponseSchemaError("OpenREL response item contains unsupported fields.")
        iri = payload.get("iri")
        if not isinstance(iri, str) or not iri.strip():
            raise OpenRelResponseSchemaError("OpenREL response item iri must be a nonblank string.")
        normalized_iri = self._validate_absolute_http_iri(iri)
        label = payload.get("label")
        definition = payload.get("definition")
        if label is not None and not isinstance(label, str):
            raise OpenRelResponseSchemaError("OpenREL response item label must be a string when present.")
        if definition is not None and not isinstance(definition, str):
            raise OpenRelResponseSchemaError("OpenREL response item definition must be a string when present.")
        return OpenRelLookupItem(iri=normalized_iri, label=label, definition=definition)

    def _build_url(self, path: str) -> str:
        if not path.startswith("/") or path.startswith("//"):
            raise OpenRelClientConfigurationError("OpenREL path construction failed.")
        return f"{self._base_url}{path}"

    def _validate_and_resolve(self, url: str) -> _ResolvedHost:
        parsed = urlsplit(url)
        if not parsed.hostname:
            raise OpenRelUnsafeDestinationError("OpenREL destination hostname is required.")
        port = parsed.port or (443 if parsed.scheme == "https" else 80)
        normalized_host = parsed.hostname.encode("idna").decode("ascii").lower()
        try:
            info = self._resolver(normalized_host, port)
        except OSError as exc:
            raise OpenRelUnsafeDestinationError("OpenREL destination could not be resolved safely.") from exc
        if not info:
            raise OpenRelUnsafeDestinationError("OpenREL destination could not be resolved safely.")
        resolved = tuple(sorted({row[4][0] for row in info}))
        saw_unsafe = False
        saw_safe = False
        hostname_allowed = normalized_host in self._allowed_hostnames
        for raw_ip in resolved:
            privateish = self._validate_ip(raw_ip, hostname_allowed=hostname_allowed)
            saw_unsafe = saw_unsafe or privateish
            saw_safe = saw_safe or not privateish
        if saw_unsafe and saw_safe:
            raise OpenRelUnsafeDestinationError("OpenREL destination returned mixed safe and unsafe DNS answers.")
        return _ResolvedHost(hostname=normalized_host, port=port, addresses=resolved)

    def _validate_ip(self, raw_ip: str, *, hostname_allowed: bool) -> bool:
        ip = ipaddress.ip_address(raw_ip)
        if ip in METADATA_IPS:
            raise OpenRelUnsafeDestinationError("OpenREL destination resolved to a forbidden metadata address.")
        if isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped is not None:
            raise OpenRelUnsafeDestinationError("OpenREL destination resolved to a forbidden IPv4-mapped IPv6 address.")
        if ip.is_loopback or ip.is_link_local or ip.is_multicast or ip.is_unspecified:
            raise OpenRelUnsafeDestinationError("OpenREL destination resolved to a forbidden address.")
        if ip.is_private or ip.is_reserved:
            if hostname_allowed or self._allowed_by_explicit_allowlist(ip):
                return True
            raise OpenRelUnsafeDestinationError("OpenREL destination resolved to a private or reserved address outside the explicit allow-list.")
        return False

    def _allowed_by_explicit_allowlist(self, ip: ipaddress._BaseAddress) -> bool:
        for cidr in self._allowed_cidrs:
            if ip in ipaddress.ip_network(cidr, strict=False):
                return True
        return False

    def _cache_get(self, cache_key: tuple[str, str | None, str | None]) -> Any | None:
        entry = self._cache.get(cache_key)
        if entry is None:
            return None
        expires_at, value = entry
        if self._monotonic() >= expires_at:
            self._cache.pop(cache_key, None)
            return None
        return copy.deepcopy(value)

    def _cache_set(self, cache_key: tuple[str, str | None, str | None], value: Any) -> None:
        if len(self._cache) >= _MAX_CACHE_ENTRIES and cache_key not in self._cache:
            oldest_key = min(self._cache.items(), key=lambda item: item[1][0])[0]
            self._cache.pop(oldest_key, None)
        self._cache[cache_key] = (self._monotonic() + self.settings.cache_ttl_seconds, copy.deepcopy(value))

    @staticmethod
    def _normalize_hostnames(hostnames: tuple[str, ...]) -> tuple[str, ...]:
        return tuple(sorted({item.encode("idna").decode("ascii").lower() for item in hostnames if item}))

    @staticmethod
    def _validate_absolute_http_iri(value: str) -> str:
        parsed = urlsplit(value.strip())
        if parsed.scheme not in {"http", "https"} or not parsed.netloc or not parsed.hostname:
            raise OpenRelResponseSchemaError("OpenREL response item iri must be an absolute HTTP(S) IRI.")
        if parsed.username or parsed.password:
            raise OpenRelResponseSchemaError("OpenREL response item iri must not contain credentials.")
        return value.strip()

    @staticmethod
    def _normalize_resource_type(value: str | OpenRelResourceType) -> OpenRelResourceType:
        try:
            return value if isinstance(value, OpenRelResourceType) else OpenRelResourceType(str(value).strip().lower())
        except ValueError as exc:
            raise OpenRelUnsupportedResourceError(f"unsupported OpenREL resource type: {value}") from exc

    @staticmethod
    def _normalize_resource_id(value: str) -> str:
        if not isinstance(value, str):
            raise OpenRelClientConfigurationError("OpenREL resource id must be a string.")
        candidate = value.strip()
        lowered = candidate.lower()
        if not candidate:
            raise OpenRelClientConfigurationError("OpenREL resource id is unsafe.")
        if candidate.startswith(("/", "\\")) or candidate.startswith("//"):
            raise OpenRelClientConfigurationError("OpenREL resource id is unsafe.")
        if "://" not in candidate and candidate.count(":") <= 1:
            if (
                "\\" in candidate
                or "/" in candidate
                or ".." in lowered
                or "%2f" in lowered
                or "%5c" in lowered
                or "%2e%2e" in lowered
            ):
                raise OpenRelClientConfigurationError("OpenREL resource id is unsafe.")
            if ":" in candidate:
                prefix, suffix = candidate.split(":", 1)
                if "@" in suffix and prefix.lower() not in {"odrl", "cc"}:
                    raise OpenRelClientConfigurationError("OpenREL resource id scheme is unsupported.")
            return candidate
        parsed = urlsplit(candidate)
        if parsed.scheme:
            if parsed.scheme not in {"http", "https"}:
                raise OpenRelClientConfigurationError("OpenREL resource id scheme is unsupported.")
            if not parsed.netloc or not parsed.hostname:
                raise OpenRelClientConfigurationError("OpenREL resource IRI must include a host.")
            if parsed.username or parsed.password:
                raise OpenRelClientConfigurationError("OpenREL resource IRI must not include credentials.")
            if "%2f" in lowered or "%5c" in lowered or "%2e%2e" in lowered:
                raise OpenRelClientConfigurationError("OpenREL resource id is unsafe.")
            return candidate
        if (
            candidate.startswith("/")
            or candidate.startswith("\\")
            or candidate.startswith("//")
            or "\\" in candidate
            or "/" in candidate
            or ".." in lowered
            or "%2f" in lowered
            or "%5c" in lowered
            or "%2e%2e" in lowered
            or parsed.username is not None
            or "://" in candidate
        ):
            raise OpenRelClientConfigurationError("OpenREL resource id is unsafe.")
        return candidate

    @staticmethod
    def _validate_prefix(prefix: str | None, spec: _ResourceSpec) -> None:
        if prefix is None:
            return
        if not spec.supports_prefix:
            raise OpenRelClientConfigurationError("OpenREL prefix filters are not supported for this resource type.")
        if not isinstance(prefix, str) or not prefix.strip():
            raise OpenRelClientConfigurationError("OpenREL prefix must be a nonblank string.")

    @staticmethod
    def _validate_base_url(settings: OpenRelPolicySettings) -> str:
        base_url = (settings.base_url or "").strip()
        if not settings.enabled:
            raise OpenRelClientConfigurationError("OpenREL is disabled.")
        if settings.validation_errors:
            raise OpenRelClientConfigurationError("OpenREL settings are invalid.")
        parsed = urlsplit(base_url)
        if not parsed.scheme or parsed.scheme not in {"http", "https"} or not parsed.netloc or not parsed.hostname:
            raise OpenRelClientConfigurationError("OPENREL_BASE_URL must be a valid absolute HTTP(S) URL.")
        if parsed.username or parsed.password or parsed.query or parsed.fragment:
            raise OpenRelClientConfigurationError("OPENREL_BASE_URL must not include credentials, query, or fragment.")
        if parsed.scheme != "https" and not settings.allow_http_for_demo:
            raise OpenRelClientConfigurationError("HTTP OpenREL base URLs are only allowed for explicit demos.")
        hostname = parsed.hostname.encode("idna").decode("ascii").lower()
        port = f":{parsed.port}" if parsed.port is not None else ""
        path = parsed.path.rstrip("/")
        return f"{parsed.scheme}://{hostname}{port}{path}"


__all__ = [
    "OpenRelClient",
    "OpenRelClientConfigurationError",
    "OpenRelClientError",
    "OpenRelInvalidContentTypeError",
    "OpenRelLookupItem",
    "OpenRelMalformedJsonError",
    "OpenRelNetworkError",
    "OpenRelNotFoundError",
    "OpenRelResourceType",
    "OpenRelResponseSchemaError",
    "OpenRelResponseTooLargeError",
    "OpenRelUnexpectedStatusError",
    "OpenRelUnsafeDestinationError",
    "OpenRelUnsupportedResourceError",
]
