from __future__ import annotations

import asyncio
import inspect
import ipaddress
import random
import socket
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from email.utils import parsedate_to_datetime
from enum import Enum
from json import JSONDecodeError
from typing import Any, Awaitable, Callable, Literal
from urllib.parse import quote, urlsplit

import httpx

from src.license_facade_service.config.openrel import OpenRelSettings
from src.license_facade_service.federation.json_strict import DuplicateJsonKeyError, loads_json_no_duplicates
from src.license_facade_service.openrel.models import (
    OpenRELMapping,
    OpenRELResource,
    validate_openrel_mapping_list,
    validate_openrel_resource,
    validate_openrel_resource_list,
)

OpenRelListFamily = Literal[
    "actions",
    "constraints",
    "leftoperands",
    "mappings",
    "actionclasses",
    "assetclasses",
    "constraintclasses",
    "leftoperandclasses",
    "ruleclasses",
]
OpenRelDetailFamily = Literal[
    "actions",
    "constraints",
    "leftoperands",
    "actionclasses",
    "assetclasses",
    "constraintclasses",
    "leftoperandclasses",
    "ruleclasses",
]

_LIST_FAMILIES: tuple[str, ...] = (
    "actions",
    "constraints",
    "leftoperands",
    "mappings",
    "actionclasses",
    "assetclasses",
    "constraintclasses",
    "leftoperandclasses",
    "ruleclasses",
)
_DETAIL_FAMILIES: tuple[str, ...] = tuple(item for item in _LIST_FAMILIES if item != "mappings")

METADATA_IPS = (
    ipaddress.ip_address("169.254.169.254"),
    ipaddress.ip_address("100.100.100.200"),
)

ResolverResult = list[str] | tuple[str, ...]
Resolver = Callable[[str, int], Awaitable[ResolverResult] | ResolverResult]
SleepFn = Callable[[float], Awaitable[None]]
MonotonicFn = Callable[[], float]
WallTimeFn = Callable[[], float]
RandomFn = Callable[[], float]


class OpenRelErrorCode(str, Enum):
    DISABLED = "disabled"
    INVALID_CONFIGURATION = "invalid-configuration"
    INVALID_ID = "invalid-id"
    INVALID_PREFIX = "invalid-prefix"
    FORBIDDEN_DESTINATION = "forbidden-destination"
    DNS_FAILURE = "dns-failure"
    CONNECTION_FAILURE = "connection-failure"
    TIMEOUT = "timeout"
    PROVIDER_NOT_FOUND = "provider-not-found"
    PROVIDER_RATE_LIMITED = "provider-rate-limited"
    PROVIDER_AUTH_FAILURE = "provider-auth-failure"
    PROVIDER_UNAVAILABLE = "provider-unavailable"
    PROVIDER_ERROR = "provider-error"
    PROVIDER_BAD_REQUEST = "provider-bad-request"
    REDIRECT = "redirect"
    INVALID_CONTENT_TYPE = "invalid-content-type"
    MALFORMED_JSON = "malformed-json"
    DUPLICATE_JSON_KEY = "duplicate-json-key"
    OVERSIZED_RESPONSE = "oversized-response"
    INVALID_RESPONSE_SHAPE = "invalid-response-shape"
    INVALID_RESPONSE_SCHEMA = "invalid-response-schema"
    INTERNAL_ERROR = "internal-error"


class OpenRelClientError(Exception):
    def __init__(
        self,
        code: OpenRelErrorCode,
        detail: str,
        *,
        retryable: bool = False,
        retry_after_seconds: int | None = None,
    ) -> None:
        super().__init__(detail)
        self.code = code
        self.detail = detail
        self.retryable = retryable
        self.retry_after_seconds = retry_after_seconds


@dataclass(frozen=True)
class ResolvedDestination:
    hostname: str
    port: int
    addresses: tuple[str, ...]


class OpenRelUrlPolicy:
    """
    DNS validation is best-effort: resolvers and HTTP transports may perform
    independent lookups. Production egress policy remains required.
    """

    def __init__(self, settings: OpenRelSettings, resolver: Resolver | None = None):
        self.settings = settings
        self._resolver = resolver or self._default_resolver

    @staticmethod
    async def _default_resolver(hostname: str, port: int) -> list[str]:
        loop = asyncio.get_running_loop()
        info = await loop.getaddrinfo(hostname, port, type=socket.SOCK_STREAM)
        return [row[4][0] for row in info]

    @staticmethod
    def _normalize_hostname(hostname: str) -> str:
        return hostname.strip().rstrip(".").lower().encode("idna").decode("ascii")

    async def _resolve_answers(self, hostname: str, port: int) -> tuple[str, ...]:
        try:
            result = self._resolver(hostname, port)
            if inspect.isawaitable(result):
                result = await result
        except (TimeoutError, asyncio.TimeoutError) as exc:
            raise OpenRelClientError(
                OpenRelErrorCode.TIMEOUT,
                "OpenREL DNS resolution exceeded total timeout budget.",
                retryable=True,
            ) from exc
        except (socket.gaierror, OSError) as exc:
            raise OpenRelClientError(
                OpenRelErrorCode.DNS_FAILURE,
                "OpenREL destination could not be resolved.",
                retryable=True,
            ) from exc
        except OpenRelClientError:
            raise
        except Exception as exc:
            raise OpenRelClientError(
                OpenRelErrorCode.DNS_FAILURE,
                "OpenREL DNS resolver failed unexpectedly.",
                retryable=True,
            ) from exc

        if not isinstance(result, (list, tuple)):
            raise OpenRelClientError(OpenRelErrorCode.DNS_FAILURE, "OpenREL DNS resolver returned an invalid answer set.")
        if not result:
            raise OpenRelClientError(OpenRelErrorCode.DNS_FAILURE, "OpenREL destination returned no DNS answers.", retryable=True)

        addresses: list[str] = []
        for item in result:
            if not isinstance(item, str) or not item.strip():
                raise OpenRelClientError(OpenRelErrorCode.DNS_FAILURE, "OpenREL DNS answer was malformed.")
            addresses.append(item.strip())
        return tuple(sorted(set(addresses)))

    @staticmethod
    def _is_non_public(ip: ipaddress._BaseAddress) -> bool:
        return (
            ip.is_loopback
            or ip.is_private
            or ip.is_link_local
            or ip.is_multicast
            or ip.is_reserved
            or ip.is_unspecified
        )

    async def validate_and_resolve(self, url: str) -> ResolvedDestination:
        parsed = urlsplit(url)
        if not parsed.hostname:
            raise OpenRelClientError(OpenRelErrorCode.INVALID_CONFIGURATION, "OpenREL destination hostname is missing.")
        if parsed.username or parsed.password:
            raise OpenRelClientError(OpenRelErrorCode.INVALID_CONFIGURATION, "OpenREL destination credentials are not allowed.")
        if parsed.query or parsed.fragment:
            raise OpenRelClientError(OpenRelErrorCode.INVALID_CONFIGURATION, "OpenREL destination must not include query or fragment.")

        hostname = self._normalize_hostname(parsed.hostname)
        scheme = parsed.scheme.lower()
        if scheme not in {"https", "http"}:
            raise OpenRelClientError(OpenRelErrorCode.FORBIDDEN_DESTINATION, "OpenREL destination scheme is unsupported.")
        if scheme == "http" and not self.settings.allow_http_for_demo:
            raise OpenRelClientError(OpenRelErrorCode.FORBIDDEN_DESTINATION, "HTTP OpenREL destinations are disabled.")

        port = parsed.port or (443 if scheme == "https" else 80)
        if port not in self.settings.allowed_ports:
            raise OpenRelClientError(OpenRelErrorCode.FORBIDDEN_DESTINATION, "OpenREL destination port is not allowed.")

        answers = await self._resolve_answers(hostname, port)
        saw_public = False
        saw_non_public = False
        for raw_ip in answers:
            try:
                ip = ipaddress.ip_address(raw_ip)
            except ValueError as exc:
                raise OpenRelClientError(OpenRelErrorCode.DNS_FAILURE, "OpenREL DNS answer is not a valid IP address.") from exc

            if isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped is not None:
                raise OpenRelClientError(OpenRelErrorCode.FORBIDDEN_DESTINATION, "IPv4-mapped IPv6 destinations are forbidden.")
            if ip in METADATA_IPS:
                raise OpenRelClientError(OpenRelErrorCode.FORBIDDEN_DESTINATION, "Metadata destinations are forbidden.")

            non_public = self._is_non_public(ip)
            saw_non_public = saw_non_public or non_public
            saw_public = saw_public or not non_public
            if non_public:
                if hostname not in self.settings.allowed_hostnames:
                    raise OpenRelClientError(
                        OpenRelErrorCode.FORBIDDEN_DESTINATION,
                        "OpenREL non-public destination hostname is not allow-listed.",
                    )
                if not any(ip in ipaddress.ip_network(cidr, strict=False) for cidr in self.settings.allowed_cidrs):
                    raise OpenRelClientError(
                        OpenRelErrorCode.FORBIDDEN_DESTINATION,
                        "OpenREL non-public destination address is not in an allowed CIDR.",
                    )
        if saw_public and saw_non_public:
            raise OpenRelClientError(OpenRelErrorCode.FORBIDDEN_DESTINATION, "Mixed public and non-public DNS answers are forbidden.")
        return ResolvedDestination(hostname=hostname, port=port, addresses=answers)


class OpenRelClient:
    def __init__(
        self,
        settings: OpenRelSettings,
        *,
        http_client: httpx.AsyncClient | None = None,
        resolver: Resolver | None = None,
        sleep_fn: SleepFn = asyncio.sleep,
        monotonic_fn: MonotonicFn = time.monotonic,
        wall_time_fn: WallTimeFn = time.time,
        random_fn: RandomFn = random.random,
    ) -> None:
        self.settings = settings
        self._sleep = sleep_fn
        self._monotonic = monotonic_fn
        self._wall_time = wall_time_fn
        self._random = random_fn
        self._url_policy = OpenRelUrlPolicy(settings, resolver=resolver)
        self._owns_http_client = http_client is None
        self._http_client = http_client or httpx.AsyncClient(
            timeout=httpx.Timeout(
                connect=settings.connect_timeout_seconds,
                read=settings.read_timeout_seconds,
                write=settings.write_timeout_seconds,
                pool=settings.pool_timeout_seconds,
            ),
            follow_redirects=False,
        )
        if settings.base_url:
            parsed = urlsplit(settings.base_url)
            self._origin = f"{parsed.scheme}://{parsed.netloc}"
            self._base_path = parsed.path.rstrip("/")
        else:
            self._origin = ""
            self._base_path = ""

    async def aclose(self) -> None:
        if self._owns_http_client:
            await self._http_client.aclose()

    async def list_resources(self, family: OpenRelListFamily, *, prefix: str | None = None) -> list[OpenRELResource]:
        if family not in _LIST_FAMILIES:
            raise OpenRelClientError(OpenRelErrorCode.INVALID_CONFIGURATION, "Unsupported OpenREL list family.")
        if family == "mappings":
            raise OpenRelClientError(OpenRelErrorCode.INVALID_CONFIGURATION, "Mappings must be requested via list_mappings.")
        payload = await self._execute_request(
            kind="list",
            family=family,
            identifier=None,
            prefix=self._validate_prefix(prefix),
            response_limit=self.settings.max_list_response_bytes,
        )
        if not isinstance(payload, list):
            raise OpenRelClientError(OpenRelErrorCode.INVALID_RESPONSE_SHAPE, "OpenREL list response must be a JSON array.")
        try:
            return validate_openrel_resource_list(payload)
        except Exception as exc:
            raise OpenRelClientError(OpenRelErrorCode.INVALID_RESPONSE_SCHEMA, "OpenREL list response failed schema validation.") from exc

    async def list_mappings(self, *, prefix: str | None = None) -> list[OpenRELMapping]:
        payload = await self._execute_request(
            kind="list",
            family="mappings",
            identifier=None,
            prefix=self._validate_prefix(prefix),
            response_limit=self.settings.max_list_response_bytes,
        )
        if not isinstance(payload, list):
            raise OpenRelClientError(OpenRelErrorCode.INVALID_RESPONSE_SHAPE, "OpenREL mapping response must be a JSON array.")
        try:
            return validate_openrel_mapping_list(payload)
        except Exception as exc:
            raise OpenRelClientError(OpenRelErrorCode.INVALID_RESPONSE_SCHEMA, "OpenREL mapping response failed schema validation.") from exc

    async def get_resource(
        self,
        family: OpenRelDetailFamily,
        identifier: str,
        *,
        prefix: str | None = None,
    ) -> OpenRELResource:
        if family not in _DETAIL_FAMILIES:
            raise OpenRelClientError(OpenRelErrorCode.INVALID_CONFIGURATION, "Unsupported OpenREL detail family.")
        payload = await self._execute_request(
            kind="detail",
            family=family,
            identifier=self._validate_id(identifier),
            prefix=self._validate_prefix(prefix),
            response_limit=self.settings.max_detail_response_bytes,
        )
        if not isinstance(payload, dict):
            raise OpenRelClientError(OpenRelErrorCode.INVALID_RESPONSE_SHAPE, "OpenREL detail response must be a JSON object.")
        try:
            return validate_openrel_resource(payload)
        except Exception as exc:
            raise OpenRelClientError(OpenRelErrorCode.INVALID_RESPONSE_SCHEMA, "OpenREL detail response failed schema validation.") from exc

    def _ensure_operational(self) -> None:
        if not self.settings.enabled:
            raise OpenRelClientError(OpenRelErrorCode.DISABLED, "OpenREL integration is disabled.")
        if self.settings.validation_errors or not self.settings.base_url:
            raise OpenRelClientError(OpenRelErrorCode.INVALID_CONFIGURATION, "OpenREL configuration is invalid.")

    @staticmethod
    def _contains_control_or_nul(value: str) -> bool:
        return any(ch == "\x00" or ord(ch) < 0x20 or ord(ch) == 0x7F for ch in value)

    def _validate_id(self, identifier: str) -> str:
        if identifier == "":
            raise OpenRelClientError(OpenRelErrorCode.INVALID_ID, "OpenREL identifier must not be empty.")
        if len(identifier) > self.settings.max_id_length:
            raise OpenRelClientError(OpenRelErrorCode.INVALID_ID, "OpenREL identifier exceeds maximum length.")
        if self._contains_control_or_nul(identifier):
            raise OpenRelClientError(OpenRelErrorCode.INVALID_ID, "OpenREL identifier contains forbidden control characters.")
        segments = identifier.split("/")
        if any(seg in {".", ".."} for seg in segments):
            raise OpenRelClientError(OpenRelErrorCode.INVALID_ID, "OpenREL identifier contains forbidden path-segment values.")
        return identifier

    def _validate_prefix(self, prefix: str | None) -> str | None:
        if prefix is None or prefix == "":
            return None
        if len(prefix) > self.settings.max_prefix_length:
            raise OpenRelClientError(OpenRelErrorCode.INVALID_PREFIX, "OpenREL prefix exceeds maximum length.")
        if self._contains_control_or_nul(prefix):
            raise OpenRelClientError(OpenRelErrorCode.INVALID_PREFIX, "OpenREL prefix contains forbidden control characters.")
        return prefix

    def _build_url(self, family: str, identifier: str | None) -> str:
        path = f"{self._base_path}/{family}"
        if identifier is not None:
            path = f"{path}/{quote(identifier, safe='')}"
        return f"{self._origin}{path}"

    @staticmethod
    def _is_supported_json_content_type(content_type: str | None) -> bool:
        if content_type is None:
            return False
        media_type = content_type.split(";", 1)[0].strip().lower()
        if media_type == "application/json":
            return True
        if not media_type.startswith("application/"):
            return False
        subtype = media_type.split("/", 1)[1]
        return subtype.endswith("+json") and subtype != "+json"

    def _parse_retry_after_seconds(self, value: str | None, *, remaining_budget_seconds: float) -> int | None:
        if value is None or not value.strip():
            return None
        raw = value.strip()
        parsed_seconds: int | None = None
        if raw.isdigit():
            parsed_seconds = int(raw)
        else:
            try:
                dt = parsedate_to_datetime(raw)
            except (TypeError, ValueError):
                return None
            if dt.tzinfo is None:
                dt = dt.replace(tzinfo=timezone.utc)
            now_dt = datetime.fromtimestamp(self._wall_time(), tz=timezone.utc)
            parsed_seconds = max(0, int((dt - now_dt).total_seconds()))

        max_allowed = int(max(0.0, min(self.settings.retry_max_seconds, remaining_budget_seconds)))
        return max(0, min(parsed_seconds, max_allowed))

    def _is_retryable(self, error: OpenRelClientError) -> bool:
        return error.code in {
            OpenRelErrorCode.CONNECTION_FAILURE,
            OpenRelErrorCode.DNS_FAILURE,
            OpenRelErrorCode.TIMEOUT,
            OpenRelErrorCode.PROVIDER_UNAVAILABLE,
        }

    async def _execute_request(
        self,
        *,
        kind: Literal["list", "detail"],
        family: str,
        identifier: str | None,
        prefix: str | None,
        response_limit: int,
    ) -> Any:
        self._ensure_operational()
        url = self._build_url(family, identifier)
        deadline = self._monotonic() + self.settings.total_timeout_seconds
        attempts = self.settings.retry_attempts
        try:
            async with asyncio.timeout(self.settings.total_timeout_seconds):
                for attempt in range(attempts):
                    remaining = deadline - self._monotonic()
                    if remaining <= 0:
                        raise OpenRelClientError(OpenRelErrorCode.TIMEOUT, "OpenREL total timeout budget exhausted.", retryable=True)
                    try:
                        return await self._single_attempt(
                            kind=kind,
                            url=url,
                            prefix=prefix,
                            response_limit=response_limit,
                            remaining_budget_seconds=remaining,
                        )
                    except OpenRelClientError as exc:
                        if not self._is_retryable(exc) or attempt + 1 >= attempts:
                            raise
                        remaining = deadline - self._monotonic()
                        if remaining <= 0:
                            raise OpenRelClientError(OpenRelErrorCode.TIMEOUT, "OpenREL total timeout budget exhausted.", retryable=True) from exc
                        backoff = min(
                            self.settings.retry_base_seconds * (2**attempt) + (self._random() * 0.1),
                            self.settings.retry_max_seconds,
                        )
                        if exc.retry_after_seconds is not None:
                            backoff = max(backoff, float(exc.retry_after_seconds))
                            backoff = min(backoff, self.settings.retry_max_seconds)
                        sleep_for = min(backoff, remaining)
                        if sleep_for <= 0:
                            raise OpenRelClientError(OpenRelErrorCode.TIMEOUT, "OpenREL total timeout budget exhausted.", retryable=True) from exc
                        await self._sleep(sleep_for)
        except TimeoutError as exc:
            raise OpenRelClientError(OpenRelErrorCode.TIMEOUT, "OpenREL request exceeded total timeout budget.", retryable=True) from exc
        raise OpenRelClientError(OpenRelErrorCode.INTERNAL_ERROR, "OpenREL request failed unexpectedly.")

    async def _single_attempt(
        self,
        *,
        kind: Literal["list", "detail"],
        url: str,
        prefix: str | None,
        response_limit: int,
        remaining_budget_seconds: float,
    ) -> Any:
        await self._url_policy.validate_and_resolve(url)
        headers = {
            "Accept": "application/json",
            "Accept-Encoding": "identity",
            "User-Agent": "license-facade-service/openrel-client",
        }
        params: dict[str, str] = {}
        if prefix is not None:
            params["prefix"] = prefix
        try:
            async with self._http_client.stream("GET", url, headers=headers, params=params) as response:
                status = response.status_code
                if 300 <= status <= 399:
                    raise OpenRelClientError(OpenRelErrorCode.REDIRECT, "OpenREL redirects are not allowed.")
                if status != 200:
                    retry_after = self._parse_retry_after_seconds(
                        response.headers.get("retry-after"),
                        remaining_budget_seconds=remaining_budget_seconds,
                    )
                    if status == 404 and kind == "detail":
                        raise OpenRelClientError(OpenRelErrorCode.PROVIDER_NOT_FOUND, "OpenREL resource was not found.")
                    if status == 429:
                        raise OpenRelClientError(
                            OpenRelErrorCode.PROVIDER_RATE_LIMITED,
                            "OpenREL provider rate-limited the request.",
                            retry_after_seconds=retry_after,
                        )
                    if status in {401, 403}:
                        raise OpenRelClientError(OpenRelErrorCode.PROVIDER_AUTH_FAILURE, "OpenREL provider rejected credentials.")
                    if status == 400:
                        raise OpenRelClientError(OpenRelErrorCode.PROVIDER_BAD_REQUEST, "OpenREL provider rejected request parameters.")
                    if status in {502, 503, 504}:
                        raise OpenRelClientError(
                            OpenRelErrorCode.PROVIDER_UNAVAILABLE,
                            "OpenREL provider is temporarily unavailable.",
                            retryable=True,
                            retry_after_seconds=retry_after,
                        )
                    if status == 204 or (200 <= status < 300):
                        raise OpenRelClientError(OpenRelErrorCode.INVALID_RESPONSE_SHAPE, "OpenREL provider returned an unexpected success status.")
                    if status >= 500:
                        raise OpenRelClientError(OpenRelErrorCode.PROVIDER_ERROR, "OpenREL provider returned a server error.")
                    raise OpenRelClientError(OpenRelErrorCode.PROVIDER_ERROR, "OpenREL provider returned an unexpected status.")

                if not self._is_supported_json_content_type(response.headers.get("content-type")):
                    raise OpenRelClientError(OpenRelErrorCode.INVALID_CONTENT_TYPE, "OpenREL provider returned an unsupported content type.")

                content_length = response.headers.get("content-length")
                declared_size: int | None = None
                if content_length is not None:
                    try:
                        declared_size = int(content_length)
                    except ValueError as exc:
                        raise OpenRelClientError(OpenRelErrorCode.OVERSIZED_RESPONSE, "OpenREL Content-Length header is invalid.") from exc
                    if declared_size < 0:
                        raise OpenRelClientError(OpenRelErrorCode.OVERSIZED_RESPONSE, "OpenREL Content-Length header is invalid.")
                    if declared_size > response_limit:
                        raise OpenRelClientError(OpenRelErrorCode.OVERSIZED_RESPONSE, "OpenREL response exceeds configured byte limit.")

                body = bytearray()
                async for chunk in response.aiter_bytes():
                    body.extend(chunk)
                    if len(body) > response_limit:
                        raise OpenRelClientError(OpenRelErrorCode.OVERSIZED_RESPONSE, "OpenREL response exceeds configured byte limit.")
                if declared_size is not None and len(body) != declared_size:
                    raise OpenRelClientError(OpenRelErrorCode.OVERSIZED_RESPONSE, "OpenREL response size does not match Content-Length.")

                try:
                    return loads_json_no_duplicates(bytes(body))
                except DuplicateJsonKeyError as exc:
                    raise OpenRelClientError(OpenRelErrorCode.DUPLICATE_JSON_KEY, "OpenREL response contained duplicate JSON keys.") from exc
                except (UnicodeDecodeError, JSONDecodeError, ValueError) as exc:
                    raise OpenRelClientError(OpenRelErrorCode.MALFORMED_JSON, "OpenREL response JSON is malformed.") from exc
        except OpenRelClientError:
            raise
        except (TimeoutError, asyncio.TimeoutError) as exc:
            raise OpenRelClientError(OpenRelErrorCode.TIMEOUT, "OpenREL provider request timed out.", retryable=True) from exc
        except httpx.TimeoutException as exc:
            raise OpenRelClientError(OpenRelErrorCode.TIMEOUT, "OpenREL provider request timed out.", retryable=True) from exc
        except httpx.TransportError as exc:
            raise OpenRelClientError(OpenRelErrorCode.CONNECTION_FAILURE, "OpenREL provider connection failed.", retryable=True) from exc
