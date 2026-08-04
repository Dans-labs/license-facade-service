from __future__ import annotations

import ipaddress
import socket
from dataclasses import dataclass
from urllib.parse import urlsplit

from src.license_facade_service.config.federation import FederationSettings


class UrlSecurityError(ValueError):
    pass


METADATA_IPS = {
    ipaddress.ip_address("169.254.169.254"),
    ipaddress.ip_address("100.100.100.200"),
}


@dataclass(frozen=True)
class ResolvedHost:
    hostname: str
    port: int
    addresses: tuple[str, ...]


class FederationUrlPolicy:
    def __init__(self, settings: FederationSettings):
        self.settings = settings

    def validate_and_resolve(
        self,
        url: str,
        *,
        allowed_hostnames: tuple[str, ...] = (),
        allowed_cidrs: tuple[str, ...] = (),
        peer_allowed_hostnames: tuple[str, ...] = (),
        peer_allowed_cidrs: tuple[str, ...] = (),
        allow_redirect: bool = False,
    ) -> ResolvedHost:
        parsed = urlsplit(url)
        if not parsed.hostname:
            raise UrlSecurityError("URL hostname is required.")
        if parsed.username or parsed.password:
            raise UrlSecurityError("URL credentials are not allowed.")
        if parsed.scheme != "https":
            if not (self.settings.allow_http_for_demo and parsed.scheme == "http"):
                raise UrlSecurityError("Only HTTPS URLs are allowed.")
        port = parsed.port or (443 if parsed.scheme == "https" else 80)
        if port not in self.settings.sync_allowed_ports:
            raise UrlSecurityError("URL port is not allowed.")

        normalized_host = parsed.hostname.encode("idna").decode("ascii").lower()
        hostname_allowlist = self._normalize_hostnames(
            tuple(self.settings.sync_allowed_hostnames) + allowed_hostnames + peer_allowed_hostnames
        )
        cidr_allowlist = tuple(self.settings.sync_allowed_cidrs) + allowed_cidrs + peer_allowed_cidrs
        info = socket.getaddrinfo(normalized_host, port, type=socket.SOCK_STREAM)
        if not info:
            raise UrlSecurityError("Hostname resolution returned no addresses.")
        resolved: list[str] = []
        for row in info:
            addr = row[4][0]
            resolved.append(addr)
        unique = tuple(sorted(set(resolved)))
        saw_privateish = False
        saw_public = False
        for addr in unique:
            privateish = self._validate_ip(
                raw_ip=addr,
                hostname=normalized_host,
                hostname_allowed=normalized_host in hostname_allowlist,
                cidr_allowlist=cidr_allowlist,
            )
            saw_privateish = saw_privateish or privateish
            saw_public = saw_public or not privateish
        if saw_privateish and saw_public:
            raise UrlSecurityError("Mixed safe and unsafe DNS answers are not allowed.")
        return ResolvedHost(hostname=normalized_host, port=port, addresses=unique)

    def _validate_ip(self, raw_ip: str, *, hostname: str, hostname_allowed: bool, cidr_allowlist: tuple[str, ...]) -> bool:
        ip = ipaddress.ip_address(raw_ip)
        if ip in METADATA_IPS:
            raise UrlSecurityError("Metadata service address is forbidden.")
        if isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped is not None:
            raise UrlSecurityError("IPv4-mapped IPv6 addresses are forbidden.")
        if ip.is_loopback or ip.is_link_local or ip.is_multicast or ip.is_unspecified:
            raise UrlSecurityError("Resolved address is not allowed.")
        if ip.is_private or ip.is_reserved:
            if hostname_allowed:
                return True
            if self._allowed_by_explicit_allowlist(ip, cidr_allowlist):
                return True
            raise UrlSecurityError("Resolved private address is not in an allowed hostname or CIDR allow-list.")
        return False

    @staticmethod
    def _normalize_hostnames(hostnames: tuple[str, ...]) -> tuple[str, ...]:
        return tuple(sorted({item.encode("idna").decode("ascii").lower() for item in hostnames if item}))

    @staticmethod
    def _allowed_by_explicit_allowlist(ip: ipaddress._BaseAddress, cidr_allowlist: tuple[str, ...]) -> bool:
        for cidr in cidr_allowlist:
            if ip in ipaddress.ip_network(cidr, strict=False):
                return True
        return False
