"""SSRF protection for the HTTP probe tool.

A URL is accepted only when:

* the scheme is ``http`` or ``https`` and there is no embedded user-info;
* the host matches the configured allow-list and the port is allowed;
* every address the host resolves to is globally routable, unless
  ``allow_private_networks`` is set. This blocks loopback, RFC 1918, CGNAT,
  link-local (including cloud metadata endpoints such as 169.254.169.254),
  multicast and reserved ranges, and IPv4-mapped IPv6 forms of all of them.

The probe re-checks the peer address of the actual connection after the
request (see :mod:`mcp_devtools.backends.http`) to narrow the DNS-rebinding
window between this check and the connect.
"""

from __future__ import annotations

import ipaddress
import socket
from collections.abc import Callable
from dataclasses import dataclass
from urllib.parse import urlsplit

from mcp_devtools.errors import PermissionDenied, ValidationError
from mcp_devtools.security.permissions import Policy

IPAddress = ipaddress.IPv4Address | ipaddress.IPv6Address
Resolver = Callable[[str, int], list[str]]

ALLOWED_SCHEMES = {"http": 80, "https": 443}


def system_resolver(host: str, port: int) -> list[str]:
    try:
        infos = socket.getaddrinfo(host, port, type=socket.SOCK_STREAM)
    except socket.gaierror as exc:
        raise ValidationError(f"cannot resolve host {host!r}: {exc}") from exc
    return sorted({str(info[4][0]) for info in infos})


@dataclass(frozen=True, slots=True)
class CheckedTarget:
    url: str
    scheme: str
    host: str
    port: int
    addresses: tuple[str, ...]


def normalise_ip(raw: str) -> IPAddress:
    ip = ipaddress.ip_address(raw.split("%", 1)[0])  # drop IPv6 zone id
    if isinstance(ip, ipaddress.IPv6Address):
        if ip.ipv4_mapped is not None:
            return ip.ipv4_mapped
        if ip.sixtofour is not None:
            return ip.sixtofour
    return ip


def is_public_address(raw: str) -> bool:
    try:
        ip = normalise_ip(raw)
    except ValueError:
        return False
    return ip.is_global and not ip.is_multicast


class SsrfGuard:
    def __init__(self, policy: Policy, resolver: Resolver = system_resolver) -> None:
        self.policy = policy
        self.resolver = resolver

    @property
    def allow_private(self) -> bool:
        return self.policy.settings.http.allow_private_networks

    def check_url(self, url: str) -> CheckedTarget:
        try:
            parts = urlsplit(url.strip())
            port = parts.port
        except ValueError as exc:
            raise ValidationError(f"invalid URL: {exc}") from exc

        scheme = parts.scheme.lower()
        if scheme not in ALLOWED_SCHEMES:
            raise ValidationError(f"scheme {parts.scheme!r} is not allowed; use http or https")
        if parts.username is not None or parts.password is not None:
            raise ValidationError("URLs with embedded credentials are not allowed")
        host = (parts.hostname or "").lower()
        if not host:
            raise ValidationError("URL has no host")

        self.policy.host(host)
        port = port or ALLOWED_SCHEMES[scheme]
        self.policy.port(port)

        addresses = self._resolve(host, port)
        if not self.allow_private:
            blocked = [addr for addr in addresses if not is_public_address(addr)]
            if blocked:
                raise PermissionDenied(
                    f"host {host!r} resolves to non-public address(es) {blocked}; "
                    "set http.allow_private_networks to probe internal services"
                )
        return CheckedTarget(url.strip(), scheme, host, port, tuple(addresses))

    def check_peer(self, address: str | None) -> None:
        """Validate the address the connection actually went to."""
        if address is None or self.allow_private:
            return
        if not is_public_address(address):
            raise PermissionDenied(f"connection was made to non-public address {address}")

    def _resolve(self, host: str, port: int) -> list[str]:
        try:
            literal = ipaddress.ip_address(host.strip("[]"))
        except ValueError:
            addresses = self.resolver(host, port)
            if not addresses:
                raise ValidationError(f"host {host!r} did not resolve to any address") from None
            return addresses
        return [str(literal)]
