from __future__ import annotations

import re
import socket
from collections.abc import AsyncIterator
from ipaddress import IPv4Address, IPv4Network, IPv6Address, IPv6Network, ip_address, ip_network

from realitlscanner.models import Host, HostType

_DOMAIN_RE = re.compile(r"^[A-Za-z0-9\-.]+$")


def validate_domain(domain: str) -> bool:
    return bool(_DOMAIN_RE.match(domain))


def lookup_ip(host: str, *, enable_ipv6: bool = False) -> IPv4Address | IPv6Address:
    results = socket.getaddrinfo(host, None, socket.AF_UNSPEC, socket.SOCK_STREAM)
    for family, _, _, _, sockaddr in results:
        if family == socket.AF_INET:
            return ip_address(sockaddr[0])
        if family == socket.AF_INET6 and enable_ipv6:
            return ip_address(sockaddr[0])
    raise OSError(f"no suitable IP found for {host}")


async def iterate_lines(lines: list[str], *, enable_ipv6: bool = False) -> AsyncIterator[Host]:
    for line in lines:
        line = line.strip()
        if not line:
            continue
        try:
            addr = ip_address(line)
            if isinstance(addr, IPv4Address) or enable_ipv6:
                yield Host(ip=addr, origin=line, type=HostType.IP)
            continue
        except ValueError:
            pass
        try:
            network = ip_network(line, strict=False)
            if isinstance(network, IPv4Network) or enable_ipv6:
                for addr in network.hosts():
                    yield Host(ip=addr, origin=line, type=HostType.CIDR)
            continue
        except ValueError:
            pass
        if validate_domain(line):
            yield Host(ip=None, origin=line, type=HostType.DOMAIN)
        else:
            import logging
            logging.getLogger(__name__).warning("Not a valid IP, CIDR or domain: %s", line)


async def iterate_addr(addr: str, *, count: int = 65536, enable_ipv6: bool = False) -> AsyncIterator[Host]:
    # Only treat as CIDR if user explicitly wrote a prefix (e.g. /24)
    if "/" in addr:
        try:
            network = ip_network(addr, strict=False)
            if isinstance(network, IPv4Network) or enable_ipv6:
                for ip in network.hosts():
                    yield Host(ip=ip, origin=addr, type=HostType.CIDR)
            return
        except ValueError:
            pass

    try:
        resolved = ip_address(addr)
    except ValueError:
        resolved = lookup_ip(addr, enable_ipv6=enable_ipv6)

    yield Host(ip=resolved, origin=addr, type=HostType.IP)

    # Expand outward from the initial IP, up to `count` total
    low = int(resolved)
    high = int(resolved)
    emitted = 1
    while emitted < count:
        low -= 1
        if low >= 0 and emitted < count:
            yield Host(ip=ip_address(low), origin=str(ip_address(low)), type=HostType.IP)
            emitted += 1
        high += 1
        if emitted < count:
            yield Host(ip=ip_address(high), origin=str(ip_address(high)), type=HostType.IP)
            emitted += 1
