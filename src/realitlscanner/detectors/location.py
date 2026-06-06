from __future__ import annotations

import socket

from realitlscanner.geo import Geo


def resolve_ip(domain: str) -> str | None:
    try:
        results = socket.getaddrinfo(domain, None, socket.AF_UNSPEC, socket.SOCK_STREAM)
        for family, _, _, _, sockaddr in results:
            if family == socket.AF_INET:
                return sockaddr[0]
        if results:
            return results[0][4][0]
    except OSError:
        pass
    return None


def check_location(domain: str, geo: Geo) -> tuple[str, bool, str]:
    """Returns (country, is_domestic, ip_address)."""
    ip_str = resolve_ip(domain)
    if not ip_str:
        return "未知", False, ""

    country = geo.get_geo(ip_str)
    if country == "N/A":
        return "未知", False, ip_str

    is_domestic = country == "CN"
    return country, is_domestic, ip_str
