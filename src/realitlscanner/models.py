from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum, auto
from ipaddress import IPv4Address, IPv6Address


class HostType(Enum):
    IP = auto()
    CIDR = auto()
    DOMAIN = auto()


@dataclass(frozen=True)
class Host:
    ip: IPv4Address | IPv6Address | None
    origin: str
    type: HostType


@dataclass
class ScanResult:
    ip: str
    origin: str
    tls_version: str
    alpn: str
    domain: str
    issuer: str
    geo_code: str
    feasible: bool
    cert_length: int = 0
    cert_count: int = 1
    signature_algo: str = ""
    pubkey_algo: str = ""

    def to_csv_line(self) -> str:
        length_field = f"{self.cert_length}(certs count: {self.cert_count})"
        return ",".join([
            self.ip, self.origin, self.tls_version, self.alpn,
            length_field, self.signature_algo, self.pubkey_algo,
            self.domain, f'"{self.issuer}"', self.geo_code,
        ])


@dataclass
class CheckResult:
    domain: str
    suitable: bool = False
    error: str = ""

    # detection details
    blocked: bool = False
    blocked_reason: str = ""
    is_domestic: bool = False
    country: str = ""
    ip_address: str = ""

    tls13: bool = False
    x25519: bool = False
    h2: bool = False
    sni_match: bool = False
    handshake_ms: float = 0.0

    cert_valid: bool = False
    cert_issuer: str = ""
    cert_days_left: int = 0

    is_cdn: bool = False
    cdn_confidence: str = ""
    cdn_evidence: str = ""

    is_hot_website: bool = False

    redirected: bool = False
    final_domain: str = ""
    status_code: int = 0

    headers: dict[str, str] = field(default_factory=dict)
