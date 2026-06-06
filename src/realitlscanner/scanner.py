"""TLS scanner: scan IP ranges to find Reality-compatible endpoints."""
from __future__ import annotations

import asyncio
import logging
import ssl

from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import ec, ed448, ed25519, rsa, dsa

from realitlscanner.geo import Geo
from realitlscanner.models import Host, HostType, ScanResult
from realitlscanner.utils import lookup_ip

logger = logging.getLogger(__name__)


def _pub_key_algo_name(cert: x509.Certificate) -> str:
    key = cert.public_key()
    if isinstance(key, rsa.RSAPublicKey):
        return "RSA"
    if isinstance(key, ec.EllipticCurvePublicKey):
        return "ECDSA"
    if isinstance(key, ed25519.Ed25519PublicKey):
        return "Ed25519"
    if isinstance(key, ed448.Ed448PublicKey):
        return "Ed448"
    if isinstance(key, dsa.DSAPublicKey):
        return "DSA"
    return "Unknown"


_SIG_ALGO_MAP = {
    "1.2.840.113549.1.1.11": "SHA256-RSA",
    "1.2.840.113549.1.1.12": "SHA384-RSA",
    "1.2.840.113549.1.1.13": "SHA512-RSA",
    "1.2.840.10045.4.3.2": "ECDSA-SHA256",
    "1.2.840.10045.4.3.3": "ECDSA-SHA384",
    "1.3.101.112": "Ed25519",
}


async def scan_tls(
    host: Host,
    *,
    port: int = 443,
    timeout_sec: int = 10,
    geo: Geo,
    enable_ipv6: bool = False,
) -> ScanResult | None:
    ip = host.ip
    if ip is None:
        try:
            ip = lookup_ip(host.origin, enable_ipv6=enable_ipv6)
        except OSError as e:
            logger.debug("Failed to resolve %s: %s", host.origin, e)
            return None

    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    ctx.set_alpn_protocols(["h2", "http/1.1"])

    sni = host.origin if host.type == HostType.DOMAIN else None
    target = str(ip)

    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(target, port, ssl=ctx, server_hostname=sni),
            timeout=timeout_sec,
        )
    except (OSError, asyncio.TimeoutError):
        logger.debug("Cannot connect to %s:%d", target, port)
        return None

    try:
        ssl_obj = writer.transport.get_extra_info("ssl_object")
        if ssl_obj is None:
            return None

        tls_version = ssl_obj.version() or "Unknown"
        alpn = ssl_obj.selected_alpn_protocol() or ""

        der_cert = ssl_obj.getpeercert(binary_form=True)
        if der_cert is None:
            return None

        cert = x509.load_der_x509_certificate(der_cert)
        cn_attrs = cert.subject.get_attributes_for_oid(x509.oid.NameOID.COMMON_NAME)
        domain_str = cn_attrs[0].value if cn_attrs else ""

        issuer_org = cert.issuer.get_attributes_for_oid(x509.oid.NameOID.ORGANIZATION_NAME)
        issuer_str = " | ".join(attr.value for attr in issuer_org)

        sig_oid = cert.signature_algorithm_oid.dotted_string
        signature_algo = _SIG_ALGO_MAP.get(sig_oid, sig_oid)
        pubkey_algo = _pub_key_algo_name(cert)

        geo_code = geo.get_geo(ip)

        feasible = (
            tls_version == "TLSv1.3"
            and alpn == "h2"
            and len(domain_str) > 0
            and len(issuer_str) > 0
        )

        result = ScanResult(
            ip=target, origin=host.origin, tls_version=tls_version, alpn=alpn,
            domain=domain_str, issuer=issuer_str, geo_code=geo_code,
            feasible=feasible, cert_length=len(der_cert), cert_count=1,
            signature_algo=signature_algo, pubkey_algo=pubkey_algo,
        )

        if feasible:
            logger.debug(
                "Feasible ip=%s domain=%s issuer=%s geo=%s",
                target, domain_str, issuer_str, geo_code,
            )
        else:
            logger.debug(
                "Not feasible ip=%s tls=%s alpn=%s",
                target, tls_version, alpn,
            )

        return result
    finally:
        writer.close()
        try:
            await writer.wait_closed()
        except ssl.SSLError:
            pass
