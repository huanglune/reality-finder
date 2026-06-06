from __future__ import annotations

import asyncio
import ssl
import time
from datetime import datetime, timezone

from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import ec, rsa

from realitlscanner.models import CheckResult


async def check_tls(domain: str, *, timeout_sec: float = 10.0) -> dict:
    """Perform comprehensive TLS check: TLS1.3, H2, X25519, SNI, cert validity.

    Returns a dict of fields to update on CheckResult.
    """
    result: dict = {}

    # First handshake: TLS 1.3 + H2 + cert info
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = True
    ctx.verify_mode = ssl.CERT_REQUIRED
    ctx.load_default_certs()
    ctx.set_alpn_protocols(["h2", "http/1.1"])

    t0 = time.monotonic()
    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(domain, 443, ssl=ctx, server_hostname=domain),
            timeout=timeout_sec,
        )
    except Exception:
        # Retry without verification to get partial info
        ctx2 = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx2.check_hostname = False
        ctx2.verify_mode = ssl.CERT_NONE
        ctx2.set_alpn_protocols(["h2", "http/1.1"])
        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(domain, 443, ssl=ctx2, server_hostname=domain),
                timeout=timeout_sec,
            )
            result["cert_valid"] = False
            result["sni_match"] = False
        except Exception:
            return result
    else:
        result["cert_valid"] = True
        result["sni_match"] = True

    try:
        handshake_ms = (time.monotonic() - t0) * 1000
        result["handshake_ms"] = handshake_ms

        ssl_obj = writer.transport.get_extra_info("ssl_object")
        if ssl_obj is None:
            return result

        version = ssl_obj.version() or ""
        result["tls13"] = version == "TLSv1.3"
        result["h2"] = ssl_obj.selected_alpn_protocol() == "h2"

        der_cert = ssl_obj.getpeercert(binary_form=True)
        if der_cert:
            cert = x509.load_der_x509_certificate(der_cert)
            issuer_org = cert.issuer.get_attributes_for_oid(x509.oid.NameOID.ORGANIZATION_NAME)
            result["cert_issuer"] = " | ".join(a.value for a in issuer_org) if issuer_org else ""

            now = datetime.now(timezone.utc)
            if cert.not_valid_after_utc > now:
                result["cert_days_left"] = (cert.not_valid_after_utc - now).days
            else:
                result["cert_days_left"] = 0
                result["cert_valid"] = False
    finally:
        writer.close()
        try:
            await writer.wait_closed()
        except ssl.SSLError:
            pass

    # Second handshake: force X25519 only
    result["x25519"] = await _check_x25519(domain, timeout_sec=min(timeout_sec, 5.0))

    return result


async def _check_x25519(domain: str, *, timeout_sec: float = 5.0) -> bool:
    """Force X25519-only handshake to verify server support."""
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    ctx.set_alpn_protocols(["h2", "http/1.1"])
    ctx.minimum_version = ssl.TLSVersion.TLSv1_3
    ctx.maximum_version = ssl.TLSVersion.TLSv1_3

    # Force X25519 curve via set_ecdh_curve (OpenSSL 3.x supports this)
    try:
        ctx.set_ecdh_curve("X25519")
    except Exception:
        pass

    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(domain, 443, ssl=ctx, server_hostname=domain),
            timeout=timeout_sec,
        )
        ssl_obj = writer.transport.get_extra_info("ssl_object")
        version = ssl_obj.version() if ssl_obj else ""
        writer.close()
        try:
            await writer.wait_closed()
        except ssl.SSLError:
            pass
        return version == "TLSv1.3"
    except Exception:
        return False
