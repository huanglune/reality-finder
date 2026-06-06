"""Reality domain checker: deep verification of candidate domains."""
from __future__ import annotations

import asyncio
import logging

from realitlscanner.detectors.blocked import check_blocked
from realitlscanner.detectors.cdn import detect_cdn
from realitlscanner.detectors.hot_website import is_hot_website
from realitlscanner.detectors.location import check_location
from realitlscanner.detectors.redirect import follow_redirects
from realitlscanner.detectors.tls import check_tls
from realitlscanner.geo import Geo
from realitlscanner.models import CheckResult

logger = logging.getLogger(__name__)


async def check_domain(domain: str, *, geo: Geo, timeout_sec: float = 10.0) -> CheckResult:
    """Run full Reality suitability check on a domain."""
    result = CheckResult(domain=domain)

    # Stage 1: GFW blocked check (local, instant)
    blocked, reason = check_blocked(domain)
    if blocked:
        result.blocked = True
        result.blocked_reason = reason
        result.error = f"域名被墙: {reason}"
        return result

    # Stage 2: Redirect detection + HTTP headers
    final_domain, status_code, is_redirected, headers = await follow_redirects(
        domain, timeout=min(timeout_sec, 3.0)
    )
    result.status_code = status_code
    result.redirected = is_redirected
    result.final_domain = final_domain
    result.headers = headers

    # Use final domain for subsequent checks
    target_domain = final_domain if is_redirected else domain

    # Stage 3: Status code check
    if status_code in (401, 403, 407, 408, 429) or status_code >= 500:
        result.error = f"状态码异常: {status_code}"
        return result

    # Stage 4: Location check (needs GeoIP)
    country, is_domestic, ip_addr = check_location(target_domain, geo)
    result.country = country
    result.is_domestic = is_domestic
    result.ip_address = ip_addr
    if is_domestic:
        result.error = "国内网站"
        return result

    # Stage 5: Comprehensive TLS check (TLS1.3, X25519, H2, SNI, cert)
    tls_info = await check_tls(target_domain, timeout_sec=timeout_sec)
    result.tls13 = tls_info.get("tls13", False)
    result.x25519 = tls_info.get("x25519", False)
    result.h2 = tls_info.get("h2", False)
    result.sni_match = tls_info.get("sni_match", False)
    result.handshake_ms = tls_info.get("handshake_ms", 0.0)
    result.cert_valid = tls_info.get("cert_valid", False)
    result.cert_issuer = tls_info.get("cert_issuer", "")
    result.cert_days_left = tls_info.get("cert_days_left", 0)

    # Hard requirements
    if not result.tls13:
        result.error = "不支持TLS 1.3"
        return result
    if not result.h2:
        result.error = "不支持HTTP/2"
        return result
    if not result.x25519:
        result.error = "不支持X25519"
        return result
    if not result.sni_match:
        result.error = "SNI不匹配"
        return result
    if not result.cert_valid:
        result.error = "证书无效"
        return result

    # Stage 6: CDN detection
    is_cdn, confidence, evidence = detect_cdn(
        target_domain, headers=headers, cert_issuer=result.cert_issuer
    )
    result.is_cdn = is_cdn
    result.cdn_confidence = confidence
    result.cdn_evidence = evidence

    # Stage 7: Hot website detection
    result.is_hot_website = is_hot_website(target_domain)

    # All hard requirements passed
    result.suitable = True
    return result
