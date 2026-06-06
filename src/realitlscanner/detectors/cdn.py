from __future__ import annotations

from importlib.resources import files


_cdn_data: dict[str, set[str]] | None = None


def _load_cdn_keywords() -> dict[str, set[str]]:
    global _cdn_data
    if _cdn_data is not None:
        return _cdn_data

    _cdn_data = {
        "cname_strong_suffix": set(),
        "http_strong_header": set(),
        "http_medium_header": set(),
        "http_value_cdn_domains": set(),
        "ns_hint_suffix": set(),
        "cert_issuer_hint": set(),
    }

    try:
        data_path = files("realitlscanner.data").joinpath("cdn_keywords.txt")
        content = data_path.read_text(encoding="utf-8")
    except Exception:
        return _cdn_data

    current_section = ""
    section_map = {
        "cname_strong_suffix:": "cname_strong_suffix",
        "http_strong_header:": "http_strong_header",
        "http_medium_header:": "http_medium_header",
        "http_value_cdn_domains:": "http_value_cdn_domains",
        "ns_hint_suffix:": "ns_hint_suffix",
        "cert_issuer_hint:": "cert_issuer_hint",
    }

    for line in content.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        if line in section_map:
            current_section = section_map[line]
            continue
        if current_section:
            clean = line.split("#")[0].strip()
            if clean:
                _cdn_data[current_section].add(clean.lower())

    return _cdn_data


def detect_cdn(
    domain: str,
    headers: dict[str, str] | None = None,
    cert_issuer: str = "",
) -> tuple[bool, str, str]:
    """Detect CDN usage. Returns (is_cdn, confidence, evidence)."""
    data = _load_cdn_keywords()

    # High confidence: CNAME check
    try:
        import subprocess
        result = subprocess.run(
            ["dig", "+short", "CNAME", domain],
            capture_output=True, text=True, timeout=3,
        )
        cname_record = result.stdout.strip().lower().rstrip(".")
        if cname_record:
            for suffix in data["cname_strong_suffix"]:
                if suffix in cname_record:
                    return True, "高", f"CNAME包含{suffix}"
    except Exception:
        pass

    # High confidence: HTTP headers
    if headers:
        for header_pattern in data["http_strong_header"]:
            if ":" in header_pattern:
                h_name, h_val = header_pattern.split(":", 1)
                h_name = h_name.strip()
                h_val = h_val.strip()
                for resp_name, resp_val in headers.items():
                    if resp_name.lower() == h_name and h_val in resp_val.lower():
                        return True, "高", f"HTTP头: {resp_name}={resp_val}"
            else:
                for resp_name in headers:
                    if resp_name.lower() == header_pattern.lower():
                        return True, "高", f"HTTP头: {resp_name}"

        for cdn_domain in data["http_value_cdn_domains"]:
            for _, resp_val in headers.items():
                if cdn_domain in resp_val.lower():
                    return True, "高", f"HTTP头值包含{cdn_domain}"

    # Medium confidence: HTTP medium headers
    if headers:
        for header_pattern in data["http_medium_header"]:
            for resp_name in headers:
                if resp_name.lower() == header_pattern.lower():
                    return True, "中", f"HTTP头: {resp_name}"

    # Medium confidence: NS records
    try:
        import subprocess
        result = subprocess.run(
            ["dig", "+short", "NS", domain],
            capture_output=True, text=True, timeout=3,
        )
        ns_records = result.stdout.strip().lower()
        for hint in data["ns_hint_suffix"]:
            if hint in ns_records:
                return True, "中", f"NS记录包含{hint}"
    except Exception:
        pass

    # Low confidence: cert issuer
    if cert_issuer:
        issuer_lower = cert_issuer.lower()
        for hint in data["cert_issuer_hint"]:
            if hint in issuer_lower:
                return True, "低", f"证书颁发者包含{hint}"

    return False, "", ""
