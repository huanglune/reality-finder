from __future__ import annotations

from urllib.parse import urlparse

import httpx


async def follow_redirects(
    domain: str,
    *,
    timeout: float = 3.0,
    max_redirects: int = 5,
) -> tuple[str, int, bool, dict[str, str]]:
    """Follow redirects and return (final_domain, status_code, is_redirected, headers)."""
    url = f"https://{domain}"
    final_domain = domain
    is_redirected = False
    status_code = 0
    headers: dict[str, str] = {}

    try:
        async with httpx.AsyncClient(
            verify=False,
            timeout=timeout,
            follow_redirects=False,
        ) as client:
            for _ in range(max_redirects):
                resp = await client.get(
                    url,
                    headers={
                        "User-Agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36",
                        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
                    },
                )
                status_code = resp.status_code
                headers = {k: v for k, v in resp.headers.items()}

                if 300 <= status_code < 400:
                    location = resp.headers.get("location", "")
                    if not location:
                        break
                    if location.startswith("/"):
                        parsed = urlparse(url)
                        location = f"{parsed.scheme}://{parsed.netloc}{location}"
                    elif not location.startswith("http"):
                        location = f"https://{location}"

                    new_domain = urlparse(location).hostname
                    if new_domain and new_domain != final_domain:
                        is_redirected = True
                        final_domain = new_domain
                    url = location
                else:
                    break
    except Exception:
        pass

    return final_domain, status_code, is_redirected, headers
