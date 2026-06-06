from __future__ import annotations

from importlib.resources import files


_hot_websites: set[str] | None = None


def _load_hot_websites() -> set[str]:
    global _hot_websites
    if _hot_websites is not None:
        return _hot_websites

    _hot_websites = set()
    try:
        data_path = files("realitlscanner.data").joinpath("hot_websites.txt")
        content = data_path.read_text(encoding="utf-8")
    except Exception:
        return _hot_websites

    for line in content.splitlines():
        line = line.strip()
        if line and not line.startswith("#"):
            _hot_websites.add(line.lower())
    return _hot_websites


def is_hot_website(domain: str) -> bool:
    websites = _load_hot_websites()
    domain = domain.lower()

    if domain in websites:
        return True

    # Wildcard matching
    for pattern in websites:
        if pattern.startswith("*."):
            base = pattern[2:]
            if domain == base or domain.endswith("." + base):
                return True

    # www prefix handling
    if domain.startswith("www."):
        bare = domain[4:]
        if bare in websites:
            return True
    else:
        with_www = "www." + domain
        if with_www in websites:
            return True

    return False
