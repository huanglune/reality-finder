from __future__ import annotations

from importlib.resources import files


_gfwlist: set[str] | None = None


def _load_gfwlist() -> set[str]:
    global _gfwlist
    if _gfwlist is not None:
        return _gfwlist

    _gfwlist = set()
    try:
        data_path = files("realitlscanner.data").joinpath("gfwlist.conf")
        content = data_path.read_text(encoding="utf-8")
    except Exception:
        return _gfwlist

    in_payload = False
    for line in content.splitlines():
        line = line.strip()
        if line == "payload:":
            in_payload = True
            continue
        if not in_payload:
            continue
        if line.startswith("- '") and line.endswith("'"):
            domain = line[3:-1]
            domain = domain.removeprefix("+.")
            if domain:
                _gfwlist.add(domain.lower())
    return _gfwlist


def check_blocked(domain: str) -> tuple[bool, str]:
    gfwlist = _load_gfwlist()
    domain_lower = domain.lower()

    if domain_lower in gfwlist:
        return True, "GFW黑名单匹配"

    parts = domain_lower.split(".")
    for i in range(len(parts)):
        wildcard = "*." + ".".join(parts[i:])
        if wildcard in gfwlist:
            return True, f"通配符匹配: {wildcard}"

    return False, ""
