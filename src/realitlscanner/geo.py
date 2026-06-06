from __future__ import annotations

import logging
from importlib.resources import files
from ipaddress import IPv4Address, IPv6Address
from pathlib import Path

logger = logging.getLogger(__name__)


class Geo:
    def __init__(self) -> None:
        self._reader = None

        # Try bundled data first, then current directory
        bundled = files("realitlscanner.data").joinpath("Country.mmdb")
        if hasattr(bundled, "_path"):
            db_path = Path(str(bundled))
        else:
            db_path = Path(str(bundled))

        if not db_path.exists():
            db_path = Path("Country.mmdb")

        if not db_path.exists():
            logger.debug("Country.mmdb not found, GeoIP disabled")
            return

        try:
            import geoip2.database
            self._reader = geoip2.database.Reader(str(db_path))
            logger.debug("Enabled GeoIP")
        except Exception as e:
            logger.debug("Cannot open Country.mmdb: %s", e)

    def get_geo(self, ip: str | IPv4Address | IPv6Address) -> str:
        if self._reader is None:
            return "N/A"
        try:
            resp = self._reader.country(str(ip))
            return resp.country.iso_code or "N/A"
        except Exception:
            return "N/A"

    def close(self) -> None:
        if self._reader:
            self._reader.close()
