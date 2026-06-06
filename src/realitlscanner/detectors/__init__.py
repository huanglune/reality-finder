from realitlscanner.detectors.blocked import check_blocked
from realitlscanner.detectors.cdn import detect_cdn
from realitlscanner.detectors.hot_website import is_hot_website
from realitlscanner.detectors.location import check_location
from realitlscanner.detectors.redirect import follow_redirects
from realitlscanner.detectors.tls import check_tls

__all__ = [
    "check_blocked",
    "check_location",
    "check_tls",
    "detect_cdn",
    "follow_redirects",
    "is_hot_website",
]
