"""
GeoIP Lookup — resolves attacker IPs to country/city/coordinates.

Uses ip-api.com free tier (no API key needed, 45 requests/minute).
Results are cached in the database to avoid repeated lookups.

Private/reserved IPs return a local placeholder.
"""

import time
import logging
import urllib.request
import urllib.error
import json
import threading

logger = logging.getLogger(__name__)

_CACHE: dict[str, dict] = {}
_LOCK  = threading.Lock()

_PRIVATE_RANGES = (
    "10.", "192.168.", "172.16.", "172.17.", "172.18.", "172.19.",
    "172.20.", "172.21.", "172.22.", "172.23.", "172.24.", "172.25.",
    "172.26.", "172.27.", "172.28.", "172.29.", "172.30.", "172.31.",
    "127.", "::1", "localhost",
)

_PLACEHOLDER = {
    "country":     "Local Network",
    "countryCode": "LO",
    "city":        "Private",
    "lat":         0.0,
    "lon":         0.0,
    "isp":         "Private Network",
    "status":      "local",
}


def is_private(ip: str) -> bool:
    return any(ip.startswith(p) for p in _PRIVATE_RANGES)


def lookup(ip: str) -> dict:
    """
    Returns geo data for an IP.
    Cached after first lookup — never hits API twice for same IP.
    """
    if is_private(ip):
        return _PLACEHOLDER.copy()

    with _LOCK:
        if ip in _CACHE:
            return _CACHE[ip]

    try:
        url = f"http://ip-api.com/json/{ip}?fields=status,country,countryCode,city,lat,lon,isp,org"
        req = urllib.request.Request(url, headers={"User-Agent": "DecoyNetAI/1.0"})
        with urllib.request.urlopen(req, timeout=5) as resp:
            data = json.loads(resp.read().decode())

        if data.get("status") == "success":
            result = {
                "country":     data.get("country",     "Unknown"),
                "countryCode": data.get("countryCode", "XX"),
                "city":        data.get("city",        "Unknown"),
                "lat":         data.get("lat",         0.0),
                "lon":         data.get("lon",         0.0),
                "isp":         data.get("isp",         "Unknown"),
                "status":      "success",
            }
        else:
            result = _PLACEHOLDER.copy()

    except Exception as exc:
        logger.debug("GeoIP lookup failed for %s: %s", ip, exc)
        result = _PLACEHOLDER.copy()

    with _LOCK:
        _CACHE[ip] = result

    return result


def lookup_batch(ips: list[str]) -> dict[str, dict]:
    """Lookup multiple IPs with rate limiting."""
    results = {}
    for ip in ips:
        results[ip] = lookup(ip)
        time.sleep(0.07)   # Stay under 45 req/min limit
    return results
