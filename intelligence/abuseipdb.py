"""
AbuseIPDB Integration — checks attacker IPs against real threat intelligence.

AbuseIPDB is a free threat feed (100 checks/day on free tier).
Set ABUSEIPDB_API_KEY in config.py to enable.
If key is empty, this module does nothing and returns empty results.

Free API key: https://www.abuseipdb.com/register
"""

import urllib.request
import urllib.error
import json
import logging
import time
import threading

logger = logging.getLogger(__name__)

_CACHE: dict[str, dict] = {}
_LOCK  = threading.Lock()


class AbuseIPDB:
    def __init__(self):
        try:
            from config import ABUSEIPDB_API_KEY
            self.api_key = ABUSEIPDB_API_KEY
        except ImportError:
            self.api_key = ""

        self.enabled = bool(self.api_key)
        if self.enabled:
            logger.info("AbuseIPDB integration enabled.")

    def check(self, ip: str) -> dict:
        """
        Check an IP against AbuseIPDB.
        Returns confidence score (0-100) and abuse reports.
        """
        if not self.enabled:
            return {}

        with _LOCK:
            if ip in _CACHE:
                return _CACHE[ip]

        try:
            url = f"https://api.abuseipdb.com/api/v2/check?ipAddress={ip}&maxAgeInDays=90"
            req = urllib.request.Request(url, headers={
                "Key":    self.api_key,
                "Accept": "application/json",
            })
            with urllib.request.urlopen(req, timeout=5) as resp:
                data = json.loads(resp.read().decode())

            result = {
                "abuse_confidence_score": data["data"].get("abuseConfidenceScore", 0),
                "total_reports":          data["data"].get("totalReports", 0),
                "country_code":           data["data"].get("countryCode", ""),
                "isp":                    data["data"].get("isp", ""),
                "is_whitelisted":         data["data"].get("isWhitelisted", False),
                "last_reported":          data["data"].get("lastReportedAt", ""),
            }

            if result["abuse_confidence_score"] > 50:
                logger.warning(
                    "ABUSEIPDB HIT | ip=%s score=%d reports=%d",
                    ip, result["abuse_confidence_score"], result["total_reports"]
                )

        except Exception as exc:
            logger.debug("AbuseIPDB check failed for %s: %s", ip, exc)
            result = {}

        with _LOCK:
            _CACHE[ip] = result

        return result

    def is_known_bad(self, ip: str, threshold: int = 50) -> bool:
        result = self.check(ip)
        return result.get("abuse_confidence_score", 0) >= threshold


# Singleton
abuseipdb = AbuseIPDB()
