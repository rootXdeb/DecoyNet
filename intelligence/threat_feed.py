"""
External threat feed ingestion (placeholder — plug in real APIs here).
"""

import logging
logger = logging.getLogger(__name__)

_MOCK_FEED = [
    {"ip": "192.0.2.1",  "type": "scanner",    "confidence": 90},
    {"ip": "198.51.100.5","type": "botnet_c2",  "confidence": 85},
    {"ip": "203.0.113.10","type": "tor_exit",   "confidence": 70},
]


class ThreatFeed:
    def fetch(self) -> list[dict]:
        """
        In production: call AbuseIPDB, Shodan, OTX, etc.
        Returns a list of threat records.
        """
        logger.info("Fetching mock threat feed (%d entries).", len(_MOCK_FEED))
        return _MOCK_FEED
