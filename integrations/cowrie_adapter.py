"""
Cowrie SSH/Telnet DecoyNet adapter.
Reads Cowrie JSON log and normalises events into unified schema.
"""

import json, os, logging
from integrations.base_adapter import BaseAdapter

logger = logging.getLogger(__name__)
COWRIE_LOG_PATH = os.environ.get("COWRIE_LOG", "/var/log/cowrie/cowrie.json")


class CowrieAdapter(BaseAdapter):
    def fetch_events(self) -> list[dict]:
        if not os.path.exists(COWRIE_LOG_PATH):
            logger.warning("Cowrie log not found: %s", COWRIE_LOG_PATH)
            return []
        events = []
        with open(COWRIE_LOG_PATH) as f:
            for line in f:
                try:
                    events.append(json.loads(line))
                except json.JSONDecodeError:
                    pass
        return events

    def normalize(self, event: dict) -> dict:
        return {
            "ip":          event.get("src_ip", ""),
            "timestamp":   event.get("timestamp", ""),
            "event_type":  event.get("eventid", "unknown"),
            "command":     event.get("input", ""),
            "file":        event.get("filename", ""),
            "threat_score": 0,
            "source":      "cowrie",
        }
