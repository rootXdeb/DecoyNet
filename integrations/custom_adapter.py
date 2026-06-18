"""
Template for a custom DecoyNet adapter.
Copy this file and implement fetch_events() + normalize() for your DecoyNet.
"""

from integrations.base_adapter import BaseAdapter


class CustomAdapter(BaseAdapter):
    def fetch_events(self) -> list[dict]:
        # TODO: implement — pull from your DecoyNet's log / API / DB
        return []

    def normalize(self, event: dict) -> dict:
        return {
            "ip":          event.get("ip", ""),
            "timestamp":   event.get("ts", ""),
            "event_type":  event.get("type", "unknown"),
            "command":     event.get("cmd", ""),
            "file":        event.get("file", ""),
            "threat_score": 0,
            "source":      "custom",
        }
