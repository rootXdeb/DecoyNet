"""
Dionaea malware DecoyNet adapter.
Reads Dionaea SQLite log and normalises events.
"""

import os, logging, sqlite3
from integrations.base_adapter import BaseAdapter

logger = logging.getLogger(__name__)
DIONAEA_DB = os.environ.get("DIONAEA_DB", "/var/lib/dionaea/dionaea.sqlite")


class DionaeaAdapter(BaseAdapter):
    def fetch_events(self) -> list[dict]:
        if not os.path.exists(DIONAEA_DB):
            logger.warning("Dionaea DB not found: %s", DIONAEA_DB)
            return []
        try:
            conn = sqlite3.connect(DIONAEA_DB)
            conn.row_factory = sqlite3.Row
            rows = conn.execute(
                "SELECT * FROM connections ORDER BY connection_timestamp DESC LIMIT 500"
            ).fetchall()
            conn.close()
            return [dict(r) for r in rows]
        except Exception as exc:
            logger.error("Dionaea DB error: %s", exc)
            return []

    def normalize(self, event: dict) -> dict:
        return {
            "ip":          event.get("remote_host", ""),
            "timestamp":   event.get("connection_timestamp", ""),
            "event_type":  event.get("connection_type", "unknown"),
            "command":     "",
            "file":        event.get("download_url", ""),
            "threat_score": 0,
            "source":      "dionaea",
        }
