"""
Converts raw events from any adapter into the unified DecoyNet schema.
"""

import time


REQUIRED_FIELDS = ["ip", "timestamp", "event_type", "command", "file", "threat_score", "source"]


class Normalizer:
    def normalize(self, raw: dict, source: str = "unknown") -> dict:
        record = {field: raw.get(field, "") for field in REQUIRED_FIELDS}
        record["source"]     = source or record.get("source", "unknown")
        record["ingested_at"] = time.time()
        if not record["threat_score"]:
            record["threat_score"] = 0
        return record
