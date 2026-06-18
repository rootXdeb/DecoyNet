"""
Central in-memory + persisted knowledge base for attack patterns and IOCs.
"""

import time, logging
from database.db_manager import DatabaseManager

logger = logging.getLogger(__name__)


class KnowledgeBase:
    def __init__(self):
        self.db        = DatabaseManager()
        self._patterns: list[dict] = []
        self._iocs:     set[str]   = set()
        self._load()

    def add_pattern(self, pattern: dict):
        pattern["added"] = time.time()
        self._patterns.append(pattern)
        self.db.save_pattern(pattern)

    def add_ioc(self, ioc: str, ioc_type: str, source: str = "DecoyNet"):
        if ioc not in self._iocs:
            self._iocs.add(ioc)
            self.db.save_ioc({"value": ioc, "type": ioc_type,
                              "source": source, "timestamp": time.time()})
            logger.info("New IOC: [%s] %s", ioc_type, ioc)

    def is_known_attacker(self, ip: str) -> bool:
        return ip in self._iocs

    def get_patterns(self) -> list[dict]:
        return list(self._patterns)

    def _load(self):
        try:
            for ioc in self.db.get_iocs():
                self._iocs.add(ioc["value"])
            self._patterns = self.db.get_patterns()
            logger.debug("KnowledgeBase loaded %d IOCs, %d patterns.",
                         len(self._iocs), len(self._patterns))
        except Exception:
            pass  # Tables not yet created — populated after schema init
