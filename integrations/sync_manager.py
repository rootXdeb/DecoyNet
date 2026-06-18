"""
Synchronises intelligence across all connected DecoyNet adapters.
"""

import logging
from integrations.normalizer import Normalizer
from intelligence.knowledge_base import KnowledgeBase

logger = logging.getLogger(__name__)


class SyncManager:
    def __init__(self, adapters: list):
        self.adapters = adapters
        self.norm     = Normalizer()
        self.kb       = KnowledgeBase()

    def sync(self):
        total = 0
        for adapter in self.adapters:
            source = type(adapter).__name__
            try:
                events = adapter.run()
                for event in events:
                    record = self.norm.normalize(event, source)
                    ip = record.get("ip")
                    if ip:
                        self.kb.add_ioc(ip, "ip", source)
                    total += 1
            except Exception as exc:
                logger.error("Sync error from %s: %s", source, exc)
        logger.info("Sync complete — %d events ingested.", total)
