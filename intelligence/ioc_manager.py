"""
IOC storage and fast lookup.
"""

from intelligence.knowledge_base import KnowledgeBase


class IOCManager:
    def __init__(self):
        self._kb = KnowledgeBase()

    def record_ip(self, ip: str, source: str = "DecoyNet"):
        self._kb.add_ioc(ip, "ip", source)

    def record_hash(self, h: str, source: str = "DecoyNet"):
        self._kb.add_ioc(h, "hash", source)

    def record_url(self, url: str, source: str = "DecoyNet"):
        self._kb.add_ioc(url, "url", source)

    def is_known(self, value: str) -> bool:
        return self._kb.is_known_attacker(value)
