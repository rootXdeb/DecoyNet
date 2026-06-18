"""
Abstract base class for all DecoyNet adapters.
Each adapter must implement `fetch_events()` and `normalize(event)`.
"""

from abc import ABC, abstractmethod


class BaseAdapter(ABC):
    @abstractmethod
    def fetch_events(self) -> list[dict]:
        """Retrieve raw events from the external DecoyNet."""

    @abstractmethod
    def normalize(self, event: dict) -> dict:
        """
        Convert a raw event into the unified schema:
        {ip, timestamp, event_type, command, file, threat_score}
        """

    def run(self) -> list[dict]:
        raw = self.fetch_events()
        return [self.normalize(e) for e in raw]
