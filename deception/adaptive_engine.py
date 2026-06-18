"""
Adaptive Deception Engine — orchestrates how the DecoyNet changes
its personality based on attacker behaviour patterns.
"""

import random
import logging
from config import FAKE_VULN_EXPOSURE_CHANCE

logger = logging.getLogger(__name__)

_FAKE_VULNS = [
    "CVE-2023-44487 (HTTP/2 Rapid Reset) — Apache 2.4.51 unpatched",
    "CVE-2021-44228 (Log4Shell) — log4j 2.14.1 in /opt/app",
    "CVE-2023-23397 (Outlook RCE) — unpatched Outlook client",
    "CVE-2022-30190 (Follina) — MS Support Diagnostic Tool exposed",
]


class AdaptiveEngine:
    def __init__(self):
        self._engagement_depth: int = 0

    def on_command(self, cmd: str):
        """Call after each attacker command to deepen engagement."""
        self._engagement_depth += 1
        if self._engagement_depth % 5 == 0:
            logger.debug("Deepening deception after %d commands.", self._engagement_depth)

    def maybe_expose_vuln(self) -> str | None:
        """Randomly surface a fake vulnerability hint."""
        if random.random() < FAKE_VULN_EXPOSURE_CHANCE:
            return random.choice(_FAKE_VULNS)
        return None

    def get_fake_user_activity(self) -> str:
        """Return a plausible 'someone just logged in' noise line."""
        users = ["admin", "deploy", "sysadmin"]
        actions = ["logged in from 192.168.1.10", "ran backup.sh", "accessed /var/www/html"]
        return f"[System] {random.choice(users)} {random.choice(actions)}"
