"""
CrossSessionCorrelator — tracks attacker behaviour across multiple sessions.

When the same IP reconnects, the strategy engine immediately knows:
  - How many times they've been seen before
  - What their highest threat score was
  - What TTP stages they've reached in past sessions
  - Whether they're part of a coordinated attack group

This means the DecoyNet gets SMARTER with every session from the same source,
and can escalate to TRAP immediately on reconnection from a known bad IP.
"""

import time
import logging
from database.db_manager import DatabaseManager

logger = logging.getLogger(__name__)


class CrossSessionCorrelator:
    def __init__(self, db: DatabaseManager):
        self.db = db
        # In-memory cache for this run
        self._cache: dict[str, dict] = {}

    def lookup(self, ip: str) -> dict:
        """
        Returns cross-session intelligence for an IP address.
        Called at the start of every command dispatch.
        """
        if ip in self._cache:
            return self._cache[ip]

        # Query DB for past sessions from this IP
        rows = self.db.execute(
            """SELECT threat_score, threat_level, attacker_type, attack_chain, start_time
               FROM sessions WHERE ip = ?
               ORDER BY start_time DESC LIMIT 20""",
            (ip,)
        ).fetchall()

        if not rows:
            result = {"known_attacker": False, "session_count": 0}
            self._cache[ip] = result
            return result

        rows = [dict(r) for r in rows]
        max_score    = max(r["threat_score"] or 0 for r in rows)
        types        = list({r["attacker_type"] for r in rows if r["attacker_type"]})
        all_chains   = " | ".join(r["attack_chain"] or "" for r in rows)
        last_seen    = rows[0]["start_time"]

        # Check for coordinated attack: multiple IPs running same rare commands
        coordinated = self._check_coordinated(ip)

        result = {
            "known_attacker":  True,
            "session_count":   len(rows),
            "max_score":       max_score,
            "attacker_types":  types,
            "all_chains":      all_chains,
            "last_seen":       last_seen,
            "coordinated":     coordinated,
            "time_since_last": time.time() - last_seen if last_seen else None,
        }
        self._cache[ip] = result

        logger.info(
            "Cross-session intel | ip=%-16s sessions=%d max_score=%d coordinated=%s",
            ip, len(rows), max_score, coordinated
        )
        return result

    def record_session(self, ip: str, features: dict, score: int, chain: str):
        """Update in-memory cache after a session ends."""
        existing = self._cache.get(ip, {})
        self._cache[ip] = {
            "known_attacker": True,
            "session_count":  existing.get("session_count", 0) + 1,
            "max_score":      max(existing.get("max_score", 0), score),
            "attacker_types": list({features.get("attacker_type", "unknown")} |
                                   set(existing.get("attacker_types", []))),
            "all_chains":     (existing.get("all_chains", "") + " | " + chain).strip(" | "),
            "last_seen":      time.time(),
            "coordinated":    existing.get("coordinated", False),
        }

    def _check_coordinated(self, ip: str) -> bool:
        """
        Detects coordinated attacks: multiple different IPs running the
        same unusual command sequence within a short window.
        """
        try:
            # Find sessions from OTHER IPs in the last 30 minutes
            window_start = time.time() - 1800
            rows = self.db.execute(
                """SELECT ip, attacker_type FROM sessions
                   WHERE start_time > ? AND ip != ?
                   AND threat_level IN ('HIGH', 'CRITICAL')""",
                (window_start, ip)
            ).fetchall()

            # If 3+ other high-threat IPs active in the window → coordinated
            unique_ips = {r["ip"] for r in rows}
            if len(unique_ips) >= 3:
                logger.warning(
                    "COORDINATED ATTACK DETECTED | ip=%s + %d others in 30min window",
                    ip, len(unique_ips)
                )
                return True
        except Exception as exc:
            logger.debug("Coordination check error: %s", exc)
        return False
