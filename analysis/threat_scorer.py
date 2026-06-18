"""
Context-aware threat scoring engine.
Correlates attacker features into a 0-100 threat score with level.
"""

from config import THREAT_LEVELS


class ThreatScorer:
    _WEIGHTS = {
        "recon_count":    2,
        "lateral_count": 10,
        "exploit_count": 15,
        "exfil_count":    8,
        "command_count":  0.5,
    }

    def score(self, features: dict) -> dict:
        raw = sum(features.get(k, 0) * w for k, w in self._WEIGHTS.items())
        # Attacker type multiplier
        multiplier = {"bot": 0.6, "human": 1.0, "advanced": 1.4}.get(
            features.get("attacker_type", "unknown"), 1.0
        )
        final = min(int(raw * multiplier), 100)
        level = self._level(final)
        return {"score": final, "level": level}

    @staticmethod
    def _level(score: int) -> str:
        for level, (lo, hi) in THREAT_LEVELS.items():
            if lo <= score <= hi:
                return level
        return "CRITICAL"
