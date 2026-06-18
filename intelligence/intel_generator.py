"""
Generates a structured intelligence report from a completed session.
"""

import time
from analysis.attack_chain import AttackChain
from analysis.pattern_extractor import PatternExtractor


class IntelGenerator:
    def generate(self, session: dict, commands: list[str]) -> dict:
        chain     = AttackChain(commands).as_string()
        extractor = PatternExtractor()
        iocs      = extractor.extract(commands)
        return {
            "generated_at":  time.time(),
            "session_id":    session.get("session_id"),
            "attacker_ip":   session.get("ip"),
            "threat_level":  session.get("threat_level"),
            "threat_score":  session.get("threat_score"),
            "attacker_type": session.get("attacker_type"),
            "attack_chain":  chain,
            "iocs":          iocs,
            "command_count": session.get("command_count", 0),
        }
