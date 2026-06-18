"""
BehaviorProfiler — builds and continuously updates a live feature vector
for the current session as the attacker types commands.

Unlike the post-session BehaviorAnalyzer, this runs DURING the session
so the strategy engine can react in real time.
"""

import time
import statistics
import logging
from analysis.attack_chain import AttackChain

logger = logging.getLogger(__name__)

_RECON   = {"uname","whoami","id","hostname","ifconfig","ip","netstat","ss","ps","env","uname","cat","find","ls"}
_LATERAL = {"wget","curl","scp","ssh","nc","ncat","socat","rsync","ftp"}
_EXPLOIT = {"chmod","python","python3","perl","bash","sh","exec","eval","base64","gcc","make"}
_EXFIL   = {"cat","cp","tar","zip","gzip","scp","curl","wget","sftp"}
_PERSIST = {"crontab","useradd","adduser","passwd","systemctl","service","echo"}


class BehaviorProfiler:
    def __init__(self):
        self._commands:   list[str]   = []
        self._timestamps: list[float] = []
        self._durations:  list[float] = []

    def record(self, command: str, timestamp: float, duration: float = 0.0):
        self._commands.append(command)
        self._timestamps.append(timestamp)
        self._durations.append(duration)

    def features(self) -> dict:
        if not self._commands:
            return self._empty()

        bases = [c.strip().split()[0] for c in self._commands if c.strip()]

        recon_count   = sum(1 for b in bases if b in _RECON)
        lateral_count = sum(1 for b in bases if b in _LATERAL)
        exploit_count = sum(1 for b in bases if b in _EXPLOIT)
        exfil_count   = sum(1 for b in bases if b in _EXFIL)
        persist_count = sum(1 for b in bases if b in _PERSIST)

        inter = [
            self._timestamps[i+1] - self._timestamps[i]
            for i in range(len(self._timestamps)-1)
        ]
        mean_inter  = statistics.mean(inter)  if inter else 0.0
        stdev_inter = statistics.stdev(inter) if len(inter) > 1 else 0.0
        mean_dur    = statistics.mean(self._durations) if self._durations else 0.0
        stdev_dur   = statistics.stdev(self._durations) if len(self._durations) > 1 else 0.0

        attacker_type = self._classify(mean_inter, stdev_inter, len(self._commands))
        ttp_stages    = AttackChain(self._commands).build()

        return {
            "command_count":  len(self._commands),
            "recon_count":    recon_count,
            "lateral_count":  lateral_count,
            "exploit_count":  exploit_count,
            "exfil_count":    exfil_count,
            "persist_count":  persist_count,
            "mean_inter":     round(mean_inter,  4),
            "stdev_inter":    round(stdev_inter, 4),
            "mean_delay":     round(mean_dur,    4),
            "stdev_delay":    round(stdev_dur,   4),
            "attacker_type":  attacker_type,
            "ttp_stages":     ttp_stages,
            "unique_commands": len(set(bases)),
            "session_duration": (
                self._timestamps[-1] - self._timestamps[0]
                if len(self._timestamps) > 1 else 0.0
            ),
        }

    def _classify(self, mean_inter: float, stdev: float, cmd_count: int) -> str:
        # Very fast with low variance → automated bot
        if mean_inter < 0.1 and stdev < 0.08 and cmd_count > 5:
            return "bot"
        # Slow with high variance → human thinking between commands
        if mean_inter > 1.5 and stdev > 0.5:
            return "human"
        # Fast but variable → experienced human or semi-automated tool
        if mean_inter < 0.5 and stdev > 0.2:
            return "advanced"
        return "unknown"

    def _empty(self) -> dict:
        return {
            "command_count": 0, "recon_count": 0, "lateral_count": 0,
            "exploit_count": 0, "exfil_count": 0, "persist_count": 0,
            "mean_inter": 0.0, "stdev_inter": 0.0,
            "mean_delay": 0.0, "stdev_delay": 0.0,
            "attacker_type": "unknown", "ttp_stages": [],
            "unique_commands": 0, "session_duration": 0.0,
        }
