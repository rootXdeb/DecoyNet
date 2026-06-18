"""
Extracts behavioural features from a session's command list.
Features feed the threat scorer and ML engine.
"""

import statistics
from typing import Any


class BehaviorAnalyzer:
    # Suspicious command keywords
    _RECON   = {"uname", "whoami", "id", "hostname", "ifconfig", "ip", "netstat", "ps", "env"}
    _LATERAL = {"wget", "curl", "scp", "ssh", "nc", "ncat", "socat"}
    _EXPLOIT = {"chmod", "python", "perl", "bash", "sh", "exec", "eval", "base64"}
    _EXFIL   = {"cat", "cp", "tar", "zip", "gzip", "scp", "curl"}

    def __init__(self, commands: list[dict]):
        self.commands = commands

    def extract_features(self) -> dict[str, Any]:
        if not self.commands:
            return self._empty()

        cmds       = [c["cmd"].split()[0] for c in self.commands if c["cmd"].strip()]
        durations  = [c["duration"] for c in self.commands]
        timestamps = [c["time"] for c in self.commands]

        recon_count   = sum(1 for c in cmds if c in self._RECON)
        lateral_count = sum(1 for c in cmds if c in self._LATERAL)
        exploit_count = sum(1 for c in cmds if c in self._EXPLOIT)
        exfil_count   = sum(1 for c in cmds if c in self._EXFIL)

        # Timing: bots are fast (low mean, low stdev)
        mean_delay = statistics.mean(durations) if durations else 0
        stdev_delay = statistics.stdev(durations) if len(durations) > 1 else 0

        # Inter-command timing
        inter = [timestamps[i+1]-timestamps[i] for i in range(len(timestamps)-1)]
        mean_inter = statistics.mean(inter) if inter else 0

        attacker_type = self._classify(mean_inter, stdev_delay)

        return {
            "command_count":  len(self.commands),
            "recon_count":    recon_count,
            "lateral_count":  lateral_count,
            "exploit_count":  exploit_count,
            "exfil_count":    exfil_count,
            "mean_delay":     round(mean_delay, 4),
            "stdev_delay":    round(stdev_delay, 4),
            "mean_inter":     round(mean_inter, 4),
            "attacker_type":  attacker_type,
        }

    def _classify(self, mean_inter: float, stdev: float) -> str:
        if mean_inter < 0.1 and stdev < 0.05:
            return "bot"
        if mean_inter > 2.0:
            return "human"
        return "advanced"

    def _empty(self) -> dict:
        return {k: 0 for k in
                ["command_count","recon_count","lateral_count",
                 "exploit_count","exfil_count","mean_delay",
                 "stdev_delay","mean_inter"]} | {"attacker_type": "unknown"}
