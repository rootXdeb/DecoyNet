"""
EngagementTraps — injects targeted bait into responses based on what
the attacker appears to be interested in.

This is NOT random fake data. The trap is matched to what the attacker
has been looking for so far in the session, making it highly believable.

Example:
  - Attacker runs: mysql, cat .env, grep password
  → Trap injects a "hint" about a backup SQL file containing credentials

  - Attacker runs: wget, curl, chmod, bash
  → Trap injects a note about a cron job running a vulnerable script

This is what keeps advanced attackers engaged for much longer.
"""

import random
import logging
from adaptive.strategy_engine import Strategy

logger = logging.getLogger(__name__)


class EngagementTraps:

    def maybe_inject(
        self,
        strategy: Strategy,
        features: dict,
        cmd:      str,
        cwd:      str,
    ) -> str | None:
        """
        Decides whether to inject a trap hint after this command.
        Returns a string to append to the response, or None.
        """
        if strategy == Strategy.DEFLECT:
            return None

        # Only inject occasionally — too frequent = suspicious
        if random.random() > self._injection_probability(strategy):
            return None

        return self._select_trap(features, cmd, cwd, strategy)

    # ── Trap selection ────────────────────────────────────────────────────────

    def _select_trap(
        self,
        features: dict,
        cmd:      str,
        cwd:      str,
        strategy: Strategy,
    ) -> str | None:
        """
        Match trap to attacker's apparent interest.
        """
        stages        = features.get("ttp_stages", [])
        exfil_count   = features.get("exfil_count", 0)
        exploit_count = features.get("exploit_count", 0)
        lateral_count = features.get("lateral_count", 0)

        # Database-interest traps
        if cmd in ("mysql", "psql") or "password" in cmd.lower() or "db" in cwd.lower():
            return self._db_trap(strategy)

        # Credential-hunting traps
        if cmd in ("cat", "grep", "find") and exfil_count > 0:
            return self._cred_trap(strategy)

        # Download / C2 traps
        if cmd in ("wget", "curl") and "C2 / Download" in stages:
            return self._download_trap(strategy)

        # Lateral movement traps
        if cmd in ("ssh", "scp", "nc") or lateral_count > 1:
            return self._lateral_trap(strategy)

        # Persistence traps
        if cmd in ("crontab", "useradd", "systemctl"):
            return self._persistence_trap(strategy)

        # Generic TRAP strategy — always inject something interesting
        if strategy == Strategy.TRAP:
            return random.choice([
                self._db_trap(strategy),
                self._cred_trap(strategy),
                self._lateral_trap(strategy),
            ])

        return None

    # ── Trap content ──────────────────────────────────────────────────────────

    def _db_trap(self, strategy: Strategy) -> str:
        hints = [
            "\r\n\x1b[33m[cron] backup_db.sh: Dumped corp_production → /root/backup.sql (142MB)\x1b[0m",
            "\r\n\x1b[33m[mysql] Last login: root from 10.0.0.30 — /root/backup.sql created\x1b[0m",
        ]
        return random.choice(hints)

    def _cred_trap(self, strategy: Strategy) -> str:
        hints = [
            "\r\n\x1b[33m[system] Note: /root/.aws/credentials updated 3 days ago\x1b[0m",
            "\r\n\x1b[33m[system] Last vault sync: /root/notes.txt contains plaintext fallback credentials\x1b[0m",
        ]
        return random.choice(hints)

    def _download_trap(self, strategy: Strategy) -> str:
        hints = [
            "\r\n\x1b[33m[firewall] Outbound connections on port 4444 logged — check /var/log/ufw.log\x1b[0m",
            "\r\n\x1b[33m[system] wget/curl activity detected — audit log at /var/log/downloads.log\x1b[0m",
        ]
        return random.choice(hints)

    def _lateral_trap(self, strategy: Strategy) -> str:
        hints = [
            "\r\n\x1b[33m[ssh] Key-based auth available to: deploy@10.0.0.50 (no passphrase on /root/.ssh/id_rsa)\x1b[0m",
            "\r\n\x1b[33m[system] db-primary.internal (10.0.0.10) accepting connections on 3306 without firewall\x1b[0m",
        ]
        return random.choice(hints)

    def _persistence_trap(self, strategy: Strategy) -> str:
        hints = [
            "\r\n\x1b[33m[cron] Existing job: /root/sync_db.sh runs every 2 min as root (writeable)\x1b[0m",
            "\r\n\x1b[33m[system] /etc/cron.d/ is world-writeable — check permissions\x1b[0m",
        ]
        return random.choice(hints)

    # ── Injection probability ─────────────────────────────────────────────────

    def _injection_probability(self, strategy: Strategy) -> float:
        return {
            Strategy.OBSERVE: 0.05,   # Very rare — don't tip our hand
            Strategy.ENGAGE:  0.20,   # Occasional hints to keep them interested
            Strategy.TRAP:    0.45,   # Frequent bait — we want maximum engagement
        }.get(strategy, 0.0)
