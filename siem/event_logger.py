"""
Event Logger — writes every DecoyNet event as structured JSON.

Any SIEM consumes this file via:
  - Filebeat (Elastic)
  - Splunk Universal Forwarder
  - Fluentd / Logstash
  - Graylog GELF input
  - Any tool that reads JSON log files

Format: one JSON object per line (NDJSON)
"""

import json
import os
import time
import logging
import threading
from datetime import datetime, timezone

from config import LOG_DIR

logger      = logging.getLogger(__name__)
EVENT_LOG   = os.path.join(LOG_DIR, "events.json")
_lock       = threading.Lock()


class EventLogger:

    # Event type constants
    EVT_AUTH_ATTEMPT    = "AUTH_ATTEMPT"
    EVT_SESSION_START   = "SESSION_START"
    EVT_SESSION_END     = "SESSION_END"
    EVT_COMMAND         = "COMMAND_EXEC"
    EVT_DOWNLOAD        = "DOWNLOAD_ATTEMPT"
    EVT_MALWARE         = "MALWARE_UPLOAD"
    EVT_SQL_INJECT      = "SQL_INJECTION"
    EVT_PATH_TRAVERSAL  = "PATH_TRAVERSAL"
    EVT_WEBSHELL        = "WEBSHELL_ATTEMPT"
    EVT_BRUTE_FORCE     = "BRUTE_FORCE"
    EVT_COORDINATED     = "COORDINATED_ATTACK"
    EVT_STRATEGY_CHANGE = "STRATEGY_CHANGE"
    EVT_RCE_ATTEMPT     = "RCE_ATTEMPT"
    EVT_ALERT           = "ALERT"

    def log(
        self,
        event_type:   str,
        protocol:     str,
        src_ip:       str,
        severity:     str  = "INFO",
        session_id:   str  = "",
        threat_score: int  = 0,
        threat_level: str  = "LOW",
        details:      dict = None,
    ):
        event = {
            # Standard fields every SIEM expects
            "timestamp":    datetime.now(timezone.utc).isoformat(),
            "epoch":        time.time(),
            "event_type":   event_type,
            "protocol":     protocol,
            "src_ip":       src_ip,
            "severity":     severity,
            "session_id":   session_id,
            "threat_score": threat_score,
            "threat_level": threat_level,
            # Product identity
            "product":      "DecoyNetAI",
            "version":      "1.0",
            "hostname":     os.uname().nodename,
            # Protocol-specific details
            "details":      details or {},
        }

        line = json.dumps(event) + "\n"
        with _lock:
            try:
                with open(EVENT_LOG, "a") as f:
                    f.write(line)
            except Exception as exc:
                logger.error("EventLogger write error: %s", exc)

        if severity in ("HIGH", "CRITICAL"):
            logger.warning("SIEM | %s | %s | %s | score=%d",
                           event_type, protocol, src_ip, threat_score)

    # ── Convenience methods ───────────────────────────────────────────────────

    def log_auth(self, protocol, src_ip, username, password, session_id=""):
        self.log(
            event_type = self.EVT_AUTH_ATTEMPT,
            protocol   = protocol,
            src_ip     = src_ip,
            severity   = "MEDIUM",
            session_id = session_id,
            details    = {"username": username, "password": password},
        )

    def log_command(self, protocol, src_ip, command, strategy, threat_score=0, session_id=""):
        self.log(
            event_type   = self.EVT_COMMAND,
            protocol     = protocol,
            src_ip       = src_ip,
            severity     = "HIGH" if threat_score >= 60 else "MEDIUM",
            session_id   = session_id,
            threat_score = threat_score,
            details      = {"command": command, "strategy": strategy},
        )

    def log_session_end(self, protocol, src_ip, session_id, duration,
                        command_count, threat_score, threat_level,
                        attacker_type, attack_chain, strategy):
        severity = (
            "CRITICAL" if threat_level == "CRITICAL" else
            "HIGH"     if threat_level == "HIGH"     else
            "MEDIUM"   if threat_level == "MEDIUM"   else "LOW"
        )
        self.log(
            event_type   = self.EVT_SESSION_END,
            protocol     = protocol,
            src_ip       = src_ip,
            severity     = severity,
            session_id   = session_id,
            threat_score = threat_score,
            threat_level = threat_level,
            details      = {
                "duration":      round(duration, 2),
                "command_count": command_count,
                "attacker_type": attacker_type,
                "attack_chain":  attack_chain,
                "strategy":      strategy,
            },
        )

    def log_web_attack(self, src_ip, method, path, attack_type, score, session_id=""):
        severity = "CRITICAL" if score >= 85 else "HIGH" if score >= 60 else "MEDIUM"
        self.log(
            event_type   = attack_type,
            protocol     = "HTTP",
            src_ip       = src_ip,
            severity     = severity,
            session_id   = session_id,
            threat_score = score,
            details      = {"method": method, "path": path},
        )


# Singleton instance used across all modules
event_logger = EventLogger()
