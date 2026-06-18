"""
Syslog Sender — sends events to any remote SIEM over UDP/TCP port 514.

Every SIEM in existence accepts syslog:
- Splunk
- Elastic
- Graylog
- IBM QRadar
- Microsoft Sentinel
- Any Linux syslog daemon

Customer just sets SIEM_SYSLOG_HOST in config.py and events flow automatically.
If SIEM_SYSLOG_HOST is empty, this module does nothing — DecoyNet runs standalone.
"""

import socket
import logging
import time
from datetime import datetime, timezone

logger = logging.getLogger(__name__)

# Syslog severity mapping
_SYSLOG_SEVERITY = {
    "LOW":      6,   # Informational
    "MEDIUM":   5,   # Notice
    "HIGH":     4,   # Warning
    "CRITICAL": 2,   # Critical
}

# Syslog facility: security/authorization messages = 4
_FACILITY = 4


class SyslogSender:
    def __init__(self):
        from config import SIEM_SYSLOG_HOST, SIEM_SYSLOG_PORT
        self.host    = SIEM_SYSLOG_HOST
        self.port    = SIEM_SYSLOG_PORT
        self.enabled = bool(self.host)
        if self.enabled:
            logger.info("Syslog sender enabled → %s:%d", self.host, self.port)

    def send(
        self,
        event_type:   str,
        protocol:     str,
        src_ip:       str,
        threat_level: str = "LOW",
        threat_score: int = 0,
        details:      dict = None,
    ):
        if not self.enabled:
            return

        details  = details or {}
        severity = _SYSLOG_SEVERITY.get(threat_level, 6)
        priority = (_FACILITY * 8) + severity
        ts       = datetime.now(timezone.utc).strftime("%b %d %H:%M:%S")
        hostname = socket.gethostname()

        msg = (
            f"<{priority}>{ts} {hostname} DecoyNetAI: "
            f"event={event_type} protocol={protocol} src={src_ip} "
            f"level={threat_level} score={threat_score}"
        )

        for k, v in details.items():
            msg += f" {k}={str(v)[:50]}"

        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.sendto(msg.encode("utf-8", errors="replace"), (self.host, self.port))
            sock.close()
        except Exception as exc:
            logger.debug("Syslog send error: %s", exc)


# Singleton
syslog_sender = SyslogSender()
