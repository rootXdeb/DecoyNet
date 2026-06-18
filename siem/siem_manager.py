"""
SIEM Manager — single entry point for all SIEM output.

Every protocol calls this one class.
It simultaneously writes to:
  1. JSON log file   (Elastic/Filebeat/Logstash)
  2. CEF log file    (Splunk/QRadar/ArcSight)
  3. Syslog remote   (any SIEM with syslog input)
  4. Triggers alerts if severity is HIGH/CRITICAL
"""

import logging
from siem.event_logger import event_logger
from siem.cef_formatter import cef_formatter
from siem.syslog_sender import syslog_sender

logger = logging.getLogger(__name__)


class SIEMManager:

    def emit(
        self,
        event_type:   str,
        protocol:     str,
        src_ip:       str,
        severity:     str  = "LOW",
        session_id:   str  = "",
        threat_score: int  = 0,
        threat_level: str  = "LOW",
        details:      dict = None,
    ):
        """
        Single call that sends to all configured SIEM outputs.
        Call this from every protocol handler.
        """
        details = details or {}

        # 1. JSON log — universal SIEM feed
        event_logger.log(
            event_type   = event_type,
            protocol     = protocol,
            src_ip       = src_ip,
            severity     = severity,
            session_id   = session_id,
            threat_score = threat_score,
            threat_level = threat_level,
            details      = details,
        )

        # 2. CEF log — Splunk / QRadar / ArcSight
        cef_formatter.write(
            event_type   = event_type,
            protocol     = protocol,
            src_ip       = src_ip,
            threat_level = threat_level,
            threat_score = threat_score,
            session_id   = session_id,
            details      = details,
        )

        # 3. Syslog — any remote SIEM (only if configured)
        syslog_sender.send(
            event_type   = event_type,
            protocol     = protocol,
            src_ip       = src_ip,
            threat_level = threat_level,
            threat_score = threat_score,
            details      = details,
        )

        # 4. Trigger alerts for high severity events
        if severity in ("HIGH", "CRITICAL"):
            self._trigger_alert(event_type, protocol, src_ip,
                                threat_score, threat_level, details)

    def _trigger_alert(self, event_type, protocol, src_ip,
                       threat_score, threat_level, details):
        try:
            from alerts.alert_engine import alert_engine
            alert_engine.fire(
                event_type   = event_type,
                protocol     = protocol,
                src_ip       = src_ip,
                threat_score = threat_score,
                threat_level = threat_level,
                details      = details,
            )
        except Exception as exc:
            logger.debug("Alert trigger error: %s", exc)


# Singleton — import this everywhere
siem = SIEMManager()
