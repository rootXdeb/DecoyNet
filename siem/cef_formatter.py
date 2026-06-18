"""
CEF Formatter — Common Event Format output.

CEF is the industry standard log format understood natively by:
- Splunk
- IBM QRadar
- HP ArcSight
- Microsoft Sentinel
- Any enterprise SIEM

Format:
CEF:Version|Device Vendor|Device Product|Device Version|Event ID|Name|Severity|Extensions
"""

import time
import os
import logging
from datetime import datetime, timezone

from config import LOG_DIR

logger   = logging.getLogger(__name__)
CEF_LOG  = os.path.join(LOG_DIR, "events.cef")

# Severity mapping (CEF uses 0-10)
_CEF_SEVERITY = {
    "LOW":      3,
    "MEDIUM":   5,
    "HIGH":     8,
    "CRITICAL": 10,
}

# Event ID mapping
_EVENT_IDS = {
    "AUTH_ATTEMPT":    100,
    "SESSION_END":     200,
    "COMMAND_EXEC":    300,
    "SQL_INJECTION":   400,
    "PATH_TRAVERSAL":  401,
    "WEBSHELL_ATTEMPT":402,
    "DOWNLOAD_ATTEMPT":500,
    "MALWARE_UPLOAD":  501,
    "BRUTE_FORCE":     600,
    "COORDINATED_ATTACK": 700,
    "RCE_ATTEMPT":     800,
    "ALERT":           900,
}


class CEFFormatter:

    def format_event(
        self,
        event_type:   str,
        protocol:     str,
        src_ip:       str,
        threat_level: str = "LOW",
        threat_score: int = 0,
        session_id:   str = "",
        details:      dict = None,
    ) -> str:
        details     = details or {}
        severity    = _CEF_SEVERITY.get(threat_level, 3)
        event_id    = _EVENT_IDS.get(event_type, 999)
        ts          = int(time.time() * 1000)  # milliseconds

        # Build extension fields
        extensions = [
            f"rt={ts}",
            f"src={src_ip}",
            f"proto={protocol}",
            f"cs1={session_id}",
            f"cs1Label=SessionID",
            f"cn1={threat_score}",
            f"cn1Label=ThreatScore",
            f"cs2={threat_level}",
            f"cs2Label=ThreatLevel",
        ]

        # Add detail fields
        if "username" in details:
            extensions.append(f"suser={details['username']}")
        if "command" in details:
            cmd = str(details["command"])[:100].replace("|", "/")
            extensions.append(f"cs3={cmd}")
            extensions.append("cs3Label=Command")
        if "attack_chain" in details:
            chain = str(details["attack_chain"])[:200].replace("|", "->")
            extensions.append(f"cs4={chain}")
            extensions.append("cs4Label=AttackChain")
        if "attacker_type" in details:
            extensions.append(f"cs5={details['attacker_type']}")
            extensions.append("cs5Label=AttackerType")
        if "path" in details:
            extensions.append(f"request={details['path']}")
        if "method" in details:
            extensions.append(f"requestMethod={details['method']}")

        ext_str = " ".join(extensions)

        # CEF format
        cef_line = (
            f"CEF:0|DecoyNetAI|AdaptiveDecoyNet|1.0|"
            f"{event_id}|{event_type}|{severity}|{ext_str}"
        )
        return cef_line

    def write(self, event_type, protocol, src_ip,
              threat_level="LOW", threat_score=0,
              session_id="", details=None):
        line = self.format_event(
            event_type   = event_type,
            protocol     = protocol,
            src_ip       = src_ip,
            threat_level = threat_level,
            threat_score = threat_score,
            session_id   = session_id,
            details      = details,
        )
        try:
            with open(CEF_LOG, "a") as f:
                f.write(line + "\n")
        except Exception as exc:
            logger.error("CEF write error: %s", exc)


# Singleton
cef_formatter = CEFFormatter()
