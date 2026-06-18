"""
Email Alert — sends email notification on HIGH/CRITICAL threats.
Configure ALERT_EMAIL and SMTP settings in config.py.
If not configured, this silently does nothing.
"""

import smtplib
import logging
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart

logger = logging.getLogger(__name__)


def send_email(payload: dict):
    try:
        from config import (
            ALERT_EMAIL, SMTP_HOST, SMTP_PORT,
            SMTP_USER, SMTP_PASSWORD
        )
    except ImportError:
        return

    if not ALERT_EMAIL or not SMTP_HOST:
        return

    threat_level = payload.get("threat_level", "HIGH")
    src_ip       = payload.get("src_ip", "unknown")
    event_type   = payload.get("event_type", "THREAT")
    score        = payload.get("threat_score", 0)
    protocol     = payload.get("protocol", "unknown")
    timestamp    = payload.get("timestamp", "")
    details      = payload.get("details", {})

    subject = f"[DecoyNetAI] {threat_level} ALERT — {event_type} from {src_ip}"

    body = f"""
DecoyNetAI Security Alert
==========================

Threat Level  : {threat_level}
Event Type    : {event_type}
Attacker IP   : {src_ip}
Protocol      : {protocol}
Threat Score  : {score}/100
Time          : {timestamp}

Details
-------
"""
    for k, v in details.items():
        body += f"{k:<20}: {v}\n"

    body += """
---
This alert was generated automatically by DecoyNetAI.
Log in to your dashboard for full session details.
"""

    try:
        msg = MIMEMultipart()
        msg["From"]    = SMTP_USER or "DecoyNet@alert.local"
        msg["To"]      = ALERT_EMAIL
        msg["Subject"] = subject
        msg.attach(MIMEText(body, "plain"))

        with smtplib.SMTP(SMTP_HOST, SMTP_PORT, timeout=10) as server:
            if SMTP_PASSWORD:
                server.starttls()
                server.login(SMTP_USER, SMTP_PASSWORD)
            server.sendmail(msg["From"], ALERT_EMAIL, msg.as_string())

        logger.info("Email alert sent to %s", ALERT_EMAIL)

    except Exception as exc:
        logger.debug("Email send failed: %s", exc)
