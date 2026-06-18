"""
Webhook Alert — sends alerts to Slack, Teams, or any generic webhook.
Configure SLACK_WEBHOOK and GENERIC_WEBHOOK in config.py.
If not configured, silently does nothing.
"""

import json
import logging
import urllib.request
import urllib.error

logger = logging.getLogger(__name__)

_LEVEL_EMOJI = {
    "LOW":      "🟢",
    "MEDIUM":   "🟡",
    "HIGH":     "🟠",
    "CRITICAL": "🔴",
}


def send_slack(payload: dict):
    try:
        from config import SLACK_WEBHOOK
    except ImportError:
        return

    if not SLACK_WEBHOOK:
        return

    level    = payload.get("threat_level", "HIGH")
    emoji    = _LEVEL_EMOJI.get(level, "🔴")
    src_ip   = payload.get("src_ip", "unknown")
    event    = payload.get("event_type", "THREAT")
    score    = payload.get("threat_score", 0)
    protocol = payload.get("protocol", "unknown")
    ts       = payload.get("timestamp", "")
    details  = payload.get("details", {})

    chain        = details.get("attack_chain", "N/A")
    attacker_type = details.get("attacker_type", "unknown")

    message = {
        "text": f"{emoji} *DecoyNetAI {level} ALERT*",
        "attachments": [{
            "color": "#ff0000" if level == "CRITICAL" else "#ff8800",
            "fields": [
                {"title": "Event",         "value": event,         "short": True},
                {"title": "Protocol",      "value": protocol,      "short": True},
                {"title": "Attacker IP",   "value": src_ip,        "short": True},
                {"title": "Threat Score",  "value": f"{score}/100","short": True},
                {"title": "Attacker Type", "value": attacker_type, "short": True},
                {"title": "Time",          "value": ts,            "short": True},
                {"title": "Attack Chain",  "value": chain,         "short": False},
            ],
            "footer": "DecoyNetAI Adaptive Deception Platform",
        }]
    }

    _post_json(SLACK_WEBHOOK, message)


def send_generic_webhook(payload: dict):
    try:
        from config import GENERIC_WEBHOOK
    except ImportError:
        return

    if not GENERIC_WEBHOOK:
        return

    _post_json(GENERIC_WEBHOOK, payload)


def _post_json(url: str, data: dict):
    try:
        body = json.dumps(data).encode("utf-8")
        req  = urllib.request.Request(
            url,
            data    = body,
            headers = {"Content-Type": "application/json"},
            method  = "POST",
        )
        with urllib.request.urlopen(req, timeout=10) as resp:
            logger.info("Webhook alert sent → %s [%d]", url[:50], resp.status)
    except Exception as exc:
        logger.debug("Webhook send failed: %s", exc)
