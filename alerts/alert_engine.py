"""
Alert Engine — fires alerts when threat level crosses threshold.

Calls all configured alert channels simultaneously:
- Email
- Slack/Teams webhook
- Generic webhook (PagerDuty, OpsGenie, etc.)
"""

import time
import logging
import threading

logger = logging.getLogger(__name__)

# Don't fire the same alert twice within this window (seconds)
_COOLDOWN = 300


class AlertEngine:
    def __init__(self):
        self._recent: dict[str, float] = {}
        self._lock   = threading.Lock()

    def fire(
        self,
        event_type:   str,
        protocol:     str,
        src_ip:       str,
        threat_score: int,
        threat_level: str,
        details:      dict = None,
    ):
        # Only alert on HIGH and CRITICAL
        if threat_level not in ("HIGH", "CRITICAL"):
            return

        # Cooldown — don't spam alerts for the same IP
        key = f"{src_ip}:{event_type}"
        with self._lock:
            last = self._recent.get(key, 0)
            if time.time() - last < _COOLDOWN:
                return
            self._recent[key] = time.time()

        payload = {
            "event_type":   event_type,
            "protocol":     protocol,
            "src_ip":       src_ip,
            "threat_score": threat_score,
            "threat_level": threat_level,
            "details":      details or {},
            "timestamp":    time.strftime("%Y-%m-%d %H:%M:%S UTC", time.gmtime()),
        }

        logger.warning(
            "ALERT FIRED | %s | %s | ip=%s score=%d",
            threat_level, event_type, src_ip, threat_score
        )

        # Fire all channels in parallel so one slow channel doesn't block others
        threads = [
            threading.Thread(target=self._send_email,   args=(payload,), daemon=True),
            threading.Thread(target=self._send_slack,   args=(payload,), daemon=True),
            threading.Thread(target=self._send_webhook, args=(payload,), daemon=True),
        ]
        for t in threads:
            t.start()

    # ── Alert channels ────────────────────────────────────────────────────────

    def _send_email(self, payload: dict):
        try:
            from alerts.email_alert import send_email
            send_email(payload)
        except Exception as exc:
            logger.debug("Email alert error: %s", exc)

    def _send_slack(self, payload: dict):
        try:
            from alerts.webhook_alert import send_slack
            send_slack(payload)
        except Exception as exc:
            logger.debug("Slack alert error: %s", exc)

    def _send_webhook(self, payload: dict):
        try:
            from alerts.webhook_alert import send_generic_webhook
            send_generic_webhook(payload)
        except Exception as exc:
            logger.debug("Webhook alert error: %s", exc)


# Singleton
alert_engine = AlertEngine()
