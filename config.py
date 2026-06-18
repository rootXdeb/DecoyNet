"""
Global configuration for the AI-Driven Adaptive DecoyNet Platform.
"""

import os

# ── Network ────────────────────────────────────────────────────────────────
DECOYNET_HOST = "0.0.0.0"
DECOYNET_PORT = 2222          # Fake SSH port
HTTP_PORT     = 8080          # Fake HTTP port
DASHBOARD_PORT = 5000         # Flask dashboard

# ── Database ───────────────────────────────────────────────────────────────
BASE_DIR   = os.path.dirname(os.path.abspath(__file__))
DB_PATH    = os.path.join(BASE_DIR, "database", "DecoyNet.db")

# ── Directories ────────────────────────────────────────────────────────────
LOG_DIR        = os.path.join(BASE_DIR, "logs")
QUARANTINE_DIR = os.path.join(BASE_DIR, "malware", "quarantine")
MODEL_DIR      = os.path.join(BASE_DIR, "ml_engine", "models")

# ── Threat Scoring ─────────────────────────────────────────────────────────
THREAT_LEVELS = {
    "LOW":      (0,  30),
    "MEDIUM":   (31, 60),
    "HIGH":     (61, 85),
    "CRITICAL": (86, 100),
}

# ── Session ────────────────────────────────────────────────────────────────
SESSION_TIMEOUT    = 300       # seconds
MAX_CONNECTIONS    = 50
COMMAND_LOG_LIMIT  = 1000

# ── ML ─────────────────────────────────────────────────────────────────────
ML_RETRAIN_INTERVAL = 3600     # Retrain every hour (seconds)
MIN_SAMPLES_TO_TRAIN = 20

# ── Deception ──────────────────────────────────────────────────────────────
BANNER_ROTATION_INTERVAL = 1800   # seconds
FAKE_VULN_EXPOSURE_CHANCE = 0.3   # 30% chance to surface a fake vuln

# ── Logging ────────────────────────────────────────────────────────────────
LOG_LEVEL = "INFO"

# ── Protocol Ports ──────────────────────────────────────────────────────────
HTTP_PORT          = 8080
FTP_PORT           = 2121
TELNET_PORT        = 2323
MYSQL_PORT         = 3306
REDIS_PORT         = 6379
SMTP_PORT_HONEY    = 2525
RDP_PORT           = 3389
SMB_PORT           = 4445
MONGODB_PORT       = 27017
ELASTICSEARCH_PORT = 9200
VNC_PORT           = 5900

# ── SIEM Output ─────────────────────────────────────────────────────────────
SIEM_SYSLOG_HOST   = ""        # e.g. "192.168.1.100" — leave blank if no SIEM
SIEM_SYSLOG_PORT   = 514

# ── Alerts ──────────────────────────────────────────────────────────────────
ALERT_EMAIL        = ""        # e.g. "soc@company.com"
SMTP_HOST          = ""        # e.g. "smtp.gmail.com"
SMTP_PORT          = 587
SMTP_USER          = ""
SMTP_PASSWORD      = ""
SLACK_WEBHOOK      = ""        # e.g. "https://hooks.slack.com/services/..."
GENERIC_WEBHOOK    = ""        # e.g. PagerDuty / OpsGenie endpoint

# ── Additional Protocols ────────────────────────────────────────────────────
POSTGRESQL_PORT  = 5432
LDAP_PORT        = 389
MEMCACHED_PORT   = 11211
SIP_PORT         = 5060

# ── Threat Intelligence ─────────────────────────────────────────────────────
ABUSEIPDB_API_KEY = ""   # Get free key at https://www.abuseipdb.com/register
