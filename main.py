"""
DecoyNetAI — Main entry point.
Starts all protocol DecoyNets, ML trainer, report scheduler, and dashboard.
"""

import threading
import logging
import sys
import os

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from config import (
    DECOYNET_HOST, DECOYNET_PORT, DASHBOARD_PORT, LOG_LEVEL, LOG_DIR,
    HTTP_PORT, FTP_PORT, TELNET_PORT, MYSQL_PORT, REDIS_PORT,
    SMTP_PORT_HONEY, RDP_PORT, SMB_PORT, MONGODB_PORT,
    ELASTICSEARCH_PORT, VNC_PORT,
    POSTGRESQL_PORT, LDAP_PORT, MEMCACHED_PORT, SIP_PORT,
)

os.makedirs(LOG_DIR, exist_ok=True)
logging.basicConfig(
    level=getattr(logging, LOG_LEVEL),
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    handlers=[
        logging.FileHandler(os.path.join(LOG_DIR, "errors.log")),
        logging.StreamHandler(sys.stdout),
    ],
)
logger = logging.getLogger("main")

# ── Step 1: DB schema FIRST ───────────────────────────────────────────────────
from database.db_manager import DatabaseManager
from database.models import initialize_schema, update_schema_for_adaptive
from database.migrations import run_migrations

db = DatabaseManager()
initialize_schema(db)
update_schema_for_adaptive(db)
run_migrations(db)
logger.info("Database ready.")

# ── Step 2: Import all modules ────────────────────────────────────────────────
from ssh_engine.ssh_server import RealSSHServer
from protocols.http_DecoyNet import HTTPDecoyNet
from protocols.ftp_DecoyNet import FTPDecoyNet
from protocols.telnet_DecoyNet import TelnetDecoyNet
from protocols.mysql_DecoyNet import MySQLDecoyNet
from protocols.redis_DecoyNet import RedisDecoyNet
from protocols.smtp_DecoyNet import SMTPDecoyNet
from protocols.rdp_DecoyNet import RDPDecoyNet
from protocols.smb_DecoyNet import SMBDecoyNet
from protocols.mongodb_DecoyNet import MongoDBDecoyNet
from protocols.elasticsearch_DecoyNet import ElasticsearchDecoyNet
from protocols.vnc_DecoyNet import VNCDecoyNet
from protocols.postgresql_DecoyNet import PostgreSQLDecoyNet
from protocols.ldap_DecoyNet import LDAPDecoyNet
from protocols.memcached_DecoyNet import MemcachedDecoyNet
from protocols.sip_DecoyNet import SIPDecoyNet
from ml_engine.model_trainer import ModelTrainer
from reports.report_scheduler import ReportScheduler
from dashboard.app import create_app


def _start(name, target):
    t = threading.Thread(target=target, daemon=True, name=name)
    t.start()
    return t


def main():
    logger.info("=" * 60)
    logger.info("  DecoyNetAI — Adaptive Deception Platform")
    logger.info("=" * 60)

    protocols = [
        ("SSH",           lambda: RealSSHServer(DECOYNET_HOST, DECOYNET_PORT).start()),
        ("HTTP",          lambda: HTTPDecoyNet(DECOYNET_HOST, HTTP_PORT).start()),
        ("FTP",           lambda: FTPDecoyNet(DECOYNET_HOST, FTP_PORT).start()),
        ("Telnet",        lambda: TelnetDecoyNet(DECOYNET_HOST, TELNET_PORT).start()),
        ("MySQL",         lambda: MySQLDecoyNet(DECOYNET_HOST, MYSQL_PORT).start()),
        ("Redis",         lambda: RedisDecoyNet(DECOYNET_HOST, REDIS_PORT).start()),
        ("SMTP",          lambda: SMTPDecoyNet(DECOYNET_HOST, SMTP_PORT_HONEY).start()),
        ("RDP",           lambda: RDPDecoyNet(DECOYNET_HOST, RDP_PORT).start()),
        ("SMB",           lambda: SMBDecoyNet(DECOYNET_HOST, SMB_PORT).start()),
        ("MongoDB",       lambda: MongoDBDecoyNet(DECOYNET_HOST, MONGODB_PORT).start()),
        ("Elasticsearch", lambda: ElasticsearchDecoyNet(DECOYNET_HOST, ELASTICSEARCH_PORT).start()),
        ("VNC",           lambda: VNCDecoyNet(DECOYNET_HOST, VNC_PORT).start()),
        ("PostgreSQL",    lambda: PostgreSQLDecoyNet(DECOYNET_HOST, POSTGRESQL_PORT).start()),
        ("LDAP",          lambda: LDAPDecoyNet(DECOYNET_HOST, LDAP_PORT).start()),
        ("Memcached",     lambda: MemcachedDecoyNet(DECOYNET_HOST, MEMCACHED_PORT).start()),
        ("SIP",           lambda: SIPDecoyNet(DECOYNET_HOST, SIP_PORT).start()),
    ]

    for name, target in protocols:
        try:
            _start(name, target)
            logger.info("  ✓ %-20s started", name)
        except Exception as e:
            logger.error("  ✗ %-20s failed: %s", name, e)

    _start("MLTrainer",       ModelTrainer().run_loop)
    _start("ReportScheduler", ReportScheduler().run_loop)

    logger.info("=" * 60)
    logger.info("  Dashboard → http://0.0.0.0:%d", DASHBOARD_PORT)
    logger.info("  All systems live. Waiting for attackers...")
    logger.info("=" * 60)

    app = create_app()
    app.run(host="0.0.0.0", port=DASHBOARD_PORT, debug=False, use_reloader=False)


if __name__ == "__main__":
    main()
