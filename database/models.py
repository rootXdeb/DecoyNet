"""
Database schema definitions and initialiser.
"""

import logging
from database.db_manager import DatabaseManager

logger = logging.getLogger(__name__)

_SCHEMA = """
CREATE TABLE IF NOT EXISTS sessions (
    session_id   TEXT PRIMARY KEY,
    ip           TEXT,
    port         INTEGER,
    start_time   REAL,
    duration     REAL,
    command_count INTEGER,
    threat_score  INTEGER,
    threat_level  TEXT,
    attacker_type TEXT
);

CREATE TABLE IF NOT EXISTS auth_attempts (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    session_id TEXT,
    ip         TEXT,
    username   TEXT,
    password   TEXT,
    timestamp  REAL
);

CREATE TABLE IF NOT EXISTS malware_captures (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    session_id    TEXT,
    original_name TEXT,
    stored_name   TEXT,
    path          TEXT,
    size          INTEGER,
    timestamp     REAL,
    md5           TEXT,
    sha1          TEXT,
    sha256        TEXT,
    file_type     TEXT
);

CREATE TABLE IF NOT EXISTS iocs (
    id        INTEGER PRIMARY KEY AUTOINCREMENT,
    value     TEXT UNIQUE,
    type      TEXT,
    source    TEXT,
    timestamp REAL
);

CREATE TABLE IF NOT EXISTS patterns (
    id    INTEGER PRIMARY KEY AUTOINCREMENT,
    data  TEXT,
    added REAL
);
"""


def initialize_schema(db: DatabaseManager):
    for statement in _SCHEMA.strip().split(";"):
        stmt = statement.strip()
        if stmt:
            db.execute(stmt)
    initialize_protocol_tables(db)
    logger.info("Database schema initialised.")


def update_schema_for_adaptive(db):
    """Add new columns needed by the adaptive SSH engine."""
    new_cols = [
        "ALTER TABLE sessions ADD COLUMN final_strategy TEXT DEFAULT 'OBSERVE'",
        "ALTER TABLE sessions ADD COLUMN attack_chain TEXT DEFAULT ''",
        "ALTER TABLE sessions ADD COLUMN username TEXT DEFAULT ''",
        "ALTER TABLE sessions ADD COLUMN password TEXT DEFAULT ''",
    ]
    for stmt in new_cols:
        try:
            db.execute(stmt)
        except Exception:
            pass  # column already exists


def initialize_protocol_tables(db):
    """Extra tables for multi-protocol DecoyNet data."""
    stmts = [
        """CREATE TABLE IF NOT EXISTS http_requests (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            session_id  TEXT,
            ip          TEXT,
            method      TEXT,
            path        TEXT,
            user_agent  TEXT,
            body        TEXT,
            attack_type TEXT,
            threat_score INTEGER,
            timestamp   REAL
        )""",
    ]
    for s in stmts:
        try:
            db.execute(s)
        except Exception:
            pass
