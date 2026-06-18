"""
Seeds the database with realistic-looking fake enterprise data
to increase attacker engagement and dwell time.
"""

import logging
from deception.fake_users import generate_users
from database.db_manager import DatabaseManager

logger = logging.getLogger(__name__)


def seed_honey_data(db: DatabaseManager):
    users = generate_users(30)
    for u in users:
        try:
            db.execute(
                "INSERT OR IGNORE INTO honey_users (id,username,email,role,pw_hash,created) VALUES (?,?,?,?,?,?)",
                (u["id"], u["username"], u["email"], u["role"], u["pw_hash"], u["created"]),
            )
        except Exception:
            pass
    logger.info("Honey data seeded: %d users.", len(users))


def initialize_honey_tables(db: DatabaseManager):
    db.execute("""
        CREATE TABLE IF NOT EXISTS honey_users (
            id       INTEGER PRIMARY KEY,
            username TEXT UNIQUE,
            email    TEXT,
            role     TEXT,
            pw_hash  TEXT,
            created  INTEGER
        )
    """)
    db.execute("""
        CREATE TABLE IF NOT EXISTS honey_transactions (
            id       INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id  INTEGER,
            amount   REAL,
            currency TEXT,
            ts       INTEGER
        )
    """)
    db.execute("""
        CREATE TABLE IF NOT EXISTS honey_api_keys (
            id      INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER,
            key     TEXT UNIQUE,
            scope   TEXT,
            active  INTEGER DEFAULT 1
        )
    """)
    logger.info("Honey tables initialised.")
