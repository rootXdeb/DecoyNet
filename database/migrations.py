"""
Lightweight schema migration system.
Each migration is a function applied once, tracked in a migrations table.
"""

import logging
from database.db_manager import DatabaseManager

logger = logging.getLogger(__name__)

_MIGRATIONS = {}


def migration(version: int):
    def decorator(fn):
        _MIGRATIONS[version] = fn
        return fn
    return decorator


# ── Registered migrations ──────────────────────────────────────────────────

@migration(1)
def add_cluster_col(db: DatabaseManager):
    """Add ML cluster column to sessions."""
    db.execute("ALTER TABLE sessions ADD COLUMN cluster INTEGER DEFAULT -1")


@migration(2)
def add_anomaly_col(db: DatabaseManager):
    """Add anomaly flag column to sessions."""
    db.execute("ALTER TABLE sessions ADD COLUMN is_anomaly INTEGER DEFAULT 0")


# ── Runner ─────────────────────────────────────────────────────────────────

def run_migrations(db: DatabaseManager):
    db.execute("""
        CREATE TABLE IF NOT EXISTS _migrations (
            version INTEGER PRIMARY KEY,
            applied_at REAL
        )
    """)
    applied = {r["version"] for r in db.execute("SELECT version FROM _migrations").fetchall()}

    for version in sorted(_MIGRATIONS):
        if version in applied:
            continue
        try:
            _MIGRATIONS[version](db)
            import time
            db.execute("INSERT INTO _migrations (version, applied_at) VALUES (?,?)",
                       (version, time.time()))
            logger.info("Migration %d applied.", version)
        except Exception as exc:
            logger.warning("Migration %d skipped: %s", version, exc)
