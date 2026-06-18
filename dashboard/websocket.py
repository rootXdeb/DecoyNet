"""
WebSocket events — pushes live attack data to connected dashboard clients.
"""

import time
from flask_socketio import emit
from dashboard.app import socketio
from database.db_manager import DatabaseManager

db = DatabaseManager()


@socketio.on("connect")
def on_connect():
    stats = db.get_stats()
    emit("stats_update", stats)
    recent = db.get_recent_sessions(10)
    emit("session_feed", recent)


@socketio.on("request_stats")
def on_request_stats():
    emit("stats_update", db.get_stats())


def broadcast_new_session(session: dict):
    """Call this from SessionHandler when a session closes."""
    socketio.emit("new_session", session)


def broadcast_alert(level: str, message: str):
    """Push a threat alert to all connected clients."""
    socketio.emit("threat_alert", {
        "level":   level,
        "message": message,
        "time":    time.time(),
    })
