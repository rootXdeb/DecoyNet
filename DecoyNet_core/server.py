"""
Core TCP socket server. Listens for incoming attacker connections
and spawns a SessionHandler for each one.
"""

import socket
import threading
import logging
from config import MAX_CONNECTIONS
from DecoyNet_core.session_handler import SessionHandler

logger = logging.getLogger(__name__)


class DecoyNetServer:
    def __init__(self, host: str, port: int):
        self.host = host
        self.port = port
        self._active_sessions: dict = {}
        self._lock = threading.Lock()

    def start(self):
        srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        srv.bind((self.host, self.port))
        srv.listen(MAX_CONNECTIONS)
        logger.info(f"DecoyNetServer listening on {self.host}:{self.port}")

        while True:
            try:
                conn, addr = srv.accept()
                ip, port = addr
                logger.info(f"New connection from {ip}:{port}")
                handler = SessionHandler(conn, ip, port)
                t = threading.Thread(
                    target=self._handle_session,
                    args=(handler, ip),
                    daemon=True,
                )
                t.start()
                with self._lock:
                    self._active_sessions[ip] = handler
            except Exception as exc:
                logger.error(f"Accept error: {exc}")

    def _handle_session(self, handler: "SessionHandler", ip: str):
        try:
            handler.run()
        finally:
            with self._lock:
                self._active_sessions.pop(ip, None)

    @property
    def active_count(self) -> int:
        return len(self._active_sessions)
