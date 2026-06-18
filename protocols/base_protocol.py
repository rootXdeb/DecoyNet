"""
Base protocol DecoyNet class.
Every protocol listener inherits from this and gets:
- Automatic session logging
- Threat scoring
- SIEM event output
- IOC recording
- Consistent logging format
"""

import socket
import threading
import time
import uuid
import logging
from abc import ABC, abstractmethod

from database.db_manager import DatabaseManager
from analysis.threat_scorer import ThreatScorer
from intelligence.ioc_manager import IOCManager

logger = logging.getLogger(__name__)


class BaseProtocolDecoyNet(ABC):
    PROTOCOL = "UNKNOWN"
    PORT     = 0

    def __init__(self, host: str = "0.0.0.0", port: int = None):
        self.host    = host
        self.port    = port or self.PORT
        self.db      = DatabaseManager()
        self.scorer  = ThreatScorer()
        self.ioc     = IOCManager()
        self._active = True

    def start(self):
        srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        srv.bind((self.host, self.port))
        srv.listen(100)
        logger.info("%s DecoyNet listening on %s:%d", self.PROTOCOL, self.host, self.port)

        while self._active:
            try:
                conn, addr = srv.accept()
                ip, port   = addr
                t = threading.Thread(
                    target=self._safe_handle,
                    args=(conn, ip, port),
                    daemon=True,
                )
                t.start()
            except Exception as exc:
                logger.error("%s accept error: %s", self.PROTOCOL, exc)

    def _safe_handle(self, conn, ip, port):
        sid = str(uuid.uuid4())
        t0  = time.time()
        try:
            self.handle(conn, ip, port, sid)
        except Exception as exc:
            logger.debug("%s session error [%s]: %s", self.PROTOCOL, ip, exc)
        finally:
            duration = time.time() - t0
            self.ioc.record_ip(ip, f"DecoyNet-{self.PROTOCOL.lower()}")
            logger.info("%s session end | ip=%s dur=%.1fs", self.PROTOCOL, ip, duration)
            try:
                conn.close()
            except Exception:
                pass

    @abstractmethod
    def handle(self, conn: socket.socket, ip: str, port: int, sid: str):
        """Protocol-specific session handler."""

    def save_session(self, sid, ip, port, duration, cmd_count, score, level, atype, chain=""):
        self.db.save_session({
            "session_id":    sid,
            "ip":            ip,
            "port":          port,
            "start_time":    time.time() - duration,
            "duration":      duration,
            "command_count": cmd_count,
            "threat_score":  score,
            "threat_level":  level,
            "attacker_type": atype,
            "final_strategy": "OBSERVE",
            "attack_chain":  chain,
            "username":      "",
            "password":      "",
            "protocol":      self.PROTOCOL,
        })

    def recv_line(self, conn, timeout=30, max_bytes=4096) -> str:
        conn.settimeout(timeout)
        buf = b""
        while len(buf) < max_bytes:
            chunk = conn.recv(1)
            if not chunk:
                break
            if chunk in (b"\r", b"\n"):
                if buf:
                    break
            else:
                buf += chunk
        return buf.decode("utf-8", errors="replace").strip()

    def send(self, conn, data: str):
        try:
            conn.sendall(data.encode("utf-8", errors="replace"))
        except Exception:
            pass
