"""
Manages a single attacker session: banner delivery, command loop,
logging, and hand-off to the analysis pipeline.
"""

import socket
import time
import logging
import uuid
from config import SESSION_TIMEOUT
from DecoyNet_core.banner_manager import BannerManager
from DecoyNet_core.fake_shell import FakeShell
from DecoyNet_core.command_parser import CommandParser
from analysis.behavior_analyzer import BehaviorAnalyzer
from analysis.threat_scorer import ThreatScorer
from database.db_manager import DatabaseManager

logger = logging.getLogger(__name__)


class SessionHandler:
    def __init__(self, conn: socket.socket, ip: str, port: int):
        self.conn   = conn
        self.ip     = ip
        self.port   = port
        self.sid    = str(uuid.uuid4())
        self.start  = time.time()
        self.commands: list[dict] = []
        self._db    = DatabaseManager()

    # ── Public ──────────────────────────────────────────────────────────────
    def run(self):
        self.conn.settimeout(SESSION_TIMEOUT)
        try:
            self._send(BannerManager().get_banner())
            self._send("login: ")
            username = self._recv_line()
            self._send("Password: ")
            password = self._recv_line(echo=False)
            self._log_auth(username, password)
            self._send("\nWelcome to Ubuntu 20.04.6 LTS\n\n")
            self._command_loop()
        except (socket.timeout, ConnectionResetError, BrokenPipeError):
            pass
        except Exception as exc:
            logger.exception(f"Session {self.sid} error: {exc}")
        finally:
            self._finalise()

    # ── Private ─────────────────────────────────────────────────────────────
    def _command_loop(self):
        shell  = FakeShell()
        parser = CommandParser(shell)
        while True:
            self._send(shell.prompt())
            line = self._recv_line()
            if line is None or line.lower() in ("exit", "logout", "quit"):
                break
            t0  = time.time()
            out = parser.execute(line, self.ip)
            elapsed = time.time() - t0
            self.commands.append({
                "cmd": line, "output": out, "time": t0, "duration": elapsed
            })
            self._send(out + "\n" if out else "")

    def _finalise(self):
        duration = time.time() - self.start
        analyzer = BehaviorAnalyzer(self.commands)
        features = analyzer.extract_features()
        scorer   = ThreatScorer()
        score    = scorer.score(features)

        self._db.save_session({
            "session_id": self.sid, "ip": self.ip, "port": self.port,
            "start_time": self.start, "duration": duration,
            "command_count": len(self.commands),
            "threat_score": score["score"],
            "threat_level": score["level"],
            "attacker_type": features.get("attacker_type", "unknown"),
        })
        logger.info(
            f"Session {self.sid} closed | ip={self.ip} "
            f"cmds={len(self.commands)} score={score['score']} level={score['level']}"
        )
        try:
            self.conn.close()
        except Exception:
            pass

    def _send(self, data: str):
        self.conn.sendall(data.encode("utf-8", errors="replace"))

    def _recv_line(self, echo: bool = True) -> str | None:
        buf = b""
        while True:
            chunk = self.conn.recv(1)
            if not chunk:
                return None
            if chunk in (b"\r", b"\n"):
                break
            buf += chunk
        return buf.decode("utf-8", errors="replace").strip()

    def _log_auth(self, username: str, password: str):
        logger.info(f"Auth attempt | session={self.sid} user={username} pass={password}")
        self._db.save_auth_attempt({
            "session_id": self.sid, "ip": self.ip,
            "username": username, "password": password,
            "timestamp": time.time(),
        })
