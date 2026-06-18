"""
Real SSH server using Paramiko.
Requires: pip install paramiko
"""

import socket
import threading
import logging

try:
    import paramiko
    PARAMIKO_AVAILABLE = True
except ImportError:
    PARAMIKO_AVAILABLE = False

from ssh_engine.host_key import get_host_key
from ssh_engine.ssh_interface import DecoyNetServerInterface
from ssh_engine.adaptive_shell import AdaptiveShellSession
from database.db_manager import DatabaseManager
from intelligence.ioc_manager import IOCManager

logger = logging.getLogger(__name__)


class RealSSHServer:
    def __init__(self, host: str = "0.0.0.0", port: int = 2222):
        self.host     = host
        self.port     = port
        self.db       = DatabaseManager()
        self.ioc      = IOCManager()
        self._lock    = threading.Lock()
        self._sessions: dict = {}

        if not PARAMIKO_AVAILABLE:
            logger.error("paramiko not installed. Run: pip install paramiko")
            logger.error("SSH DecoyNet will NOT start until paramiko is installed.")

    def start(self):
        if not PARAMIKO_AVAILABLE:
            logger.error("SSH DecoyNet disabled — install paramiko first.")
            return

        self.host_key = get_host_key()
        srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        srv.bind((self.host, self.port))
        srv.listen(100)
        logger.info("Real SSH DecoyNet listening on %s:%d", self.host, self.port)

        while True:
            try:
                conn, addr = srv.accept()
                ip, port   = addr
                logger.info("SSH connection from %s:%d", ip, port)
                t = threading.Thread(
                    target=self._handle,
                    args=(conn, ip, port),
                    daemon=True,
                )
                t.start()
                with self._lock:
                    self._sessions[ip] = t
            except Exception as exc:
                logger.error("SSH accept error: %s", exc)

    def _handle(self, conn, ip, port):
        transport = None
        try:
            transport = paramiko.Transport(conn)
            transport.local_version = "SSH-2.0-OpenSSH_8.2p1 Ubuntu-4ubuntu0.5"
            transport.add_server_key(self.host_key)

            interface = DecoyNetServerInterface(ip, self.db)
            transport.start_server(server=interface)

            channel = transport.accept(30)
            if channel is None:
                return

            interface.shell_event.wait(10)

            session = AdaptiveShellSession(
                channel  = channel,
                ip       = ip,
                username = interface.username,
                password = interface.password,
                db       = self.db,
                ioc      = self.ioc,
            )
            session.run()

        except Exception as exc:
            logger.debug("SSH session error [%s]: %s", ip, exc)
        finally:
            with self._lock:
                self._sessions.pop(ip, None)
            if transport:
                try:
                    transport.close()
                except Exception:
                    pass
