"""
Paramiko ServerInterface — handles SSH authentication and channel requests.
"""

import threading
import time
import logging

try:
    import paramiko
    PARAMIKO_AVAILABLE = True
except ImportError:
    PARAMIKO_AVAILABLE = False
    # Create a dummy base class so the import doesn't crash
    class _DummyServerInterface:
        pass
    paramiko_ServerInterface = _DummyServerInterface
else:
    paramiko_ServerInterface = paramiko.ServerInterface

from database.db_manager import DatabaseManager

logger = logging.getLogger(__name__)


class DecoyNetServerInterface(paramiko_ServerInterface):

    def __init__(self, ip: str, db: DatabaseManager):
        self.ip          = ip
        self.db          = db
        self.username    = ""
        self.password    = ""
        self.session_id  = ""
        self.shell_event = threading.Event()

    def check_auth_password(self, username: str, password: str) -> int:
        self.username = username
        self.password = password
        logger.warning("AUTH | ip=%-16s user=%-20s pass=%s", self.ip, username, password)
        self.db.save_auth_attempt({
            "session_id": self.session_id or "pre-session",
            "ip":         self.ip,
            "username":   username,
            "password":   password,
            "timestamp":  time.time(),
        })
        return paramiko.AUTH_SUCCESSFUL

    def check_auth_publickey(self, username: str, key) -> int:
        self.username = username
        return paramiko.AUTH_SUCCESSFUL

    def get_allowed_auths(self, username: str) -> str:
        return "password,publickey"

    def check_channel_request(self, kind: str, chanid: int) -> int:
        if kind == "session":
            return paramiko.OPEN_SUCCEEDED
        return paramiko.OPEN_FAILED_ADMINISTRATIVELY_PROHIBITED

    def check_channel_pty_request(self, channel, term, width, height, pixelwidth, pixelheight, modes) -> bool:
        return True

    def check_channel_shell_request(self, channel) -> bool:
        self.shell_event.set()
        return True

    def check_channel_exec_request(self, channel, command: bytes) -> bool:
        self.shell_event.set()
        return True

    def check_channel_subsystem_request(self, channel, name: str) -> bool:
        return name == "sftp"
