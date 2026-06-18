"""
FTP DecoyNet — fake FTP server on port 21.

Captures:
- Anonymous login attempts
- Credential brute force
- File upload attempts (malware delivery)
- Directory traversal
"""

import socket
import time
import logging
import uuid

from protocols.base_protocol import BaseProtocolDecoyNet

logger = logging.getLogger(__name__)

_FAKE_FILES = [
    "backup_2024.tar.gz",
    "employee_data.csv",
    "financial_report_Q4.xlsx",
    "passwords.txt",
    "config_backup.zip",
]


class FTPDecoyNet(BaseProtocolDecoyNet):
    PROTOCOL = "FTP"
    PORT     = 21

    def handle(self, conn: socket.socket, ip: str, port: int, sid: str):
        t0       = time.time()
        commands = []
        username = ""
        password = ""

        self.send(conn, "220 Microsoft FTP Service\r\n")

        while True:
            try:
                line = self.recv_line(conn, timeout=60)
                if not line:
                    break

                parts = line.split(" ", 1)
                cmd   = parts[0].upper()
                arg   = parts[1] if len(parts) > 1 else ""
                commands.append(line)

                logger.info("FTP | ip=%-16s cmd=%s arg=%s", ip, cmd, arg[:40])

                if cmd == "USER":
                    username = arg
                    self.send(conn, f"331 Password required for {arg}\r\n")

                elif cmd == "PASS":
                    password = arg
                    self.db.save_auth_attempt({
                        "session_id": sid, "ip": ip,
                        "username": username, "password": password,
                        "timestamp": time.time(),
                    })
                    logger.warning("FTP AUTH | ip=%s user=%s pass=%s", ip, username, password)
                    self.send(conn, "230 User logged in\r\n")

                elif cmd == "SYST":
                    self.send(conn, "215 Windows_NT\r\n")

                elif cmd == "PWD":
                    self.send(conn, '257 "/" is current directory\r\n')

                elif cmd == "LIST":
                    self.send(conn, "150 Opening data connection\r\n")
                    self.send(conn, "226 Transfer complete\r\n")

                elif cmd == "NLST":
                    self.send(conn, "150 Opening data connection\r\n")
                    for f in _FAKE_FILES:
                        self.send(conn, f + "\r\n")
                    self.send(conn, "226 Transfer complete\r\n")

                elif cmd == "RETR":
                    logger.warning("FTP DOWNLOAD | ip=%s file=%s", ip, arg)
                    self.send(conn, "550 File not found\r\n")

                elif cmd == "STOR":
                    logger.warning("FTP UPLOAD ATTEMPT | ip=%s file=%s", ip, arg)
                    self.send(conn, "550 Permission denied\r\n")

                elif cmd == "QUIT":
                    self.send(conn, "221 Goodbye\r\n")
                    break

                elif cmd == "PASV":
                    self.send(conn, "227 Entering Passive Mode (10,0,2,15,196,82)\r\n")

                elif cmd == "TYPE":
                    self.send(conn, "200 Type set\r\n")

                else:
                    self.send(conn, f"502 {cmd} not implemented\r\n")

            except Exception:
                break

        duration = time.time() - t0
        features = {"command_count": len(commands), "attacker_type": "unknown",
                    "recon_count": 0, "lateral_count": 0, "exploit_count": 0, "exfil_count": 0}
        score    = self.scorer.score(features)
        self.save_session(sid, ip, port, duration, len(commands),
                          score["score"], score["level"], "unknown")
