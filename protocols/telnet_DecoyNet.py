"""
Telnet DecoyNet — fake Telnet server on port 23.

Captures:
- Mirai and variant botnet credential attempts
- IoT device brute force
- Malware download commands
- Bot C2 communication attempts
"""

import socket
import time
import logging

from protocols.base_protocol import BaseProtocolDecoyNet

logger = logging.getLogger(__name__)

# Common Mirai/botnet credentials
_BOT_CREDS = [
    ("root","root"), ("admin","admin"), ("admin",""), ("root",""),
    ("guest","guest"), ("support","support"), ("root","toor"),
    ("admin","1234"), ("root","password"), ("user","user"),
]


class TelnetDecoyNet(BaseProtocolDecoyNet):
    PROTOCOL = "TELNET"
    PORT     = 23

    def handle(self, conn: socket.socket, ip: str, port: int, sid: str):
        t0       = time.time()
        commands = []

        # Telnet negotiation bytes — makes it look like a real telnet server
        conn.sendall(bytes([0xff, 0xfb, 0x01, 0xff, 0xfb, 0x03, 0xff, 0xfd, 0x18]))
        self.send(conn, "\r\nBusyBox v1.25.1 (2018-01-01) built-in shell\r\n")
        self.send(conn, "\r\nlogin: ")

        username = self.recv_line(conn, timeout=30)
        self.send(conn, "\r\nPassword: ")
        password = self.recv_line(conn, timeout=30)

        self.db.save_auth_attempt({
            "session_id": sid, "ip": ip,
            "username": username, "password": password,
            "timestamp": time.time(),
        })
        logger.warning("TELNET AUTH | ip=%-16s user=%s pass=%s", ip, username, password)

        # Always accept — capture what bot does next
        self.send(conn, "\r\n\r\n# ")

        while True:
            try:
                line = self.recv_line(conn, timeout=60)
                if not line:
                    break

                commands.append(line)
                logger.warning("TELNET CMD | ip=%-16s cmd=%s", ip, line[:80])

                # Detect malware download
                if any(kw in line for kw in ["wget", "curl", "tftp", "busybox"]):
                    logger.warning("TELNET MALWARE | ip=%s cmd=%s", ip, line)
                    self.send(conn, "\r\n")

                elif line.strip() in ("exit", "logout", "quit"):
                    break

                else:
                    self.send(conn, "\r\n# ")

            except Exception:
                break

        duration = time.time() - t0
        cmd_count = len(commands)
        exfil  = sum(1 for c in commands if any(k in c for k in ["wget","curl","tftp"]))
        features = {
            "command_count": cmd_count, "recon_count": 0,
            "lateral_count": 0, "exploit_count": exfil,
            "exfil_count": exfil, "attacker_type": "bot",
            "mean_delay": 0.1, "stdev_delay": 0.0,
            "mean_inter": 0.1,
        }
        score = self.scorer.score(features)
        self.save_session(sid, ip, port, duration, cmd_count,
                          score["score"], score["level"], "bot",
                          "IoT Botnet Attack")
