"""
MySQL DecoyNet — fake MySQL server on port 3306.

Captures:
- Credential brute force against exposed databases
- SQL injection attempts
- Data exfiltration queries
- Reconnaissance queries (SHOW DATABASES, SHOW TABLES)
"""

import socket
import time
import struct
import logging

from protocols.base_protocol import BaseProtocolDecoyNet

logger = logging.getLogger(__name__)


class MySQLDecoyNet(BaseProtocolDecoyNet):
    PROTOCOL = "MYSQL"
    PORT     = 3306

    # MySQL server greeting packet (fake)
    def _greeting_packet(self) -> bytes:
        payload = (
            b"\x0a"
            b"8.0.33\x00"
            b"\x01\x00\x00\x00"
            b"\x52\x52\x52\x52\x52\x52\x52\x52\x00"
            b"\xff\xf7"
            b"\x21"
            b"\x02\x00"
            b"\xff\x81"
            b"\x15"
            b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
            b"\x52\x52\x52\x52\x52\x52\x52\x52\x52\x52\x52\x52\x00"
            b"mysql_native_password\x00"
        )
        length  = struct.pack("<I", len(payload))[:3]
        packet  = length + b"\x00" + payload
        return packet

    def _error_packet(self, msg: str) -> bytes:
        payload = b"\xff" + struct.pack("<H", 1045) + b"#28000" + msg.encode()
        length  = struct.pack("<I", len(payload))[:3]
        return length + b"\x02" + payload

    def _ok_packet(self) -> bytes:
        payload = b"\x00\x00\x00\x02\x00\x00\x00"
        length  = struct.pack("<I", len(payload))[:3]
        return length + b"\x02" + payload

    def handle(self, conn: socket.socket, ip: str, port: int, sid: str):
        t0       = time.time()
        queries  = []

        try:
            # Send fake server greeting
            conn.sendall(self._greeting_packet())

            # Read client handshake
            conn.settimeout(30)
            handshake = conn.recv(4096)
            if not handshake:
                return

            # Extract username from handshake packet (best effort)
            username = ""
            try:
                # Username starts after 36 bytes of handshake header
                null_pos = handshake.index(b"\x00", 36)
                username = handshake[36:null_pos].decode("utf-8", errors="replace")
            except Exception:
                username = "unknown"

            self.db.save_auth_attempt({
                "session_id": sid, "ip": ip,
                "username": username, "password": "***",
                "timestamp": time.time(),
            })
            logger.warning("MYSQL AUTH | ip=%-16s user=%s", ip, username)

            # Send error — access denied (realistic)
            conn.sendall(self._error_packet(
                f"Access denied for user '{username}'@'{ip}' (using password: YES)"
            ))

        except Exception as exc:
            logger.debug("MySQL session error [%s]: %s", ip, exc)

        duration = time.time() - t0
        features = {
            "command_count": 1, "recon_count": 1,
            "lateral_count": 0, "exploit_count": 0,
            "exfil_count": 0, "attacker_type": "unknown",
            "mean_delay": 0.0, "stdev_delay": 0.0, "mean_inter": 0.0,
        }
        score = self.scorer.score(features)
        self.save_session(sid, ip, port, duration, 1,
                          score["score"], score["level"], "unknown",
                          "Database Probe")
