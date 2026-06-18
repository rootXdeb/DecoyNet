"""
PostgreSQL DecoyNet — fake PostgreSQL server on port 5432.
Captures credential brute force and exposed database attacks.
"""

import socket
import time
import struct
import logging

from protocols.base_protocol import BaseProtocolDecoyNet

logger = logging.getLogger(__name__)


class PostgreSQLDecoyNet(BaseProtocolDecoyNet):
    PROTOCOL = "POSTGRESQL"
    PORT     = 5432

    def _error_response(self, msg: str) -> bytes:
        body = b"E" + f"SFATAL\x00C28P01\x00M{msg}\x00\x00".encode()
        return struct.pack("!I", len(body) + 4) + body[1:]

    def handle(self, conn: socket.socket, ip: str, port: int, sid: str):
        t0 = time.time()
        try:
            conn.settimeout(30)
            # Read startup packet
            data = conn.recv(1024)
            if not data or len(data) < 8:
                return

            # Extract username from startup message
            username = "unknown"
            database = "unknown"
            try:
                payload = data[8:]
                parts   = payload.split(b"\x00")
                params  = {}
                for i in range(0, len(parts) - 1, 2):
                    if parts[i]:
                        params[parts[i].decode(errors="replace")] = \
                            parts[i+1].decode(errors="replace")
                username = params.get("user", "unknown")
                database = params.get("database", "unknown")
            except Exception:
                pass

            logger.warning("POSTGRESQL AUTH | ip=%-16s user=%s db=%s",
                           ip, username, database)

            self.db.save_auth_attempt({
                "session_id": sid, "ip": ip,
                "username":   username,
                "password":   f"db={database}",
                "timestamp":  time.time(),
            })

            # Send authentication request (MD5)
            salt = b"\x52\x52\x52\x52"
            auth_req = struct.pack("!cII", b"R", 12, 5) + salt
            conn.sendall(auth_req)

            # Read password response
            pwd_data = conn.recv(1024)
            if pwd_data:
                logger.warning("POSTGRESQL PASSWORD | ip=%s hash=%s",
                               ip, pwd_data[5:].hex()[:32])

            # Send auth failure
            err_msg = (
                b"E"
                b"\x53FATAL\x00"
                b"\x43\x32\x38\x50\x30\x31\x00"
                b"\x4dpassword authentication failed for user "
                + f'"{username}"'.encode()
                + b"\x00\x00"
            )
            length = struct.pack("!I", len(err_msg) + 4)
            conn.sendall(err_msg[:1] + length + err_msg[1:])

        except Exception as exc:
            logger.debug("PostgreSQL session [%s]: %s", ip, exc)

        duration = time.time() - t0
        features = {
            "command_count": 1, "recon_count": 1, "lateral_count": 0,
            "exploit_count": 0, "exfil_count": 0, "attacker_type": "unknown",
            "mean_delay": 0.0, "stdev_delay": 0.0, "mean_inter": 0.0,
        }
        score = self.scorer.score(features)
        self.save_session(sid, ip, port, duration, 1,
                          score["score"], score["level"], "unknown",
                          "PostgreSQL Probe")
