"""
VNC DecoyNet — fake VNC server on port 5900.

Captures:
- Brute force against unprotected VNC servers
- Remote access tool abuse
- Automated scanner fingerprinting
"""

import socket
import time
import logging

from protocols.base_protocol import BaseProtocolDecoyNet

logger = logging.getLogger(__name__)


class VNCDecoyNet(BaseProtocolDecoyNet):
    PROTOCOL = "VNC"
    PORT     = 5900

    def handle(self, conn: socket.socket, ip: str, port: int, sid: str):
        t0 = time.time()

        try:
            conn.settimeout(30)

            # RFB protocol version handshake
            self.send(conn, "RFB 003.008\n")
            client_ver = conn.recv(12)

            # Security type: VNC Authentication (2)
            conn.sendall(bytes([0x01, 0x02]))
            sec_type = conn.recv(1)

            # Send 16-byte VNC challenge
            challenge = bytes([0x52] * 16)
            conn.sendall(challenge)

            # Read 16-byte response (the password attempt)
            response = conn.recv(16)
            if response:
                logger.warning("VNC AUTH | ip=%-16s response_hex=%s",
                               ip, response.hex()[:32])
                self.db.save_auth_attempt({
                    "session_id": sid, "ip": ip,
                    "username": "vnc",
                    "password": f"hex:{response.hex()[:16]}",
                    "timestamp": time.time(),
                })

            # Send auth failed
            conn.sendall(bytes([0x00, 0x00, 0x00, 0x01]))
            self.send(conn, "Authentication failed\n")

        except Exception as exc:
            logger.debug("VNC session [%s]: %s", ip, exc)

        duration = time.time() - t0
        features = {
            "command_count": 1, "recon_count": 1,
            "lateral_count": 1, "exploit_count": 0,
            "exfil_count": 0, "attacker_type": "bot",
            "mean_delay": 0.0, "stdev_delay": 0.0, "mean_inter": 0.0,
        }
        score = self.scorer.score(features)
        self.save_session(sid, ip, port, duration, 1,
                          score["score"], score["level"], "bot", "VNC Brute Force")
