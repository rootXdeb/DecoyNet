"""
RDP DecoyNet — fake Remote Desktop Protocol server on port 3389.

Captures:
- Credential brute force attempts
- BlueKeep/DejaBlue scanner fingerprinting
- Ransomware group reconnaissance
- Automated RDP scanning tools
"""

import socket
import time
import logging

from protocols.base_protocol import BaseProtocolDecoyNet

logger = logging.getLogger(__name__)


class RDPDecoyNet(BaseProtocolDecoyNet):
    PROTOCOL = "RDP"
    PORT     = 3389

    # Minimal RDP negotiation response — looks like a real Windows server
    _RDP_NEG_RESPONSE = bytes([
        0x03, 0x00, 0x00, 0x13,  # TPKT header
        0x0e, 0xd0, 0x00, 0x00,  # X.224 Connection Confirm
        0x00, 0x00, 0x00,
        0x02, 0x00, 0x08, 0x00,  # RDP Negotiation Response
        0x00, 0x00, 0x00, 0x00
    ])

    def handle(self, conn: socket.socket, ip: str, port: int, sid: str):
        t0 = time.time()

        try:
            conn.settimeout(30)
            # Read client connection request
            data = conn.recv(1024)
            if not data:
                return

            logger.warning("RDP PROBE | ip=%-16s bytes=%d", ip, len(data))

            # Send fake RDP negotiation response
            conn.sendall(self._RDP_NEG_RESPONSE)

            # Read next packet (client MCS Connect Initial)
            data2 = conn.recv(4096)
            if data2:
                logger.warning("RDP HANDSHAKE | ip=%-16s stage=2 bytes=%d", ip, len(data2))

            # Log auth attempt — RDP scanners always send credentials
            self.db.save_auth_attempt({
                "session_id": sid,
                "ip":         ip,
                "username":   "Administrator",
                "password":   "***RDP-SCAN***",
                "timestamp":  time.time(),
            })

        except Exception as exc:
            logger.debug("RDP session [%s]: %s", ip, exc)

        duration = time.time() - t0
        features = {
            "command_count": 1, "recon_count": 1,
            "lateral_count": 1, "exploit_count": 0,
            "exfil_count": 0, "attacker_type": "bot",
            "mean_delay": 0.0, "stdev_delay": 0.0, "mean_inter": 0.0,
        }
        score = self.scorer.score(features)
        self.save_session(sid, ip, port, duration, 1,
                          score["score"], score["level"], "bot", "RDP Scan")
