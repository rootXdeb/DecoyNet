"""
SMB DecoyNet — fake Windows file share on port 445.

Captures:
- EternalBlue/WannaCry scanner attempts
- Ransomware lateral movement
- Credential brute force against file shares
- Network reconnaissance
"""

import socket
import time
import logging

from protocols.base_protocol import BaseProtocolDecoyNet

logger = logging.getLogger(__name__)


class SMBDecoyNet(BaseProtocolDecoyNet):
    PROTOCOL = "SMB"
    PORT     = 445

    def handle(self, conn: socket.socket, ip: str, port: int, sid: str):
        t0 = time.time()

        try:
            conn.settimeout(30)
            data = conn.recv(1024)
            if not data:
                return

            logger.warning("SMB PROBE | ip=%-16s bytes=%d", ip, len(data))

            # Detect EternalBlue attempt by packet signature
            if b"\xff\x53\x4d\x42" in data or b"\xfe\x53\x4d\x42" in data:
                logger.warning("SMB ETERNALBLUE ATTEMPT | ip=%s", ip)

            # Fake SMB negotiate response
            smb_response = (
                b"\x00\x00\x00\x55"   # NetBIOS session
                b"\xff\x53\x4d\x42"   # SMB1 header
                b"\x72\x00\x00\x00"   # Negotiate protocol
                b"\x00\x00\x00\x00\x00\x00\x00\x00"
                b"\x00\x00\x00\x00\x00\x00\x00\x00"
                b"\x00\x00\x00\x00\x00\x00\x00\x00"
            )
            conn.sendall(smb_response)

            # Read next packet
            data2 = conn.recv(4096)
            if data2:
                logger.warning("SMB STAGE2 | ip=%-16s bytes=%d", ip, len(data2))

        except Exception as exc:
            logger.debug("SMB session [%s]: %s", ip, exc)

        duration = time.time() - t0
        features = {
            "command_count": 1, "recon_count": 1,
            "lateral_count": 1, "exploit_count": 1,
            "exfil_count": 0, "attacker_type": "bot",
            "mean_delay": 0.0, "stdev_delay": 0.0, "mean_inter": 0.0,
        }
        score = self.scorer.score(features)
        self.save_session(sid, ip, port, duration, 1,
                          score["score"], score["level"], "bot", "SMB Scan")
