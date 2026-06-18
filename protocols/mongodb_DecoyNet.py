"""
MongoDB DecoyNet — fake MongoDB server on port 27017.

Captures:
- Unauthorized access to exposed databases
- Data exfiltration attempts
- Reconnaissance queries
"""

import socket
import time
import struct
import logging

from protocols.base_protocol import BaseProtocolDecoyNet

logger = logging.getLogger(__name__)


class MongoDBDecoyNet(BaseProtocolDecoyNet):
    PROTOCOL = "MONGODB"
    PORT     = 27017

    def handle(self, conn: socket.socket, ip: str, port: int, sid: str):
        t0       = time.time()
        queries  = 0

        try:
            conn.settimeout(30)
            while True:
                # Read MongoDB wire protocol header (16 bytes)
                header = conn.recv(16)
                if not header or len(header) < 16:
                    break

                msg_len = struct.unpack("<I", header[:4])[0]
                body    = conn.recv(min(msg_len - 16, 65536))
                queries += 1

                logger.warning("MONGODB QUERY | ip=%-16s len=%d", ip, msg_len)

                # Send empty success response
                resp_body = (
                    b"\x01\x00\x00\x00"   # cursorID
                    b"\x00\x00\x00\x00"
                    b"\x00\x00\x00\x00"
                    b"\x00\x00\x00\x00"   # startingFrom
                    b"\x00\x00\x00\x00"   # numberReturned = 0
                )
                resp_len  = struct.pack("<I", 16 + len(resp_body))
                resp_id   = struct.pack("<I", 1)
                resp_to   = header[8:12]
                resp_op   = struct.pack("<I", 1)  # OP_REPLY
                conn.sendall(resp_len + resp_id + resp_to + resp_op + resp_body)

                if queries > 20:
                    break

        except Exception as exc:
            logger.debug("MongoDB session [%s]: %s", ip, exc)

        duration = time.time() - t0
        features = {
            "command_count": queries, "recon_count": queries,
            "lateral_count": 0, "exploit_count": 0,
            "exfil_count": 0, "attacker_type": "unknown",
            "mean_delay": 0.1, "stdev_delay": 0.0, "mean_inter": 0.1,
        }
        score = self.scorer.score(features)
        self.save_session(sid, ip, port, duration, queries,
                          score["score"], score["level"], "unknown", "MongoDB Probe")
