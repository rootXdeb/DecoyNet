"""
SIP DecoyNet — fake VoIP server on port 5060.
Captures toll fraud attempts and VoIP scanning.
"""

import socket
import time
import logging

from protocols.base_protocol import BaseProtocolDecoyNet

logger = logging.getLogger(__name__)


class SIPDecoyNet(BaseProtocolDecoyNet):
    PROTOCOL = "SIP"
    PORT     = 5060

    def handle(self, conn: socket.socket, ip: str, port: int, sid: str):
        t0       = time.time()
        requests = []

        try:
            conn.settimeout(30)
            while len(requests) < 10:
                data = conn.recv(4096)
                if not data:
                    break

                text = data.decode("utf-8", errors="replace")
                requests.append(text[:200])

                first_line = text.split("\r\n")[0] if "\r\n" in text else text[:80]
                logger.warning("SIP | ip=%-16s msg=%s", ip, first_line)

                # Extract SIP method
                method = first_line.split(" ")[0] if first_line else ""

                if method == "REGISTER":
                    logger.warning("SIP REGISTER | ip=%s", ip)
                    # Send 401 Unauthorized to capture credentials
                    response = (
                        "SIP/2.0 401 Unauthorized\r\n"
                        "Via: SIP/2.0/UDP 10.0.0.1:5060\r\n"
                        "WWW-Authenticate: Digest realm=\"corp.internal\","
                        " nonce=\"fake_nonce_12345\"\r\n"
                        "Content-Length: 0\r\n\r\n"
                    )
                    self.send(conn, response)

                elif method == "INVITE":
                    logger.warning("SIP INVITE TOLL FRAUD | ip=%s", ip)
                    response = (
                        "SIP/2.0 403 Forbidden\r\n"
                        "Via: SIP/2.0/UDP 10.0.0.1:5060\r\n"
                        "Content-Length: 0\r\n\r\n"
                    )
                    self.send(conn, response)

                elif method == "OPTIONS":
                    response = (
                        "SIP/2.0 200 OK\r\n"
                        "Allow: INVITE, ACK, CANCEL, OPTIONS, BYE, REGISTER\r\n"
                        "Content-Length: 0\r\n\r\n"
                    )
                    self.send(conn, response)

                else:
                    self.send(conn, "SIP/2.0 400 Bad Request\r\nContent-Length: 0\r\n\r\n")

        except Exception as exc:
            logger.debug("SIP session [%s]: %s", ip, exc)

        duration = time.time() - t0
        features = {
            "command_count": len(requests), "recon_count": 1,
            "lateral_count": 0, "exploit_count": 1 if len(requests) > 1 else 0,
            "exfil_count": 0, "attacker_type": "bot",
            "mean_delay": 0.2, "stdev_delay": 0.05, "mean_inter": 0.2,
        }
        score = self.scorer.score(features)
        self.save_session(sid, ip, port, duration, len(requests),
                          score["score"], score["level"], "bot",
                          "SIP Toll Fraud Attempt")
