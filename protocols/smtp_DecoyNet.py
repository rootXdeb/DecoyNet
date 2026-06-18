"""
SMTP DecoyNet — fake email server on port 25.

Captures:
- Spam relay attempts
- Phishing infrastructure testing
- Open relay abuse
- Email harvesting
"""

import socket
import time
import logging

from protocols.base_protocol import BaseProtocolDecoyNet

logger = logging.getLogger(__name__)


class SMTPDecoyNet(BaseProtocolDecoyNet):
    PROTOCOL = "SMTP"
    PORT     = 25

    def handle(self, conn: socket.socket, ip: str, port: int, sid: str):
        t0       = time.time()
        commands = []
        sender   = ""
        rcpt     = ""

        self.send(conn, "220 mail.corp.internal ESMTP Postfix (Ubuntu)\r\n")

        while True:
            try:
                line = self.recv_line(conn, timeout=60)
                if not line:
                    break

                commands.append(line)
                cmd = line.split(" ")[0].upper()
                logger.info("SMTP | ip=%-16s cmd=%s", ip, line[:80])

                if cmd == "EHLO" or cmd == "HELO":
                    self.send(conn,
                        "250-mail.corp.internal\r\n"
                        "250-PIPELINING\r\n"
                        "250-SIZE 10240000\r\n"
                        "250-AUTH LOGIN PLAIN\r\n"
                        "250 STARTTLS\r\n"
                    )

                elif cmd == "AUTH":
                    logger.warning("SMTP AUTH | ip=%s method=%s", ip, line)
                    self.send(conn, "235 Authentication successful\r\n")

                elif cmd == "MAIL":
                    sender = line
                    logger.warning("SMTP SENDER | ip=%s from=%s", ip, line)
                    self.send(conn, "250 Ok\r\n")

                elif cmd == "RCPT":
                    rcpt = line
                    logger.warning("SMTP RCPT | ip=%s to=%s", ip, line)
                    self.send(conn, "250 Ok\r\n")

                elif cmd == "DATA":
                    self.send(conn, "354 End data with <CR><LF>.<CR><LF>\r\n")
                    body = ""
                    while True:
                        data_line = self.recv_line(conn, timeout=30)
                        if data_line == ".":
                            break
                        body += data_line + "\n"
                    logger.warning("SMTP DATA | ip=%s body_len=%d", ip, len(body))
                    self.send(conn, "250 Ok: queued as FAKE123\r\n")

                elif cmd == "QUIT":
                    self.send(conn, "221 Bye\r\n")
                    break

                else:
                    self.send(conn, "502 Command not implemented\r\n")

            except Exception:
                break

        duration = time.time() - t0
        relay    = any("MAIL" in c or "RCPT" in c for c in commands)
        features = {
            "command_count": len(commands), "recon_count": 0,
            "lateral_count": 0, "exploit_count": 1 if relay else 0,
            "exfil_count": 0, "attacker_type": "bot",
            "mean_delay": 0.5, "stdev_delay": 0.1, "mean_inter": 0.5,
        }
        score = self.scorer.score(features)
        self.save_session(sid, ip, port, duration, len(commands),
                          score["score"], score["level"], "bot",
                          "SMTP Relay Attempt" if relay else "SMTP Probe")
