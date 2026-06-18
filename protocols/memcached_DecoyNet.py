"""
Memcached DecoyNet — fake Memcached server on port 11211.
Captures amplification attack attempts and unauthorized data access.
"""

import socket
import time
import logging

from protocols.base_protocol import BaseProtocolDecoyNet

logger = logging.getLogger(__name__)


class MemcachedDecoyNet(BaseProtocolDecoyNet):
    PROTOCOL = "MEMCACHED"
    PORT     = 11211

    def handle(self, conn: socket.socket, ip: str, port: int, sid: str):
        t0       = time.time()
        commands = []

        try:
            conn.settimeout(30)
            while len(commands) < 20:
                data = conn.recv(4096)
                if not data:
                    break

                text = data.decode("utf-8", errors="replace").strip()
                if not text:
                    continue

                commands.append(text)
                cmd = text.split()[0].lower() if text.split() else ""
                logger.warning("MEMCACHED | ip=%-16s cmd=%s", ip, text[:80])

                if cmd == "stats":
                    # Return fake stats — amplification bait
                    self.send(conn,
                        "STAT pid 1337\r\n"
                        "STAT uptime 86400\r\n"
                        "STAT version 1.6.17\r\n"
                        "STAT bytes 1048576\r\n"
                        "STAT curr_items 142\r\n"
                        "STAT total_connections 9821\r\n"
                        "END\r\n"
                    )
                elif cmd == "get":
                    self.send(conn, "END\r\n")
                elif cmd == "set":
                    self.send(conn, "STORED\r\n")
                elif cmd == "flush_all":
                    logger.warning("MEMCACHED FLUSH | ip=%s", ip)
                    self.send(conn, "OK\r\n")
                elif cmd == "version":
                    self.send(conn, "VERSION 1.6.17\r\n")
                elif cmd in ("quit", "exit"):
                    break
                else:
                    self.send(conn, "ERROR\r\n")

        except Exception as exc:
            logger.debug("Memcached session [%s]: %s", ip, exc)

        duration = time.time() - t0
        features = {
            "command_count": len(commands), "recon_count": len(commands),
            "lateral_count": 0, "exploit_count": 0,
            "exfil_count": 0, "attacker_type": "bot",
            "mean_delay": 0.1, "stdev_delay": 0.0, "mean_inter": 0.1,
        }
        score = self.scorer.score(features)
        self.save_session(sid, ip, port, duration, len(commands),
                          score["score"], score["level"], "bot",
                          "Memcached Probe")
