"""
Redis DecoyNet — fake Redis server on port 6379.

Captures:
- Unauthorized access attempts
- Cron job injection via Redis (common RCE technique)
- Config file write attempts
- Data exfiltration via Redis commands
"""

import socket
import time
import logging

from protocols.base_protocol import BaseProtocolDecoyNet

logger = logging.getLogger(__name__)


class RedisDecoyNet(BaseProtocolDecoyNet):
    PROTOCOL = "REDIS"
    PORT     = 6379

    def handle(self, conn: socket.socket, ip: str, port: int, sid: str):
        t0       = time.time()
        commands = []

        # Redis does not send a banner — just waits for commands
        while True:
            try:
                conn.settimeout(60)
                data = conn.recv(4096)
                if not data:
                    break

                text = data.decode("utf-8", errors="replace").strip()
                if not text:
                    continue

                # Parse Redis inline or RESP protocol
                lines = text.split("\r\n")
                cmd_parts = [l for l in lines if l and not l.startswith("*") and not l.startswith("$")]
                cmd = cmd_parts[0].upper() if cmd_parts else ""

                commands.append(text[:200])
                logger.warning("REDIS CMD | ip=%-16s cmd=%s", ip, text[:80])

                # Detect RCE via cron injection
                if "config" in text.lower() and "set" in text.lower():
                    logger.warning("REDIS RCE ATTEMPT | ip=%s payload=%s", ip, text[:200])
                    self._send_resp(conn, "-ERR unknown command\r\n")

                elif cmd in ("CONFIG",):
                    logger.warning("REDIS CONFIG ACCESS | ip=%s", ip)
                    self._send_resp(conn, "-NOAUTH Authentication required\r\n")

                elif cmd == "PING":
                    self._send_resp(conn, "+PONG\r\n")

                elif cmd in ("INFO",):
                    self._send_resp(conn, self._fake_info())

                elif cmd in ("KEYS",):
                    self._send_resp(conn, "*3\r\n$8\r\nsessions\r\n$5\r\nusers\r\n$6\r\ncache1\r\n")

                elif cmd in ("GET",):
                    self._send_resp(conn, "$-1\r\n")  # nil

                elif cmd in ("SET",):
                    self._send_resp(conn, "+OK\r\n")

                elif cmd in ("QUIT", "EXIT"):
                    self._send_resp(conn, "+OK\r\n")
                    break

                else:
                    self._send_resp(conn, "-ERR unknown command\r\n")

            except Exception:
                break

        duration  = time.time() - t0
        rce_count = sum(1 for c in commands if "config" in c.lower())
        features  = {
            "command_count": len(commands), "recon_count": 1,
            "lateral_count": 0, "exploit_count": rce_count,
            "exfil_count": 0, "attacker_type": "unknown",
            "mean_delay": 0.1, "stdev_delay": 0.0, "mean_inter": 0.1,
        }
        score = self.scorer.score(features)
        self.save_session(sid, ip, port, duration, len(commands),
                          score["score"], score["level"], "unknown",
                          "Redis RCE Attempt" if rce_count else "Redis Probe")

    def _send_resp(self, conn, data: str):
        try:
            conn.sendall(data.encode("utf-8", errors="replace"))
        except Exception:
            pass

    def _fake_info(self) -> str:
        return (
            "$500\r\n"
            "# Server\r\nredis_version:7.0.11\r\nos:Linux 5.15.0 x86_64\r\n"
            "# Clients\r\nconnected_clients:3\r\n"
            "# Memory\r\nused_memory_human:1.23M\r\n"
            "# Keyspace\r\ndb0:keys=142,expires=30\r\n\r\n"
        )
