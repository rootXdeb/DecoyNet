"""
LDAP DecoyNet — fake Active Directory on port 389.
Captures credential harvesting and directory enumeration attacks.
"""

import socket
import time
import logging

from protocols.base_protocol import BaseProtocolDecoyNet

logger = logging.getLogger(__name__)


class LDAPDecoyNet(BaseProtocolDecoyNet):
    PROTOCOL = "LDAP"
    PORT     = 389

    # Minimal LDAP bind response (success)
    _BIND_SUCCESS = bytes([
        0x30, 0x0c,             # SEQUENCE
        0x02, 0x01, 0x01,       # messageID = 1
        0x61, 0x07,             # bindResponse
        0x0a, 0x01, 0x00,       # resultCode = success
        0x04, 0x00,             # matchedDN = ""
        0x04, 0x00,             # errorMessage = ""
    ])

    # LDAP bind error response
    _BIND_ERROR = bytes([
        0x30, 0x0c,
        0x02, 0x01, 0x01,
        0x61, 0x07,
        0x0a, 0x01, 0x31,       # resultCode = invalidCredentials (49)
        0x04, 0x00,
        0x04, 0x00,
    ])

    def handle(self, conn: socket.socket, ip: str, port: int, sid: str):
        t0       = time.time()
        attempts = 0

        try:
            conn.settimeout(30)
            while attempts < 10:
                data = conn.recv(4096)
                if not data:
                    break

                attempts += 1
                logger.warning("LDAP BIND | ip=%-16s bytes=%d attempt=%d",
                               ip, len(data), attempts)

                # Try to extract username from bind request
                username = self._extract_dn(data)
                password = self._extract_password(data)

                if username:
                    logger.warning("LDAP CREDS | ip=%s dn=%s pass=%s",
                                   ip, username, password[:20] if password else "")
                    self.db.save_auth_attempt({
                        "session_id": sid, "ip": ip,
                        "username":   username,
                        "password":   password or "",
                        "timestamp":  time.time(),
                    })

                # First attempt succeeds (lures attacker in), then fail
                if attempts == 1:
                    conn.sendall(self._BIND_SUCCESS)
                else:
                    conn.sendall(self._BIND_ERROR)

        except Exception as exc:
            logger.debug("LDAP session [%s]: %s", ip, exc)

        duration = time.time() - t0
        features = {
            "command_count": attempts, "recon_count": attempts,
            "lateral_count": 1, "exploit_count": 0,
            "exfil_count": 0, "attacker_type": "unknown",
            "mean_delay": 0.5, "stdev_delay": 0.1, "mean_inter": 0.5,
        }
        score = self.scorer.score(features)
        self.save_session(sid, ip, port, duration, attempts,
                          score["score"], score["level"], "unknown",
                          "LDAP Enumeration")

    def _extract_dn(self, data: bytes) -> str:
        try:
            text = data.decode("utf-8", errors="replace")
            for prefix in ["cn=", "CN=", "uid=", "UID="]:
                if prefix in text:
                    start = text.index(prefix)
                    end   = text.index(",", start) if "," in text[start:] else start + 40
                    return text[start:end].strip()
        except Exception:
            pass
        return ""

    def _extract_password(self, data: bytes) -> str:
        try:
            # Password is usually a simple string after the DN in bind request
            if len(data) > 20:
                return data[-20:].decode("utf-8", errors="replace").strip()
        except Exception:
            pass
        return ""
