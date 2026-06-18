"""
HTTP DecoyNet — fake web server on port 80.

Captures:
- SQL injection attempts
- Path traversal attacks
- Admin panel brute force
- Web shell upload attempts
- Scanner fingerprinting (Nikto, sqlmap, dirb)
- LFI/RFI attacks
- WordPress/phpMyAdmin probing
"""

import socket
import time
import re
import logging
import uuid
from urllib.parse import urlparse, unquote

from protocols.base_protocol import BaseProtocolDecoyNet
from database.db_manager import DatabaseManager

logger = logging.getLogger(__name__)

# Attack pattern detection
_SQLI_PATTERNS   = [r"union\s+select", r"or\s+1=1", r"drop\s+table", r"insert\s+into", r"'--", r"xp_cmdshell"]
_TRAVERSAL       = [r"\.\./", r"etc/passwd", r"etc/shadow", r"win/system32"]
_SCANNERS        = ["nikto", "sqlmap", "nmap", "masscan", "zgrab", "python-requests", "curl", "wget"]
_ADMIN_PATHS     = ["/wp-admin", "/phpmyadmin", "/admin", "/.env", "/config.php", "/shell.php", "/.git"]
_SHELL_PATTERNS  = ["cmd=", "exec=", "system(", "passthru(", "shell_exec(", "eval("]

# Fake pages
_INDEX_PAGE = """HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nServer: Apache/2.4.51 (Ubuntu)\r\nX-Powered-By: PHP/7.4.3\r\n\r\n
<!DOCTYPE html><html><head><title>Company Portal</title></head>
<body><h1>Welcome to Corp Internal Portal</h1>
<p>Please <a href='/login'>login</a> to continue.</p>
</body></html>"""

_LOGIN_PAGE = """HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nServer: Apache/2.4.51 (Ubuntu)\r\n\r\n
<!DOCTYPE html><html><head><title>Login</title></head>
<body><form method='POST' action='/login'>
<input name='username' placeholder='Username'/>
<input name='password' type='password' placeholder='Password'/>
<button type='submit'>Login</button>
</form></body></html>"""

_404_PAGE = "HTTP/1.1 404 Not Found\r\nContent-Type: text/html\r\nServer: Apache/2.4.51 (Ubuntu)\r\n\r\n<h1>404 Not Found</h1>"
_403_PAGE = "HTTP/1.1 403 Forbidden\r\nContent-Type: text/html\r\nServer: Apache/2.4.51 (Ubuntu)\r\n\r\n<h1>403 Forbidden</h1>"


class HTTPDecoyNet(BaseProtocolDecoyNet):
    PROTOCOL = "HTTP"
    PORT     = 80

    def handle(self, conn: socket.socket, ip: str, port: int, sid: str):
        t0 = time.time()
        conn.settimeout(30)
        try:
            raw = b""
            while b"\r\n\r\n" not in raw:
                chunk = conn.recv(4096)
                if not chunk:
                    break
                raw += chunk
                if len(raw) > 65536:
                    break
        except Exception:
            return

        request = raw.decode("utf-8", errors="replace")
        if not request.strip():
            return

        lines      = request.split("\r\n")
        first_line = lines[0] if lines else ""
        parts      = first_line.split(" ")
        method     = parts[0] if len(parts) > 0 else "GET"
        path       = unquote(parts[1]) if len(parts) > 1 else "/"
        user_agent = next((l.split(": ", 1)[1] for l in lines if l.lower().startswith("user-agent:")), "")

        # Extract POST body
        body = request.split("\r\n\r\n", 1)[1] if "\r\n\r\n" in request else ""

        # Detect attack type
        attack_type, severity, score = self._classify_request(method, path, body, user_agent)

        # Log to database
        self.db.save_http_request({
            "session_id":  sid,
            "ip":          ip,
            "method":      method,
            "path":        path,
            "user_agent":  user_agent,
            "body":        body[:500],
            "attack_type": attack_type,
            "threat_score": score,
            "timestamp":   time.time(),
        })

        logger.warning(
            "HTTP %s %s | ip=%-16s ua=%s attack=%s score=%d",
            method, path[:60], ip, user_agent[:40], attack_type, score
        )

        # Save to sessions table so dashboard shows it
        level = "CRITICAL" if score >= 85 else "HIGH" if score >= 60 else "MEDIUM" if score >= 30 else "LOW"
        self.save_session(
            sid, ip, port, time.time() - t0, 1,
            score, level, "bot", attack_type
        )

        # Send response
        response = self._build_response(path, method, body)
        try:
            conn.sendall(response.encode("utf-8", errors="replace"))
        except Exception:
            pass

    def _classify_request(self, method, path, body, ua):
        combined = (path + body + ua).lower()

        # SQL injection
        for p in _SQLI_PATTERNS:
            if re.search(p, combined, re.IGNORECASE):
                return "SQL_INJECTION", "HIGH", 75

        # Path traversal
        for p in _TRAVERSAL:
            if re.search(p, combined, re.IGNORECASE):
                return "PATH_TRAVERSAL", "HIGH", 70

        # Web shell
        for p in _SHELL_PATTERNS:
            if p in combined:
                return "WEBSHELL_ATTEMPT", "CRITICAL", 95

        # Scanner
        for s in _SCANNERS:
            if s in ua.lower():
                return "SCANNER", "MEDIUM", 40

        # Admin probing
        for a in _ADMIN_PATHS:
            if a in path:
                return "ADMIN_PROBE", "MEDIUM", 45

        return "NORMAL_REQUEST", "LOW", 10

    def _build_response(self, path, method, body):
        if path in ("/", "/index.html", "/index.php"):
            return _INDEX_PAGE
        if path in ("/login", "/login.php"):
            if method == "POST":
                return "HTTP/1.1 302 Found\r\nLocation: /dashboard\r\nServer: Apache/2.4.51\r\n\r\n"
            return _LOGIN_PAGE
        if any(a in path for a in _ADMIN_PATHS):
            return _403_PAGE
        if path in ("/etc/passwd", "/etc/shadow"):
            return _403_PAGE
        return _404_PAGE
