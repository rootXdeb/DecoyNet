"""
AdaptiveShellSession — the core intelligence of the DecoyNet.

This is NOT a hardcoded fake shell.

How it works:
─────────────
1. Every command the attacker types is passed through the BehaviorProfiler
   which continuously updates a live feature vector for this session.

2. After every command the AdaptiveStrategyEngine consults:
     • The live ML cluster prediction (K-Means)
     • The anomaly score (Isolation Forest)
     • The cross-session correlation engine
     • The attacker's current TTP stage (recon / lateral / exploit / exfil)
   …and selects a RESPONSE STRATEGY from the strategy registry.

3. The selected strategy controls:
     • Response depth  (shallow/surface ↔ deep/revealing)
     • Response delay  (instant ↔ slow — slows down bots)
     • Filesystem view (minimal ↔ full with planted secrets)
     • Error realism   (generic ↔ service-specific errors)
     • Vuln exposure   (hide ↔ surface fake CVEs as bait)
     • Engagement traps (fake credential files, fake DB dumps)

4. After the session ends, the complete feature vector is saved and the
   ML models are triggered for incremental update so the NEXT session
   from a similar attacker gets an even better-tuned response.

Strategies (the closed feedback loop):
───────────────────────────────────────
STRATEGY_DEFLECT   → Bot/scanner detected. Return instant, minimal,
                     slightly wrong outputs to waste scanner time.
STRATEGY_OBSERVE   → Unknown attacker. Respond normally, watch carefully,
                     collect as much intel as possible.
STRATEGY_ENGAGE    → Human attacker confirmed. Deepen the deception:
                     surface credentials, fake DB files, fake AWS keys.
                     Slow responses slightly to seem like a real server.
STRATEGY_TRAP      → Advanced/persistent attacker. Surface targeted bait
                     matched to their apparent interest (DB? serve DB dump.
                     Web? serve config files with credentials).
"""

import time
import threading
import logging
import random
import re
import os
import uuid

try:
    import paramiko
except ImportError:
    paramiko = None

from analysis.behavior_analyzer import BehaviorAnalyzer
from analysis.attack_chain import AttackChain
from analysis.threat_scorer import ThreatScorer
from adaptive.strategy_engine import AdaptiveStrategyEngine, Strategy
from adaptive.behavior_profiler import BehaviorProfiler
from adaptive.response_library import ResponseLibrary
from adaptive.engagement_traps import EngagementTraps
from correlation.cross_session import CrossSessionCorrelator
from deception.fake_filesystem import FakeFilesystem
from malware.capture import MalwareCapture
from database.db_manager import DatabaseManager
from intelligence.ioc_manager import IOCManager

logger = logging.getLogger(__name__)


class AdaptiveShellSession:
    """
    A fully stateful, ML-driven interactive SSH shell session.
    Every response is chosen based on real-time attacker profiling.
    """

    def __init__(
        self,
        channel,
        ip: str,
        username: str,
        password: str,
        db: DatabaseManager,
        ioc: IOCManager,
    ):
        self.channel   = channel
        self.ip        = ip
        self.username  = username
        self.password  = password
        self.db        = db
        self.ioc       = ioc
        self.sid       = str(uuid.uuid4())
        self.start_time = time.time()

        # ── Core components ──────────────────────────────────────────────────
        self.profiler    = BehaviorProfiler()
        self.strategy_engine = AdaptiveStrategyEngine()
        self.response_lib    = ResponseLibrary()
        self.traps           = EngagementTraps()
        self.fs              = FakeFilesystem()
        self.correlator      = CrossSessionCorrelator(db)
        self.malware_cap     = MalwareCapture()
        self.scorer          = ThreatScorer()

        # ── Session state ────────────────────────────────────────────────────
        self.cwd             = "/root" if username == "root" else f"/home/{username}"
        self.env             = self._build_env()
        self.command_history: list[dict] = []
        self.current_strategy: Strategy  = Strategy.OBSERVE
        self.hostname        = random.choice(
            ["web-prod-01", "db-server-02", "api-gateway-03", "fileserver-04"]
        )
        self._input_buf      = ""
        self._running        = True

    # ── Public entry point ───────────────────────────────────────────────────

    def run(self):
        """Main session loop — reads commands, dispatches adaptive responses."""
        try:
            self._send_motd()
            self._command_loop()
        except Exception as exc:
            logger.debug("Session %s error: %s", self.sid, exc)
        finally:
            self._finalise()

    # ── MOTD ─────────────────────────────────────────────────────────────────

    def _send_motd(self):
        motd = (
            "\r\nWelcome to Ubuntu 20.04.6 LTS (GNU/Linux 5.15.0-76-generic x86_64)\r\n"
            "\r\n"
            " * Documentation:  https://help.ubuntu.com\r\n"
            " * Management:     https://landscape.canonical.com\r\n"
            " * Support:        https://ubuntu.com/advantage\r\n"
            "\r\n"
            f"  System information as of {time.strftime('%a %b %d %H:%M:%S UTC %Y')}\r\n"
            "\r\n"
            f"  System load:  0.{random.randint(10,60)}          "
            f"Users logged in:       {random.randint(1,3)}\r\n"
            f"  Usage of /:   {random.randint(28,62)}.{random.randint(1,9)}% of 98.28GB   "
            f"IPv4 address for eth0: 10.0.2.{random.randint(10,250)}\r\n"
            f"  Memory usage: {random.randint(24,71)}%              "
            f"IPv6 address for eth0: fe80::a00:27ff:fe{random.randint(10,99)}:ef{random.randint(10,99)}\r\n"
            f"  Swap usage:   0%\r\n"
            "\r\n"
            f"Last login: {self._fake_last_login()}\r\n\r\n"
        )
        self._send(motd)

    # ── Command loop ─────────────────────────────────────────────────────────

    def _command_loop(self):
        self._send(self._prompt())
        buf = b""

        while self._running:
            try:
                self.channel.settimeout(300)
                data = self.channel.recv(1024)
                if not data:
                    break

                # Handle backspace, carriage return, newline
                for byte in data:
                    ch = bytes([byte])
                    if ch in (b"\r", b"\n"):
                        line = buf.decode("utf-8", errors="replace").strip()
                        buf = b""
                        self._send("\r\n")
                        if line:
                            response = self._dispatch(line)
                            if response is not None:
                                self._send(response)
                        if not self._running:
                            break
                        self._send(self._prompt())
                    elif ch == b"\x7f" or ch == b"\x08":   # backspace
                        if buf:
                            buf = buf[:-1]
                            self._send(b"\x08 \x08")
                    elif ch == b"\x03":   # Ctrl-C
                        self._send("^C\r\n")
                        buf = b""
                        self._send(self._prompt())
                    elif ch == b"\x04":   # Ctrl-D
                        self._running = False
                        break
                    else:
                        buf += ch
                        self._send(ch)   # echo

            except Exception:
                break

    # ── Command dispatcher ───────────────────────────────────────────────────

    def _dispatch(self, raw_line: str) -> str:
        """
        Core adaptive dispatch:
        1. Profile the command → update live feature vector
        2. Re-evaluate strategy via ML + correlation
        3. Generate response according to current strategy
        4. Check for engagement traps to inject
        5. Apply strategy-specific delay
        6. Return final response
        """
        t0 = time.time()

        # ── 1. Profile ───────────────────────────────────────────────────────
        self.profiler.record(raw_line, t0)
        features = self.profiler.features()

        # ── 2. Adaptive strategy selection ──────────────────────────────────
        cross_intel = self.correlator.lookup(self.ip)
        new_strategy = self.strategy_engine.evaluate(
            features     = features,
            cross_intel  = cross_intel,
            command      = raw_line,
            session_id   = self.sid,
        )
        if new_strategy != self.current_strategy:
            logger.info(
                "STRATEGY CHANGE | ip=%-16s  %s → %s  (cmd: %s)",
                self.ip,
                self.current_strategy.name,
                new_strategy.name,
                raw_line[:40],
            )
            self.current_strategy = new_strategy

        # ── 3. Generate base response ────────────────────────────────────────
        parts = raw_line.strip().split()
        cmd   = parts[0] if parts else ""
        args  = parts[1:] if len(parts) > 1 else []

        response = self._execute(cmd, args, raw_line)

        # ── 4. Engagement traps ──────────────────────────────────────────────
        trap = self.traps.maybe_inject(
            strategy = self.current_strategy,
            features = features,
            cmd      = cmd,
            cwd      = self.cwd,
        )
        if trap:
            response = response + "\r\n" + trap if response else trap

        # ── 5. Strategy delay (slows bots, makes humans stay longer) ─────────
        delay = self.strategy_engine.response_delay(self.current_strategy, features)
        if delay > 0:
            time.sleep(delay)

        # ── 6. Record command ────────────────────────────────────────────────
        elapsed = time.time() - t0
        self.command_history.append({
            "cmd":      raw_line,
            "output":   response,
            "time":     t0,
            "duration": elapsed,
            "strategy": self.current_strategy.name,
        })

        return response.replace("\n", "\r\n") if response else ""

    # ── Command implementations ──────────────────────────────────────────────

    def _execute(self, cmd: str, args: list[str], raw: str) -> str:
        """
        Routes command to handler. Response content and depth varies
        based on current strategy — same command, different strategies,
        different responses.
        """
        handlers = {
            "ls":       self._cmd_ls,
            "dir":      self._cmd_ls,
            "cd":       self._cmd_cd,
            "pwd":      self._cmd_pwd,
            "cat":      self._cmd_cat,
            "whoami":   self._cmd_whoami,
            "id":       self._cmd_id,
            "uname":    self._cmd_uname,
            "hostname": self._cmd_hostname,
            "ifconfig": self._cmd_ifconfig,
            "ip":       self._cmd_ip,
            "netstat":  self._cmd_netstat,
            "ss":       self._cmd_netstat,
            "ps":       self._cmd_ps,
            "env":      self._cmd_env,
            "echo":     self._cmd_echo,
            "history":  self._cmd_history,
            "wget":     self._cmd_wget,
            "curl":     self._cmd_curl,
            "python":   self._cmd_python,
            "python3":  self._cmd_python,
            "perl":     self._cmd_perl,
            "bash":     self._cmd_bash,
            "sh":       self._cmd_bash,
            "sudo":     self._cmd_sudo,
            "su":       self._cmd_su,
            "chmod":    self._cmd_chmod,
            "chown":    self._cmd_chown,
            "useradd":  self._cmd_useradd,
            "adduser":  self._cmd_useradd,
            "crontab":  self._cmd_crontab,
            "find":     self._cmd_find,
            "grep":     self._cmd_grep,
            "awk":      self._cmd_awk,
            "sed":      self._cmd_sed,
            "tar":      self._cmd_tar,
            "unzip":    self._cmd_unzip,
            "ssh":      self._cmd_ssh,
            "scp":      self._cmd_scp,
            "nc":       self._cmd_nc,
            "ncat":     self._cmd_nc,
            "nmap":     self._cmd_nmap,
            "passwd":   self._cmd_passwd,
            "apt":      self._cmd_apt,
            "apt-get":  self._cmd_apt,
            "yum":      self._cmd_apt,
            "systemctl":self._cmd_systemctl,
            "service":  self._cmd_service,
            "mysql":    self._cmd_mysql,
            "exit":     self._cmd_exit,
            "logout":   self._cmd_exit,
            "quit":     self._cmd_exit,
            "clear":    lambda a, r: "\033[2J\033[H",
            "reset":    lambda a, r: "\033[2J\033[H",
            "help":     self._cmd_help,
        }

        handler = handlers.get(cmd)
        if handler:
            return handler(args, raw)

        # Unknown command — strategy affects the error realism
        return self._unknown_cmd(cmd, args)

    # ── Individual command handlers ───────────────────────────────────────────
    # Each one checks self.current_strategy to vary response depth/content.

    def _cmd_ls(self, args, raw) -> str:
        flags   = [a for a in args if a.startswith("-")]
        path    = next((a for a in args if not a.startswith("-")), self.cwd)
        entries = self.fs.listdir_detailed(path, self.current_strategy)
        if "-l" in " ".join(flags) or "-la" in " ".join(flags) or "-al" in " ".join(flags):
            return entries["long"]
        return entries["short"]

    def _cmd_cd(self, args, raw) -> str:
        target = args[0] if args else "~"
        if target in ("~", ""):
            self.cwd = "/root" if self.username == "root" else f"/home/{self.username}"
        elif target == "..":
            self.cwd = os.path.dirname(self.cwd) or "/"
        elif target.startswith("/"):
            self.cwd = target.rstrip("/") or "/"
        else:
            self.cwd = (self.cwd.rstrip("/") + "/" + target).rstrip("/")
        return ""

    def _cmd_pwd(self, args, raw) -> str:
        return self.cwd

    def _cmd_cat(self, args, raw) -> str:
        if not args:
            return ""
        path = args[0] if args[0].startswith("/") else self.cwd + "/" + args[0]
        return self.fs.read_file(path, self.current_strategy)

    def _cmd_whoami(self, args, raw) -> str:
        return self.username

    def _cmd_id(self, args, raw) -> str:
        if self.username == "root":
            return "uid=0(root) gid=0(root) groups=0(root)"
        uid = random.randint(1000, 1005)
        return f"uid={uid}({self.username}) gid={uid}({self.username}) groups={uid}({self.username}),27(sudo)"

    def _cmd_uname(self, args, raw) -> str:
        if "-a" in args:
            return f"Linux {self.hostname} 5.15.0-76-generic #83-Ubuntu SMP Thu Jun 15 19:16:32 UTC 2023 x86_64 x86_64 x86_64 GNU/Linux"
        if "-r" in args:
            return "5.15.0-76-generic"
        return "Linux"

    def _cmd_hostname(self, args, raw) -> str:
        return self.hostname

    def _cmd_ifconfig(self, args, raw) -> str:
        ip_last = random.randint(10, 250)
        return (
            f"eth0: flags=4163<UP,BROADCAST,RUNNING,MULTICAST>  mtu 1500\r\n"
            f"        inet 10.0.2.{ip_last}  netmask 255.255.255.0  broadcast 10.0.2.255\r\n"
            f"        inet6 fe80::a00:27ff:fe8a:{ip_last:02x}ef  prefixlen 64  scopeid 0x20<link>\r\n"
            f"        ether 08:00:27:8a:ef:{ip_last:02x}  txqueuelen 1000  (Ethernet)\r\n"
            f"        RX packets 18432  bytes 14219040 (14.2 MB)\r\n"
            f"        TX packets 9821   bytes 1203440 (1.2 MB)\r\n"
            f"\r\nlo: flags=73<UP,LOOPBACK,RUNNING>  mtu 65536\r\n"
            f"        inet 127.0.0.1  netmask 255.0.0.0\r\n"
        )

    def _cmd_ip(self, args, raw) -> str:
        if args and args[0] in ("a", "addr", "address"):
            return self._cmd_ifconfig([], raw)
        if args and args[0] in ("r", "route"):
            return (
                "default via 10.0.2.1 dev eth0 proto dhcp src 10.0.2.15 metric 100\r\n"
                "10.0.2.0/24 dev eth0 proto kernel scope link src 10.0.2.15\r\n"
            )
        return ""

    def _cmd_netstat(self, args, raw) -> str:
        # Strategy-aware: ENGAGE/TRAP shows more open ports as bait
        base = (
            "Active Internet connections (only servers)\r\n"
            "Proto Recv-Q Send-Q Local Address           Foreign Address         State\r\n"
            "tcp        0      0 0.0.0.0:22              0.0.0.0:*               LISTEN\r\n"
            "tcp        0      0 0.0.0.0:80              0.0.0.0:*               LISTEN\r\n"
            "tcp        0      0 127.0.0.1:3306          0.0.0.0:*               LISTEN\r\n"
        )
        if self.current_strategy in (Strategy.ENGAGE, Strategy.TRAP):
            base += (
                "tcp        0      0 0.0.0.0:6379          0.0.0.0:*               LISTEN\r\n"
                "tcp        0      0 0.0.0.0:27017         0.0.0.0:*               LISTEN\r\n"
                "tcp        0      0 0.0.0.0:5432          0.0.0.0:*               LISTEN\r\n"
            )
        return base

    def _cmd_ps(self, args, raw) -> str:
        procs = (
            "  PID TTY          TIME CMD\r\n"
            "    1 ?        00:00:02 systemd\r\n"
            "  412 ?        00:00:01 sshd\r\n"
            "  891 ?        00:00:00 cron\r\n"
            " 1024 ?        00:00:03 apache2\r\n"
            " 1337 pts/0    00:00:00 bash\r\n"
            " 1440 pts/0    00:00:00 ps\r\n"
        )
        if self.current_strategy in (Strategy.ENGAGE, Strategy.TRAP):
            # Surface interesting processes as bait
            procs += (
                " 2001 ?        00:01:12 mysqld\r\n"
                " 2108 ?        00:00:44 redis-server\r\n"
                " 2240 ?        00:00:07 backup.sh\r\n"
            )
        return procs

    def _cmd_env(self, args, raw) -> str:
        base_env = "\r\n".join(f"{k}={v}" for k, v in self.env.items())
        if self.current_strategy in (Strategy.ENGAGE, Strategy.TRAP):
            # Leak fake secrets in environment — targeted bait
            base_env += (
                "\r\nAWS_ACCESS_KEY_ID=AKIAFAKE00000000PROD1"
                "\r\nAWS_SECRET_ACCESS_KEY=FakeSecretKey/PROD/2024/xxxxxxxxxxxx"
                "\r\nDB_PASSWORD=Pr0d@DB_P4ssw0rd!"
                "\r\nSECRET_KEY=django-insecure-FAKE-SECRET-KEY-DO-NOT-USE"
            )
        return base_env

    def _cmd_echo(self, args, raw) -> str:
        text = " ".join(args)
        # Handle $VAR substitution
        for key, val in self.env.items():
            text = text.replace(f"${key}", val)
        return text

    def _cmd_history(self, args, raw) -> str:
        # Strategy-aware history — ENGAGE/TRAP leaks interesting past commands
        base = [
            "ls -la", "cat /etc/passwd", "uname -a", "whoami", "id",
            "ifconfig", "ps aux", "netstat -an",
        ]
        if self.current_strategy in (Strategy.ENGAGE, Strategy.TRAP):
            base += [
                "mysql -u root -pPr0d@DB_P4ssw0rd! corp_db",
                "cat /root/.aws/credentials",
                "scp backup.tar.gz deploy@192.168.10.5:/backups/",
                "crontab -l",
                "cat /var/www/html/.env",
            ]
        return "\r\n".join(f"  {i+1}  {c}" for i, c in enumerate(base))

    def _cmd_wget(self, args, raw) -> str:
        url = next((a for a in args if not a.startswith("-")), "")
        if not url:
            return "wget: missing URL"

        # Log the download attempt as IOC
        self.ioc.record_url(url, "DecoyNet-wget")
        logger.warning("DOWNLOAD ATTEMPT | ip=%s url=%s", self.ip, url)

        # Strategy: DEFLECT → simulate connection refused; others → simulate success
        if self.current_strategy == Strategy.DEFLECT:
            return f"--{time.strftime('%Y-%m-%d %H:%M:%S')}--  {url}\r\nConnecting to {url.split('/')[2]}... failed: Connection refused."

        return (
            f"--{time.strftime('%Y-%m-%d %H:%M:%S')}--  {url}\r\n"
            f"Connecting to {url.split('/')[2] if '//' in url else url}... connected.\r\n"
            f"HTTP request sent, awaiting response... 200 OK\r\n"
            f"Length: {random.randint(10000, 500000)} ({random.randint(10, 500)}K) [application/octet-stream]\r\n"
            f"Saving to: '{url.split('/')[-1] or 'index.html'}'\r\n\r\n"
            f"100%[======================================>] {random.randint(10,500)}K  "
            f"{random.randint(100,900)}KB/s   in 0.{random.randint(1,9)}s\r\n\r\n"
            f"{time.strftime('%Y-%m-%d %H:%M:%S')} ({random.randint(100,900)} KB/s) - "
            f"'{url.split('/')[-1] or 'index.html'}' saved [{random.randint(10000,500000)}/{random.randint(10000,500000)}]\r\n"
        )

    def _cmd_curl(self, args, raw) -> str:
        url = next((a for a in args if not a.startswith("-")), "")
        if not url:
            return "curl: try 'curl --help'"
        self.ioc.record_url(url, "DecoyNet-curl")
        if self.current_strategy == Strategy.DEFLECT:
            return f"curl: (7) Failed to connect to {url}: Connection refused"
        return '{"status":"ok","server":"nginx/1.18.0","timestamp":' + str(int(time.time())) + '}'

    def _cmd_python(self, args, raw) -> str:
        if not args:
            return (
                "Python 3.10.12 (main, Nov 20 2023, 15:14:05) [GCC 11.4.0] on linux\r\n"
                "Type \"help\", \"copyright\", \"credits\" or \"license\" for more information.\r\n"
                ">>> "
            )
        if "-c" in args:
            idx = args.index("-c")
            code = args[idx + 1] if idx + 1 < len(args) else ""
            logger.warning("PYTHON EXEC | ip=%s code=%s", self.ip, code[:100])
            # Fake execution — never actually run anything
            if "import" in code or "socket" in code:
                return ""
            return ""
        return ""

    def _cmd_perl(self, args, raw) -> str:
        logger.warning("PERL EXEC | ip=%s args=%s", self.ip, args)
        return ""

    def _cmd_bash(self, args, raw) -> str:
        if "-c" in args:
            idx = args.index("-c")
            cmd = args[idx + 1] if idx + 1 < len(args) else ""
            logger.warning("BASH -c | ip=%s cmd=%s", self.ip, cmd[:100])
            # Recurse into dispatch for the inline command
            parts = cmd.split()
            if parts:
                return self._execute(parts[0], parts[1:], cmd)
        return ""

    def _cmd_sudo(self, args, raw) -> str:
        if not args:
            return f"usage: sudo [-AbEefGHknPSsVv] ..."
        # Pass through to the command handler
        return self._execute(args[0], args[1:], " ".join(args))

    def _cmd_su(self, args, raw) -> str:
        user = args[0] if args else "root"
        return f"Password: "   # attacker will type a password — we'll capture it next input

    def _cmd_chmod(self, args, raw) -> str:
        logger.info("CHMOD | ip=%s args=%s", self.ip, args)
        return ""   # Silent success

    def _cmd_chown(self, args, raw) -> str:
        return ""

    def _cmd_useradd(self, args, raw) -> str:
        user = args[-1] if args else "newuser"
        logger.warning("USERADD | ip=%s user=%s — PERSISTENCE ATTEMPT", self.ip, user)
        return ""

    def _cmd_crontab(self, args, raw) -> str:
        if "-l" in args:
            if self.current_strategy in (Strategy.ENGAGE, Strategy.TRAP):
                return (
                    "# m h  dom mon dow   command\r\n"
                    "*/5 * * * * /opt/scripts/backup.sh >> /var/log/backup.log 2>&1\r\n"
                    "0 2 * * * /root/sync_db.sh\r\n"
                    "30 3 * * 0 tar -czf /backups/weekly.tar.gz /var/www/html\r\n"
                )
            return "no crontab for " + self.username
        logger.warning("CRONTAB EDIT | ip=%s args=%s — PERSISTENCE ATTEMPT", self.ip, args)
        return ""

    def _cmd_find(self, args, raw) -> str:
        path = args[0] if args else "."
        name_flag = ""
        if "-name" in args:
            idx = args.index("-name")
            name_flag = args[idx + 1] if idx + 1 < len(args) else ""

        # Strategy: ENGAGE/TRAP surface more interesting files
        results = [
            f"{path}/config.py",
            f"{path}/settings.py",
            f"{path}/.env",
        ]
        if self.current_strategy in (Strategy.ENGAGE, Strategy.TRAP):
            results += [
                f"{path}/.aws/credentials",
                f"{path}/backup.sql",
                f"{path}/id_rsa",
                f"{path}/deploy_key",
                f"{path}/.ssh/authorized_keys",
            ]
        if name_flag:
            results = [r for r in results if name_flag.replace("*","") in r]
        return "\r\n".join(results[:15])

    def _cmd_grep(self, args, raw) -> str:
        if len(args) < 2:
            return ""
        pattern, filepath = args[0], args[-1]
        content = self.fs.read_file(
            filepath if filepath.startswith("/") else self.cwd + "/" + filepath,
            self.current_strategy
        )
        matches = [l for l in content.split("\n") if re.search(pattern, l, re.IGNORECASE)]
        return "\r\n".join(matches)

    def _cmd_awk(self, args, raw) -> str:
        return ""   # Fake silent execution

    def _cmd_sed(self, args, raw) -> str:
        return ""

    def _cmd_tar(self, args, raw) -> str:
        if any(a in ("c", "-c", "-czf", "-czvf", "czf") for a in args):
            logger.warning("TAR CREATE | ip=%s args=%s — possible exfil staging", self.ip, args)
        return ""

    def _cmd_unzip(self, args, raw) -> str:
        fname = args[0] if args else ""
        return f"Archive:  {fname}\r\n  inflating: README\r\n  inflating: payload\r\n"

    def _cmd_ssh(self, args, raw) -> str:
        dest = args[-1] if args else ""
        logger.warning("SSH LATERAL | ip=%s dest=%s", self.ip, dest)
        return f"ssh: connect to host {dest} port 22: Connection timed out"

    def _cmd_scp(self, args, raw) -> str:
        logger.warning("SCP TRANSFER | ip=%s args=%s", self.ip, args)
        return "scp: Connection closed"

    def _cmd_nc(self, args, raw) -> str:
        dest = " ".join(a for a in args if not a.startswith("-"))
        logger.warning("NETCAT | ip=%s args=%s", self.ip, args)
        if self.current_strategy == Strategy.DEFLECT:
            return "(UNKNOWN) [(UNKNOWN) port 0 (?)]"
        # Simulate connection that hangs (wastes attacker time)
        time.sleep(random.uniform(3, 8))
        return ""

    def _cmd_nmap(self, args, raw) -> str:
        logger.warning("NMAP SCAN | ip=%s args=%s", self.ip, args)
        return (
            f"Starting Nmap 7.80 ( https://nmap.org ) at {time.strftime('%Y-%m-%d %H:%M')} UTC\r\n"
            "Nmap scan report for localhost (127.0.0.1)\r\n"
            "Host is up (0.000087s latency).\r\n"
            "Not shown: 997 closed ports\r\n"
            "PORT     STATE SERVICE\r\n"
            "22/tcp   open  ssh\r\n"
            "80/tcp   open  http\r\n"
            "3306/tcp open  mysql\r\n"
        )

    def _cmd_passwd(self, args, raw) -> str:
        return "passwd: Authentication token manipulation error"

    def _cmd_apt(self, args, raw) -> str:
        pkg = args[-1] if args else ""
        if args and args[0] in ("install", "-y"):
            return (
                f"Reading package lists... Done\r\n"
                f"Building dependency tree... Done\r\n"
                f"The following NEW packages will be installed: {pkg}\r\n"
                f"0 upgraded, 1 newly installed, 0 to remove and 12 not upgraded.\r\n"
                f"Need to get 1,234 kB of archives.\r\n"
                f"Selecting previously unselected package {pkg}.\r\n"
                f"Setting up {pkg} ... done\r\n"
            )
        return ""

    def _cmd_systemctl(self, args, raw) -> str:
        action  = args[0] if args else "status"
        service = args[1] if len(args) > 1 else ""
        if action == "status":
            return (
                f"● {service}.service - {service.capitalize()} Service\r\n"
                f"     Loaded: loaded (/lib/systemd/system/{service}.service; enabled)\r\n"
                f"     Active: active (running) since {time.strftime('%a %Y-%m-%d %H:%M:%S UTC')}; 2h ago\r\n"
                f"   Main PID: {random.randint(800,2000)} ({service})\r\n"
            )
        return ""

    def _cmd_service(self, args, raw) -> str:
        service = args[0] if args else ""
        action  = args[1] if len(args) > 1 else "status"
        return f" * {service} is running" if action == "status" else ""

    def _cmd_mysql(self, args, raw) -> str:
        logger.warning("MYSQL ACCESS | ip=%s args=%s", self.ip, args)
        if self.current_strategy in (Strategy.ENGAGE, Strategy.TRAP):
            return (
                "Welcome to the MySQL monitor.  Commands end with ; or \\g.\r\n"
                "Your MySQL connection id is 42\r\n"
                "Server version: 8.0.33-0ubuntu0.20.04.2 (Ubuntu)\r\n\r\n"
                "mysql> "
            )
        return "ERROR 1045 (28000): Access denied for user 'root'@'localhost' (using password: YES)"

    def _cmd_exit(self, args, raw) -> str:
        self._running = False
        return "logout\r\n"

    def _cmd_help(self, args, raw) -> str:
        return (
            "GNU bash, version 5.1.16(1)-release (x86_64-pc-linux-gnu)\r\n"
            "These shell commands are defined internally. Type 'help' to see this list.\r\n\r\n"
            "cd, ls, cat, echo, env, find, grep, history, hostname, id,\r\n"
            "ifconfig, ip, netstat, nmap, passwd, ps, pwd, ssh, sudo,\r\n"
            "uname, useradd, wget, curl, chmod, crontab, mysql, systemctl\r\n"
        )

    def _unknown_cmd(self, cmd: str, args: list) -> str:
        if self.current_strategy == Strategy.DEFLECT:
            return f"-bash: {cmd}: command not found"
        # For OBSERVE/ENGAGE/TRAP, sometimes suggest similar commands (more realistic)
        similar = {"lss": "ls", "pss": "ps", "catt": "cat", "grpe": "grep"}
        if cmd in similar:
            return f"-bash: {cmd}: command not found\r\nDid you mean '{similar[cmd]}'?"
        return f"-bash: {cmd}: command not found"

    # ── Session finalisation ─────────────────────────────────────────────────

    def _finalise(self):
        duration = time.time() - self.start_time
        commands = [c["cmd"] for c in self.command_history]

        # Full feature extraction
        analyzer = BehaviorAnalyzer(self.command_history)
        features = analyzer.extract_features()

        # Threat score
        scorer = ThreatScorer()
        score  = scorer.score(features)

        # Attack chain
        chain = AttackChain(commands).as_string()

        # Cross-session update — future sessions from this IP benefit
        self.correlator.record_session(
            ip       = self.ip,
            features = features,
            score    = score["score"],
            chain    = chain,
        )

        # IOC recording
        self.ioc.record_ip(self.ip, "DecoyNet-ssh")

        # Persist session record
        record = {
            "session_id":    self.sid,
            "ip":            self.ip,
            "port":          22,
            "start_time":    self.start_time,
            "duration":      duration,
            "command_count": len(self.command_history),
            "threat_score":  score["score"],
            "threat_level":  score["level"],
            "attacker_type": features.get("attacker_type", "unknown"),
            "final_strategy": self.current_strategy.name,
            "attack_chain":  chain,
            "username":      self.username,
            "password":      self.password,
        }
        self.db.save_session(record)

        logger.info(
            "SESSION END | id=%s ip=%-16s dur=%.1fs cmds=%d "
            "score=%d level=%s type=%s strategy=%s chain=[%s]",
            self.sid[:8], self.ip, duration, len(self.command_history),
            score["score"], score["level"],
            features.get("attacker_type"), self.current_strategy.name, chain
        )

        try:
            self.channel.close()
        except Exception:
            pass

    # ── Helpers ──────────────────────────────────────────────────────────────

    def _send(self, data):
        try:
            if isinstance(data, str):
                data = data.encode("utf-8", errors="replace")
            self.channel.sendall(data)
        except Exception:
            self._running = False

    def _prompt(self) -> str:
        symbol = "#" if self.username == "root" else "$"
        return f"{self.username}@{self.hostname}:{self.cwd}{symbol} "

    def _build_env(self) -> dict:
        return {
            "USER":    self.username,
            "HOME":    "/root" if self.username == "root" else f"/home/{self.username}",
            "SHELL":   "/bin/bash",
            "TERM":    "xterm-256color",
            "LANG":    "en_US.UTF-8",
            "PATH":    "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
            "LOGNAME": self.username,
            "PWD":     self.cwd,
        }

    def _fake_last_login(self) -> str:
        days = random.randint(1, 30)
        hour = random.randint(0, 23)
        mn   = random.randint(0, 59)
        ip   = f"192.168.{random.randint(1,10)}.{random.randint(2,254)}"
        return f"{'Mon Tue Wed Thu Fri Sat Sun'.split()[random.randint(0,6)]} {time.strftime('%b')} {random.randint(1,28):2d} {hour:02d}:{mn:02d}:{random.randint(0,59):02d} 2024 from {ip}"
