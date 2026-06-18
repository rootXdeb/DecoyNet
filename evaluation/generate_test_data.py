"""
Generate synthetic attack session data for ML training and evaluation.

Creates realistic sessions for 4 attacker types:
- bot:      automated scanner, fast, repetitive
- human:    slow, exploratory, varied commands
- advanced: fast but varied, targeted, high exploit count
- unknown:  random mix

Run this first before running ml_evaluation.py
Usage: python3 -m evaluation.generate_test_data
"""

import sys
import os
import time
import random
import uuid

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from database.db_manager import DatabaseManager
from database.models import initialize_schema, update_schema_for_adaptive


def make_bot_session() -> dict:
    """Automated scanner — fast, low inter-command time, repetitive commands"""
    return {
        "session_id":    str(uuid.uuid4()),
        "ip":            f"10.{random.randint(0,255)}.{random.randint(0,255)}.{random.randint(1,254)}",
        "port":          2222,
        "start_time":    time.time() - random.randint(0, 86400),
        "duration":      random.uniform(2, 15),
        "command_count": random.randint(5, 20),
        "threat_score":  random.randint(20, 50),
        "threat_level":  "MEDIUM",
        "attacker_type": "bot",
        "final_strategy":"DEFLECT",
        "attack_chain":  "Reconnaissance",
        "username":      random.choice(["root","admin","guest","ubuntu"]),
        "password":      random.choice(["root","admin","123456","password","toor"]),
        "protocol":      "SSH",
        # ML feature columns
        "recon_count":   random.randint(3, 8),
        "lateral_count": 0,
        "exploit_count": 0,
        "exfil_count":   0,
        "mean_delay":    random.uniform(0.01, 0.08),
        "stdev_delay":   random.uniform(0.001, 0.02),
        "mean_inter":    random.uniform(0.02, 0.09),
    }


def make_human_session() -> dict:
    """Human attacker — slow, exploratory, high inter-command time"""
    return {
        "session_id":    str(uuid.uuid4()),
        "ip":            f"185.{random.randint(0,255)}.{random.randint(0,255)}.{random.randint(1,254)}",
        "port":          2222,
        "start_time":    time.time() - random.randint(0, 86400),
        "duration":      random.uniform(60, 600),
        "command_count": random.randint(8, 35),
        "threat_score":  random.randint(50, 80),
        "threat_level":  random.choice(["MEDIUM", "HIGH"]),
        "attacker_type": "human",
        "final_strategy":"ENGAGE",
        "attack_chain":  "Reconnaissance → C2 / Download",
        "username":      random.choice(["root","admin","deploy"]),
        "password":      random.choice(["password1","letmein","welcome","qwerty"]),
        "protocol":      "SSH",
        "recon_count":   random.randint(3, 8),
        "lateral_count": random.randint(0, 3),
        "exploit_count": random.randint(1, 4),
        "exfil_count":   random.randint(0, 3),
        "mean_delay":    random.uniform(0.5, 3.0),
        "stdev_delay":   random.uniform(0.3, 1.5),
        "mean_inter":    random.uniform(1.5, 8.0),
    }


def make_advanced_session() -> dict:
    """Advanced attacker — fast but targeted, high exploit count"""
    return {
        "session_id":    str(uuid.uuid4()),
        "ip":            f"91.{random.randint(0,255)}.{random.randint(0,255)}.{random.randint(1,254)}",
        "port":          2222,
        "start_time":    time.time() - random.randint(0, 86400),
        "duration":      random.uniform(30, 300),
        "command_count": random.randint(15, 60),
        "threat_score":  random.randint(75, 100),
        "threat_level":  random.choice(["HIGH", "CRITICAL"]),
        "attacker_type": "advanced",
        "final_strategy":"TRAP",
        "attack_chain":  "Reconnaissance → C2 / Download → Execution → Exfiltration",
        "username":      "root",
        "password":      random.choice(["P@ssw0rd","Admin123!","root@123"]),
        "protocol":      random.choice(["SSH", "HTTP", "MySQL"]),
        "recon_count":   random.randint(4, 10),
        "lateral_count": random.randint(2, 6),
        "exploit_count": random.randint(4, 10),
        "exfil_count":   random.randint(2, 7),
        "mean_delay":    random.uniform(0.1, 0.5),
        "stdev_delay":   random.uniform(0.1, 0.4),
        "mean_inter":    random.uniform(0.2, 0.8),
    }


def make_unknown_session() -> dict:
    """Unknown/mixed — random characteristics"""
    return {
        "session_id":    str(uuid.uuid4()),
        "ip":            f"45.{random.randint(0,255)}.{random.randint(0,255)}.{random.randint(1,254)}",
        "port":          random.choice([22, 80, 3306, 6379]),
        "start_time":    time.time() - random.randint(0, 86400),
        "duration":      random.uniform(5, 120),
        "command_count": random.randint(1, 15),
        "threat_score":  random.randint(5, 40),
        "threat_level":  "LOW",
        "attacker_type": "unknown",
        "final_strategy":"OBSERVE",
        "attack_chain":  "Reconnaissance",
        "username":      random.choice(["admin","test","oracle","postgres"]),
        "password":      random.choice(["","test","oracle","admin"]),
        "protocol":      random.choice(["HTTP","FTP","Telnet","Redis"]),
        "recon_count":   random.randint(0, 4),
        "lateral_count": 0,
        "exploit_count": 0,
        "exfil_count":   0,
        "mean_delay":    random.uniform(0.05, 2.0),
        "stdev_delay":   random.uniform(0.01, 0.5),
        "mean_inter":    random.uniform(0.1, 3.0),
    }


def generate(n_per_class: int = 100):
    db = DatabaseManager()
    initialize_schema(db)
    update_schema_for_adaptive(db)

    generators = [
        ("bot",      make_bot_session),
        ("human",    make_human_session),
        ("advanced", make_advanced_session),
        ("unknown",  make_unknown_session),
    ]

    total = 0
    for label, fn in generators:
        for _ in range(n_per_class):
            session = fn()
            db.save_session(session)
            total += 1
        print(f"  Generated {n_per_class} {label} sessions.")

    print(f"\nTotal sessions in DB: {total}")
    return total


if __name__ == "__main__":
    n = int(sys.argv[1]) if len(sys.argv) > 1 else 100
    print(f"Generating {n} sessions per class ({n*4} total)...\n")
    generate(n)
    print("\nDone. Now run: python3 -m evaluation.ml_evaluation")
