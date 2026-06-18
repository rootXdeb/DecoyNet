"""
Standalone bot vs human vs advanced attacker classifier (rule-based fallback
when ML model is not yet trained).
"""


class BotClassifier:
    def classify(self, features: dict) -> str:
        inter = features.get("mean_inter", 1.0)
        stdev = features.get("stdev_delay", 0.5)
        cmds  = features.get("command_count", 0)

        if inter < 0.05 and cmds > 10:
            return "bot"
        if inter > 3.0 and stdev > 0.5:
            return "human"
        if features.get("exploit_count", 0) > 3:
            return "advanced"
        return "unknown"
