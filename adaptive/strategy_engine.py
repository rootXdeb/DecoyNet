"""
AdaptiveStrategyEngine — the closed feedback loop.

After every command this engine re-evaluates which strategy the DecoyNet
should use for THIS attacker RIGHT NOW, based on:

  1. Live session features (from BehaviorProfiler)
  2. ML cluster prediction (K-Means — what group does this attacker belong to?)
  3. Anomaly score (Isolation Forest — is this an unusual attack pattern?)
  4. Cross-session intelligence (has this IP been seen before? coordinated?)
  5. Current TTP stage (recon / lateral movement / exploitation / exfiltration)

The output is one of four strategies that controls EVERYTHING about how
the DecoyNet responds — depth, delay, what secrets to surface, what traps to set.

This is the closed loop:
  session features → ML prediction → strategy → response → new features → ML update
"""

import logging
import time
import random
from enum import Enum, auto
from typing import Optional

logger = logging.getLogger(__name__)


class Strategy(Enum):
    """
    DEFLECT  — Minimal, slightly wrong responses. For bots and scanners.
               Goal: waste as little of our resources as possible, confuse scanner.

    OBSERVE  — Normal-looking responses, no extra bait. For unknown attackers.
               Goal: watch, collect features, classify before committing to strategy.

    ENGAGE   — Deep responses, surface credentials and interesting files.
               For confirmed human attackers. Goal: keep them busy as long as possible.

    TRAP     — Targeted bait matched to the attacker's apparent interest.
               For advanced/persistent attackers. Goal: maximum intelligence collection,
               lead them into prepared traps.
    """
    DEFLECT = auto()
    OBSERVE = auto()
    ENGAGE  = auto()
    TRAP    = auto()


# TTP stage weights — how dangerous each stage combination is
_STAGE_RISK = {
    "Reconnaissance":  1,
    "C2 / Download":   3,
    "Execution":       4,
    "Exfiltration":    5,
    "Persistence":     5,
}

# Cluster → default strategy mapping (updated by ML predictions)
_CLUSTER_STRATEGY = {
    0: Strategy.DEFLECT,   # Automated scanner cluster
    1: Strategy.OBSERVE,   # Low-activity / probe cluster
    2: Strategy.ENGAGE,    # Human attacker cluster
    3: Strategy.TRAP,      # Advanced/targeted attacker cluster
}


class AdaptiveStrategyEngine:
    """
    Re-evaluates strategy after every command.
    Consults live ML models for prediction.
    """

    def __init__(self):
        # Lazy-load ML models to avoid startup failures if not yet trained
        self._kmeans   = None
        self._iforest  = None
        self._dtree    = None
        self._last_model_load = 0.0

    def evaluate(
        self,
        features:    dict,
        cross_intel: dict,
        command:     str,
        session_id:  str,
    ) -> Strategy:
        """
        Core evaluation — returns the best Strategy for this moment.
        Falls back gracefully if ML models are not yet trained.
        """
        self._maybe_reload_models()

        # ── Rule-based fast path (always runs) ──────────────────────────────
        rule_strategy = self._rule_based(features, cross_intel, command)

        # ── ML-based refinement (runs if models are trained) ────────────────
        ml_strategy = self._ml_based(features)

        # ── Merge: ML overrides rules only if confidence is high ────────────
        final = self._merge(rule_strategy, ml_strategy, features)

        return final

    def response_delay(self, strategy: Strategy, features: dict) -> float:
        """
        Returns how many seconds to wait before sending the response.

        DEFLECT: 0      — respond instantly (waste their time with wrong data)
        OBSERVE: 0–0.3  — near-instant (look like a normal server)
        ENGAGE:  0.5–2  — human-like typing delay
        TRAP:    1–4    — slow server simulation (buys us more time)
        """
        attacker_type = features.get("attacker_type", "unknown")
        if strategy == Strategy.DEFLECT:
            return 0.0
        if strategy == Strategy.OBSERVE:
            return random.uniform(0.05, 0.3) if attacker_type != "bot" else 0.0
        if strategy == Strategy.ENGAGE:
            return random.uniform(0.3, 1.5)
        if strategy == Strategy.TRAP:
            return random.uniform(1.0, 3.5)
        return 0.0

    # ── Rule-based evaluation ────────────────────────────────────────────────

    def _rule_based(self, features: dict, cross_intel: dict, command: str) -> Strategy:
        attacker_type = features.get("attacker_type", "unknown")
        cmd_count     = features.get("command_count", 0)
        exploit_count = features.get("exploit_count", 0)
        exfil_count   = features.get("exfil_count", 0)
        lateral_count = features.get("lateral_count", 0)
        mean_inter    = features.get("mean_inter", 1.0)
        stages        = features.get("ttp_stages", [])

        # Known bad actor from cross-session intel
        if cross_intel.get("known_attacker") and cross_intel.get("max_score", 0) > 70:
            return Strategy.TRAP

        # Bot/scanner — very fast typing, lots of commands
        if attacker_type == "bot" or (mean_inter < 0.05 and cmd_count > 5):
            return Strategy.DEFLECT

        # Confirmed human with exploitation or exfiltration activity
        if attacker_type in ("human", "advanced"):
            if "Exfiltration" in stages or exfil_count > 2:
                return Strategy.TRAP
            if "Execution" in stages or exploit_count > 2:
                return Strategy.ENGAGE
            if lateral_count > 1:
                return Strategy.ENGAGE

        # Early session, not yet classified
        if cmd_count < 5:
            return Strategy.OBSERVE

        # Default for human with only recon so far
        if attacker_type == "human":
            return Strategy.ENGAGE

        return Strategy.OBSERVE

    # ── ML-based evaluation ──────────────────────────────────────────────────

    def _ml_based(self, features: dict) -> Optional[Strategy]:
        """
        Consults K-Means cluster prediction and Isolation Forest anomaly score.
        Returns None if models are not yet trained.
        """
        if not self._kmeans or not self._iforest:
            return None

        try:
            cluster_id   = self._kmeans.predict(features)
            anomaly_data = self._iforest.predict(features)
            anomaly      = anomaly_data.get("anomaly", False)

            # Anomalous session = we haven't seen this pattern before → TRAP
            if anomaly:
                logger.debug("Anomaly detected → TRAP strategy")
                return Strategy.TRAP

            ml_strategy = _CLUSTER_STRATEGY.get(cluster_id, Strategy.OBSERVE)
            logger.debug("KMeans cluster=%d → %s", cluster_id, ml_strategy.name)
            return ml_strategy

        except Exception as exc:
            logger.debug("ML evaluation error (using rules only): %s", exc)
            return None

    # ── Merge rule + ML ──────────────────────────────────────────────────────

    def _merge(
        self,
        rule:     Strategy,
        ml:       Optional[Strategy],
        features: dict,
    ) -> Strategy:
        """
        Merges rule-based and ML-based strategies.

        Priority:
          1. If ML says TRAP → always TRAP (anomaly or advanced cluster)
          2. If both agree → use it
          3. If they disagree → escalate to the more aggressive one
             (we'd rather over-engage than under-engage)
          4. If no ML → use rules
        """
        if ml is None:
            return rule

        if ml == Strategy.TRAP:
            return Strategy.TRAP

        if rule == ml:
            return rule

        # Escalate to more aggressive strategy
        order = [Strategy.DEFLECT, Strategy.OBSERVE, Strategy.ENGAGE, Strategy.TRAP]
        return max(rule, ml, key=lambda s: order.index(s))

    # ── Model loader ─────────────────────────────────────────────────────────

    def _maybe_reload_models(self):
        """Reload ML models every 5 minutes so we always use the latest."""
        now = time.time()
        if now - self._last_model_load < 300 and self._kmeans is not None:
            return
        try:
            from ml_engine.kmeans_cluster import KMeansClusterer
            from ml_engine.isolation_forest import AnomalyDetector
            self._kmeans  = KMeansClusterer()
            self._iforest = AnomalyDetector()
            self._last_model_load = now
            if self._kmeans.model:
                logger.debug("ML models reloaded into strategy engine.")
        except Exception as exc:
            logger.debug("Model reload skipped: %s", exc)
