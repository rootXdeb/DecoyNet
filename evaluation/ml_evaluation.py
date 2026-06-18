"""
ML Model Evaluation — measures accuracy of all three ML models.

Produces:
- Accuracy, Precision, Recall, F1-Score for Decision Tree
- Silhouette Score for K-Means clustering
- Anomaly detection rate for Isolation Forest
- Confusion matrix
- Saves results to logs/reports/ml_evaluation.json

Usage: python3 -m evaluation.ml_evaluation
"""

import sys
import os
import json
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import numpy as np
from sklearn.metrics import (
    accuracy_score, precision_score, recall_score,
    f1_score, confusion_matrix, classification_report
)
from sklearn.metrics import silhouette_score
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import LabelEncoder

from database.db_manager import DatabaseManager
from database.models import initialize_schema, update_schema_for_adaptive
from ml_engine.feature_extractor import sessions_to_matrix, FEATURE_COLS
from ml_engine.kmeans_cluster import KMeansClusterer
from ml_engine.isolation_forest import AnomalyDetector
from ml_engine.decision_tree import AttackerClassifier

REPORTS_DIR = os.path.join(os.path.dirname(os.path.dirname(__file__)), "logs", "reports")
os.makedirs(REPORTS_DIR, exist_ok=True)


def evaluate():
    print("\n" + "="*60)
    print("  DecoyNetAI — ML Model Evaluation")
    print("="*60)

    db       = DatabaseManager()
    initialize_schema(db)
    update_schema_for_adaptive(db)
    sessions = db.get_all_sessions()

    if len(sessions) < 20:
        print(f"\n[!] Only {len(sessions)} sessions in DB.")
        print("    Run first: python3 -m evaluation.generate_test_data")
        return

    print(f"\n[+] Loaded {len(sessions)} sessions from database.")

    # Filter labelled sessions
    labelled = [s for s in sessions if s.get("attacker_type") in
                ("bot", "human", "advanced", "unknown")]
    print(f"[+] Labelled sessions: {len(labelled)}")

    X      = sessions_to_matrix(labelled)
    labels = [s["attacker_type"] for s in labelled]
    le     = LabelEncoder().fit(["bot", "human", "advanced", "unknown"])
    y      = le.transform(labels)

    results = {
        "generated_at":   time.strftime("%Y-%m-%d %H:%M:%S UTC", time.gmtime()),
        "total_sessions": len(sessions),
        "labelled":       len(labelled),
        "class_distribution": {
            t: labels.count(t) for t in ["bot", "human", "advanced", "unknown"]
        },
    }

    # ── 1. Decision Tree ──────────────────────────────────────────────────────
    print("\n[1] Decision Tree Classifier")
    print("-" * 40)

    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, random_state=42, stratify=y
    )

    clf = AttackerClassifier()
    clf.train(labelled)

    if clf.model:
        y_pred = clf.model.predict(X_test)
        acc    = accuracy_score(y_test, y_pred)
        prec   = precision_score(y_test, y_pred, average="weighted", zero_division=0)
        rec    = recall_score(y_test, y_pred, average="weighted", zero_division=0)
        f1     = f1_score(y_test, y_pred, average="weighted", zero_division=0)
        cm     = confusion_matrix(y_test, y_pred).tolist()
        report = classification_report(
            y_test, y_pred,
            target_names=le.classes_,
            zero_division=0
        )

        print(f"  Accuracy  : {acc*100:.2f}%")
        print(f"  Precision : {prec*100:.2f}%")
        print(f"  Recall    : {rec*100:.2f}%")
        print(f"  F1-Score  : {f1*100:.2f}%")
        print(f"\n  Classification Report:\n{report}")
        print(f"  Confusion Matrix:\n  {cm}")

        results["decision_tree"] = {
            "accuracy":         round(acc, 4),
            "precision":        round(prec, 4),
            "recall":           round(rec, 4),
            "f1_score":         round(f1, 4),
            "confusion_matrix": cm,
            "class_report":     report,
        }
    else:
        print("  [!] Model not trained yet.")

    # ── 2. K-Means Clustering ─────────────────────────────────────────────────
    print("\n[2] K-Means Clustering")
    print("-" * 40)

    kmeans = KMeansClusterer()
    kmeans.train(labelled)

    if kmeans.model and X.shape[0] >= kmeans.N_CLUSTERS:
        Xs      = kmeans.scaler.transform(X)
        cluster_labels = kmeans.model.predict(Xs)
        sil     = silhouette_score(Xs, cluster_labels)
        inertia = kmeans.model.inertia_

        # Count sessions per cluster
        cluster_counts = {}
        for c in cluster_labels:
            cluster_counts[int(c)] = cluster_counts.get(int(c), 0) + 1

        print(f"  Silhouette Score : {sil:.4f}  (closer to 1.0 = better clusters)")
        print(f"  Inertia          : {inertia:.2f}")
        print(f"  Sessions per cluster: {cluster_counts}")

        results["kmeans"] = {
            "silhouette_score":    round(sil, 4),
            "inertia":             round(inertia, 2),
            "n_clusters":          kmeans.N_CLUSTERS,
            "sessions_per_cluster":cluster_counts,
        }
    else:
        print("  [!] Not enough data or model not trained.")

    # ── 3. Isolation Forest ───────────────────────────────────────────────────
    print("\n[3] Isolation Forest Anomaly Detection")
    print("-" * 40)

    iforest = AnomalyDetector()
    iforest.train(labelled)

    if iforest.model:
        Xs        = iforest.scaler.transform(X)
        preds     = iforest.model.predict(Xs)
        anomalies = int((preds == -1).sum())
        normal    = int((preds == 1).sum())
        rate      = anomalies / len(preds) * 100

        # Advanced sessions should be detected as anomalies
        advanced_idx = [i for i, s in enumerate(labelled) if s["attacker_type"] == "advanced"]
        if advanced_idx:
            adv_preds    = preds[advanced_idx]
            adv_detected = int((adv_preds == -1).sum())
            adv_rate     = adv_detected / len(advanced_idx) * 100
        else:
            adv_detected, adv_rate = 0, 0.0

        print(f"  Total anomalies detected : {anomalies} / {len(preds)} ({rate:.1f}%)")
        print(f"  Normal sessions          : {normal}")
        print(f"  Advanced attackers caught: {adv_detected} / {len(advanced_idx)} ({adv_rate:.1f}%)")
        print(f"  Contamination rate       : 10% (configured)")

        results["isolation_forest"] = {
            "total_anomalies":        anomalies,
            "total_normal":           normal,
            "anomaly_rate_pct":       round(rate, 2),
            "advanced_detected":      adv_detected,
            "advanced_detection_rate":round(adv_rate, 2),
        }
    else:
        print("  [!] Not enough data or model not trained.")

    # ── 4. Strategy accuracy simulation ──────────────────────────────────────
    print("\n[4] Strategy Selection Accuracy")
    print("-" * 40)

    from adaptive.strategy_engine import AdaptiveStrategyEngine, Strategy

    engine          = AdaptiveStrategyEngine()
    correct         = 0
    expected_map    = {
        "bot":      Strategy.DEFLECT,
        "human":    Strategy.ENGAGE,
        "advanced": Strategy.TRAP,
        "unknown":  Strategy.OBSERVE,
    }

    for s in labelled[:200]:
        features = {k: s.get(k, 0) for k in FEATURE_COLS}
        features["attacker_type"] = s.get("attacker_type", "unknown")
        features["ttp_stages"]    = []
        strategy = engine.evaluate(
            features    = features,
            cross_intel = {},
            command     = "ls",
            session_id  = s["session_id"],
        )
        expected = expected_map.get(s["attacker_type"], Strategy.OBSERVE)
        if strategy == expected:
            correct += 1

    total_tested = min(200, len(labelled))
    strat_acc    = correct / total_tested * 100 if total_tested else 0

    print(f"  Correct strategy selected: {correct} / {total_tested} ({strat_acc:.1f}%)")
    results["strategy_engine"] = {
        "correct":      correct,
        "total_tested": total_tested,
        "accuracy_pct": round(strat_acc, 2),
    }

    # ── Save results ──────────────────────────────────────────────────────────
    out_path = os.path.join(REPORTS_DIR, "ml_evaluation.json")
    with open(out_path, "w") as f:
        json.dump(results, f, indent=2)

    print("\n" + "="*60)
    print("  EVALUATION SUMMARY")
    print("="*60)
    if "decision_tree" in results:
        dt = results["decision_tree"]
        print(f"  Decision Tree Accuracy : {dt['accuracy']*100:.2f}%")
        print(f"  Decision Tree F1-Score : {dt['f1_score']*100:.2f}%")
    if "kmeans" in results:
        km = results["kmeans"]
        print(f"  K-Means Silhouette     : {km['silhouette_score']:.4f}")
    if "isolation_forest" in results:
        iso = results["isolation_forest"]
        print(f"  IForest Anomaly Rate   : {iso['anomaly_rate_pct']:.1f}%")
        print(f"  Advanced Detection     : {iso['advanced_detection_rate']:.1f}%")
    print(f"  Strategy Accuracy      : {results['strategy_engine']['accuracy_pct']:.1f}%")
    print(f"\n  Full results saved → {out_path}")
    print("="*60 + "\n")

    return results


if __name__ == "__main__":
    evaluate()
