"""
Isolation Forest — detects anomalous / unknown attack patterns.
"""

import os, pickle, logging
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler
from config import MODEL_DIR
from ml_engine.feature_extractor import sessions_to_matrix

logger = logging.getLogger(__name__)
_MODEL_PATH  = os.path.join(MODEL_DIR, "iforest.pkl")
_SCALER_PATH = os.path.join(MODEL_DIR, "iforest_scaler.pkl")


class AnomalyDetector:
    def __init__(self):
        self.model  = None
        self.scaler = None
        self._load()

    def train(self, sessions: list[dict]):
        X = sessions_to_matrix(sessions)
        if X.shape[0] < 10:
            logger.warning("Not enough samples for IForest (%d)", X.shape[0])
            return
        self.scaler = StandardScaler().fit(X)
        Xs = self.scaler.transform(X)
        self.model  = IsolationForest(contamination=0.1, random_state=42).fit(Xs)
        self._save()
        logger.info("IsolationForest trained on %d sessions.", X.shape[0])

    def predict(self, session: dict) -> dict:
        """Returns {'anomaly': bool, 'score': float}."""
        if not self.model:
            return {"anomaly": False, "score": 0.0}
        X  = sessions_to_matrix([session])
        Xs = self.scaler.transform(X)
        score = float(self.model.decision_function(Xs)[0])
        label = self.model.predict(Xs)[0]
        return {"anomaly": label == -1, "score": round(score, 4)}

    def _save(self):
        os.makedirs(MODEL_DIR, exist_ok=True)
        with open(_MODEL_PATH,  "wb") as f: pickle.dump(self.model,  f)
        with open(_SCALER_PATH, "wb") as f: pickle.dump(self.scaler, f)

    def _load(self):
        try:
            with open(_MODEL_PATH,  "rb") as f: self.model  = pickle.load(f)
            with open(_SCALER_PATH, "rb") as f: self.scaler = pickle.load(f)
        except FileNotFoundError:
            pass
