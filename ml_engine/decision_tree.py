"""
Decision Tree classifier — classifies attacker as bot / human / advanced.
"""

import os, pickle, logging
from sklearn.tree import DecisionTreeClassifier
from sklearn.preprocessing import LabelEncoder
from config import MODEL_DIR
from ml_engine.feature_extractor import sessions_to_matrix

logger = logging.getLogger(__name__)
_MODEL_PATH = os.path.join(MODEL_DIR, "dtree.pkl")
_ENC_PATH   = os.path.join(MODEL_DIR, "dtree_encoder.pkl")


class AttackerClassifier:
    LABELS = ["bot", "human", "advanced", "unknown"]

    def __init__(self):
        self.model   = None
        self.encoder = LabelEncoder().fit(self.LABELS)
        self._load()

    def train(self, sessions: list[dict]):
        labelled = [s for s in sessions if s.get("attacker_type") in self.LABELS]
        if len(labelled) < 10:
            logger.warning("Not enough labelled samples for DTree (%d)", len(labelled))
            return
        X = sessions_to_matrix(labelled)
        y = self.encoder.transform([s["attacker_type"] for s in labelled])
        self.model = DecisionTreeClassifier(max_depth=6, random_state=42).fit(X, y)
        self._save()
        logger.info("DecisionTree trained on %d labelled sessions.", len(labelled))

    def predict(self, session: dict) -> str:
        if not self.model:
            return "unknown"
        X = sessions_to_matrix([session])
        label_idx = self.model.predict(X)[0]
        return self.encoder.inverse_transform([label_idx])[0]

    def _save(self):
        os.makedirs(MODEL_DIR, exist_ok=True)
        with open(_MODEL_PATH, "wb") as f: pickle.dump(self.model,   f)
        with open(_ENC_PATH,   "wb") as f: pickle.dump(self.encoder, f)

    def _load(self):
        try:
            with open(_MODEL_PATH, "rb") as f: self.model   = pickle.load(f)
            with open(_ENC_PATH,   "rb") as f: self.encoder = pickle.load(f)
        except FileNotFoundError:
            pass
