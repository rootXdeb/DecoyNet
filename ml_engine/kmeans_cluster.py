"""
K-Means clustering — groups attack sessions into behaviour clusters.
"""

import os, pickle, logging
import numpy as np
from sklearn.cluster import KMeans
from sklearn.preprocessing import StandardScaler
from config import MODEL_DIR
from ml_engine.feature_extractor import sessions_to_matrix

logger = logging.getLogger(__name__)
_MODEL_PATH  = os.path.join(MODEL_DIR, "kmeans.pkl")
_SCALER_PATH = os.path.join(MODEL_DIR, "kmeans_scaler.pkl")


class KMeansClusterer:
    N_CLUSTERS = 4

    def __init__(self):
        self.model  = None
        self.scaler = None
        self._load()

    def train(self, sessions: list[dict]):
        X = sessions_to_matrix(sessions)
        if X.shape[0] < self.N_CLUSTERS:
            logger.warning("Not enough samples to train KMeans (%d)", X.shape[0])
            return
        self.scaler = StandardScaler().fit(X)
        Xs = self.scaler.transform(X)
        self.model  = KMeans(n_clusters=self.N_CLUSTERS, random_state=42, n_init=10).fit(Xs)
        self._save()
        logger.info("KMeans trained on %d sessions.", X.shape[0])

    def predict(self, session: dict) -> int:
        if not self.model:
            return -1
        X  = sessions_to_matrix([session])
        Xs = self.scaler.transform(X)
        return int(self.model.predict(Xs)[0])

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
