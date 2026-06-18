"""
Background loop that retrains all ML models periodically.
"""

import time, logging
from config import ML_RETRAIN_INTERVAL, MIN_SAMPLES_TO_TRAIN
from database.db_manager import DatabaseManager
from ml_engine.kmeans_cluster import KMeansClusterer
from ml_engine.isolation_forest import AnomalyDetector
from ml_engine.decision_tree import AttackerClassifier

logger = logging.getLogger(__name__)


class ModelTrainer:
    def __init__(self):
        self.db      = DatabaseManager()
        self.kmeans  = KMeansClusterer()
        self.iforest = AnomalyDetector()
        self.dtree   = AttackerClassifier()

    def run_loop(self):
        while True:
            try:
                self._train_all()
            except Exception as exc:
                logger.exception("Training loop error: %s", exc)
            time.sleep(ML_RETRAIN_INTERVAL)

    def _train_all(self):
        sessions = self.db.get_all_sessions()
        if len(sessions) < MIN_SAMPLES_TO_TRAIN:
            logger.debug("Skipping training — only %d sessions.", len(sessions))
            return
        logger.info("Retraining models on %d sessions...", len(sessions))
        self.kmeans.train(sessions)
        self.iforest.train(sessions)
        self.dtree.train(sessions)
        logger.info("Model retraining complete.")
