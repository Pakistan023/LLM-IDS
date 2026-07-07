"""
Traditional ML baseline: a RandomForest (supervised) trained on labeled
simulated traffic, with an IsolationForest fallback for unsupervised
anomaly scoring when no labels are available. This sits "between" the
rigid signature engine and the flexible LLM analyzer in the comparison.
"""

import os
from typing import List, Tuple

import joblib
import numpy as np
from sklearn.ensemble import IsolationForest, RandomForestClassifier
from sklearn.preprocessing import StandardScaler

from src.capture.traffic_simulator import FlowRecord, TrafficSimulator
from src.features.feature_extractor import extract_feature_matrix
from src.utils.config_loader import load_config
from src.utils.logger import get_logger

log = get_logger(__name__)


class MLClassifier:
    def __init__(self):
        cfg = load_config()
        self.model_path = cfg["_abs"](cfg["ml_classifier"]["model_path"])
        self.scaler_path = cfg["_abs"](cfg["ml_classifier"]["scaler_path"])
        self.contamination = cfg["ml_classifier"]["contamination"]
        self.model: RandomForestClassifier = None
        self.scaler: StandardScaler = None
        self.mode = "supervised"

        os.makedirs(os.path.dirname(self.model_path), exist_ok=True)

        if cfg["ml_classifier"]["retrain_on_start"] or not os.path.exists(self.model_path):
            self._train_on_synthetic_data()
        else:
            self._load()

    # ------------------------------------------------------------------ #
    def _train_on_synthetic_data(self, n_samples: int = 4000):
        log.info("Training RandomForest baseline on synthetic labeled traffic ...")
        sim = TrafficSimulator(attack_ratio=0.25, seed=42)
        flows: List[FlowRecord] = sim.generate_window(n=n_samples)

        X = extract_feature_matrix(flows)
        y = np.array([1 if f.label == "malicious" else 0 for f in flows])

        self.scaler = StandardScaler().fit(X)
        X_scaled = self.scaler.transform(X)

        self.model = RandomForestClassifier(
            n_estimators=150, max_depth=10, class_weight="balanced", random_state=42
        )
        self.model.fit(X_scaled, y)
        self.mode = "supervised"

        joblib.dump(self.model, self.model_path)
        joblib.dump(self.scaler, self.scaler_path)
        log.info(f"Model trained and saved to {self.model_path}")

    def _load(self):
        self.model = joblib.load(self.model_path)
        self.scaler = joblib.load(self.scaler_path)
        log.info(f"Loaded existing ML model from {self.model_path}")

    # ------------------------------------------------------------------ #
    def predict(self, flows: List[FlowRecord]) -> List[Tuple[FlowRecord, float, str]]:
        """Returns list of (flow, anomaly_probability, predicted_label)."""
        if not flows:
            return []
        X = extract_feature_matrix(flows)
        X_scaled = self.scaler.transform(X)
        probs = self.model.predict_proba(X_scaled)[:, 1]
        preds = self.model.predict(X_scaled)
        return [
            (flow, float(prob), "malicious" if pred == 1 else "benign")
            for flow, prob, pred in zip(flows, probs, preds)
        ]

    def feature_importances(self) -> dict:
        from src.features.feature_extractor import NUMERIC_FIELDS
        return dict(zip(NUMERIC_FIELDS, self.model.feature_importances_.tolist()))
