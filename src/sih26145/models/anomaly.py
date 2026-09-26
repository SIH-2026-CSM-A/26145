"""Trained IsolationForest: novelty against benign flows (docs/MODELS.md)."""

import joblib
import numpy as np

NAN_SENTINEL = -1.0  # undefined store features (warm-up, < 2 gaps); every real value is >= 0


def impute(X: np.ndarray) -> np.ndarray:
    """IsolationForest cannot split on NaN; undefined values get a value no real one takes."""
    return np.where(np.isnan(X), NAN_SENTINEL, X)


class IsolationForestFlowModel:
    model_name = "isolation_forest_flow_model"
    threat_class = "THREAT_UNSUPERVISED_ANOMALY"

    def __init__(self, path: str, threshold: float, benign_quantiles):
        self.model = joblib.load(path)
        self.model.set_params(n_jobs=1)
        self.threshold = threshold
        self.benign_quantiles = np.asarray(benign_quantiles, dtype=np.float64)

    def scores(self, X: np.ndarray) -> np.ndarray:
        """Higher = more anomalous (negated score_samples)."""
        return -self.model.score_samples(impute(X))

    def confidence(self, scores: np.ndarray) -> np.ndarray:
        """Share of out-of-fold benign flows scoring lower: a percentile, not a probability."""
        q = self.benign_quantiles
        return np.searchsorted(q, scores, side="right") / len(q)
