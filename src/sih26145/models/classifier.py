"""Trained LightGBM flow classifier: malicious vs benign flow behaviour (docs/MODELS.md)."""

from typing import List, Tuple

import lightgbm
import numpy as np


class LightGBMFlowClassifier:
    model_name = "lightgbm_flow_classifier"
    threat_class = "THREAT_ML_MALICIOUS_FLOW"

    def __init__(self, text: str, threshold: float, features: List[str]):
        """`text`: the LightGBM text model from a verified bundle. LightGBM parses its own text
        format (no pickle); the bundle's signature is checked before this runs."""
        self.booster = lightgbm.Booster(model_str=text)
        self.threshold = threshold
        self.features = features

    def probabilities(self, X: np.ndarray) -> np.ndarray:
        return self.booster.predict(X, num_threads=1)

    def top_contributions(self, X: np.ndarray, k: int = 5) -> List[Tuple[Tuple[str, float, float], ...]]:
        """LightGBM's built-in pred_contrib (TreeSHAP, log-odds): the k features pushing each
        row's score hardest, with their values. The last column is the bias term."""
        if not len(X):
            return []
        contrib = self.booster.predict(X, pred_contrib=True, num_threads=1)[:, :-1]
        out = []
        for row, c in zip(X, contrib):
            top = np.argsort(-np.abs(c))[:k]
            out.append(tuple((self.features[i], float(row[i]), round(float(c[i]), 4)) for i in top))
        return out
