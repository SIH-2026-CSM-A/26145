"""Prediction schema and version of the trained flow models."""

from dataclasses import dataclass, field
from typing import Any, Dict, Tuple

# Trained on CTU-13-Extended scenarios 1, 5, 6, 11, 12 (header-only full traffic) plus the
# generated attack captures; docs/MODELS.md. A version other than "synthetic-baseline" opens
# the ML gate in EvidenceAggregator.
ML_MODEL_VERSION = "ctu13x5-lgbm-if-1.0.0"


@dataclass(frozen=True)
class MLPrediction:
    """One model's verdict on one flow."""
    model_name: str
    threat_class: str
    anomaly_score: float  # the model's raw score (LightGBM probability, or IsolationForest anomaly score)
    probability: float    # confidence in [0, 1]: LightGBM probability, or the IsolationForest
                          # score's percentile among out-of-fold benign scores
    is_anomaly: bool      # score above the model's alert-budget threshold
    metadata: Dict[str, Any] = field(default_factory=dict)
    # Top LightGBM pred_contrib features for flagged flows: (feature, value, contribution)
    evidence: Tuple[Tuple[str, float, float], ...] = ()
