"""Prediction and Model Schemas for Classical ML Detectors in SIH26145."""

from dataclasses import dataclass, field
from typing import Dict, Any


@dataclass(frozen=True)
class MLPrediction:
    """Structured ML inference result produced by classical machine learning models."""
    model_name: str
    threat_class: str
    anomaly_score: float  # Unsupervised score (-1.0 to 1.0 or decision function)
    probability: float    # Supervised probability (0.0 to 1.0)
    is_anomaly: bool
    metadata: Dict[str, Any] = field(default_factory=dict)
