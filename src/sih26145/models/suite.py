"""Classical ML Model Suite Evaluator for SIH26145."""

from typing import List
from sih26145.features.models import FeatureVector
from sih26145.models.schemas import MLPrediction
from sih26145.models.anomaly import IsolationForestAnomalyDetector
from sih26145.models.classifier import RandomForestThreatClassifier


class MLModelSuite:
    """Runs all classical ML models (Isolation Forest, Random Forest) against a FeatureVector."""

    def __init__(self):
        self.anomaly_detector = IsolationForestAnomalyDetector()
        self.threat_classifier = RandomForestThreatClassifier()

    def predict(self, fv: FeatureVector) -> List[MLPrediction]:
        """Run FeatureVector through ML model suite and return predictions."""
        predictions: List[MLPrediction] = []
        
        pred_anomaly = self.anomaly_detector.predict(fv)
        predictions.append(pred_anomaly)

        pred_class = self.threat_classifier.predict(fv)
        predictions.append(pred_class)

        return predictions
