"""Rule Detector Suite Evaluator for SIH26145."""

from typing import List
from sih26145.features.models import FeatureVector
from sih26145.detectors.models import RuleHit
from sih26145.detectors.rules.detectors import (
    DDoSVolumeDetector,
    C2BeaconDetector,
    DGALexicalDetector,
    DNSTunnelDetector,
    EncryptedAnomalyDetector,
    ReconPortScanDetector,
    ExfiltrationDetector,
)


class RuleDetectorSuite:
    """Evaluates all registered deterministic rule detectors against a FeatureVector."""

    def __init__(self):
        self.detectors = [
            DDoSVolumeDetector(),
            C2BeaconDetector(),
            DGALexicalDetector(),
            DNSTunnelDetector(),
            EncryptedAnomalyDetector(),
            ReconPortScanDetector(),
            ExfiltrationDetector(),
        ]

    def evaluate(self, fv: FeatureVector) -> List[RuleHit]:
        """Run FeatureVector through all registered rule detectors and return active hits."""
        hits: List[RuleHit] = []
        for det in self.detectors:
            hit = det.detect(fv)
            if hit is not None:
                hits.append(hit)
        return hits
