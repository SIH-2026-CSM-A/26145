"""Rule Detector Suite Evaluator for SIH26145."""

from collections import OrderedDict
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

    def __init__(self, dedupe_seconds: float = 300.0, memo_cap: int = 65536):
        self.dedupe_seconds = dedupe_seconds
        self.memo_cap = memo_cap
        self._last_fired: OrderedDict = OrderedDict()  # (detector, entity) -> event time
        self.detectors = [
            DDoSVolumeDetector(),
            C2BeaconDetector(),
            DGALexicalDetector(),
            DNSTunnelDetector(),
            EncryptedAnomalyDetector(),
            ReconPortScanDetector(),
            ExfiltrationDetector(),
        ]

    def evaluate(self, fv: FeatureVector, ctx=None) -> List[RuleHit]:
        """Run a flow through all registered rule detectors and return active hits."""
        hits: List[RuleHit] = []
        for det in self.detectors:
            hit = det.detect(fv, ctx)
            if hit is not None and not self._repeat(hit, ctx):
                hits.append(hit)
        return hits

    def last_fired(self, detector_name: str, entity: str):
        """Event time of the last alert this suite let through for (detector, entity), or None."""
        return self._last_fired.get((detector_name, entity))

    def _repeat(self, hit: RuleHit, ctx) -> bool:
        """One alert per (detector, entity) per dedupe period of event time; an ongoing
        flood or scan would otherwise raise an alert for every flow it contains."""
        if not hit.entity or ctx is None:
            return False
        key, t = (hit.detector_name, hit.entity), ctx.flow.last_time
        last = self._last_fired.get(key)
        if last is not None and abs(t - last) < self.dedupe_seconds:
            return True
        self._last_fired[key] = t
        self._last_fired.move_to_end(key)
        if len(self._last_fired) > self.memo_cap:
            self._last_fired.popitem(last=False)
        return False
