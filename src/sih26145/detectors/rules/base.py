"""Abstract Base Class for Rule Detectors."""

from abc import ABC, abstractmethod
from typing import Optional
from sih26145.features.models import FeatureVector
from sih26145.detectors.models import RuleHit


class BaseRuleDetector(ABC):
    """Abstract interface for a deterministic signature/heuristic rule detector."""

    @property
    @abstractmethod
    def name(self) -> str:
        pass

    @property
    @abstractmethod
    def threat_class(self) -> str:
        pass

    @abstractmethod
    def detect(self, fv: FeatureVector) -> Optional[RuleHit]:
        """Evaluate FeatureVector and return RuleHit if threat signature matches."""
        pass
