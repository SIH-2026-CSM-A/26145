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
    def detect(self, fv: FeatureVector, ctx=None) -> Optional[RuleHit]:
        """Evaluate a flow and return a RuleHit if the threat signature matches.

        `ctx` is a DetectionContext (flow, FeatureStore, NetworkPolicy) or None when only the
        FeatureVector is available. Every feature read, through `fv` or `ctx`, must be
        declared for this detector in feature_contract.toml.
        """
        pass
