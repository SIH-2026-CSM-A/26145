"""Data Models for Rule-Based and ML Threat Detectors in SIH26145."""

from dataclasses import dataclass, field
from typing import Dict, Any


@dataclass(frozen=True)
class RuleHit:
    """Represents a deterministic rule detection hit with evidence metadata."""
    detector_name: str
    threat_class: str
    rule_id: str
    severity: str  # "LOW", "MED", "HIGH", "CRITICAL"
    confidence: float  # 0.0 to 1.0
    evidence: Dict[str, Any] = field(default_factory=dict)
