"""Data Models for Rule-Based and ML Threat Detectors in SIH26145."""

from dataclasses import dataclass, field
from typing import Dict, Any, Tuple

# Version of the rule set as a whole; reported as alert model_version "rules-<version>".
RULESET_VERSION = "2.0.0"  # 2.0.0: (a)-(e) on tier-2 features; 1.1.0: (f) direction-aware


@dataclass(frozen=True)
class RuleHit:
    """Represents a deterministic rule detection hit with evidence metadata."""
    detector_name: str
    threat_class: str
    rule_id: str
    severity: str  # "LOW", "MEDIUM", "HIGH", "CRITICAL"
    confidence: float  # 0.0 to 1.0
    # feature -> value, or feature -> {"value", "baseline", "baseline_source"}
    evidence: Dict[str, Any] = field(default_factory=dict)
    # Contract features this hit could not use on this flow, and what replaced them
    substitutions: Tuple[Dict[str, Any], ...] = ()
    # What the hit is about (destination, host, pair); the suite raises one alert per
    # (detector, entity) per dedupe period. Empty = never deduplicated.
    entity: str = ""
