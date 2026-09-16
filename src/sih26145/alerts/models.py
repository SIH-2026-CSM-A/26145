"""Versioned Structured Alert Data Model matching sih26145.alert.v1 schema contract."""

import json
import math
import uuid
from copy import deepcopy
from datetime import datetime, timezone
from dataclasses import dataclass, field
from typing import Dict, Any, List


def _sanitize_value(val: Any) -> Any:
    """Recursively sanitize float values replacing NaN/Inf with 0.0 for JSON compatibility."""
    if isinstance(val, float):
        return val if math.isfinite(val) else 0.0
    elif isinstance(val, dict):
        return {k: _sanitize_value(v) for k, v in val.items()}
    elif isinstance(val, list):
        return [_sanitize_value(v) for v in val]
    return val


@dataclass
class Alert:
    """Represents a versioned structured threat alert (sih26145.alert.v1)."""
    threat_class: str
    detector: Dict[str, str]
    flow: Dict[str, Any]
    confidence: float
    severity: str
    evidence: Dict[str, Any]
    feature_summary: Dict[str, Any]
    version: str = "1.0"
    alert_id: str = field(default_factory=lambda: f"urn:uuid:{uuid.uuid4()}")
    timestamp: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())

    def to_dict(self) -> Dict[str, Any]:
        """Return alert as dictionary strictly adhering to sih26145.alert.v1 schema."""
        raw_dict = {
            "$schema": "https://sih26145.ntro.gov.in/schemas/alert.v1.json",
            "version": self.version,
            "alert_id": self.alert_id,
            "timestamp": self.timestamp,
            "threat_class": self.threat_class,
            "detector": deepcopy(self.detector),
            "flow": deepcopy(self.flow),
            "confidence": round(max(0.0, min(1.0, float(self.confidence))), 4),
            "severity": self.severity,
            "evidence": deepcopy(self.evidence),
            "feature_summary": deepcopy(self.feature_summary),
        }
        return _sanitize_value(raw_dict)

    def to_json(self, indent: int = 2) -> str:
        """Return JSON-formatted alert string."""
        return json.dumps(self.to_dict(), indent=indent)
