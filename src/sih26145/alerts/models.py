"""Versioned structured alert (sih26145.alert.v2) and the v1 -> v2 upgrade."""

import json
import math
import uuid
from copy import deepcopy
from datetime import datetime, timezone
from dataclasses import dataclass, field
from typing import Dict, Any, List, Optional

from sih26145.contract import load_contract
from sih26145.flow.community_id import community_id

SCHEMA_V1 = "https://sih26145.ntro.gov.in/schemas/alert.v1.json"
SCHEMA_V2 = "https://sih26145.ntro.gov.in/schemas/alert.v2.json"
OBSERVABILITY_STATES = ("bidirectional", "forward_only", "reverse_only")


def _sanitize_value(val: Any) -> Any:
    """Recursively sanitize float values replacing NaN/Inf with 0.0 for JSON compatibility."""
    if isinstance(val, float):
        return val if math.isfinite(val) else 0.0
    elif isinstance(val, dict):
        return {k: _sanitize_value(v) for k, v in val.items()}
    elif isinstance(val, list):
        return [_sanitize_value(v) for v in val]
    return val


def evidence_item(feature: str, value: Any, baseline: Any = None, baseline_source: Optional[str] = None,
                  contribution: Optional[float] = None) -> Dict[str, Any]:
    """One v2 evidence row: a contract feature, its observed value, and what normal looks like.
    Model evidence adds `contribution`: the feature's pred_contrib to the model score (log-odds)."""
    row = {"feature": feature, "value": value, "baseline": baseline, "baseline_source": baseline_source}
    if contribution is not None:
        row["contribution"] = contribution
    return row


@dataclass
class Alert:
    """A structured threat alert (sih26145.alert.v2).

    `detection` holds the raw detector output (rule ids, ML scores, metrics) — this was the
    v1 `evidence` object. v2 `evidence` is a list of contract features with value and baseline.
    """
    threat_class: str
    detector: Dict[str, str]
    flow: Dict[str, Any]
    confidence: float
    severity: str
    detection: Dict[str, Any]
    feature_summary: Dict[str, Any]
    evidence: List[Dict[str, Any]] = field(default_factory=list)
    flow_id: Optional[str] = None
    observability_state: Optional[str] = None
    substitutions: List[Dict[str, Any]] = field(default_factory=list)
    contract_version: Optional[str] = field(default_factory=lambda: load_contract().version)
    model_version: Optional[str] = None
    campaign_id: Optional[str] = None
    host_stage: Optional[str] = None
    record_hash: Optional[str] = None
    # Fast lane (docs/ARCHITECTURE.md §9a): true until the flow lane confirms; the confirming
    # alert names the provisional one in `confirms`.
    provisional: bool = False
    confirms: Optional[str] = None
    # Aggregate alerts (per destination / per source): flow_id is a window id and these are the
    # Community IDs of the top contributing flows, the triggering flow first (§10).
    contributing_flows: Optional[List[str]] = None
    version: str = "2.0"
    alert_id: str = field(default_factory=lambda: f"urn:uuid:{uuid.uuid4()}")
    timestamp: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())

    def __post_init__(self):
        if self.observability_state is not None and self.observability_state not in OBSERVABILITY_STATES:
            raise ValueError(f"invalid observability_state {self.observability_state!r}")

    def to_dict(self) -> Dict[str, Any]:
        """Return the alert as a dictionary in the sih26145.alert.v2 shape."""
        raw_dict = {
            "$schema": SCHEMA_V2,
            "version": self.version,
            "alert_id": self.alert_id,
            "timestamp": self.timestamp,
            "flow_id": self.flow_id,
            "threat_class": self.threat_class,
            "confidence": round(max(0.0, min(1.0, float(self.confidence))), 4),
            "severity": self.severity,
            "evidence": deepcopy(self.evidence),
            "observability_state": self.observability_state,
            "substitutions": deepcopy(self.substitutions),
            "contract_version": self.contract_version,
            "model_version": self.model_version,
            "campaign_id": self.campaign_id,
            "host_stage": self.host_stage,
            "record_hash": self.record_hash,
            "provisional": self.provisional,
            "confirms": self.confirms,
            "contributing_flows": list(self.contributing_flows) if self.contributing_flows is not None else None,
            "detector": deepcopy(self.detector),
            "detection": deepcopy(self.detection),
            "flow": deepcopy(self.flow),
            "feature_summary": deepcopy(self.feature_summary),
        }
        return _sanitize_value(raw_dict)

    def to_json(self, indent: int = 2) -> str:
        """Return JSON-formatted alert string."""
        return json.dumps(self.to_dict(), indent=indent)


def upgrade_v1_dict(d: Dict[str, Any]) -> Dict[str, Any]:
    """Rewrite a stored sih26145.alert.v1 dict into the v2 shape.

    Fields v1 never measured stay null (observability_state, contract_version,
    model_version) rather than being back-filled with values that were never observed.
    """
    if d.get("version") != "1.0":
        return d
    old = d.get("evidence") if isinstance(d.get("evidence"), dict) else {}
    if {"rule_matches", "ml_scores", "metrics"} & set(old):
        detection = {"rule_matches": old.get("rule_matches", []), "ml_scores": old.get("ml_scores", []),
                     "metrics": old.get("metrics", {})}
    else:
        detection = {"rule_matches": [], "ml_scores": [], "metrics": old}
    features = load_contract().features
    metrics = detection["metrics"] if isinstance(detection["metrics"], dict) else {}
    flow = d.get("flow") or {}
    try:
        flow_id = community_id(flow["protocol"], flow["src_ip"], flow["dst_ip"],
                               flow.get("src_port", 0), flow.get("dst_port", 0))
    except (KeyError, ValueError, TypeError):
        flow_id = None

    up = {k: v for k, v in d.items() if k != "evidence"}
    up.update({
        "$schema": SCHEMA_V2,
        "version": "2.0",
        "flow_id": flow_id,
        "evidence": [evidence_item(k, v) for k, v in metrics.items() if k in features],
        "observability_state": None,
        "substitutions": [],
        "contract_version": None,
        "model_version": None,
        "campaign_id": None,
        "host_stage": None,
        "record_hash": None,
        "detection": detection,
        "migrated_from": "1.0",
    })
    return up
