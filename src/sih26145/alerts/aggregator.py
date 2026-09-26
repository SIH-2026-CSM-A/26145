"""Evidence Aggregator Engine for SIH26145."""

import math
from copy import deepcopy
from datetime import datetime, timezone
from typing import List, Dict, Any, Optional

from sih26145.contract import load_contract
from sih26145.flow.community_id import community_id
from sih26145.flow.models import FlowRecord
from sih26145.features.models import FeatureVector
from sih26145.detectors.models import RuleHit, RULESET_VERSION
from sih26145.models.schemas import MLPrediction, ML_MODEL_VERSION
from sih26145.alerts.models import Alert, evidence_item


SEVERITY_RANKS = {"LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}
RANK_TO_SEVERITY = {1: "LOW", 2: "MEDIUM", 3: "HIGH", 4: "CRITICAL"}


def _resolve_ml_severity(probability: float) -> str:
    """Map ML prediction probability/score to standard severity category.
    
    NOTE ON ARCHITECTURE SEMANTICS:
    docs/ARCHITECTURE.md Section 9 & 10 specifies severity levels (LOW, MEDIUM, HIGH, CRITICAL)
    but leaves exact numerical ML score threshold mapping unspecified. The 0.8 boundary
    is an explicit implementation convention, not an architecture-mandated constant.
    """
    if probability >= 0.8:
        return "HIGH"
    elif probability >= 0.5:
        return "MEDIUM"
    return "LOW"


ML_ONLY_MAX_SEVERITY = "MEDIUM"  # a model alone never raises HIGH or CRITICAL


def _cap_ml_only(severity: str) -> str:
    return RANK_TO_SEVERITY[min(SEVERITY_RANKS[severity], SEVERITY_RANKS[ML_ONLY_MAX_SEVERITY])]


def _ml_evidence(m: MLPrediction) -> List[Dict[str, Any]]:
    """The flow's top LightGBM pred_contrib features with their values."""
    return [evidence_item(f, v, None, "lgbm_pred_contrib", contribution=c) for f, v, c in m.evidence]


def _flow_id(flow: FlowRecord) -> str:
    key = flow.flow_key
    if key.protocol in ("ICMP", "ICMPv6"):
        return community_id(key.protocol, key.src_ip, key.dst_ip, flow.icmp_type or 0, flow.icmp_code or 0)
    return community_id(key.protocol, key.src_ip, key.dst_ip, key.src_port or 0, key.dst_port)


def _split_evidence(raw: Dict[str, Any], features) -> tuple:
    """RuleHit evidence -> (v2 evidence rows for contract features, flat metrics dict)."""
    rows, metrics = [], {}
    for name, v in raw.items():
        if isinstance(v, dict) and "value" in v:
            value, baseline, source = v["value"], v.get("baseline"), v.get("baseline_source")
        else:
            value, baseline, source = v, None, None
        metrics[name] = deepcopy(value)
        if name in features:
            rows.append(evidence_item(name, deepcopy(value), baseline, source))
    return rows, metrics


class EvidenceAggregator:
    """Synthesizes RuleHits and MLPredictions into versioned Alert instances.

    ML gate: open while ML_MODEL_VERSION names trained models (not "synthetic-baseline").
    Open: a flagged flow with no rule hit raises an ML alert capped at MEDIUM (only from a model
    whose prediction allows `alerts_alone`); a flagged flow
    with rule hits raises those alerts' confidence and severity (agreement). Closed: scores
    are only attached to rule alerts.
    """

    def __init__(self, ml_can_alert: bool = ML_MODEL_VERSION != "synthetic-baseline"):
        self.ml_can_alert = ml_can_alert

    def _attach(self, groups: Dict[str, Dict[str, Any]], flagged: List[MLPrediction]) -> None:
        """Rule + model on the same flow. Closed gate: the scores are attached and nothing
        else changes. Open gate: agreement raises confidence to the higher of the two and
        severity by one level, and the model's top features join the evidence."""
        top = max(float(m.probability) for m in flagged)
        for data in groups.values():
            data["ml_scores"] += [round(float(m.probability), 4) for m in flagged]
            data["detector_type"] = "HYBRID_RULE_ML"
            if self.ml_can_alert:
                data["confidence"] = min(1.0, max(data["confidence"], top))
                data["severity"] = RANK_TO_SEVERITY[min(4, SEVERITY_RANKS.get(data["severity"], 1) + 1)]
                data["evidence"] += _ml_evidence(flagged[0])

    def aggregate(
        self,
        flow: FlowRecord,
        fv: FeatureVector,
        rule_hits: List[RuleHit],
        ml_predictions: List[MLPrediction],
    ) -> List[Alert]:
        """Fuse rule hits and ML predictions into structured versioned Alerts."""
        alerts: List[Alert] = []
        threat_groups: Dict[str, Dict[str, Any]] = {}

        # 1. Process Rule Hits (Phase 07)
        features = load_contract().features
        for rh in rule_hits:
            tc = rh.threat_class
            rows, metrics = _split_evidence(rh.evidence, features)
            if tc not in threat_groups:
                threat_groups[tc] = {
                    "rule_matches": [rh.rule_id],
                    "ml_scores": [],
                    "severity": rh.severity,
                    "confidence": float(rh.confidence),
                    "detector_name": rh.detector_name,
                    "detector_type": "RULE",
                    "metrics": metrics,
                    "evidence": rows,
                    "substitutions": [deepcopy(s) for s in rh.substitutions],
                }
            else:
                if rh.rule_id not in threat_groups[tc]["rule_matches"]:
                    threat_groups[tc]["rule_matches"].append(rh.rule_id)
                threat_groups[tc]["confidence"] = max(threat_groups[tc]["confidence"], float(rh.confidence))
                threat_groups[tc]["metrics"].update(metrics)
                threat_groups[tc]["evidence"] += rows
                threat_groups[tc]["substitutions"] += [deepcopy(s) for s in rh.substitutions]
                
                current_rank = SEVERITY_RANKS.get(threat_groups[tc]["severity"], 1)
                new_rank = SEVERITY_RANKS.get(rh.severity, 1)
                threat_groups[tc]["severity"] = RANK_TO_SEVERITY[max(current_rank, new_rank)]

        # 2. ML predictions: models flag a flow; they do not name a rule's class
        flagged = [m for m in ml_predictions if m.is_anomaly and m.threat_class != "BENIGN"]
        if flagged and threat_groups:
            self._attach(threat_groups, flagged)
        elif flagged and self.ml_can_alert:
            for m in flagged:
                if not m.metadata.get("alerts_alone", True):
                    continue  # this model only corroborates rule alerts (docs/MODELS.md)
                threat_groups[m.threat_class] = {
                    "rule_matches": [],
                    "ml_scores": [round(float(m.probability), 4)],
                    "severity": _cap_ml_only(_resolve_ml_severity(float(m.probability))),
                    "confidence": float(m.probability),
                    "detector_name": m.model_name,
                    "detector_type": "ML",
                    "metrics": {**deepcopy(m.metadata), "score": round(float(m.anomaly_score), 6)},
                    "evidence": _ml_evidence(m),
                    "substitutions": [],
                }

        # 3. Formulate Alert objects for active threat groups
        start_iso = datetime.fromtimestamp(flow.start_time, tz=timezone.utc).isoformat()
        end_iso = datetime.fromtimestamp(flow.last_time, tz=timezone.utc).isoformat()
        flow_id = _flow_id(flow)

        flow_meta: Dict[str, Any] = {
            "src_ip": flow.flow_key.src_ip,
            "dst_ip": flow.flow_key.dst_ip,
            "dst_port": int(flow.flow_key.dst_port),
            "protocol": flow.flow_key.protocol,
            "window_start": start_iso,
            "window_end": end_iso,
        }
        if flow.flow_key.src_port is not None:
            flow_meta["src_port"] = int(flow.flow_key.src_port)

        pps_val = fv.pps if math.isfinite(fv.pps) else 0.0
        bps_val = fv.bps if math.isfinite(fv.bps) else 0.0

        feature_summary = {
            "total_packets": int(fv.total_packets),
            "total_bytes": int(fv.total_bytes),
            "pps": round(float(pps_val), 2),
            "bps": round(float(bps_val), 2),
        }

        for tc, data in threat_groups.items():
            detector_info = {
                "name": data["detector_name"],
                "type": data["detector_type"],
                "version": ML_MODEL_VERSION if data["detector_type"] == "ML" else RULESET_VERSION,
            }
            model_version = {
                "RULE": f"rules-{RULESET_VERSION}",
                "ML": f"ml-{ML_MODEL_VERSION}",
                "HYBRID_RULE_ML": f"rules-{RULESET_VERSION}+ml-{ML_MODEL_VERSION}",
            }[data["detector_type"]]

            alert = Alert(
                threat_class=tc,
                detector=detector_info,
                flow=flow_meta,
                confidence=min(1.0, max(0.0, float(data["confidence"]))),
                severity=data["severity"],
                detection={
                    "rule_matches": data["rule_matches"],
                    "ml_scores": data["ml_scores"],
                    "metrics": data["metrics"],
                },
                feature_summary=feature_summary,
                evidence=data["evidence"],
                flow_id=flow_id,
                observability_state=flow.observability_state,
                substitutions=data["substitutions"],
                model_version=model_version,
                timestamp=end_iso,
            )
            alerts.append(alert)

        return alerts
