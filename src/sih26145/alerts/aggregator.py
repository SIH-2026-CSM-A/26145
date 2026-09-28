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


# Detectors whose hits name a destination or a source rather than one flow (RuleHit.entity).
# Their alerts get a window flow_id and the top contributing flows (docs/ARCHITECTURE.md §10).
AGGREGATE_SCOPE = {"ddos_volume_detector": "dst", "recon_portscan_detector": "src",
                   "dga_lexical_detector": "src", "dns_tunnel_detector": "src", "fastlane_detector": None}
TOP_N = 5


def window_id(scope: str, entity: str, start: float, length: float) -> str:
    """flow_id of an aggregate alert: win:<dst|src>:<ip>:<window start, epoch s>:<length s>."""
    return f"win:{scope}:{entity}:{int(start)}:{int(length)}"


class WindowTopFlows:
    """Top-N flows by bytes per destination and per source in the current store window, kept
    so an aggregate alert can name the flows that made it. Bounded: `cap` entities per scope."""

    def __init__(self, window: float, n: int = TOP_N, cap: int = 4096):
        self.window, self.n, self.cap = window, n, cap
        self._t = {"dst": {}, "src": {}}  # entity -> [wid, [(bytes, cid), ...]]

    def update(self, flow: FlowRecord) -> None:
        wid, cid, nbytes = int(flow.last_time // self.window), _flow_id(flow), flow.total_bytes
        for scope, ip in (("dst", flow.flow_key.dst_ip), ("src", flow.flow_key.src_ip)):
            table = self._t[scope]
            row = table.get(ip)
            if row is None or row[0] != wid:
                if row is None and len(table) >= self.cap:
                    table.pop(next(iter(table)))
                row = table[ip] = [wid, []]
            top = row[1]
            if len(top) < self.n or nbytes > top[-1][0]:
                top.append((nbytes, cid))
                top.sort(key=lambda x: -x[0])
                del top[self.n:]

    def top(self, scope: str, ip: str, trigger: str) -> List[str]:
        row = self._t[scope].get(ip)
        rest = [cid for _, cid in (row[1] if row else ()) if cid != trigger]
        return [trigger] + rest[: self.n - 1]


def provisional_alert(scope: str, hit: RuleHit, win) -> Alert:
    """A fast-lane hit as an alert v2: provisional until the flow lane confirms it."""
    rows, metrics = _split_evidence(hit.evidence, load_contract().features)
    tuples = win.contributing(scope, hit.entity, TOP_N)
    proto, src, dst, sport, dport = tuples[0]
    packets = win.packets(scope, hit.entity)
    start = datetime.fromtimestamp(win.start, tz=timezone.utc).isoformat()
    end = datetime.fromtimestamp(win.start + 1.0, tz=timezone.utc).isoformat()
    return Alert(
        threat_class=hit.threat_class,
        detector={"name": hit.detector_name, "type": "RULE", "version": RULESET_VERSION},
        flow={"src_ip": src, "dst_ip": dst, "dst_port": int(dport or 0), "protocol": proto,
              "window_start": start, "window_end": end, "src_port": int(sport or 0)},
        confidence=float(hit.confidence), severity=hit.severity,
        detection={"rule_matches": [hit.rule_id], "ml_scores": [], "metrics": metrics,
                   "lane": "fast lane, 1-s window", "entity": hit.entity},
        feature_summary={"total_packets": int(packets or 0), "total_bytes": 0, "pps": float(packets or 0), "bps": 0.0},
        evidence=rows, flow_id=window_id(scope, hit.entity, win.start, 1.0),
        observability_state=None,  # measured per flow; the fast lane sees packets, not flows
        model_version=f"rules-{RULESET_VERSION}", timestamp=end, provisional=True,
        contributing_flows=[community_id(*t) for t in tuples],
    )


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

    def __init__(self, ml_can_alert: bool = ML_MODEL_VERSION != "synthetic-baseline",
                 top: Optional[WindowTopFlows] = None):
        self.ml_can_alert = ml_can_alert
        self.top = top  # set by the orchestrator: aggregate alerts then name their top flows

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
                    "entity": rh.entity,
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

            scope, entity = AGGREGATE_SCOPE.get(data["detector_name"]), data.get("entity")
            aggregate_id = contributing = None
            if scope and entity:
                wstart = (flow.last_time // self.top.window) * self.top.window if self.top else flow.last_time
                aggregate_id = window_id(scope, entity, wstart, self.top.window if self.top else 0)
                contributing = self.top.top(scope, entity, flow_id) if self.top else [flow_id]
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
                    **({"entity": entity} if aggregate_id else {}),
                },
                feature_summary=feature_summary,
                evidence=data["evidence"],
                flow_id=aggregate_id or flow_id,
                contributing_flows=contributing,
                observability_state=flow.observability_state,
                substitutions=data["substitutions"],
                model_version=model_version,
                timestamp=end_iso,
            )
            alerts.append(alert)

        return alerts
