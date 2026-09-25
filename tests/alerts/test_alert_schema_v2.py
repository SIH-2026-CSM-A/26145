"""sih26145.alert.v2: every field present, typed, and derived from the flow it describes."""

from datetime import datetime, timezone

import pytest

from sih26145.alerts import Alert, EvidenceAggregator
from sih26145.contract import load_contract
from sih26145.detectors import RuleHit
from sih26145.detectors.models import RULESET_VERSION
from sih26145.features import FeatureExtractor
from sih26145.flow import FlowTracker
from sih26145.flow.community_id import community_id
from sih26145.ingest.models import PacketMetadata
from sih26145.models import MLPrediction

V2_KEYS = {
    "$schema", "version", "alert_id", "timestamp", "flow_id", "threat_class", "confidence",
    "severity", "evidence", "observability_state", "substitutions", "contract_version",
    "model_version", "campaign_id", "host_stage", "record_hash", "detector", "detection",
    "flow", "feature_summary",
}
CLIENT, SERVER = ("192.168.1.52", 54585), ("8.8.8.8", 53)


def make_flow(both_halves: bool):
    tracker = FlowTracker()
    tracker.process_packet(PacketMetadata(10.0, 80, 80, 4, CLIENT[0], SERVER[0], "UDP", src_port=CLIENT[1], dst_port=SERVER[1]))
    if both_halves:
        tracker.process_packet(PacketMetadata(10.5, 120, 120, 4, SERVER[0], CLIENT[0], "UDP", src_port=SERVER[1], dst_port=CLIENT[1]))
    (flow,) = tracker.flush_expired(1000.0)
    return flow


def rule_hit(**kw):
    base = dict(detector_name="dns_tunnel_detector", threat_class="THREAT_DNS_TUNNEL",
                rule_id="RULE_X", severity="HIGH", confidence=0.9, evidence={"dns_query_count": 7})
    base.update(kw)
    return RuleHit(**base)


def aggregate(flow, hits, preds=()):
    return EvidenceAggregator().aggregate(flow, FeatureExtractor().extract(flow), list(hits), list(preds))


def test_v2_alert_carries_every_field_derived_from_the_flow():
    flow = make_flow(both_halves=True)
    (alert,) = aggregate(flow, [rule_hit()])
    d = alert.to_dict()

    assert set(d) == V2_KEYS
    assert d["$schema"].endswith("alert.v2.json") and d["version"] == "2.0"
    assert d["flow_id"] == "1:d/FP5EW3wiY1vCndhwleRRKHowQ=" == community_id("UDP", *CLIENT[:1], SERVER[0], CLIENT[1], SERVER[1])
    assert d["timestamp"] == datetime.fromtimestamp(10.5, tz=timezone.utc).isoformat()
    assert d["observability_state"] == "bidirectional"
    assert d["contract_version"] == load_contract().version
    assert d["model_version"] == f"rules-{RULESET_VERSION}"
    assert d["evidence"] == [{"feature": "dns_query_count", "value": 7, "baseline": None, "baseline_source": None}]
    assert d["substitutions"] == []
    assert d["campaign_id"] is None and d["host_stage"] is None and d["record_hash"] is None
    assert d["detection"]["rule_matches"] == ["RULE_X"]


def test_observability_state_is_measured_per_flow():
    (one_sided,) = aggregate(make_flow(both_halves=False), [rule_hit()])
    assert one_sided.to_dict()["observability_state"] == "forward_only"


def test_evidence_rows_keep_baselines_and_only_contract_features():
    hit = rule_hit(evidence={
        "dns_query_count": {"value": 40, "baseline": 3.5, "baseline_source": "host_ewma"},
        "not_a_contract_feature": 1,
    }, substitutions=({"unavailable_on_this_flow": "dns_nxdomain_rate", "substituted_by": ["dns_query_count"]},))
    (alert,) = aggregate(make_flow(True), [hit])
    d = alert.to_dict()
    assert d["evidence"] == [{"feature": "dns_query_count", "value": 40, "baseline": 3.5, "baseline_source": "host_ewma"}]
    assert d["detection"]["metrics"] == {"dns_query_count": 40, "not_a_contract_feature": 1}
    assert d["substitutions"][0]["unavailable_on_this_flow"] == "dns_nxdomain_rate"


def test_alerts_carrying_ml_scores_declare_the_synthetic_model():
    """Gated: a synthetic prediction alone raises nothing; attached to a rule alert, the
    alert's model_version names the synthetic model."""
    pred = MLPrediction("isolation_forest_anomaly_detector", "THREAT_UNSUPERVISED_ANOMALY", -0.2, 0.7, True)
    assert aggregate(make_flow(True), [], [pred]) == []
    hit = RuleHit("x", "THREAT_UNSUPERVISED_ANOMALY", "RULE_X", "LOW", 0.5)
    (alert,) = aggregate(make_flow(True), [hit], [pred])
    assert alert.to_dict()["model_version"] == f"rules-{RULESET_VERSION}+ml-synthetic-baseline"


def test_invalid_observability_state_is_rejected():
    with pytest.raises(ValueError):
        Alert("THREAT_TEST", {}, {}, 0.5, "LOW", {}, {}, observability_state="unidirectional")
