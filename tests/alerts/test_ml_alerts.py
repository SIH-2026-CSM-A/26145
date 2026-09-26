"""With the gate open: ML-only alerts are capped at MEDIUM, rule + model agreement raises
severity, and every ML-raised alert carries its top pred_contrib features."""

import pytest

from sih26145.alerts import EvidenceAggregator
from sih26145.detectors import RuleHit
from sih26145.features import FeatureExtractor
from sih26145.flow.models import FlowKey, FlowRecord
from sih26145.models import MLPrediction
from sih26145.models.schemas import ML_MODEL_VERSION

EVIDENCE = (("pair_iat_n", 40.0, 2.1), ("dst_port_class", 2.0, -0.4))


def flow_and_fv():
    key = FlowKey(src_ip="192.168.1.10", src_port=12345, dst_ip="203.0.113.9", dst_port=8080, protocol="TCP")
    flow = FlowRecord(flow_key=key, start_time=1700000000.0, last_time=1700000002.0, packet_count=20, total_bytes=2000)
    return flow, FeatureExtractor().extract(flow)


def lgbm(p):
    return MLPrediction("lightgbm_flow_classifier", "THREAT_ML_MALICIOUS_FLOW", p, p, True, {"threshold": 0.5}, EVIDENCE)


def test_trained_models_open_the_gate():
    assert ML_MODEL_VERSION != "synthetic-baseline" and EvidenceAggregator().ml_can_alert


@pytest.mark.parametrize("p", [0.51, 0.8, 0.99])
def test_ml_only_alert_is_capped_at_medium(p):
    (alert,) = EvidenceAggregator().aggregate(*flow_and_fv(), [], [lgbm(p)])
    assert alert.detector["type"] == "ML" and alert.threat_class == "THREAT_ML_MALICIOUS_FLOW"
    assert alert.severity in ("LOW", "MEDIUM")


def test_ml_only_alert_carries_its_top_contributing_features():
    (alert,) = EvidenceAggregator().aggregate(*flow_and_fv(), [], [lgbm(0.9)])
    assert [(e["feature"], e["value"], e["contribution"], e["baseline_source"]) for e in alert.evidence] == \
        [("pair_iat_n", 40.0, 2.1, "lgbm_pred_contrib"), ("dst_port_class", 2.0, -0.4, "lgbm_pred_contrib")]


def test_rule_and_model_agreement_raises_severity_one_level():
    hit = RuleHit("c2_beacon_detector", "THREAT_C2_BEACON", "RULE_C2_PERIODIC_FLOWS", "HIGH", 0.8, {"pair_iat_n": 12})
    (alert,) = EvidenceAggregator().aggregate(*flow_and_fv(), [hit], [lgbm(0.9)])
    assert alert.threat_class == "THREAT_C2_BEACON" and alert.detector["type"] == "HYBRID_RULE_ML"
    assert alert.severity == "CRITICAL" and alert.confidence == 0.9
    assert {e["feature"] for e in alert.evidence} >= {"pair_iat_n", "dst_port_class"}


def test_unflagged_model_scores_change_nothing():
    quiet = MLPrediction("lightgbm_flow_classifier", "THREAT_ML_MALICIOUS_FLOW", 0.1, 0.1, False)
    assert EvidenceAggregator().aggregate(*flow_and_fv(), [], [quiet]) == []


def test_a_corroborating_model_raises_nothing_alone_but_agrees_with_rules():
    forest = MLPrediction("isolation_forest_flow_model", "THREAT_UNSUPERVISED_ANOMALY", 0.7, 0.99, True,
                          {"alerts_alone": False}, EVIDENCE)
    assert EvidenceAggregator().aggregate(*flow_and_fv(), [], [forest]) == []
    hit = RuleHit("recon_portscan_detector", "THREAT_RECON_PORTSCAN", "RULE_RECON_FANOUT_SYN_ONLY", "MEDIUM", 0.7)
    (alert,) = EvidenceAggregator().aggregate(*flow_and_fv(), [hit], [forest])
    assert alert.severity == "HIGH" and alert.detection["ml_scores"] == [0.99]


def test_shipped_forest_corroborates_only():
    from sih26145.models import MLModelSuite
    assert MLModelSuite().alone == {"lgbm": True, "iforest": False}
