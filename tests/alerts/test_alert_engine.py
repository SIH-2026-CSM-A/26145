"""Adversarial and boundary unit tests for EvidenceAggregator and Alert schema contract."""

import json
import math
import pytest

from sih26145.flow.models import FlowKey, FlowRecord
from sih26145.features import FeatureExtractor
from sih26145.detectors import RuleHit, RuleDetectorSuite
from sih26145.models import MLPrediction
from sih26145.alerts import Alert, EvidenceAggregator
from sih26145.alerts.aggregator import _resolve_ml_severity


def test_alert_schema_contract():
    alert = Alert(
        threat_class="THREAT_DNS_TUNNEL",
        detector={"name": "dns_tunnel_detector", "type": "HYBRID_RULE_ML", "version": "1.0.0"},
        flow={"src_ip": "192.168.1.100", "dst_ip": "10.0.0.53", "dst_port": 53, "protocol": "UDP", "window_start": "2026-09-16T15:00:00Z", "window_end": "2026-09-16T15:00:15Z"},
        confidence=0.92,
        severity="HIGH",
        detection={"rule_matches": ["RULE_DNS_TUNNEL_PAYLOAD_DEPTH"], "ml_scores": [0.89], "metrics": {"subdomain_depth": 5}},
        feature_summary={"total_packets": 50, "total_bytes": 15000, "pps": 3.33, "bps": 1000.0},
    )
    
    d = alert.to_dict()
    assert d["$schema"] == "https://sih26145.ntro.gov.in/schemas/alert.v2.json"
    assert d["version"] == "2.0"
    assert d["alert_id"].startswith("urn:uuid:")
    assert "timestamp" in d
    assert d["threat_class"] == "THREAT_DNS_TUNNEL"
    assert d["confidence"] == 0.92
    assert d["severity"] == "HIGH"
    
    # Verify JSON round-trip
    json_str = alert.to_json()
    parsed = json.loads(json_str)
    assert parsed["alert_id"] == d["alert_id"]
    assert parsed["$schema"] == d["$schema"]


def test_confidence_bounding_and_quantization():
    # Exact boundaries: 0.0, 1.0, 0.9999, 1.05 -> capped to 1.0
    a_exact_zero = Alert("THREAT_TEST", {}, {}, 0.0, "LOW", {}, {})
    assert a_exact_zero.to_dict()["confidence"] == 0.0

    a_exact_one = Alert("THREAT_TEST", {}, {}, 1.0, "HIGH", {}, {})
    assert a_exact_one.to_dict()["confidence"] == 1.0

    a_below = Alert("THREAT_TEST", {}, {}, 0.9999, "HIGH", {}, {})
    assert a_below.to_dict()["confidence"] == 0.9999

    a_above = Alert("THREAT_TEST", {}, {}, 1.05, "HIGH", {}, {})
    assert a_above.to_dict()["confidence"] == 1.0


def test_ml_severity_implementation_convention_resolution():
    """Test implementation convention for ML probability -> severity mapping.
    
    Note: docs/ARCHITECTURE.md defines severity categories (LOW, MEDIUM, HIGH, CRITICAL)
    without specifying exact numerical ML probability threshold values.
    """
    # Exact boundary 0.8 -> HIGH
    assert _resolve_ml_severity(0.8) == "HIGH"
    # Just-below 0.799999 -> MEDIUM
    assert _resolve_ml_severity(0.799999) == "MEDIUM"
    # Just-above 0.800001 -> HIGH
    assert _resolve_ml_severity(0.800001) == "HIGH"
    # Below 0.5 -> LOW
    assert _resolve_ml_severity(0.499) == "LOW"


def test_evidence_aggregation_rule_only():
    key = FlowKey(src_ip="192.168.1.10", src_port=12345, dst_ip="10.0.0.1", dst_port=80, protocol="TCP")
    flow = FlowRecord(flow_key=key, start_time=1700000000.0, last_time=1700000002.0, packet_count=20000, total_bytes=20000000, packet_sizes=[1000]*20000)
    fv = FeatureExtractor().extract(flow)
    
    rule_hits = [
        RuleHit(
            detector_name="ddos_volume_detector",
            threat_class="THREAT_DDOS_VOLUME",
            rule_id="RULE_DDOS_VOLUME_THRESHOLD",
            severity="CRITICAL",
            confidence=0.95,
            evidence={"pps": fv.pps}
        )
    ]
    
    aggregator = EvidenceAggregator()
    alerts = aggregator.aggregate(flow, fv, rule_hits, [])
    assert len(alerts) == 1
    assert alerts[0].detector["type"] == "RULE"
    assert alerts[0].confidence == 0.95
    assert alerts[0].severity == "CRITICAL"


def test_evidence_aggregation_ml_only():
    key = FlowKey(src_ip="192.168.1.10", src_port=12345, dst_ip="10.0.0.1", dst_port=80, protocol="TCP")
    flow = FlowRecord(flow_key=key, start_time=1700000000.0, last_time=1700000002.0, packet_count=20, total_bytes=2000)
    fv = FeatureExtractor().extract(flow)
    
    ml_preds = [
        MLPrediction(
            model_name="isolation_forest_anomaly_detector",
            threat_class="THREAT_UNSUPERVISED_ANOMALY",
            anomaly_score=-0.5,
            probability=0.85,
            is_anomaly=True,
            metadata={"contamination": 0.05}
        )
    ]
    
    aggregator = EvidenceAggregator()
    alerts = aggregator.aggregate(flow, fv, [], ml_preds)
    assert len(alerts) == 1
    assert alerts[0].detector["type"] == "ML"
    assert alerts[0].confidence == 0.85
    assert alerts[0].severity == "HIGH"


def test_evidence_aggregation_hybrid_uninvented_fused_confidence():
    key = FlowKey(src_ip="192.168.1.10", dst_ip="10.0.0.1", dst_port=80, protocol="TCP")
    flow = FlowRecord(flow_key=key, start_time=1700000000.0, last_time=1700000002.0, packet_count=20000, total_bytes=20000000)
    fv = FeatureExtractor().extract(flow)
    
    rule_hits = [
        RuleHit(
            detector_name="ddos_volume_detector",
            threat_class="THREAT_DDOS_VOLUME",
            rule_id="RULE_DDOS_VOLUME_THRESHOLD",
            severity="HIGH",
            confidence=0.90,
            evidence={"pps": fv.pps}
        )
    ]
    ml_preds = [
        MLPrediction(
            model_name="random_forest_threat_classifier",
            threat_class="THREAT_DDOS_VOLUME",
            anomaly_score=0.95,
            probability=0.95,
            is_anomaly=True,
            metadata={}
        )
    ]
    
    aggregator = EvidenceAggregator()
    alerts = aggregator.aggregate(flow, fv, rule_hits, ml_preds)
    assert len(alerts) == 1
    # Fused confidence is exact max(0.90, 0.95) = 0.95 (no arbitrary 1.1 multiplier)
    assert alerts[0].confidence == 0.95
    assert alerts[0].detector["type"] == "HYBRID_RULE_ML"


def test_benign_traffic_zero_alerts():
    key = FlowKey(src_ip="192.168.1.10", dst_ip="10.0.0.1", dst_port=80, protocol="TCP")
    flow = FlowRecord(flow_key=key, start_time=1700000000.0, last_time=1700000002.0, packet_count=3, total_bytes=600)
    fv = FeatureExtractor().extract(flow)
    
    aggregator = EvidenceAggregator()
    alerts = aggregator.aggregate(flow, fv, [], [])
    assert len(alerts) == 0


def test_payload_security_boundary():
    key = FlowKey(src_ip="192.168.1.10", dst_ip="10.0.0.1", dst_port=80, protocol="TCP")
    flow = FlowRecord(flow_key=key, start_time=1700000000.0, last_time=1700000002.0, packet_count=5, total_bytes=500)
    fv = FeatureExtractor().extract(flow)
    
    rule_hits = [
        RuleHit(
            detector_name="exfiltration_detector",
            threat_class="THREAT_EXFILTRATION",
            rule_id="RULE_EXFIL_HIGH_BYTE_STREAM",
            severity="HIGH",
            confidence=0.87,
            evidence={"bps": fv.bps}
        )
    ]
    
    aggregator = EvidenceAggregator()
    alerts = aggregator.aggregate(flow, fv, rule_hits, [])
    json_repr = json.dumps(alerts[0].to_dict())
    
    for key_name in ["raw_payload", "payload_bytes", "decrypted_payload", "plaintext_content", "packet_body"]:
        assert key_name not in json_repr


def test_nan_and_inf_float_sanitization():
    key = FlowKey(src_ip="192.168.1.10", dst_ip="10.0.0.1", dst_port=80, protocol="TCP")
    flow = FlowRecord(flow_key=key, start_time=1700000000.0, last_time=1700000000.0, packet_count=0, total_bytes=0)
    fv = FeatureExtractor().extract(flow)
    
    rule_hits = [
        RuleHit(
            detector_name="ddos_volume_detector",
            threat_class="THREAT_DDOS_VOLUME",
            rule_id="RULE_DDOS_VOLUME_THRESHOLD",
            severity="HIGH",
            confidence=0.90,
            evidence={"nan_val": float("nan"), "posinf_val": float("inf"), "neginf_val": float("-inf")}
        )
    ]
    
    aggregator = EvidenceAggregator()
    alerts = aggregator.aggregate(flow, fv, rule_hits, [])
    d = alerts[0].to_dict()
    
    assert d["detection"]["metrics"]["nan_val"] == 0.0
    assert d["detection"]["metrics"]["posinf_val"] == 0.0
    assert d["detection"]["metrics"]["neginf_val"] == 0.0
    
    json_str = alerts[0].to_json()
    assert isinstance(json_str, str)


def test_alert_immutability_and_deep_copy():
    key = FlowKey(src_ip="192.168.1.10", dst_ip="10.0.0.1", dst_port=80, protocol="TCP")
    flow = FlowRecord(flow_key=key, start_time=1700000000.0, last_time=1700000002.0, packet_count=10, total_bytes=1000)
    fv = FeatureExtractor().extract(flow)
    
    evidence_metrics = {"test_metric": 100}
    rule_hits = [
        RuleHit(
            detector_name="recon_portscan_detector",
            threat_class="THREAT_RECON_PORTSCAN",
            rule_id="RULE_RECON_SYN_SWEEP",
            severity="MEDIUM",
            confidence=0.85,
            evidence=evidence_metrics
        )
    ]
    
    aggregator = EvidenceAggregator()
    alerts = aggregator.aggregate(flow, fv, rule_hits, [])
    alert1 = alerts[0]
    
    evidence_metrics["test_metric"] = 9999
    assert alert1.to_dict()["detection"]["metrics"]["test_metric"] == 100


def test_alert_id_uniqueness():
    a1 = Alert("THREAT_TEST", {}, {}, 0.9, "HIGH", {}, {})
    a2 = Alert("THREAT_TEST", {}, {}, 0.9, "HIGH", {}, {})
    assert a1.alert_id != a2.alert_id
    assert a1.alert_id.startswith("urn:uuid:")
    assert a2.alert_id.startswith("urn:uuid:")


def test_unrelated_flows_do_not_merge():
    key1 = FlowKey(src_ip="192.168.1.10", dst_ip="10.0.0.1", dst_port=80, protocol="TCP")
    flow1 = FlowRecord(flow_key=key1, start_time=1700000000.0, last_time=1700000002.0, packet_count=20000, total_bytes=20000000)
    fv1 = FeatureExtractor().extract(flow1)

    key2 = FlowKey(src_ip="192.168.1.20", dst_ip="10.0.0.2", dst_port=443, protocol="TCP")
    flow2 = FlowRecord(flow_key=key2, start_time=1700000000.0, last_time=1700000002.0, packet_count=20000, total_bytes=20000000)
    fv2 = FeatureExtractor().extract(flow2)

    rule_hit = RuleHit("ddos_volume_detector", "THREAT_DDOS_VOLUME", "RULE_DDOS_VOLUME_THRESHOLD", "HIGH", 0.90, {})
    
    aggregator = EvidenceAggregator()
    alerts1 = aggregator.aggregate(flow1, fv1, [rule_hit], [])
    alerts2 = aggregator.aggregate(flow2, fv2, [rule_hit], [])

    assert len(alerts1) == 1
    assert len(alerts2) == 1
    assert alerts1[0].flow["src_ip"] == "192.168.1.10"
    assert alerts2[0].flow["src_ip"] == "192.168.1.20"
    assert alerts1[0].alert_id != alerts2[0].alert_id
