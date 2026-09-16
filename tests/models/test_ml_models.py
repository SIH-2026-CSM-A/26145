"""Unit tests for classical ML anomaly detectors and threat classifiers."""

import math
import numpy as np
import pytest
from sih26145.features.models import FeatureVector
from sih26145.models import (
    MLPrediction,
    IsolationForestAnomalyDetector,
    RandomForestThreatClassifier,
    MLModelSuite,
)
from sih26145.models.anomaly import feature_vector_to_array


def make_fv(**kwargs) -> FeatureVector:
    defaults = {
        "flow_key_str": "192.168.1.10->10.0.0.1:80/TCP",
        "duration": 2.0,
        "total_packets": 5,
        "total_bytes": 500,
        "pps": 2.5,
        "bps": 250.0,
        "pkt_size_min": 100.0,
        "pkt_size_max": 100.0,
        "pkt_size_mean": 100.0,
        "pkt_size_std": 0.0,
        "pkt_size_q25": 100.0,
        "pkt_size_q50": 100.0,
        "pkt_size_q75": 100.0,
        "iat_mean": 0.5,
        "iat_var": 0.01,
        "iat_min": 0.4,
        "iat_max": 0.6,
        "jitter": 0.05,
        "burstiness_ratio": 0.0,
        "small_pkt_ratio": 0.0,
        "is_tcp": 1.0,
        "is_udp": 0.0,
        "is_icmp": 0.0,
        "dst_port": 80,
        "dns_query_count": 0,
        "dns_max_domain_entropy": 0.0,
        "dns_max_subdomain_depth": 0,
        "tls_client_hello_count": 0,
        "tls_max_sni_entropy": 0.0,
        "tls_max_sni_length": 0,
        "has_syn": 1.0,
        "has_fin": 0.0,
        "has_rst": 0.0,
    }
    defaults.update(kwargs)
    return FeatureVector(**defaults)


def test_feature_vector_to_array_shape_and_sanitization():
    fv = make_fv()
    arr = feature_vector_to_array(fv)
    assert arr.shape == (32,)
    assert arr.dtype == np.float64
    assert np.all(np.isfinite(arr))

    # Test non-finite value handling (NaN, +Inf, -Inf)
    fv_nan = make_fv(duration=float("nan"), pps=float("inf"), bps=float("-inf"))
    arr_nan = feature_vector_to_array(fv_nan)
    assert arr_nan.shape == (32,)
    assert np.all(np.isfinite(arr_nan))
    assert arr_nan[0] == 0.0
    assert arr_nan[3] == 0.0
    assert arr_nan[4] == 0.0


def test_isolation_forest_anomaly_detector():
    detector = IsolationForestAnomalyDetector(contamination=0.01)
    benign_samples = [make_fv(total_packets=10+i, total_bytes=500+i*10, pps=2.5+i*0.1) for i in range(50)]
    detector.fit_baseline(benign_samples)
    
    normal_fv = make_fv(total_packets=25, total_bytes=650, pps=3.0)
    pred_normal = detector.predict(normal_fv)
    assert isinstance(pred_normal, MLPrediction)
    assert pred_normal.model_name == "isolation_forest_anomaly_detector"
    assert pred_normal.is_anomaly is False
    assert 0.0 <= pred_normal.probability <= 1.0
    
    anomaly_fv = make_fv(total_packets=50000, total_bytes=50000000, pps=25000.0, bps=25000000.0)
    pred_anomaly = detector.predict(anomaly_fv)
    assert pred_anomaly.is_anomaly is True


def test_isolation_forest_decision_score_boundary():
    detector = IsolationForestAnomalyDetector(contamination=0.05)
    fv = make_fv()
    pred = detector.predict(fv)
    
    # Check decision score inequality consistency
    expected_is_anomaly = bool(pred.anomaly_score < 0.0)
    assert pred.is_anomaly == expected_is_anomaly
    assert pred.metadata["decision_threshold"] == 0.0


def test_random_forest_threat_classifier_classes_and_probabilities():
    classifier = RandomForestThreatClassifier()
    classifier.fit_synthetic_baseline()
    
    fv = make_fv()
    pred = classifier.predict(fv)
    
    assert isinstance(pred, MLPrediction)
    assert pred.model_name == "random_forest_threat_classifier"
    
    # Class probability dictionary checks
    class_probs = pred.metadata["class_probabilities"]
    assert len(class_probs) == 4
    for c in ["BENIGN", "THREAT_C2_BEACON", "THREAT_DNS_DGA", "THREAT_EXFILTRATION"]:
        assert c in class_probs
        assert 0.0 <= class_probs[c] <= 1.0
    
    # Sum of probabilities must equal ~1.0
    total_prob = sum(class_probs.values())
    assert abs(total_prob - 1.0) < 1e-4


def test_random_forest_synthetic_evaluation_all_classes():
    classifier = RandomForestThreatClassifier()
    classifier.fit_synthetic_baseline()

    # 1. Benign sample
    fv_benign = make_fv(duration=2.5, total_packets=7, total_bytes=600, pps=3.0, bps=300.0, dst_port=80)
    pred_b = classifier.predict(fv_benign)
    assert pred_b.threat_class == "BENIGN"

    # 2. C2 Beacon sample
    fv_c2 = make_fv(duration=32.0, total_packets=32, total_bytes=1500, pps=1.0, bps=50.0, iat_mean=1.0, iat_var=0.00001, dst_port=443)
    pred_c2 = classifier.predict(fv_c2)
    assert pred_c2.threat_class == "THREAT_C2_BEACON"

    # 3. DGA sample
    fv_dga = make_fv(duration=0.5, total_packets=2, total_bytes=200, is_tcp=0.0, is_udp=1.0, dst_port=53, dns_query_count=1, dns_max_domain_entropy=4.6)
    pred_dga = classifier.predict(fv_dga)
    assert pred_dga.threat_class == "THREAT_DNS_DGA"

    # 4. Exfiltration sample
    fv_exfil = make_fv(duration=12.0, total_packets=500, total_bytes=5000000, pps=50.0, bps=4000000.0, small_pkt_ratio=0.01, dst_port=8080)
    pred_exfil = classifier.predict(fv_exfil)
    assert pred_exfil.threat_class == "THREAT_EXFILTRATION"


def test_zero_vector_and_extreme_values():
    suite = MLModelSuite()
    
    # Zero vector
    fv_zero = make_fv(
        duration=0.0, total_packets=0, total_bytes=0, pps=0.0, bps=0.0,
        pkt_size_min=0.0, pkt_size_max=0.0, pkt_size_mean=0.0, pkt_size_std=0.0,
        pkt_size_q25=0.0, pkt_size_q50=0.0, pkt_size_q75=0.0,
        iat_mean=0.0, iat_var=0.0, iat_min=0.0, iat_max=0.0, jitter=0.0,
        burstiness_ratio=0.0, small_pkt_ratio=0.0, is_tcp=0.0, is_udp=0.0, is_icmp=0.0,
        dst_port=0, dns_query_count=0, dns_max_domain_entropy=0.0, dns_max_subdomain_depth=0,
        tls_client_hello_count=0, tls_max_sni_entropy=0.0, tls_max_sni_length=0,
        has_syn=0.0, has_fin=0.0, has_rst=0.0
    )
    preds_zero = suite.predict(fv_zero)
    assert len(preds_zero) == 2
    for p in preds_zero:
        assert isinstance(p, MLPrediction)
        assert np.isfinite(p.probability)

    # Extreme vector
    fv_extreme = make_fv(
        duration=1e6, total_packets=1000000, total_bytes=1000000000,
        pps=1e6, bps=1e9, burstiness_ratio=100.0
    )
    preds_extreme = suite.predict(fv_extreme)
    assert len(preds_extreme) == 2
    for p in preds_extreme:
        assert isinstance(p, MLPrediction)
        assert np.isfinite(p.probability)


def test_deterministic_ml_model_suite_evaluation():
    suite = MLModelSuite()
    fv = make_fv(pps=15000.0)
    preds1 = suite.predict(fv)
    preds2 = suite.predict(fv)
    assert preds1 == preds2
