"""Unit tests for deterministic rule threat detectors."""

import pytest
from sih26145.features.models import FeatureVector
from sih26145.detectors import RuleDetectorSuite, RuleHit


def make_fv(**kwargs) -> FeatureVector:
    """Helper to create a default FeatureVector for testing."""
    defaults = {
        "flow_key_str": "192.168.1.10->10.0.0.1:80/TCP",
        "duration": 2.0,
        "total_packets": 3,
        "total_bytes": 600,
        "pps": 1.5,
        "bps": 300.0,
        "pkt_size_min": 100.0,
        "pkt_size_max": 300.0,
        "pkt_size_mean": 200.0,
        "pkt_size_std": 81.65,
        "pkt_size_q25": 150.0,
        "pkt_size_q50": 200.0,
        "pkt_size_q75": 250.0,
        "iat_mean": 1.0,
        "iat_var": 0.5,
        "iat_min": 0.5,
        "iat_max": 1.5,
        "jitter": 0.2,
        "burstiness_ratio": 0.4,
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
    }
    defaults.update(kwargs)
    return FeatureVector(**defaults)


def test_benign_traffic_no_rule_hits():
    suite = RuleDetectorSuite()
    fv = make_fv()
    hits = suite.evaluate(fv)
    assert len(hits) == 0


def test_ddos_volume_detector_hit():
    suite = RuleDetectorSuite()
    fv = make_fv(pps=15000.0, bps=12000000.0)
    hits = suite.evaluate(fv)
    assert len(hits) >= 1
    hit = next(h for h in hits if h.threat_class == "THREAT_DDOS_VOLUME")
    assert hit.rule_id == "RULE_DDOS_VOLUME_THRESHOLD"
    assert hit.severity == "HIGH"


def test_c2_beacon_detector_hit():
    suite = RuleDetectorSuite()
    fv = make_fv(total_packets=20, duration=20.0, iat_var=0.001, pps=1.0)
    hits = suite.evaluate(fv)
    assert len(hits) >= 1
    hit = next(h for h in hits if h.threat_class == "THREAT_C2_BEACON")
    assert hit.rule_id == "RULE_C2_PERIODIC_IAT"


def test_dga_lexical_detector_hit():
    suite = RuleDetectorSuite()
    fv = make_fv(is_tcp=0.0, is_udp=1.0, dst_port=53, dns_query_count=1, dns_max_domain_entropy=4.5)
    hits = suite.evaluate(fv)
    assert len(hits) >= 1
    hit = next(h for h in hits if h.threat_class == "THREAT_DNS_DGA")
    assert hit.rule_id == "RULE_DGA_HIGH_DOMAIN_ENTROPY"


def test_dns_tunnel_detector_hit():
    suite = RuleDetectorSuite()
    fv = make_fv(is_tcp=0.0, is_udp=1.0, dst_port=53, dns_query_count=1, dns_max_subdomain_depth=5)
    hits = suite.evaluate(fv)
    assert len(hits) >= 1
    hit = next(h for h in hits if h.threat_class == "THREAT_DNS_TUNNEL")
    assert hit.rule_id == "RULE_DNS_TUNNEL_PAYLOAD_DEPTH"


def test_recon_portscan_detector_hit():
    suite = RuleDetectorSuite()
    fv = make_fv(is_tcp=1.0, small_pkt_ratio=0.9, total_packets=2, duration=0.1)
    hits = suite.evaluate(fv)
    assert len(hits) >= 1
    hit = next(h for h in hits if h.threat_class == "THREAT_RECON_PORTSCAN")
    assert hit.rule_id == "RULE_RECON_SYN_SWEEP"


def _exfil_ctx(flow, store=None):
    from sih26145.detectors.context import DetectionContext
    from sih26145.features.directional import NetworkPolicy
    from sih26145.features.store import FeatureStore
    store = store or FeatureStore()
    store.update(flow)
    return DetectionContext(flow, store, NetworkPolicy())


def test_exfiltration_detector_hit():
    """Both halves captured: detector (f) uses the outbound/inbound byte ratio.

    Rewritten for the direction-aware detector: exfiltration needs internal->external bytes
    under the CIDR policy, so it is evaluated with a DetectionContext, not a bare vector.
    """
    from sih26145.flow.models import FlowKey, FlowRecord
    flow = FlowRecord(FlowKey("192.168.1.51", "203.0.113.99", 443, "TCP", 51515), 100.0, 110.0,
                      fwd_packets=800, fwd_bytes=2_000_000, rev_packets=80, rev_bytes=20_000)
    suite = RuleDetectorSuite()
    hits = suite.evaluate(make_fv(bps=800000.0, duration=10.0, small_pkt_ratio=0.05), _exfil_ctx(flow))
    hit = next(h for h in hits if h.threat_class == "THREAT_EXFILTRATION")
    assert hit.rule_id == "RULE_EXFIL_OUTBOUND_RATIO"
    assert hit.evidence["outbound_inbound_byte_ratio"]["value"] == 100.0
    assert hit.substitutions == ()


def test_encrypted_anomaly_detector_hit():
    suite = RuleDetectorSuite()
    fv = make_fv(tls_client_hello_count=1, tls_max_sni_entropy=4.5, dst_port=443)
    hits = suite.evaluate(fv)
    assert len(hits) >= 1
    hit = next(h for h in hits if h.threat_class == "THREAT_ENCRYPTED_ANOMALY")
    assert hit.rule_id == "RULE_ENCRYPTED_SNI_PORT_ANOMALY"


def test_icmp_exfiltration_detector_hit():
    """One half captured (ICMP echo requests leaving, no replies): detector (f) cannot use
    the ratio and substitutes the host's egress baseline + destination rarity."""
    from sih26145.features.store import FeatureStore
    from sih26145.flow.models import FlowKey, FlowRecord
    store = FeatureStore()
    for minute in range(6):  # routine pings to a popular host build the egress baseline
        t = 1000.0 + minute * 60
        store.update(FlowRecord(FlowKey("192.168.1.51", "203.0.113.1", 0, "ICMP", 0), t, t + 1,
                                fwd_packets=4, fwd_bytes=392))
    tunnel = FlowRecord(FlowKey("192.168.1.51", "198.51.100.99", 0, "ICMP", 0), 1400.0, 1430.0,
                        fwd_packets=900, fwd_bytes=900_000, icmp_type=8)
    suite = RuleDetectorSuite()
    fv = make_fv(is_tcp=0.0, is_icmp=1.0, total_bytes=900_000, duration=30.0, small_pkt_ratio=0.0)
    hits = suite.evaluate(fv, _exfil_ctx(tunnel, store))
    hit = next(h for h in hits if h.threat_class == "THREAT_EXFILTRATION")
    assert hit.rule_id == "RULE_EXFIL_EGRESS_BASELINE"
    assert hit.substitutions[0]["unavailable_on_this_flow"] == "outbound_inbound_byte_ratio"


def test_detector_threshold_boundaries():
    suite = RuleDetectorSuite()
    # Below threshold -> no hits
    fv_below = make_fv(pps=500.0, bps=1000.0, burstiness_ratio=0.5)
    hits_below = suite.evaluate(fv_below)
    assert len(hits_below) == 0

    # Critical severity DDoS threshold -> pps > 50000.0
    fv_crit = make_fv(pps=60000.0)
    hits_crit = suite.evaluate(fv_crit)
    hit_crit = next(h for h in hits_crit if h.threat_class == "THREAT_DDOS_VOLUME")
    assert hit_crit.severity == "CRITICAL"


def test_deterministic_rule_suite_evaluation():
    suite = RuleDetectorSuite()
    fv = make_fv(pps=15000.0)
    hits1 = suite.evaluate(fv)
    hits2 = suite.evaluate(fv)
    assert hits1 == hits2


def test_adversarial_benign_controls_zero_false_positives():
    """Adversarial test verifying normal benign traffic does not trigger false positives across any threat class."""
    suite = RuleDetectorSuite()

    # 1. Benign normal HTTP GET session
    fv_http = make_fv(pps=12.0, bps=5000.0, total_packets=45, duration=3.5, is_tcp=1.0, dst_port=80, small_pkt_ratio=0.1)
    assert len(suite.evaluate(fv_http)) == 0

    # 2. Benign standard DNS lookup (low entropy, standard port 53)
    fv_dns = make_fv(is_tcp=0.0, is_udp=1.0, dst_port=53, dns_query_count=1, dns_max_domain_entropy=2.3, dns_max_subdomain_depth=1)
    assert len(suite.evaluate(fv_dns)) == 0

    # 3. Benign TLS session over port 443 (standard SNI entropy)
    fv_tls = make_fv(is_tcp=1.0, dst_port=443, tls_client_hello_count=1, tls_max_sni_entropy=2.9, tls_max_sni_length=22)
    assert len(suite.evaluate(fv_tls)) == 0

    # 4. Benign ICMP Ping (64-byte standard echo request)
    fv_icmp = make_fv(is_tcp=0.0, is_icmp=1.0, total_bytes=64, total_packets=1, duration=0.001)
    assert len(suite.evaluate(fv_icmp)) == 0

    # 5. Benign multi-packet TCP download session
    fv_download = make_fv(is_tcp=1.0, dst_port=443, total_packets=500, total_bytes=750000, pps=50.0, bps=75000.0, small_pkt_ratio=0.02)
    assert len(suite.evaluate(fv_download)) == 0

