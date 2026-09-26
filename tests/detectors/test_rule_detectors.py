"""Unit tests for deterministic rule threat detectors."""

import pytest
from sih26145.features.models import FeatureVector
from sih26145.detectors import RuleDetectorSuite, RuleHit
from sih26145.detectors.context import DetectionContext
from sih26145.features import FeatureExtractor
from sih26145.features.directional import NetworkPolicy
from sih26145.features.store import FeatureStore
from sih26145.flow.models import FlowKey, FlowRecord
from sih26145.detectors.rules.detectors import C2BeaconDetector, DDoSVolumeDetector
from sih26145.utils.attack_scenarios import ramnit_dga

SYN = 0x02


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



# ---- (a)-(e) read tier-2 features: drive them through a FeatureStore, flow by flow ----------

def mk(src, dst, dport, proto="TCP", t=1000.0, sport=40000, dur=0.1, **kw):
    return FlowRecord(FlowKey(src, dst, dport, proto, sport), t, t + dur, **kw)


def run_flows(flows, suite=None):
    """Feed flows into a store in order, as the pipeline does; return every hit raised."""
    suite, store, hits = suite or RuleDetectorSuite(), FeatureStore(), []
    for f in flows:
        store.update(f)
        hits += suite.evaluate(FeatureExtractor().extract(f), DetectionContext(f, store, NetworkPolicy()))
    return hits


def rules(hits, threat_class):
    return [h.rule_id for h in hits if h.threat_class == threat_class]


def test_ddos_syn_flood_from_many_sources_alerts_once():
    n = DDoSVolumeDetector.MIN_SRCS + 50
    flows = [mk(f"198.18.{i // 200}.{i % 200 + 1}", "10.50.0.10", 80, t=1000 + i * 0.05, sport=1024 + i,
                fwd_packets=1, fwd_bytes=54, fwd_tcp_flags=SYN) for i in range(n)]
    hits = run_flows(flows)
    assert rules(hits, "THREAT_DDOS_VOLUME") == ["RULE_DDOS_SYN_FLOOD"]
    hit = hits[0]
    assert hit.severity == "CRITICAL" and hit.entity == "10.50.0.10"


def test_ddos_reflection_counts_only_unsolicited_answers():
    unsolicited = [mk(f"198.18.1.{i + 1}", "10.50.0.20", 3074, "UDP", t=1000 + i * 0.1, sport=123,
                      fwd_packets=15, fwd_bytes=21000) for i in range(60)]
    assert rules(run_flows(unsolicited), "THREAT_DDOS_VOLUME") == ["RULE_DDOS_UDP_REFLECTION"]
    # the same answers to queries the host sent (host initiated, both halves) are not reflection
    solicited = [mk("10.50.0.20", f"198.18.1.{i + 1}", 123, "UDP", t=1000 + i * 0.1, sport=3074,
                    fwd_packets=1, fwd_bytes=90, rev_packets=15, rev_bytes=21000) for i in range(60)]
    assert rules(run_flows(solicited), "THREAT_DDOS_VOLUME") == []


def test_c2_needs_min_gaps_between_periodic_flows():
    def beacons(n):
        return [mk("192.168.1.70", "203.0.113.66", 443, t=1000 + 30 * i, sport=45000 + i) for i in range(n)]
    gaps = C2BeaconDetector.MIN_GAPS
    assert rules(run_flows(beacons(gaps)), "THREAT_C2_BEACON") == []            # one gap short
    assert rules(run_flows(beacons(gaps + 1)), "THREAT_C2_BEACON") == ["RULE_C2_PERIODIC_FLOWS"]


def dns_flow(i, name, host="192.168.1.80", nx=True):
    return mk(host, "10.0.0.53", 53, "UDP", t=1000 + i, sport=20000 + i, fwd_packets=1, fwd_bytes=80,
              rev_packets=1, rev_bytes=120, dns_queries=[name], dns_responses=1, dns_nxdomain=int(nx))


def test_dga_with_nxdomain_answers_is_high():
    hits = run_flows([dns_flow(i, n) for i, n in enumerate(ramnit_dga(0x79159C10, 120))])
    (hit,) = [h for h in hits if h.threat_class == "THREAT_DNS_DGA"]
    assert hit.rule_id == "RULE_DGA_NXDOMAIN_HIGH_ENTROPY" and hit.severity == "HIGH"
    assert hit.evidence["src_nxdomain_rate_w"]["value"] == 1.0


def test_dga_names_that_resolve_do_not_alert():
    hits = run_flows([dns_flow(i, n, nx=False) for i, n in enumerate(ramnit_dga(0x79159C10, 120))])
    assert rules(hits, "THREAT_DNS_DGA") == []


def test_dns_tunnel_needs_volume_and_long_names():
    long_names = [f"{'a%02d' % i}{'x' * 50}.t.example.org" for i in range(60)]
    assert rules(run_flows([dns_flow(i, n, nx=False) for i, n in enumerate(long_names)]),
                 "THREAT_DNS_TUNNEL") == ["RULE_DNS_TUNNEL_VOLUME_LENGTH"]
    assert rules(run_flows([dns_flow(i, n, nx=False) for i, n in enumerate(long_names[:40])]),
                 "THREAT_DNS_TUNNEL") == []


def test_recon_sweep_of_syn_only_flows_alerts_once():
    flows = [mk("192.168.1.52", "10.0.0.200", port, t=1000 + port * 0.01, fwd_packets=1, fwd_bytes=54,
                fwd_tcp_flags=SYN) for port in range(1, 41)]
    assert rules(run_flows(flows), "THREAT_RECON_PORTSCAN") == ["RULE_RECON_FANOUT_SYN_ONLY"]


def test_encrypted_rare_ja4_repeated_small_sessions():
    flows = [mk("192.168.1.90", "203.0.113.77", 443, t=1000 + 10 * i, sport=46000 + i, dur=0.5,
                fwd_packets=6, fwd_bytes=1500, total_bytes=3000, tls_ja4=["t12d040300_rare_rare"])
             for i in range(6)]
    assert rules(run_flows(flows), "THREAT_ENCRYPTED_ANOMALY") == ["RULE_TLS_RARE_JA4_REPEATED"]
    assert rules(run_flows(flows[:4]), "THREAT_ENCRYPTED_ANOMALY") == []   # below MIN_PAIR_FLOWS
