"""Unit tests for FeatureExtractor and Shannon entropy calculations."""

import pytest
from sih26145.flow.models import FlowKey, FlowRecord
from sih26145.features import FeatureExtractor, FeatureVector, entropy_of_string


def test_entropy_of_string():
    # Empty string
    assert entropy_of_string("") == 0.0
    # Single repeating char -> 0 bits of entropy
    assert entropy_of_string("aaaaa") == 0.0
    # Two equiprobable chars -> 1.0 bit
    assert pytest.approx(entropy_of_string("ab"), 0.001) == 1.0
    # Random domain string has higher entropy
    assert entropy_of_string("x9f2a8q1z7.example.com") > 3.0


def test_feature_extraction_from_flow():
    key = FlowKey(src_ip="192.168.1.10", src_port=12345, dst_ip="10.0.0.1", dst_port=80, protocol="TCP")
    flow = FlowRecord(
        flow_key=key,
        start_time=100.0,
        last_time=102.0,
        packet_count=3,
        total_bytes=600,
        packet_sizes=[100, 200, 300],
        inter_arrival_times=[1.0, 1.0],
        tcp_flags_seen=0x02,
    )
    
    extractor = FeatureExtractor()
    fv = extractor.extract(flow)
    
    assert fv.duration == 2.0
    assert fv.total_packets == 3
    assert fv.total_bytes == 600
    assert pytest.approx(fv.pps, 0.01) == 1.5
    assert pytest.approx(fv.bps, 0.01) == 300.0
    assert fv.pkt_size_min == 100.0
    assert fv.pkt_size_max == 300.0
    assert fv.pkt_size_mean == 200.0
    assert fv.iat_mean == 1.0
    assert fv.is_tcp == 1.0
    assert fv.is_udp == 0.0
    assert fv.dst_port == 80


def test_dns_and_tls_feature_extraction():
    key = FlowKey(src_ip="192.168.1.50", dst_ip="8.8.8.8", dst_port=53, protocol="UDP")
    flow = FlowRecord(
        flow_key=key,
        start_time=100.0,
        last_time=101.0,
        packet_count=2,
        total_bytes=250,
        packet_sizes=[100, 150],
        inter_arrival_times=[1.0],
        dns_queries=["v1x9q2z8a.covert.domain.com"],
        tls_snis=["secure.banking.com"],
    )
    
    extractor = FeatureExtractor()
    fv = extractor.extract(flow)
    
    assert fv.dns_query_count == 1
    assert fv.dns_max_domain_entropy > 3.0
    assert fv.dns_max_subdomain_depth == 3
    assert fv.tls_client_hello_count == 1
    assert fv.tls_max_sni_length == len("secure.banking.com")


def test_zero_duration_flow():
    """Verify that zero duration flows do not cause division by zero or NaN/Inf."""
    key = FlowKey(src_ip="10.0.0.1", src_port=5000, dst_ip="10.0.0.2", dst_port=80, protocol="TCP")
    flow = FlowRecord(
        flow_key=key,
        start_time=100.0,
        last_time=100.0,
        packet_count=1,
        total_bytes=100,
        packet_sizes=[100],
        inter_arrival_times=[],
    )
    extractor = FeatureExtractor()
    fv = extractor.extract(flow)

    assert fv.duration == 0.0
    assert fv.pps == 1.0
    assert fv.bps == 100.0
    assert fv.iat_mean == 0.0
    assert fv.jitter == 0.0


def test_tcp_flags_feature_extraction():
    """Verify TCP flag indicators (has_syn, has_fin, has_rst)."""
    key = FlowKey(src_ip="1.1.1.1", src_port=100, dst_ip="2.2.2.2", dst_port=80, protocol="TCP")
    flow = FlowRecord(
        flow_key=key,
        start_time=100.0,
        last_time=101.0,
        packet_count=2,
        total_bytes=120,
        packet_sizes=[60, 60],
        tcp_flags_seen=0x03, # SYN (0x02) | FIN (0x01)
    )
    extractor = FeatureExtractor()
    fv = extractor.extract(flow)

    assert fv.has_syn == 1.0
    assert fv.has_fin == 1.0
    assert fv.has_rst == 0.0


def test_icmp_feature_extraction():
    """Verify ICMP protocol indicator and zero port handling."""
    key = FlowKey(src_ip="192.168.1.50", src_port=0, dst_ip="10.0.0.99", dst_port=0, protocol="ICMP")
    flow = FlowRecord(
        flow_key=key,
        start_time=100.0,
        last_time=101.0,
        packet_count=1,
        total_bytes=84,
        packet_sizes=[84],
    )
    extractor = FeatureExtractor()
    fv = extractor.extract(flow)

    assert fv.is_icmp == 1.0
    assert fv.is_tcp == 0.0
    assert fv.is_udp == 0.0
    assert fv.dst_port == 0


def test_finite_values_invariant():
    """Verify that extracted numerical features are always finite numbers (no NaN or Inf)."""
    import math
    key = FlowKey(src_ip="1.2.3.4", src_port=1, dst_ip="5.6.7.8", dst_port=2, protocol="UDP")
    flow = FlowRecord(
        flow_key=key,
        start_time=100.0,
        last_time=100.0,
        packet_count=0,
        total_bytes=0,
        packet_sizes=[],
        inter_arrival_times=[],
    )
    extractor = FeatureExtractor()
    fv = extractor.extract(flow)

    for field_name, value in fv.__dict__.items():
        if isinstance(value, float):
            assert math.isfinite(value), f"Field {field_name} produced non-finite float value {value}"


def test_deterministic_feature_extraction():
    """Verify that extracting features from identical FlowRecord yields identical FeatureVector."""
    key = FlowKey(src_ip="1.1.1.1", src_port=80, dst_ip="2.2.2.2", dst_port=80, protocol="TCP")
    flow = FlowRecord(
        flow_key=key,
        start_time=100.0,
        last_time=105.0,
        packet_count=5,
        total_bytes=1000,
        packet_sizes=[200, 200, 200, 200, 200],
        inter_arrival_times=[1.0, 1.0, 1.0, 1.0],
    )
    extractor = FeatureExtractor()
    fv1 = extractor.extract(flow)
    fv2 = extractor.extract(flow)

    assert fv1 == fv2
