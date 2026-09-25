"""Unit tests for FlowTracker and unidirectional flow assembly."""

import pytest
from sih26145.ingest.models import PacketMetadata
from sih26145.flow import FlowTracker, FlowKey, FlowRecord


def make_packet(ts, src_ip="192.168.1.10", src_port=1000, dst_ip="10.0.0.1", dst_port=80, proto="TCP", size=100, tcp_flags=0x02, dns_name=None, sni=None):
    return PacketMetadata(
        timestamp=ts,
        captured_len=size,
        packet_len=size,
        ip_version=4,
        src_ip=src_ip,
        src_port=src_port,
        dst_ip=dst_ip,
        dst_port=dst_port,
        protocol=proto,
        tcp_flags=tcp_flags,
        dns_query_name=dns_name,
        tls_sni=sni,
    )


def test_unidirectional_accumulation_5tuple():
    tracker = FlowTracker(mode="5tuple", active_timeout=60.0, idle_timeout=15.0)
    
    # Send 3 unidirectional packets over 2 seconds
    flushed = tracker.process_packet(make_packet(100.0, size=100))
    assert len(flushed) == 0
    
    flushed = tracker.process_packet(make_packet(101.0, size=200))
    assert len(flushed) == 0
    
    flushed = tracker.process_packet(make_packet(102.0, size=300))
    assert len(flushed) == 0
    
    assert tracker.get_active_flow_count() == 1
    
    # Flush idle flows at t=120.0 (idle for 18 seconds)
    expired = tracker.flush_expired(120.0)
    assert len(expired) == 1
    flow = expired[0]
    
    assert flow.packet_count == 3
    assert flow.total_bytes == 600
    assert flow.packet_sizes == [100, 200, 300]
    assert flow.inter_arrival_times == [1.0, 1.0]
    assert flow.duration == 2.0
    assert flow.is_idle_expired is True
    assert tracker.get_active_flow_count() == 0


def test_behavioral_4tuple_mode():
    tracker = FlowTracker(mode="4tuple")
    
    # 2 packets from different source ports to same destination port
    tracker.process_packet(make_packet(100.0, src_port=1001, size=150))
    tracker.process_packet(make_packet(100.5, src_port=1002, size=250))
    
    # Should aggregate into single 4-tuple flow
    assert tracker.get_active_flow_count() == 1
    
    expired = tracker.flush_expired(120.0)
    assert len(expired) == 1
    flow = expired[0]
    assert flow.packet_count == 2
    assert flow.total_bytes == 400


def test_active_timeout():
    tracker = FlowTracker(active_timeout=10.0)
    
    # First packet at t=100.0
    flushed = tracker.process_packet(make_packet(100.0))
    assert len(flushed) == 0
    
    # Packet at t=111.0 (> 10s active timeout)
    flushed = tracker.process_packet(make_packet(111.0))
    assert len(flushed) == 1
    active_flushed = flushed[0]
    assert active_flushed.is_active_expired is True
    assert active_flushed.packet_count == 1
    
    # Active tracker now holds the new flow window
    assert tracker.get_active_flow_count() == 1


def test_lru_eviction():
    tracker = FlowTracker(max_flows=2)
    
    tracker.process_packet(make_packet(100.0, src_port=1001))
    tracker.process_packet(make_packet(100.1, src_port=1002))
    assert tracker.get_active_flow_count() == 2
    
    # Adding 3rd flow triggers LRU eviction of 1st flow
    flushed = tracker.process_packet(make_packet(100.2, src_port=1003))
    assert len(flushed) == 1
    evicted = flushed[0]
    assert evicted.is_evicted is True
    assert evicted.flow_key.src_port == 1001
    assert tracker.get_active_flow_count() == 2


def test_icmp_flow_assembly():
    """Verify that ICMP packets with None for ports are assembled into flows properly."""
    tracker = FlowTracker()
    pkt = PacketMetadata(
        timestamp=100.0,
        captured_len=84,
        packet_len=84,
        ip_version=4,
        src_ip="192.168.1.50",
        src_port=None,
        dst_ip="10.0.0.99",
        dst_port=None,
        protocol="ICMP",
        icmp_type=8,
        icmp_code=0,
    )
    
    flushed = tracker.process_packet(pkt)
    assert len(flushed) == 0
    assert tracker.get_active_flow_count() == 1
    
    expired = tracker.flush_expired(120.0)
    assert len(expired) == 1
    flow = expired[0]
    assert flow.flow_key.protocol == "ICMP"
    assert flow.flow_key.src_port == 0
    assert flow.flow_key.dst_port == 0
    assert flow.packet_count == 1
    assert flow.total_bytes == 84


def test_out_of_order_timestamps():
    """Verify that out-of-order packet timestamps maintain last_time monotonicity."""
    tracker = FlowTracker()
    tracker.process_packet(make_packet(100.0, size=100))
    tracker.process_packet(make_packet(95.0, size=100))   # Out of order timestamp
    tracker.process_packet(make_packet(105.0, size=100))  # Later timestamp
    
    expired = tracker.flush_expired(130.0)
    assert len(expired) == 1
    flow = expired[0]
    
    assert flow.start_time == 100.0
    assert flow.last_time == 105.0
    assert flow.duration == 5.0
    assert flow.inter_arrival_times == [0.0, 5.0]


def test_tcp_connection_flags():
    """Verify TCP flag properties (has_syn, has_fin, has_rst, is_terminated)."""
    tracker = FlowTracker()
    tracker.process_packet(make_packet(100.0, tcp_flags=0x02)) # SYN
    tracker.process_packet(make_packet(101.0, tcp_flags=0x10)) # ACK
    tracker.process_packet(make_packet(102.0, tcp_flags=0x01)) # FIN
    
    expired = tracker.flush_expired(120.0)
    flow = expired[0]
    assert flow.has_syn is True
    assert flow.has_fin is True
    assert flow.has_rst is False
    assert flow.is_terminated is True


def test_bidirectional_packets_merge_into_one_flow():
    """A->B and its true reverse B->A (ports swapped) are one flow with reverse_seen.

    Replaces test_bidirectional_separate_keys: the capture may hold both halves of a
    conversation, and the flow must measure that rather than split it.
    """
    tracker = FlowTracker()
    tracker.process_packet(make_packet(100.0, src_ip="1.1.1.1", src_port=40000, dst_ip="2.2.2.2", dst_port=80))
    tracker.process_packet(make_packet(100.1, src_ip="2.2.2.2", src_port=80, dst_ip="1.1.1.1", dst_port=40000, tcp_flags=0x12))

    assert tracker.get_active_flow_count() == 1
    (flow,) = tracker.flush_expired(200.0)
    assert flow.reverse_seen is True
    assert flow.observability_state == "bidirectional"
    assert (flow.fwd_packets, flow.rev_packets) == (1, 1)

    # Same IPs but not a reversed 5-tuple (ports not swapped) stay separate
    tracker.process_packet(make_packet(300.0, src_ip="1.1.1.1", dst_ip="2.2.2.2"))
    tracker.process_packet(make_packet(300.1, src_ip="2.2.2.2", dst_ip="1.1.1.1"))
    assert tracker.get_active_flow_count() == 2


def test_dns_and_tls_metadata_aggregation():
    """Verify DNS queries and TLS SNIs are aggregated without duplication."""
    tracker = FlowTracker()
    tracker.process_packet(make_packet(100.0, dns_name="example.com", sni="example.com"))
    tracker.process_packet(make_packet(100.1, dns_name="example.com", sni="other.com"))
    
    expired = tracker.flush_expired(120.0)
    flow = expired[0]
    assert flow.dns_queries == ["example.com"]
    assert flow.tls_snis == ["example.com", "other.com"]


def test_malformed_metadata_handling():
    """Verify incomplete or malformed PacketMetadata returns [] gracefully."""
    tracker = FlowTracker()
    pkt = PacketMetadata(timestamp=100.0, captured_len=50, packet_len=50, src_ip=None, dst_ip="10.0.0.1", protocol="TCP")
    assert tracker.process_packet(pkt) == []
    assert tracker.get_active_flow_count() == 0
