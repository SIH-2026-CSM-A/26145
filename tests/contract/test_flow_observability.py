"""Runtime layer: per-flow observability, direction policy, and reverse-dependent guards."""

import pytest

from sih26145.contract import UnavailableFeatureError
from sih26145.features.directional import NetworkPolicy, flow_feature
from sih26145.flow import FlowTracker
from sih26145.ingest.models import PacketMetadata

SYN, ACK, SYNACK, PSHACK = 0x02, 0x10, 0x12, 0x18
CLIENT, SERVER = ("192.168.1.5", 50000), ("203.0.113.9", 443)
POLICY = NetworkPolicy()


def pkt(ts, src, dst, size=100, flags=None, proto="TCP", **kw):
    return PacketMetadata(
        timestamp=ts, captured_len=size, packet_len=size, ip_version=4,
        src_ip=src[0], src_port=src[1], dst_ip=dst[0], dst_port=dst[1],
        protocol=proto, tcp_flags=flags, **kw,
    )


def run(*packets, mode="5tuple"):
    tracker = FlowTracker(mode=mode)
    for p in packets:
        tracker.process_packet(p)
    return tracker.flush_expired(10_000.0)


def test_full_duplex_handshake_is_bidirectional_with_rtt():
    (flow,) = run(
        pkt(1.000, CLIENT, SERVER, 60, SYN),
        pkt(1.020, SERVER, CLIENT, 60, SYNACK),
        pkt(1.021, CLIENT, SERVER, 60, ACK),
        pkt(1.030, CLIENT, SERVER, 2000, PSHACK),
        pkt(1.050, SERVER, CLIENT, 200, PSHACK),
    )
    assert flow.observability_state == "bidirectional"
    assert (flow.fwd_packets, flow.rev_packets) == (3, 2)
    assert (flow.fwd_bytes, flow.rev_bytes) == (2120, 260)
    assert flow_feature(flow, "tcp_handshake_completed", POLICY) is True
    assert flow_feature(flow, "tcp_rtt", POLICY) == pytest.approx(0.020)
    assert flow_feature(flow, "outbound_inbound_byte_ratio", POLICY) == pytest.approx(2120 / 260)
    assert flow_feature(flow, "egress_bytes", POLICY) == 2120


def test_forward_only_flow_raises_for_every_reverse_dependent_feature():
    (flow,) = run(pkt(1.0, CLIENT, SERVER, 60, SYN), pkt(1.1, CLIENT, SERVER, 1500, PSHACK))
    assert flow.observability_state == "forward_only"
    assert flow_feature(flow, "reverse_seen", POLICY) is False
    for name in ("outbound_inbound_byte_ratio", "tcp_handshake_completed", "tcp_rtt"):
        with pytest.raises(UnavailableFeatureError, match="reverse direction not observed"):
            flow_feature(flow, name, POLICY)
    assert flow_feature(flow, "egress_bytes", POLICY) == 1560


def test_one_way_view_of_a_download_is_reverse_only_with_zero_egress():
    (flow,) = run(pkt(1.0, SERVER, CLIENT, 1514, PSHACK), pkt(1.001, SERVER, CLIENT, 1514, PSHACK))
    assert flow.observability_state == "reverse_only"
    assert flow_feature(flow, "flow_direction", POLICY) == "inbound"
    assert flow_feature(flow, "egress_bytes", POLICY) == 0


def test_nxdomain_rate_needs_responses_and_counts_them():
    client, resolver = ("192.168.1.5", 53000), ("192.168.1.1", 53)
    q = dict(proto="UDP", dns_query_name="x1.example", dns_is_response=False)
    (only_queries,) = run(pkt(1.0, client, resolver, **q))
    with pytest.raises(UnavailableFeatureError):
        flow_feature(only_queries, "dns_nxdomain_rate", POLICY)

    r = dict(proto="UDP", dns_query_name="x1.example", dns_is_response=True)
    (both,) = run(
        pkt(1.0, client, resolver, **q),
        pkt(1.01, resolver, client, dns_rcode=3, **r),
        pkt(1.02, resolver, client, dns_rcode=0, **r),
    )
    assert flow_feature(both, "dns_nxdomain_rate", POLICY) == pytest.approx(0.5)

    (responses_only,) = run(pkt(1.0, resolver, client, dns_rcode=3, **r))
    assert responses_only.observability_state == "reverse_only"
    assert flow_feature(responses_only, "dns_nxdomain_rate", POLICY) == 1.0


def test_four_tuple_mode_never_matches_reverse_packets():
    flows = run(pkt(1.0, CLIENT, SERVER, flags=SYN), pkt(1.1, SERVER, CLIENT, flags=SYNACK), mode="4tuple")
    assert len(flows) == 2
    assert all(not f.reverse_seen for f in flows)


def test_unavailable_feature_is_refused_by_the_accessor():
    (flow,) = run(pkt(1.0, CLIENT, SERVER, flags=SYN))
    with pytest.raises(UnavailableFeatureError):
        flow_feature(flow, "quic_client_hello", POLICY)


def test_network_policy_defaults_and_env_override(monkeypatch):
    assert POLICY.is_internal("10.1.2.3") and POLICY.is_internal("fd00::1")
    assert not POLICY.is_internal("203.0.113.9")
    monkeypatch.setenv("SIH26145_INTERNAL_CIDRS", "203.0.113.0/24")
    custom = NetworkPolicy.from_env()
    assert custom.is_internal("203.0.113.9") and not custom.is_internal("10.1.2.3")
