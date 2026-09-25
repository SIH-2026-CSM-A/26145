"""FeatureStore rollups: exact on small inputs, windowed, contract-governed, memory-bounded."""

import gc
import tracemalloc

import pytest

from sih26145.contract import UnavailableFeatureError, load_contract
from sih26145.features.store import FeatureStore
from sih26145.features.store_readers import READERS as _READERS
from sih26145.features.store_state import StoreConfig
from sih26145.flow.models import FlowKey, FlowRecord

SYN, ACK = 0x02, 0x10


def flow(src, dst, dport=443, proto="TCP", start=0.0, dur=0.5, fwd_bytes=500, rev_bytes=0, flags=SYN | ACK, **kw):
    f = FlowRecord(FlowKey(src, dst, dport, proto, kw.pop("sport", 40000)), start, start + dur,
                   packet_count=2, total_bytes=fwd_bytes + rev_bytes,
                   fwd_packets=1, fwd_bytes=fwd_bytes, fwd_tcp_flags=flags if proto == "TCP" else 0,
                   rev_packets=1 if rev_bytes else 0, rev_bytes=rev_bytes, **kw)
    return f


def test_every_served_feature_is_declared_in_the_contract():
    assert set(_READERS) - set(load_contract().features) == set()


def test_host_rollups_count_exactly_on_small_inputs():
    s = FeatureStore()
    s.update(flow("192.168.1.5", "10.0.0.1", 22, start=1))
    s.update(flow("192.168.1.5", "10.0.0.2", 22, start=2, flags=SYN))       # half-open
    s.update(flow("192.168.1.5", "10.0.0.3", 3389, start=3, flags=SYN))     # half-open
    s.update(flow("192.168.1.5", "10.0.0.3", 3389, start=4))
    assert s.get("src_flows_w", "192.168.1.5") == 4
    assert round(s.get("src_distinct_dsts_w", "192.168.1.5")) == 3
    assert round(s.get("src_distinct_dst_ports_w", "192.168.1.5")) == 2
    assert s.get("src_syn_only_ratio_w", "192.168.1.5") == pytest.approx(0.5)
    assert s.get("dst_syn_only_ratio_w", "10.0.0.3") == pytest.approx(0.5)
    assert s.get("src_flows_w", "192.168.9.9") == 0.0


def test_windows_cover_current_and_previous_then_expire():
    s = FeatureStore(StoreConfig(window=60.0))
    s.update(flow("192.168.1.5", "10.0.0.1", start=10))
    s.update(flow("192.168.1.6", "10.0.0.9", start=70))    # next window: first flow still counted
    assert s.get("src_flows_w", "192.168.1.5") == 1
    s.update(flow("192.168.1.6", "10.0.0.9", start=130))   # two windows later: expired
    assert s.get("src_flows_w", "192.168.1.5") == 0


def test_destination_fan_in_and_source_entropy():
    s = FeatureStore()
    for i in range(300):
        s.update(flow(f"203.0.{i >> 8}.{i & 255}", "192.168.1.80", 80, start=1 + i * 0.01))
    s.update(flow("192.168.1.7", "192.168.1.81", 80, start=5))
    assert abs(s.get("dst_distinct_srcs_w", "192.168.1.80") - 300) / 300 < 0.2
    assert s.get("dst_src_ip_entropy_w", "192.168.1.80") > 6.5
    assert s.get("dst_src_ip_entropy_w", "192.168.1.81") == 0.0
    assert s.get("dst_flows_w", "192.168.1.80") == 300


def test_dns_rollups_and_reverse_dependent_nxdomain():
    s = FeatureStore()
    q = dict(proto="UDP", dport=53, flags=0)
    s.update(flow("192.168.1.5", "192.168.1.1", start=1, dns_queries=["www.example.com"], **q))
    s.update(flow("192.168.1.5", "192.168.1.1", start=2, dns_queries=["xk3q9vz7wp2m.example.com"], **q))
    assert s.get("src_dns_queries_w", "192.168.1.5") == 2
    assert s.get("src_high_entropy_qnames_w", "192.168.1.5") == 1
    assert s.get("src_qname_len_sum_w", "192.168.1.5") == len("www.example.com") + len("xk3q9vz7wp2m.example.com")
    with pytest.raises(UnavailableFeatureError):
        s.get("src_nxdomain_rate_w", "192.168.1.5")          # only queries were captured
    s.update(flow("192.168.1.5", "192.168.1.1", start=3, rev_bytes=90, dns_queries=["nope.example"],
                  dns_responses=2, dns_nxdomain=1, **q))
    assert s.get("src_nxdomain_rate_w", "192.168.1.5") == pytest.approx(0.5)


def test_egress_counts_only_bytes_leaving_the_enclave():
    s = FeatureStore()
    s.update(flow("192.168.1.5", "203.0.113.9", start=1, fwd_bytes=4000, rev_bytes=90_000))  # upload side 4000
    s.update(flow("203.0.113.9", "192.168.1.5", 443, start=2, fwd_bytes=1_000_000,           # one-way view of a
                  fwd_is_responder=True, sport=443))                                           # download
    s.update(flow("192.168.1.5", "192.168.1.6", start=3, fwd_bytes=9_999))                   # internal
    assert s.get("src_egress_bytes_1m", "192.168.1.5") == 4000


def test_egress_zscore_needs_a_baseline_then_flags_a_burst():
    s = FeatureStore()
    host = "192.168.1.5"
    for minute in range(6):
        s.update(flow(host, "203.0.113.9", start=minute * 60 + 5, fwd_bytes=2000 + minute * 50))
        if minute < 4:
            assert s.get("src_egress_bytes_z", host) is None   # fewer than 5 closed minutes
    s.update(flow(host, "198.51.100.77", start=6 * 60 + 5, fwd_bytes=5_000_000))
    assert s.get("src_egress_bytes_z", host) > 10
    assert s.get("src_egress_bytes_5m", host) >= 5_000_000
    assert s.get("dst_distinct_srcs_longterm", "198.51.100.77") == pytest.approx(1, abs=0.1)


def test_pair_periodicity_and_first_contact():
    s = FeatureStore()
    for i in range(10):
        s.update(flow("192.168.1.5", "203.0.113.50", start=i * 30.0, sport=40000 + i))
    key = ("192.168.1.5", "203.0.113.50")
    assert s.get("pair_iat_n", key) == 9
    assert s.get("pair_iat_mean", key) == pytest.approx(30.0)
    assert s.get("pair_iat_cv", key) == pytest.approx(0.0, abs=1e-9)
    assert s.get("pair_history_count", key) >= 10
    s.update(flow("192.168.1.5", "198.51.100.1", start=300))
    assert s.get("pair_history_count", ("192.168.1.5", "198.51.100.1")) == 1


def test_link_visibility_is_the_fraction_of_flows_with_both_halves():
    s = FeatureStore()
    assert s.get("link_reverse_visibility_w") is None
    s.update(flow("192.168.1.5", "203.0.113.9", start=1, rev_bytes=100))
    s.update(flow("192.168.1.5", "203.0.113.9", start=2, sport=40001))
    s.update(flow("192.168.1.6", "203.0.113.9", start=3))
    assert s.get("link_reverse_visibility_w") == pytest.approx(1 / 3)


def test_off_hours_uses_enclave_local_time():
    from datetime import datetime, timedelta, timezone
    ist = timezone(timedelta(hours=5, minutes=30))
    s = FeatureStore(StoreConfig(utc_offset_hours=5.5, work_hours=(9, 18)))
    monday_noon = datetime(2026, 9, 21, 12, 0, tzinfo=ist)
    assert monday_noon.weekday() == 0
    assert s.get("off_hours", monday_noon.timestamp()) is False
    assert s.get("off_hours", (monday_noon + timedelta(hours=12)).timestamp()) is True   # midnight
    assert s.get("off_hours", (monday_noon + timedelta(days=5)).timestamp()) is True     # Saturday
    assert s.get("off_hours", datetime(2026, 9, 21, 4, 0, tzinfo=timezone.utc).timestamp()) is False  # 09:30 IST


def test_contract_gate_on_reads():
    s = FeatureStore()
    with pytest.raises(UnavailableFeatureError):
        s.get("quic_client_hello")
    with pytest.raises(KeyError):
        s.get("not_a_feature", "x")


def test_memory_stays_under_ceiling_during_a_flood_of_distinct_sources():
    cfg = StoreConfig(max_hosts=200, max_dsts=200, max_pairs=500)
    load_contract()
    gc.collect()
    tracemalloc.start()
    try:
        s = FeatureStore(cfg)
        for i in range(10_000):  # 50x the host cap, every source distinct
            s.update(flow(f"10.{i >> 16}.{(i >> 8) & 255}.{i & 255}", f"198.51.{(i % 1000) >> 8}.{i % 256}",
                          start=i * 0.01, tls_ja4=[f"t13d_{i % 40}"]))
        _, peak = tracemalloc.get_traced_memory()
    finally:
        tracemalloc.stop()
    assert (len(s.hosts), len(s.dsts), len(s.pairs)) == (200, 200, 500)
    assert peak <= s.memory_ceiling_bytes(), f"peak {peak} > ceiling {s.memory_ceiling_bytes()}"
