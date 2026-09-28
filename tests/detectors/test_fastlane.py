"""Fast lane (docs/ARCHITECTURE.md §9a): 1-s packet counters raise a provisional alert for floods
and scans before any flow closes, and the flow-lane alert for the same entity confirms it."""

import pytest

from sih26145.detectors.fastlane import SET_CAP, FastLane
from sih26145.flow.community_id import community_id
from sih26145.ingest.models import PacketMetadata
from sih26145.orchestrator import ThreatDetectionPipeline
from sih26145.storage import chain
from sih26145.utils import attack_scenarios as atk
from sih26145.utils.pcap_generator import _write


async def replay(tmp_path, packets, db=":memory:"):
    pcap = str(tmp_path / "capture.pcap")
    _write(pcap, packets)
    pipeline = ThreatDetectionPipeline(db)
    try:
        return await pipeline.process_pcap(pcap)
    finally:
        await pipeline.storage.close()


@pytest.mark.asyncio
@pytest.mark.parametrize("scenario,rule,scope,confirmer", [
    ("syn_flood", "RULE_FAST_SYN_FLOOD", "dst", "RULE_DDOS_SYN_FLOOD"),
    ("spoofed_flood", "RULE_FAST_SYN_FLOOD", "dst", "RULE_DDOS_SYN_FLOOD"),
    ("udp_reflection", "RULE_FAST_UDP_REFLECTION", "dst", "RULE_DDOS_UDP_REFLECTION"),
    ("port_sweep", "RULE_FAST_SCAN", "src", "RULE_RECON_FANOUT_SYN_ONLY"),
])
async def test_fast_lane_fires_first_and_the_flow_lane_confirms(tmp_path, scenario, rule, scope, confirmer):
    alerts = await replay(tmp_path, atk.ATTACK_SCENARIOS[scenario]())
    (fast,) = [a for a in alerts if a.provisional]
    assert fast.detection["rule_matches"] == [rule] and fast.detection["lane"] == "fast lane, 1-s window"
    entity = fast.detection["entity"]
    assert fast.flow_id.startswith(f"win:{scope}:{entity}:") and fast.flow_id.endswith(":1")
    assert fast.contributing_flows and all(c.startswith("1:") for c in fast.contributing_flows)
    assert fast.observability_state is None and fast.campaign_id is None
    (flow_lane,) = [a for a in alerts if a.detection["rule_matches"] == [confirmer]]
    assert flow_lane.confirms == fast.alert_id and not flow_lane.provisional
    assert alerts.index(fast) < alerts.index(flow_lane)  # raised before any flow closed


@pytest.mark.asyncio
async def test_flow_lane_aggregate_alert_names_its_window_and_trigger(tmp_path):
    alerts = await replay(tmp_path, atk.port_sweep())
    (recon,) = [a for a in alerts if not a.provisional]
    f = recon.flow
    trigger = community_id(f["protocol"], f["src_ip"], f["dst_ip"], f["src_port"], f["dst_port"])
    assert recon.flow_id.startswith("win:src:192.168.1.52:") and recon.flow_id.endswith(":60")
    assert int(recon.flow_id.split(":")[3]) % 60 == 0
    assert recon.contributing_flows[0] == trigger and len(recon.contributing_flows) <= 5


@pytest.mark.asyncio
async def test_both_lanes_append_to_one_verifiable_chain(tmp_path):
    db = str(tmp_path / "log.db")
    alerts = await replay(tmp_path, atk.syn_flood() + atk.port_sweep(atk.T0 + 30), db)
    assert sum(a.provisional for a in alerts) == 2
    res = chain.verify(db)
    assert res["ok"] and res["n"] == len(alerts)


def _syn(t, src, dst="10.0.0.1", ttl=64, flags=0x02, dport=80):
    return PacketMetadata(t, 60, 60, 4, src, dst, "TCP", ttl=ttl, src_port=40000, dst_port=dport, tcp_flags=flags)


def test_completed_handshakes_are_not_syn_only():
    """A flash crowd: 100 sources SYN then ACK in the same second. No hit."""
    fl = FastLane()
    for i in range(100):
        fl.observe(_syn(10.0 + i / 200, f"198.51.100.{i}"))
        fl.observe(_syn(10.0 + i / 200 + 0.001, f"198.51.100.{i}", flags=0x10))
    win, hits = fl.flush()
    assert hits == [] and win.store_feature("fl_dst_syn_only_share_1s", "10.0.0.1") == 0.0


def test_window_closes_on_the_next_second_and_counts_saturate():
    fl = FastLane()
    for i in range(SET_CAP + 100):
        assert fl.observe(_syn(20.0 + i / 1e5, f"10.{i // 65536}.{i // 256 % 256}.{i % 256}", ttl=50 + i % 3)) is None
    win, hits = fl.observe(_syn(21.0, "192.0.2.1"))
    assert win.start == 20.0 and win.store_feature("fl_dst_syn_srcs_1s", "10.0.0.1") == SET_CAP
    assert win.store_feature("fl_dst_ttl_spread_1s", "10.0.0.1") == 2
    assert [h.rule_id for _, h in hits] == ["RULE_FAST_SYN_FLOOD"]
    assert fl.observe(_syn(20.5, "192.0.2.2")) is None  # reordered packet: counted in the open second
