"""Detector (f) picks its evidence from what the capture holds, and says which path it took.

The same exfiltration is replayed twice through the real pipeline: once as a full-duplex
capture and once with only the outbound half.
"""

import pytest

from sih26145.detectors.context import DetectionContext
from sih26145.detectors.rules.detectors import ExfiltrationDetector
from sih26145.features.directional import NetworkPolicy
from sih26145.features.store import FeatureStore
from sih26145.flow.models import FlowKey, FlowRecord
from sih26145.orchestrator import ThreatDetectionPipeline
from sih26145.utils.pcap_generator import generate_exfil_pcap


async def exfil_alerts(tmp_path, bidirectional):
    pcap = str(tmp_path / f"exfil_{bidirectional}.pcap")
    generate_exfil_pcap(pcap, bidirectional)
    pipeline = ThreatDetectionPipeline(":memory:")
    try:
        alerts = await pipeline.process_pcap(pcap)
    finally:
        await pipeline.storage.close()
    return [a.to_dict() for a in alerts if a.threat_class == "THREAT_EXFILTRATION"]


@pytest.mark.asyncio
async def test_forward_only_capture_takes_the_substitute_path_and_names_it(tmp_path):
    alerts = await exfil_alerts(tmp_path, bidirectional=False)
    assert len(alerts) == 1, f"expected one exfil alert, got {len(alerts)}"
    alert = alerts[0]
    assert alert["observability_state"] == "forward_only"
    assert alert["detection"]["rule_matches"] == ["RULE_EXFIL_EGRESS_BASELINE"]
    assert len(alert["substitutions"]) == 1, "forward-only exfil alert must name its substitution"
    sub = alert["substitutions"][0]
    assert sub["unavailable_on_this_flow"] == "outbound_inbound_byte_ratio"
    assert sub["substituted_by"] == ["src_egress_bytes_z", "dst_distinct_srcs_longterm", "off_hours"]
    features = {e["feature"] for e in alert["evidence"]}
    assert "outbound_inbound_byte_ratio" not in features
    assert {"src_egress_bytes_z", "dst_distinct_srcs_longterm", "off_hours"} <= features
    assert alert["flow"]["dst_ip"] == "198.51.100.77"


@pytest.mark.asyncio
async def test_bidirectional_capture_takes_the_ratio_path(tmp_path):
    alerts = await exfil_alerts(tmp_path, bidirectional=True)
    assert len(alerts) == 1, f"expected one exfil alert, got {len(alerts)}"
    alert = alerts[0]
    assert alert["observability_state"] == "bidirectional"
    assert alert["detection"]["rule_matches"] == ["RULE_EXFIL_OUTBOUND_RATIO"]
    assert alert["substitutions"] == []
    ratio = next(e for e in alert["evidence"] if e["feature"] == "outbound_inbound_byte_ratio")
    assert ratio["value"] > 10 and ratio["baseline_source"] == "rule_threshold"
    assert alert["flow"]["dst_ip"] == "198.51.100.77"


def _ctx(flow, store=None):
    store = store or FeatureStore()
    store.update(flow)
    return DetectionContext(flow, store, NetworkPolicy())


def test_a_one_way_view_of_a_download_is_not_exfiltration():
    download = FlowRecord(FlowKey("203.0.113.9", "192.168.1.5", 50000, "TCP", 443), 1.0, 3.0,
                          fwd_packets=2000, fwd_bytes=3_000_000, fwd_is_responder=True)
    assert ExfiltrationDetector().detect(None, _ctx(download)) is None


def test_internal_transfers_and_missing_context_are_not_exfiltration():
    internal = FlowRecord(FlowKey("192.168.1.5", "192.168.1.9", 445, "TCP", 50000), 1.0, 3.0,
                          fwd_packets=2000, fwd_bytes=3_000_000, rev_packets=10, rev_bytes=600)
    assert ExfiltrationDetector().detect(None, _ctx(internal)) is None
    assert ExfiltrationDetector().detect(None, None) is None


def test_substitute_path_stays_silent_until_the_host_has_a_baseline():
    burst = FlowRecord(FlowKey("192.168.1.70", "198.51.100.5", 443, "TCP", 50000), 10.0, 20.0,
                       fwd_packets=700, fwd_bytes=1_000_000)
    assert ExfiltrationDetector().detect(None, _ctx(burst)) is None
