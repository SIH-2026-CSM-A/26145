"""Strict one-way replay (docs/ONEWAY.md): scripts/oneway.py keeps only boundary-crossing
packets of one direction, and an inbound flood is still caught on the IN variant alone."""

import importlib.util
from pathlib import Path

import pytest

from sih26145.features.directional import NetworkPolicy
from sih26145.ingest.reader import PcapReader
from sih26145.orchestrator import ThreatDetectionPipeline
from sih26145.utils import attack_scenarios as atk
from sih26145.utils.pcap_generator import _write

ROOT = Path(__file__).resolve().parents[2]
spec = importlib.util.spec_from_file_location("oneway", ROOT / "scripts" / "oneway.py")
oneway = importlib.util.module_from_spec(spec)
spec.loader.exec_module(oneway)


def test_variants_keep_only_their_direction(tmp_path):
    policy = NetworkPolicy(None)  # RFC1918 internal
    src = tmp_path / "mixed.pcap"
    # external -> internal flood, internal -> external upload, internal -> internal scan
    _write(str(src), atk.syn_flood() + atk.exfil_upload(atk.T0 + 20) + atk.port_sweep(atk.T0 + 40))
    for variant, want in (("IN", (False, True)), ("OUT", (True, False))):
        out = tmp_path / f"{variant}.pcap"
        res = oneway.rewrite(variant, str(src), str(out), policy)
        pkts = list(PcapReader(str(out)))
        assert res["kept"] == len(pkts) > 0
        assert {(policy.is_internal(p.src_ip), policy.is_internal(p.dst_ip)) for p in pkts} == {want}


@pytest.mark.asyncio
async def test_inbound_flood_is_caught_on_the_in_variant_alone(tmp_path):
    src, out = tmp_path / "flood.pcap", tmp_path / "IN.pcap"
    _write(str(src), atk.syn_flood())
    oneway.rewrite("IN", str(src), str(out), NetworkPolicy(None))
    pipeline = ThreatDetectionPipeline(":memory:")
    try:
        alerts = await pipeline.process_pcap(str(out))
    finally:
        await pipeline.storage.close()
    rules = sorted(a.detection["rule_matches"][0] for a in alerts)
    assert rules == ["RULE_DDOS_SYN_FLOOD", "RULE_FAST_SYN_FLOOD"]
    assert {a.observability_state for a in alerts if not a.provisional} == {"forward_only"}
