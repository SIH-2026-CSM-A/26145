"""Benign captures from the audit's false positives, replayed through the real pipeline.

Each one is ordinary traffic and must raise zero alerts. Failures list what fired.
"""

import pytest

from sih26145.orchestrator import ThreatDetectionPipeline
from sih26145.utils.benign_scenarios import BENIGN_SCENARIOS, write_benign


async def run_capture(tmp_path, name):
    pcap = str(tmp_path / f"{name}.pcap")
    write_benign(name, pcap)
    pipeline = ThreatDetectionPipeline(":memory:")
    try:
        return await pipeline.process_pcap(pcap)
    finally:
        await pipeline.storage.close()


@pytest.mark.asyncio
@pytest.mark.parametrize("name", list(BENIGN_SCENARIOS))
async def test_benign_capture_raises_no_alerts(tmp_path, name):
    alerts = await run_capture(tmp_path, name)
    fired = [(a.threat_class, a.detection["rule_matches"], a.detector["name"]) for a in alerts]
    assert fired == [], f"{name}: {len(fired)} alert(s) on benign traffic: {fired[:5]}"
