"""Benign captures from the audit's false positives, replayed through the real pipeline.

Each one is ordinary traffic and must raise zero alerts. Failures list what fired.
"""

import pytest

from sih26145.orchestrator import ThreatDetectionPipeline
from sih26145.utils.benign_scenarios import BENIGN_SCENARIOS, write_benign


# Red when this suite landed; strict, so each marker must be removed once its detector is fixed.
FAILING_BEFORE_REWIRE = {
    "ping_c6": "AUDIT D1: synthetic IsolationForest alerts on its own",
    "rtp_stream": "AUDIT A2: per-flow IAT C2 rule",
    "dns_lookups": "AUDIT A4/D1: whole-FQDN entropy DGA rule; synthetic RF labels it DGA",
    "tls_mail_and_dot": "AUDIT D3: port-based encrypted rule",
    "back_to_back": "AUDIT A1: per-flow pps DDoS rule",
    "failed_tcp": "AUDIT D1: synthetic IsolationForest",
    "monitoring_poller": "AUDIT D1: synthetic IsolationForest",
    "flash_crowd": "AUDIT D1: synthetic IsolationForest",
    "busy_resolver": "AUDIT A4/D1: per-flow DGA rule and synthetic ML",
    "mail_ptr_burst": "AUDIT A4: per-flow DGA and tunnel rules",
}


def _params():
    return [pytest.param(n, marks=pytest.mark.xfail(strict=True, reason=FAILING_BEFORE_REWIRE[n]))
            if n in FAILING_BEFORE_REWIRE else n for n in BENIGN_SCENARIOS]


async def run_capture(tmp_path, name):
    pcap = str(tmp_path / f"{name}.pcap")
    write_benign(name, pcap)
    pipeline = ThreatDetectionPipeline(":memory:")
    try:
        return await pipeline.process_pcap(pcap)
    finally:
        await pipeline.storage.close()


@pytest.mark.asyncio
@pytest.mark.parametrize("name", _params())
async def test_benign_capture_raises_no_alerts(tmp_path, name):
    alerts = await run_capture(tmp_path, name)
    fired = [(a.threat_class, a.detection["rule_matches"], a.detector["name"]) for a in alerts]
    assert fired == [], f"{name}: {len(fired)} alert(s) on benign traffic: {fired[:5]}"
