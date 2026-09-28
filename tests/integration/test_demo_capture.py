"""The committed demo capture tells its story through the real pipeline: all six PS classes
fire, host 192.168.1.66's stages form one campaign (Discovery -> C2 -> Exfiltration), and the
DDoS is a separate campaign. Alerts on the real CTU-13 normal hosts are allowed (they are
reported in the README), but they must not join the attack host's campaign."""

import hashlib
from pathlib import Path

import pytest

from sih26145.orchestrator import ThreatDetectionPipeline

PCAP = Path(__file__).resolve().parents[2] / "demo" / "demo.pcap"
SHA256 = "ba44d087e800be6df0befdde5a7fb241073c9bfa01174b87949f6ea6d1a756f0"
CIDRS = "147.32.0.0/16,10.0.0.0/8,192.168.0.0/16,172.16.0.0/12"
PS_CLASSES = {"THREAT_DDOS_VOLUME", "THREAT_C2_BEACON", "THREAT_DNS_DGA", "THREAT_DNS_TUNNEL",
              "THREAT_ENCRYPTED_ANOMALY", "THREAT_RECON_PORTSCAN", "THREAT_EXFILTRATION"}


def test_demo_capture_is_the_committed_file():
    assert hashlib.sha256(PCAP.read_bytes()).hexdigest() == SHA256  # also in demo/ATTRIBUTION.md, DEPLOY.md
    assert PCAP.stat().st_size < 25_000_000


@pytest.mark.asyncio
async def test_demo_capture_story(monkeypatch):
    monkeypatch.setenv("SIH26145_INTERNAL_CIDRS", CIDRS)
    pipeline = ThreatDetectionPipeline(":memory:")
    try:
        alerts = await pipeline.process_pcap(str(PCAP))
        stages = await pipeline.storage.host_timeline("192.168.1.66")
    finally:
        await pipeline.storage.close()
    assert PS_CLASSES <= {a.threat_class for a in alerts}
    # the fast lane flags the SYN flood and the sweep first; the flow lane confirms both
    fast = [a for a in alerts if a.provisional]
    assert sorted(a.detection["rule_matches"][0] for a in fast) == ["RULE_FAST_SCAN", "RULE_FAST_SYN_FLOOD"]
    assert {a.confirms for a in alerts} >= {a.alert_id for a in fast}
    alerts = [a for a in alerts if not a.provisional]
    assert len(alerts) == 10
    host = [a for a in alerts if a.detection["correlation"]["host"] == "192.168.1.66"]
    assert len({a.campaign_id for a in host}) == 1
    assert list(dict.fromkeys(s["tactic_id"] for s in stages)) == ["TA0007", "TA0011", "TA0010"]
    (ddos,) = [a for a in alerts if a.threat_class == "THREAT_DDOS_VOLUME"]
    assert ddos.campaign_id != host[0].campaign_id
    others = [a for a in alerts if a not in host and a is not ddos]
    assert all(a.detection["correlation"]["host"].startswith("147.32.") for a in others)
    assert host[0].campaign_id not in {a.campaign_id for a in others}
