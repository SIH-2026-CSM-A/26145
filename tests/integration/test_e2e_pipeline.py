"""End-to-End Integration Tests for SIH26145 Threat Pipeline."""

import os
import pytest
import tempfile
from sih26145.orchestrator import ThreatDetectionPipeline
from sih26145.utils.pcap_generator import generate_threat_pcap


import asyncio


@pytest.mark.asyncio
async def test_end_to_end_pcap_analysis():
    with tempfile.NamedTemporaryFile(suffix=".pcap", delete=False) as tmp_pcap:
        pcap_path = tmp_pcap.name

    try:
        packet_count = generate_threat_pcap(pcap_path)
        assert packet_count > 0

        alert_queue = asyncio.Queue()
        pipeline = ThreatDetectionPipeline(":memory:")
        alerts = await pipeline.process_pcap(pcap_path, alert_queue=alert_queue)

        assert len(alerts) >= 6
        threat_classes = {a.threat_class for a in alerts}
        
        # Verify detection coverage across all 6 PS threat categories
        required_threat_categories = {
            "THREAT_DDOS_VOLUME",
            "THREAT_C2_BEACON",
            "THREAT_DNS_DGA",
            "THREAT_DNS_TUNNEL",
            "THREAT_ENCRYPTED_ANOMALY",
            "THREAT_RECON_PORTSCAN",
            "THREAT_EXFILTRATION",
        }
        for req_cls in required_threat_categories:
            assert req_cls in threat_classes, f"Missing required PS threat category {req_cls} in pipeline alerts!"

        # Verify canonical schema & invariants
        for alert in alerts:
            assert alert.alert_id.startswith("urn:uuid:")
            assert alert.confidence >= 0.0 and alert.confidence <= 1.0
            assert alert.severity in ["CRITICAL", "HIGH", "MEDIUM", "LOW"]
            assert alert.detector["name"] is not None
            assert alert.flow["src_ip"] is not None

        # Verify SSE queue received alerts
        assert alert_queue.qsize() == len(alerts)

        # Verify SQLite storage contains alerts
        persisted_alerts = await pipeline.storage.get_alerts(limit=1000)
        assert len(persisted_alerts) == len(alerts)
    finally:
        if os.path.exists(pcap_path):
            os.remove(pcap_path)

