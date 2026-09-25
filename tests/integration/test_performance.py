"""Empirical Performance Measurement Tests for SIH26145 Threat Pipeline."""

import time
import tempfile
import pytest
import os
from sih26145.orchestrator import ThreatDetectionPipeline
from sih26145.utils.pcap_generator import generate_threat_pcap
from sih26145.storage.database import AlertStorage
from sih26145.alerts.models import Alert
from sih26145.api.app import app
from fastapi.testclient import TestClient


@pytest.mark.asyncio
async def test_pipeline_end_to_end_performance_benchmark():
    """Benchmark end-to-end PCAP processing time, alert generation, and throughput."""
    with tempfile.NamedTemporaryFile(suffix=".pcap", delete=False) as tmp_pcap:
        pcap_path = tmp_pcap.name

    try:
        packet_count = generate_threat_pcap(pcap_path)
        assert packet_count > 0

        pipeline = ThreatDetectionPipeline(":memory:")

        start_time = time.perf_counter()
        alerts = await pipeline.process_pcap(pcap_path)
        end_time = time.perf_counter()
        await pipeline.storage.close()

        processing_time_ms = (end_time - start_time) * 1000.0
        pkt_per_sec = (packet_count / (end_time - start_time)) if (end_time > start_time) else 0.0

        print(f"\n[PERFORMANCE] PCAP Packet Count: {packet_count}")
        print(f"[PERFORMANCE] Total Processing Time: {processing_time_ms:.2f} ms")
        print(f"[PERFORMANCE] Processing Throughput: {pkt_per_sec:.2f} pps")
        print(f"[PERFORMANCE] Alerts Generated: {len(alerts)}")

        # Performance invariants
        assert processing_time_ms < 5000.0, "Processing latency exceeded 5 seconds"
        assert len(alerts) >= 4, "Expected at least 4 alerts from threat PCAP"
    finally:
        if os.path.exists(pcap_path):
            os.remove(pcap_path)


def test_api_response_time_benchmark():
    """Benchmark REST API query response time."""
    client = TestClient(app)
    start_time = time.perf_counter()
    response = client.get("/api/v1/health")
    end_time = time.perf_counter()

    latency_ms = (end_time - start_time) * 1000.0
    assert response.status_code == 200
    print(f"\n[PERFORMANCE] REST API Health Endpoint Latency: {latency_ms:.2f} ms")
    assert latency_ms < 200.0, "API response latency exceeded 200ms threshold"
