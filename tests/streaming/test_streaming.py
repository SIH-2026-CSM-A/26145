"""Streaming: bounded queue with counted drops, idle flush on a timer, live metrics, SSE."""

import importlib
import time

import pytest
from fastapi.testclient import TestClient

from sih26145.orchestrator import ThreatDetectionPipeline
from sih26145.streaming import PipelineMetrics, run_stream
from sih26145.utils.attack_scenarios import port_sweep, syn_flood
from sih26145.utils.benign_scenarios import T0
from sih26145.utils.pcap_generator import _write, create_ethernet_ip_packet as pkt

api = importlib.import_module("sih26145.api.app")  # the module; sih26145.api.app is also the FastAPI object


def capture(tmp_path, packets):
    path = str(tmp_path / "c.pcap")
    _write(path, packets)
    return path


@pytest.mark.asyncio
async def test_full_queue_drops_are_counted_not_hidden(tmp_path):
    pipeline = ThreatDetectionPipeline(":memory:")
    await pipeline.init()
    try:
        # 500 flows reach the queue in one burst at end of input; the queue holds 2
        m = await run_stream(pipeline, capture(tmp_path, syn_flood()), speed=1e6,
                             metrics=PipelineMetrics(queue_max=2))
    finally:
        await pipeline.storage.close()
    assert m.drops > 0
    assert m.flows_scored + m.drops == m.flows_flushed == 500


@pytest.mark.asyncio
async def test_lossless_mode_never_drops(tmp_path):
    pipeline = ThreatDetectionPipeline(":memory:")
    await pipeline.init()
    try:
        m = await run_stream(pipeline, capture(tmp_path, syn_flood()), metrics=PipelineMetrics(queue_max=2))
    finally:
        await pipeline.storage.close()
    assert m.drops == 0 and m.flows_scored == m.flows_flushed == 500


@pytest.mark.asyncio
async def test_idle_flow_is_scored_within_idle_timeout_plus_one_tick(tmp_path):
    # flow A: one packet at t=0, then silence; flow B arrives 2 s later (real time)
    packets = [(T0, pkt("192.168.1.10", "203.0.113.1", 50000, 443, "TCP", b"a")),
               (T0 + 2.0, pkt("192.168.1.11", "203.0.113.2", 50001, 443, "TCP", b"b"))]
    pipeline = ThreatDetectionPipeline(":memory:")
    pipeline.flow_tracker.idle_timeout = 0.3
    await pipeline.init()
    scored, score_batch = {}, pipeline.score_batch

    async def spy(flows):
        for flow in flows:
            scored[flow.flow_key.src_ip] = time.perf_counter()
        return await score_batch(flows)

    pipeline.score_batch = spy
    try:
        start = time.perf_counter()
        await run_stream(pipeline, capture(tmp_path, packets), speed=1.0, tick=0.1)
    finally:
        await pipeline.storage.close()
    waited = scored["192.168.1.10"] - start
    assert waited <= 0.3 + 0.1 + 0.25, f"idle flow scored after {waited:.3f} s"
    assert scored["192.168.1.10"] < scored["192.168.1.11"]


@pytest.mark.asyncio
async def test_alerts_reach_sse_subscribers_as_produced(tmp_path):
    pipeline = ThreatDetectionPipeline(":memory:", publish=api.broadcaster.broadcast)
    await pipeline.init()
    sub = api.broadcaster.subscribe()
    try:
        m = await run_stream(pipeline, capture(tmp_path, port_sweep()))
    finally:
        api.broadcaster.unsubscribe(sub)
        await pipeline.storage.close()
    assert m.alerts == 1 and sub.qsize() == 1
    event, payload = sub.get_nowait()
    assert event == "alert" and payload["threat_class"] == "THREAT_RECON_PORTSCAN"


@pytest.mark.asyncio
async def test_metrics_endpoint_reports_the_attached_pipeline(tmp_path):
    pipeline = ThreatDetectionPipeline(":memory:")
    await pipeline.init()
    try:
        m = await run_stream(pipeline, capture(tmp_path, port_sweep()))
    finally:
        await pipeline.storage.close()
    api.pipeline_metrics = m
    try:
        with TestClient(api.app) as client:
            data = client.get("/api/v1/metrics").json()
    finally:
        api.pipeline_metrics = None
    assert data["telemetry_source"] == "pipeline" and data["pipeline_state"] == "finished"
    for field in ("flows_per_sec", "mbps", "packets_per_sec", "active_flows", "queue_depth", "drops",
                  "link_reverse_visibility_w", "alert_latency_ms"):
        assert data[field] is not None, field
    assert data["flows_per_sec"] > 0 and data["drops"] == 0
    assert data["link_reverse_visibility_w"] == 1.0  # every sweep probe was answered
    assert set(data["alert_latency_ms"]) == {"p50", "p95", "p99"}


@pytest.mark.asyncio
async def test_batch_scoring_raises_the_same_alerts_as_one_flow_at_a_time(tmp_path, monkeypatch):
    """Each flow's features are taken before the next flow's store update, so batching only
    changes how many flows share one predict call."""
    from sih26145 import streaming
    from sih26145.utils.attack_scenarios import demo_packets

    path = capture(tmp_path, demo_packets())

    async def alerts(batch_max):
        monkeypatch.setattr(streaming, "BATCH_MAX", batch_max)
        pipeline = ThreatDetectionPipeline(":memory:")
        try:
            out = await pipeline.process_pcap(path)
        finally:
            await pipeline.storage.close()
        return sorted((a.threat_class, a.flow_id, a.severity, tuple(a.detection["ml_scores"])) for a in out)

    one, batched = await alerts(1), await alerts(256)
    assert one == batched and len(one) > 5
