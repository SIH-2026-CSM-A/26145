"""Streaming pipeline: ingest -> bounded queue -> scoring, with an idle-flush timer.

Three tasks on one event loop:
- producer (ingest): packets -> FlowTracker; flushed flows go onto a bounded asyncio.Queue.
  Paced/live replay drops a flow when the queue is full and counts it (backpressure never
  stalls capture and never hides loss). Unthrottled file analysis blocks instead (lossless).
- timer: every `tick` wall seconds, flushes flows idle for `idle_timeout` on the replay
  clock, so an idle flow is scored within idle_timeout + tick; also samples rates.
- consumer (scoring): FeatureStore -> detectors -> aggregator -> storage -> publish.
"""

import asyncio
import time
from collections import deque
from typing import Callable, Iterable, Optional

import numpy as np

from sih26145.ingest.reader import PcapReader

RATE_WINDOW_S = 5.0


class PipelineMetrics:
    """Counters and latency samples of one streaming run, read by /api/v1/metrics."""

    def __init__(self, queue_max: int = 10_000):
        self.queue_max = queue_max
        self.packets = self.wire_bytes = self.flows_flushed = self.flows_scored = 0
        self.drops = self.alerts = 0
        self.state = "starting"
        self.started = self.finished = None
        self.event_time: Optional[float] = None
        self.caught_up = False            # producer is waiting on the replay clock
        self.flow_latency = deque(maxlen=10_000)   # flush -> scored, seconds
        self.alert_latency = deque(maxlen=10_000)  # flush -> alert published, seconds
        self._samples = deque(maxlen=int(RATE_WINDOW_S) + 1)
        self.pipeline = self.queue = None

    def sample(self) -> None:
        self._samples.append((time.perf_counter(), self.packets, self.wire_bytes, self.flows_scored))

    def rates(self):
        """(flows/s, Mbps, packets/s, seconds covered): the last ~5 s while running, the
        whole run once finished."""
        if self.state == "finished" and self.started is not None:
            span = self.finished - self.started
            first, last = (0, 0, 0), (self.flows_scored, self.wire_bytes, self.packets)
        elif len(self._samples) >= 2:
            (t0, p0, b0, f0), (t1, p1, b1, f1) = self._samples[0], self._samples[-1]
            span, first, last = t1 - t0, (f0, b0, p0), (f1, b1, p1)
        else:
            return None, None, None, None
        if span <= 0:
            return None, None, None, None
        flows, nbytes, pkts = (b - a for a, b in zip(first, last))
        return flows / span, nbytes * 8 / span / 1e6, pkts / span, span

    def snapshot(self) -> dict:
        fps, mbps, pps, span = self.rates()
        lat = np.percentile(np.array(self.alert_latency) * 1000, [50, 95, 99]).tolist() if self.alert_latency else None
        store = self.pipeline.feature_store if self.pipeline else None
        return {
            "pipeline_state": self.state,
            "active_flows": self.pipeline.flow_tracker.get_active_flow_count() if self.pipeline else None,
            "flows_per_sec": fps, "mbps": mbps, "packets_per_sec": pps, "rate_window_s": span,
            "queue_depth": self.queue.qsize() if self.queue is not None else 0, "queue_max": self.queue_max,
            "drops": self.drops, "flows_scored": self.flows_scored,
            "link_reverse_visibility_w": store.get("link_reverse_visibility_w") if store else None,
            # null while no alert has been raised yet: there is nothing to measure
            "alert_latency_ms": dict(zip(("p50", "p95", "p99"), lat)) if lat else None,
        }


async def run_stream(pipeline, pcap_path: str, speed: Optional[float] = None, tick: float = 1.0,
                     metrics: Optional[PipelineMetrics] = None, drop_when_full: Optional[bool] = None,
                     on_alert: Optional[Callable] = None) -> PipelineMetrics:
    """Replay a capture through the pipeline. speed=None: as fast as possible (lossless);
    speed=k: k x real time on the capture's timestamps (drops when the queue is full)."""
    m = metrics or PipelineMetrics()
    drop = speed is not None if drop_when_full is None else drop_when_full
    queue: asyncio.Queue = asyncio.Queue(maxsize=m.queue_max)
    m.pipeline, m.queue, m.state, m.started = pipeline, queue, "running", time.perf_counter()
    clock = _ReplayClock(speed)
    m.sample()
    consumer = asyncio.create_task(_consume(pipeline, queue, m, on_alert))
    timer = asyncio.create_task(_timer(pipeline, queue, m, clock, tick, drop))
    try:
        await _produce(pipeline, PcapReader(pcap_path), queue, m, clock, tick, drop)
        await queue.put(None)  # end-of-input marker is never dropped
        await consumer
    finally:
        timer.cancel()
        consumer.cancel()
        m.state, m.finished = "finished", time.perf_counter()
    return m


class _ReplayClock:
    """Maps capture timestamps to wall time for paced replay."""

    def __init__(self, speed: Optional[float]):
        self.speed, self.t0, self.wall0 = speed, None, None

    def start(self, t: float) -> None:
        if self.t0 is None:
            self.t0, self.wall0 = t, time.perf_counter()

    def now(self) -> Optional[float]:
        return None if self.t0 is None else self.t0 + (time.perf_counter() - self.wall0) * self.speed


async def _enqueue(flows: Iterable, queue: asyncio.Queue, m: PipelineMetrics, drop: bool) -> None:
    for flow in sorted(flows, key=lambda f: f.start_time):  # oldest first: pair gaps stay ordered
        flow.flushed_at = time.perf_counter()
        m.flows_flushed += 1
        if not drop:
            await queue.put(flow)
            continue
        try:
            queue.put_nowait(flow)
        except asyncio.QueueFull:
            m.drops += 1


async def _produce(pipeline, reader, queue, m: PipelineMetrics, clock: _ReplayClock, tick: float, drop: bool):
    tracker, last_flush = pipeline.flow_tracker, None
    for n, pkt in enumerate(reader):
        if clock.speed:
            clock.start(pkt.timestamp)
            delay = (pkt.timestamp - clock.t0) / clock.speed - (time.perf_counter() - clock.wall0)
            if delay > 0:
                m.caught_up = True
                await asyncio.sleep(delay)
                m.caught_up = False
        m.packets += 1
        m.wire_bytes += pkt.packet_len
        m.event_time = pkt.timestamp
        await _enqueue(tracker.process_packet(pkt), queue, m, drop)
        if not clock.speed and (last_flush is None or pkt.timestamp - last_flush >= tick):
            await _enqueue(tracker.flush_expired(pkt.timestamp), queue, m, drop)  # event-time idle sweep
            last_flush = pkt.timestamp
        if n % 256 == 0:
            await asyncio.sleep(0)
    remaining = list(tracker._active_flows.values())
    tracker._active_flows.clear()
    await _enqueue(remaining, queue, m, drop)


async def _timer(pipeline, queue, m: PipelineMetrics, clock: _ReplayClock, tick: float, drop: bool):
    while True:
        await asyncio.sleep(tick)
        m.sample()
        if clock.speed and m.event_time is not None:
            # Waiting on the clock: capture time has really passed. Behind schedule: only
            # what has been ingested counts, so late packets don't split their flows.
            now = clock.now() if m.caught_up else m.event_time
            await _enqueue(pipeline.flow_tracker.flush_expired(now), queue, m, drop)


async def _consume(pipeline, queue, m: PipelineMetrics, on_alert: Optional[Callable]):
    while True:
        flow = await queue.get()
        if flow is None:
            return
        alerts = await pipeline.score(flow)
        done = time.perf_counter()
        m.flows_scored += 1
        m.flow_latency.append(done - flow.flushed_at)
        for alert in alerts:
            m.alerts += 1
            m.alert_latency.append(done - flow.flushed_at)
            if on_alert is not None:
                on_alert(alert)
        await asyncio.sleep(0)
