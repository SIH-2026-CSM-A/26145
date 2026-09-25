"""End-to-end throughput benchmark: flows/s and Mbps, drop %, alert latency.

Runs the real streaming pipeline (streaming.run_stream: ingest -> bounded queue -> store,
detectors, ML, aggregator -> SQLite WAL file) on a capture and reports what it measured,
with the machine it ran on.

    uv run python scripts/benchmark.py CAPTURE.pcap                 # unthrottled (lossless)
    uv run python scripts/benchmark.py CAPTURE.pcap --speed 40      # paced at 40x real time (drops counted)
    uv run python scripts/benchmark.py CAPTURE.pcap --profile out.prof

Latency is flush -> alert published (and flush -> scored for every flow): the time a flow
spends in the queue and in scoring. The wait from a flow's last packet to its flush is set
by the tracker's idle timeout (15 s) plus one timer tick and is not included.
"""

import argparse
import asyncio
import cProfile
import json
import os
import platform
import pstats
import struct
import sys
import tempfile
import time
from collections import Counter
from importlib.metadata import version

import numpy as np

from sih26145.orchestrator import ThreatDetectionPipeline
from sih26145.streaming import PipelineMetrics, run_stream


def hardware() -> dict:
    cpu = next((line.split(":", 1)[1].strip() for line in open("/proc/cpuinfo") if line.startswith("model name")),
               platform.processor())
    mem = next((int(line.split()[1]) // 1024 for line in open("/proc/meminfo") if line.startswith("MemTotal")), None)
    return {"cpu": cpu, "logical_cpus": os.cpu_count(), "mem_mib": mem, "os": platform.platform(),
            "python": platform.python_version(),
            "packages": {p: version(p) for p in ("numpy", "dpkt", "scikit-learn", "aiosqlite")}}


def capture_facts(path: str) -> dict:
    """Records, wire bytes, truncated records and time span, from the pcap record headers."""
    with open(path, "rb") as f:
        head = f.read(24)
        endian = "<" if head[:4] in (b"\xd4\xc3\xb2\xa1", b"\x4d\x3c\xb2\xa1") else ">"
        n = truncated = wire = 0
        first = last = None
        while len(rec := f.read(16)) == 16:
            sec, usec, caplen, wirelen = struct.unpack(endian + "IIII", rec)
            f.seek(caplen, 1)
            n, wire, truncated = n + 1, wire + wirelen, truncated + (caplen < wirelen)
            last = sec + usec / 1e6
            first = last if first is None else first
    return {"file": path, "file_mib": round(os.path.getsize(path) / 2**20, 1), "packets": n,
            "wire_bytes": wire, "truncated_records": truncated, "span_s": round(last - first, 1)}


def pct(samples, scale=1000.0):
    if not samples:
        return None
    return dict(zip(("p50", "p95", "p99"), np.round(np.percentile(np.array(samples) * scale, [50, 95, 99]), 2).tolist()))


async def bench(path: str, speed, queue_max: int) -> dict:
    db = tempfile.NamedTemporaryFile(suffix=".db", delete=False).name
    pipeline = ThreatDetectionPipeline(db)
    await pipeline.init()
    m, by_class = PipelineMetrics(queue_max), Counter()
    start = time.perf_counter()
    try:
        await run_stream(pipeline, path, speed=speed, metrics=m, on_alert=lambda a: by_class.update([a.threat_class]))
    finally:
        wall = time.perf_counter() - start
        await pipeline.storage.close()
        for suffix in ("", "-wal", "-shm"):
            if os.path.exists(db + suffix):
                os.remove(db + suffix)
    return {
        "mode": f"paced {speed}x real time (drop when queue full)" if speed else "unthrottled (lossless backpressure)",
        "queue_max": queue_max, "wall_s": round(wall, 2),
        "packets": m.packets, "flows_flushed": m.flows_flushed, "flows_scored": m.flows_scored,
        "drops": m.drops, "drop_pct": round(100 * m.drops / m.flows_flushed, 3) if m.flows_flushed else 0.0,
        "flows_per_s": round(m.flows_scored / wall, 1), "mbps": round(m.wire_bytes * 8 / wall / 1e6, 2),
        "packets_per_s": round(m.packets / wall, 1), "alerts": m.alerts, "alerts_by_class": dict(by_class),
        "alert_latency_ms": pct(m.alert_latency), "flow_latency_ms": pct(m.flow_latency),
    }


def main():
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("pcap")
    ap.add_argument("--speed", type=float, default=None, help="replay at this multiple of real time")
    ap.add_argument("--queue-max", type=int, default=10_000)
    ap.add_argument("--profile", help="write cProfile stats here and print the top functions by own time")
    ap.add_argument("--json", help="write the result here")
    args = ap.parse_args()

    result = {"hardware": hardware(), "capture": capture_facts(args.pcap)}
    prof = cProfile.Profile() if args.profile else None
    if prof:
        prof.enable()
    result["run"] = asyncio.run(bench(args.pcap, args.speed, args.queue_max))
    if prof:
        prof.disable()
        prof.dump_stats(args.profile)
        result["run"]["profiled"] = True  # cProfile slows the run; do not quote these rates
    print(json.dumps(result, indent=2))
    if args.json:
        with open(args.json, "w") as fh:
            json.dump(result, fh, indent=2)
    if prof:
        pstats.Stats(args.profile, stream=sys.stderr).sort_stats("tottime").print_stats(15)


if __name__ == "__main__":
    main()
