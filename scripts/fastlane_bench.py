"""Fast-lane measurements for docs/BENCHMARK.md.

    uv run python scripts/fastlane_bench.py latency SCENARIO --runs 20 --json OUT   # packet -> alert at 1x
    uv run python scripts/fastlane_bench.py ceiling --packets 2000000 --json OUT      # parser + fast lane pps

latency: the generated attack capture, followed by 45 s of unrelated traffic at 1 packet/s so
flows close by idle timeout as on a live link (not at end of file), replayed at 1x real time
through the full pipeline (run_stream). Packet -> alert = wall time from the ingest of the
capture's first attack packet to the alert's publication. Each run shifts the attack by 0.05 s
against the 1-s window grid. Reported for the fast lane (provisional) and the flow lane (the
alert that confirms it).

ceiling: 64-byte TCP SYN frames toward one destination, stamped at 1 GbE line rate for 64-byte
frames (1,488,095 packets/s), read with the real reader + parser and fed to FastLane.observe,
unthrottled, on one core. `--sources` sets how many distinct spoofed sources (0 = a new random
source every packet). Drops at and beyond the ceiling are MODELLED: a second run records each
packet's service time, and a FIFO capture ring of `--ring` slots is replayed against arrivals at
1.0x and 1.5x the measured ceiling; a packet that finds the ring full is dropped.
"""

import argparse
import asyncio
import json
import os
import platform
import random
import socket
import struct
import tempfile
import time
from collections import deque

import dpkt
import numpy as np

from sih26145.detectors.fastlane import FastLane
from sih26145.ingest.reader import PcapReader
from sih26145.orchestrator import ThreatDetectionPipeline
from sih26145.streaming import PipelineMetrics, run_stream
from sih26145.utils import attack_scenarios as atk
from sih26145.utils.benign_scenarios import T0
from sih26145.utils.pcap_generator import _write, create_ethernet_ip_packet

LINE_RATE_64B = 1_488_095  # 1 GbE: 10^9 / ((64 + 20) * 8)


def pct(xs):
    return dict(zip(("p50", "p95", "p99"), np.round(np.percentile(xs, [50, 95, 99]), 1).tolist())) if xs else None


async def one_run(scenario: str, shift: float) -> dict:
    attack = atk.ATTACK_SCENARIOS[scenario](T0 + shift)
    first = min(t for t, _ in attack)
    end = max(t for t, _ in attack)
    tail = [(end + 1 + i, create_ethernet_ip_packet("10.99.0.1", "10.99.0.2", 5353, 5353, "UDP", b"k"))
            for i in range(45)]
    path = tempfile.NamedTemporaryFile(suffix=".pcap", delete=False).name
    _write(path, attack + tail)
    pipeline = ThreatDetectionPipeline(":memory:")
    await pipeline.init()
    m, seen = PipelineMetrics(), []
    try:
        await run_stream(pipeline, path, speed=1.0, metrics=m, on_alert=lambda a: seen.append((time.perf_counter(), a)))
    finally:
        await pipeline.storage.close()
        os.remove(path)
    ingest0 = m.clock.wall0 + (first - m.clock.t0)  # speed 1: capture seconds = wall seconds
    fast = [(t, a) for t, a in seen if a.provisional]
    confirm = [(t, a) for t, a in seen if a.confirms]
    return {"shift_s": shift,
            "fast_ms": round((fast[0][0] - ingest0) * 1000, 1) if fast else None,
            "flow_ms": round((confirm[0][0] - ingest0) * 1000, 1) if confirm else None,
            "fast_rule": fast[0][1].detection["rule_matches"][0] if fast else None,
            "flow_rule": confirm[0][1].detection["rule_matches"][0] if confirm else None}


def latency(args) -> dict:
    runs = [asyncio.run(one_run(args.scenario, i * 0.05)) for i in range(args.runs)]
    fast = [r["fast_ms"] for r in runs if r["fast_ms"] is not None]
    flow = [r["flow_ms"] for r in runs if r["flow_ms"] is not None]
    return {"scenario": args.scenario, "runs": len(runs), "fast_fired": len(fast), "flow_confirmed": len(flow),
            "fast_lane_ms": pct(fast), "flow_lane_ms": pct(flow), "per_run": runs}


def syn_capture(path: str, n: int, sources: int) -> None:
    """n 64-byte Ethernet/IPv4/TCP SYN frames to 10.50.0.10:80, written straight to a pcap."""
    rng = random.Random(7)
    template = bytearray(create_ethernet_ip_packet("192.0.2.1", "10.50.0.10", 1024, 80, "TCP", b"", dpkt.tcp.TH_SYN))
    template += bytes(64 - len(template))  # Ethernet padding to the 64-byte minimum frame
    pool = [socket.inet_aton(f"{rng.randrange(11, 223)}.{rng.randrange(256)}.{rng.randrange(256)}.{rng.randrange(1, 255)}")
            for _ in range(sources)] if sources else None
    with open(path, "wb") as f:
        w = dpkt.pcap.Writer(f)
        for i in range(n):
            src = pool[i % sources] if pool else rng.getrandbits(32).to_bytes(4, "big")
            template[26:30] = src
            template[34:36] = struct.pack("!H", 1024 + i % 60000)
            w.writepkt(bytes(template), 1_790_000_000 + i / LINE_RATE_64B)


def ring_drops(service, rate: float, slots: int) -> int:
    """One server with the measured service times behind a FIFO ring of `slots` waiting
    packets; arrivals every 1/rate s. Returns packets that found the ring full."""
    in_system, last_finish, dropped = deque(), 0.0, 0
    for i, s in enumerate(service):
        t = i / rate
        while in_system and in_system[0] <= t:
            in_system.popleft()
        if len(in_system) > slots:  # one in service + `slots` waiting
            dropped += 1
            continue
        last_finish = max(t, last_finish) + s
        in_system.append(last_finish)
    return dropped


def ceiling(args) -> dict:
    path = tempfile.NamedTemporaryFile(suffix=".pcap", delete=False).name
    try:
        syn_capture(path, args.packets, args.sources)
        parser_only = []
        for _ in range(3):
            n, t0 = 0, time.perf_counter()
            for _pkt in PcapReader(path):
                n += 1
            parser_only.append(n / (time.perf_counter() - t0))
        rates, windows = [], 0
        for _ in range(3):
            fl, n, t0 = FastLane(), 0, time.perf_counter()
            for pkt in PcapReader(path):
                fl.observe(pkt)
                n += 1
            fl.flush()
            rates.append(n / (time.perf_counter() - t0))
            windows = fl.windows_closed
        # per-packet service times (the timing itself adds a little cost, so this run is slower)
        fl, service, prev = FastLane(), [], time.perf_counter()
        for pkt in PcapReader(path):
            fl.observe(pkt)
            now = time.perf_counter()
            service.append(now - prev)
            prev = now
    finally:
        os.remove(path)
    ceil = float(np.mean(rates))
    return {"packets": args.packets, "frame_bytes": 64, "sources": args.sources or "random per packet",
            "stamped_pps": LINE_RATE_64B, "runs_pps": [round(r) for r in rates], "ceiling_pps": round(ceil),
            "parser_only_pps": round(float(np.mean(parser_only))),
            "service_run_pps": round(len(service) / sum(service)), "windows": windows,
            "untracked_entities": fl.overflow,
            "ring_slots": args.ring,
            "modelled_drops": {f"{k}x": {"offered_pps": round(ceil * k), "dropped": ring_drops(service, ceil * k, args.ring),
                                         "of": len(service)} for k in (1.0, 1.5)},
            "cpu": next((ln.split(":", 1)[1].strip() for ln in open("/proc/cpuinfo") if ln.startswith("model name")), ""),
            "python": platform.python_version()}


def main():
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    sub = ap.add_subparsers(dest="cmd", required=True)
    lat = sub.add_parser("latency")
    lat.add_argument("scenario", choices=["syn_flood", "spoofed_flood", "udp_reflection", "port_sweep"])
    lat.add_argument("--runs", type=int, default=20)
    cei = sub.add_parser("ceiling")
    cei.add_argument("--packets", type=int, default=2_000_000)
    cei.add_argument("--sources", type=int, default=0)
    cei.add_argument("--ring", type=int, default=16384)
    for p in (lat, cei):
        p.add_argument("--json")
    args = ap.parse_args()
    out = latency(args) if args.cmd == "latency" else ceiling(args)
    print(json.dumps({k: v for k, v in out.items() if k != "per_run"}, indent=2))
    if args.json:
        with open(args.json, "w") as fh:
            json.dump(out, fh, indent=2)


if __name__ == "__main__":
    main()
