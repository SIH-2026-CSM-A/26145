"""Alerts of the demo capture through the real pipeline (unthrottled, lossless), with campaigns.

    SIH26145_INTERNAL_CIDRS=... uv run python scripts/demo_report.py demo/demo.pcap [--speed N]

--speed N replays paced at N x real time (the serve path, drops counted) instead of unthrottled.
"""

import argparse
import asyncio
import collections

from sih26145.orchestrator import ThreatDetectionPipeline
from sih26145.streaming import run_stream
from sih26145.utils.benign_scenarios import T0

CTU_NET = "147.32."


async def main(pcap: str, speed=None) -> None:
    pipeline = ThreatDetectionPipeline(":memory:")
    alerts = []
    try:
        await pipeline.init()
        m = await run_stream(pipeline, pcap, speed=speed, on_alert=alerts.append)
    finally:
        await pipeline.storage.close()
    print(f"speed {speed or 'unthrottled'}: {m.flows_scored} flows scored, {m.drops} dropped")
    for a in alerts:
        c = a.detection["correlation"]
        t = a.flow["window_end"]
        print(f"{t[11:19]} {a.threat_class:26} {a.severity:8} {a.flow['src_ip']:>15} -> {a.flow['dst_ip']:<15} "
              f"{a.campaign_id} {c['tactic']:<20} host {c['host']}")
    by_class = collections.Counter(a.threat_class for a in alerts)
    on_ctu = [a for a in alerts if a.detection["correlation"]["host"].startswith(CTU_NET)]
    print("\nby class:", dict(sorted(by_class.items())))
    print("campaigns:", len({a.campaign_id for a in alerts}))
    print(f"alerts whose internal host is a real CTU-13 normal host: {len(on_ctu)}",
          dict(collections.Counter(a.threat_class for a in on_ctu)))
    print("T0 =", T0)


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("pcap")
    ap.add_argument("--speed", type=float, default=None)
    args = ap.parse_args()
    asyncio.run(main(args.pcap, args.speed))
