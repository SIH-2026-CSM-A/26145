"""Runtime check behind docs/ISOLATION.md: a full replay of the demo capture through the sensor
pipeline opens no network socket. test_no_transmit.py scans the source; this one watches the
running process with a CPython audit hook, so a socket opened by any library counts too.

AF_UNIX is allowed: asyncio's event loop wakes itself through a local socketpair."""

import json
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
CIDRS = "147.32.0.0/16,10.0.0.0/8,192.168.0.0/16,172.16.0.0/12"

CHILD = r"""
import asyncio, json, socket, sys
NET = {socket.AF_INET, socket.AF_INET6, getattr(socket, "AF_PACKET", -1)}
seen = []

def hook(event, args):
    if event == "socket.__new__" and args[1] in NET:
        seen.append([event, int(args[1])])
    elif event in ("socket.connect", "socket.bind", "socket.sendto", "socket.sendmsg") and args[0].family in NET:
        seen.append([event, int(args[0].family)])

sys.addaudithook(hook)
from sih26145.orchestrator import ThreatDetectionPipeline

async def main():
    p = ThreatDetectionPipeline(":memory:")
    try:
        alerts = await p.process_pcap(sys.argv[1])
    finally:
        await p.storage.close()
    if sys.argv[2] == "inject":  # falsification: the hook must see this
        socket.socket(socket.AF_INET, socket.SOCK_DGRAM).close()
    print(json.dumps({"alerts": len(alerts), "network_sockets": seen}))

asyncio.run(main())
"""


def _replay(mode: str) -> dict:
    out = subprocess.run([sys.executable, "-c", CHILD, str(ROOT / "demo" / "demo.pcap"), mode],
                         capture_output=True, text=True, timeout=300, cwd=ROOT,
                         env={"SIH26145_INTERNAL_CIDRS": CIDRS, "PATH": "/usr/bin:/bin"})
    assert out.returncode == 0, out.stderr
    return json.loads(out.stdout.strip().splitlines()[-1])


def test_replay_opens_no_network_socket():
    res = _replay("clean")
    assert res["alerts"] > 0  # the replay really ran the detectors
    assert res["network_sockets"] == []


def test_the_hook_sees_an_injected_socket():
    assert _replay("inject")["network_sockets"] == [["socket.__new__", 2]]
