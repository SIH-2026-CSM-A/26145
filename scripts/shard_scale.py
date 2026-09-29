"""Multi-core scaling with shared-nothing shards (docs/BENCHMARK.md, "Multi-core scaling").

A receive-only packet broker splits the link by a symmetric hash; each shard is an independent
pipeline process on its own core. The split is done once, beforehand, and is not timed.

    uv run python scripts/shard_scale.py split N [--by flow|pair]    # flow: proto + sorted (ip,port) pairs
    uv run python scripts/shard_scale.py run N REP [--by flow|pair]  # N concurrent benchmark.py, taskset-pinned
    uv run python scripts/shard_scale.py calibrate                   # per-vCPU single-thread speed
    uv run python scripts/shard_scale.py report                      # medians, efficiency, alert-union check

flow keeps both directions of a 5-tuple flow together; pair (IPs + proto, no ports) keeps every
flow between two hosts together. Non-IP frames go to shard 0. Non-first IP fragments carry no
ports, so under --by flow they hash with ports 0 (counted in split.json).
"""

import argparse
import collections
import hashlib
import json
import os
import statistics
import struct
import subprocess
import sys
import time
from pathlib import Path

import dpkt

from sih26145.ingest.reader import capture_records

ROOT = Path(__file__).resolve().parents[1]
CAPTURE = Path.home() / "NewProjects/26145-data/extracted/CTU-13-Dataset/12/botnet-capture-20110819-bot.pcap"
OUT = Path.home() / "NewProjects/26145-data/bench/s8-shard"
# One vCPU per WSL virtual core (siblings are 2k, 2k+1). WSL cannot pin to a host P- or E-core.
CPUS = [0, 2, 4, 6, 8, 10, 12, 14]


def shard_key(buf: bytes, by: str):
    """(key bytes, is_non_first_fragment) or (None, False) for non-IP."""
    try:
        ip = dpkt.ethernet.Ethernet(buf).data
    except (dpkt.UnpackError, IndexError, struct.error):
        return None, False
    if isinstance(ip, dpkt.ip.IP):
        proto, frag = ip.p, ip.offset > 0
    elif isinstance(ip, dpkt.ip6.IP6):
        proto, frag = ip.nxt, False
    else:
        return None, False
    if by == "pair":
        a, b = sorted((ip.src, ip.dst))
        return bytes([proto]) + a + b, frag
    l4 = ip.data
    ports = (l4.sport, l4.dport) if not frag and isinstance(l4, (dpkt.tcp.TCP, dpkt.udp.UDP)) else (0, 0)
    a, b = sorted(((ip.src, ports[0]), (ip.dst, ports[1])))
    return bytes([proto]) + a[0] + a[1].to_bytes(2, "big") + b[0] + b[1].to_bytes(2, "big"), frag


def shard_dir(n: int, by: str) -> Path:
    return OUT / f"{by}-n{n}"


def split(n: int, by: str) -> dict:
    d = shard_dir(n, by)
    d.mkdir(parents=True, exist_ok=True)
    outs = [open(d / f"shard{i}.pcap", "wb") for i in range(n)]
    for f in outs:
        f.write(struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1))  # classic pcap, Ethernet
    pkts, wire = [0] * n, [0] * n
    non_ip = frags = 0
    with open(CAPTURE, "rb") as fin:
        for ts, buf, wirelen in capture_records(fin):
            key, frag = shard_key(buf, by)
            non_ip += key is None
            frags += frag
            i = 0 if key is None else int.from_bytes(hashlib.blake2b(key, digest_size=8).digest(), "big") % n
            sec = int(ts)
            outs[i].write(struct.pack("<IIII", sec, min(round((ts - sec) * 1e6), 999_999), len(buf), wirelen) + buf)
            pkts[i] += 1
            wire[i] += wirelen
    for f in outs:
        f.close()
    facts = {"capture": str(CAPTURE), "by": by, "n": n, "packets": pkts, "wire_bytes": wire,
             "non_ip_to_shard0": non_ip, "non_first_fragments": frags}
    (d / "split.json").write_text(json.dumps(facts, indent=2))
    return facts


def uptime() -> str:
    return subprocess.run(["uptime"], capture_output=True, text=True).stdout.strip()


def run(n: int, rep: int, by: str) -> dict:
    d = shard_dir(n, by)
    r = d / f"rep{rep}"
    r.mkdir(exist_ok=True)
    cpus = CPUS[:n]
    load = uptime()
    t0 = time.perf_counter()
    procs = [subprocess.Popen(["taskset", "-c", str(cpu), str(ROOT / ".venv/bin/python"), str(ROOT / "scripts/benchmark.py"),
                               str(d / f"shard{i}.pcap"), "--json", str(r / f"shard{i}.json"),
                               "--alerts-out", str(r / f"shard{i}.alerts.jsonl")],
                              stdout=subprocess.DEVNULL, cwd=ROOT) for i, cpu in enumerate(cpus)]
    codes = [p.wait() for p in procs]
    launch_wall = time.perf_counter() - t0
    if any(codes):
        sys.exit(f"shard process failed: exit codes {codes}")
    shards = [json.loads((r / f"shard{i}.json").read_text()) for i in range(n)]
    runs = [s["run"] for s in shards]
    wall = max(x["wall_s"] for x in runs)
    flows = sum(x["flows_scored"] for x in runs)
    wire = sum(s["capture"]["wire_bytes"] for s in shards)
    res = {"n": n, "by": by, "rep": rep, "cpus": cpus, "uptime_before": load, "loadavg_1m": float(load.split("load average:")[1].split(",")[0]),
           "shard_walls_s": [x["wall_s"] for x in runs], "slowest_wall_s": wall, "launch_to_last_exit_s": round(launch_wall, 2),
           "flows": flows, "packets": sum(x["packets"] for x in runs), "wire_bytes": wire, "drops": sum(x["drops"] for x in runs),
           "flows_per_s": round(flows / wall, 1), "mbps": round(wire * 8 / wall / 1e6, 2), "alerts": sum(x["alerts"] for x in runs)}
    (r / "result.json").write_text(json.dumps(res, indent=2))
    print(json.dumps(res))
    return res


def calibrate(passes: int = 3) -> dict:
    """The same pure-Python loop pinned to each vCPU in turn: a vCPU that is consistently slower
    suggests Windows placed it on an efficiency core. Indicative only; placement can change."""
    loop = "import time; t=time.perf_counter(); sum(i*i for i in range(10**7)); print(time.perf_counter()-t)"
    res = {cpu: [] for cpu in range(os.cpu_count())}
    for _ in range(passes):
        for cpu in res:
            out = subprocess.run(["taskset", "-c", str(cpu), sys.executable, "-c", loop], capture_output=True, text=True)
            res[cpu].append(round(float(out.stdout), 3))
    out = {"uptime_before": uptime(), "seconds_per_pass": res}
    (OUT / "calibrate.json").write_text(json.dumps(out, indent=2))
    print(json.dumps(out))
    return out


def alert_keys(rep_dir: Path) -> collections.Counter:
    c = collections.Counter()
    for f in rep_dir.glob("shard*.alerts.jsonl"):
        for line in f.read_text().splitlines():
            a = json.loads(line)
            c[(a["rule"], a["flow_id"], a["provisional"])] += 1
    return c


def by_rule(c: collections.Counter) -> dict:
    out = collections.Counter()
    for (rule, _, _), k in c.items():
        out[rule] += k
    return dict(out)


def report() -> dict:
    results = [json.loads(p.read_text()) for p in sorted(OUT.glob("*-n*/rep*/result.json"))]
    groups = collections.defaultdict(list)
    for x in results:
        groups[(x["by"], x["n"])].append(x)
    base = statistics.median(x["flows_per_s"] for x in groups[("flow", 1)])
    single = alert_keys(shard_dir(1, "flow") / "rep1")
    rows = []
    for (by, n), xs in sorted(groups.items()):
        med = lambda k: statistics.median(x[k] for x in xs)
        fps = med("flows_per_s")
        unions = [alert_keys(shard_dir(n, by) / f"rep{x['rep']}") for x in xs]
        u = unions[0]
        rows.append({"by": by, "n": n, "reps": len(xs), "cpus": xs[0]["cpus"], "flows": sorted({x["flows"] for x in xs}),
                     "slowest_wall_s": med("slowest_wall_s"), "flows_per_s": fps, "mbps": med("mbps"),
                     "efficiency": round(fps / (n * base), 3), "alerts": [x["alerts"] for x in xs],
                     "loadavg_1m": [x["loadavg_1m"] for x in xs], "per_rep_flows_per_s": [x["flows_per_s"] for x in xs],
                     "unions_identical_across_reps": all(v == u for v in unions),
                     "union_minus_single_by_rule": by_rule(u - single), "single_minus_union_by_rule": by_rule(single - u),
                     "union_equals_single": u == single})
    out = {"one_core_flows_per_s": base, "single_alerts": sum(single.values()), "single_by_rule": by_rule(single), "rows": rows}
    print(json.dumps(out, indent=2))
    (OUT / "report.json").write_text(json.dumps(out, indent=2))
    return out


def main():
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    sub = ap.add_subparsers(dest="cmd", required=True)
    s = sub.add_parser("split")
    s.add_argument("n", type=int)
    r = sub.add_parser("run")
    r.add_argument("n", type=int)
    r.add_argument("rep", type=int)
    for p in (s, r):
        p.add_argument("--by", choices=("flow", "pair"), default="flow")
    sub.add_parser("report")
    sub.add_parser("calibrate")
    a = ap.parse_args()
    if a.cmd == "split":
        print(json.dumps(split(a.n, a.by)))
    elif a.cmd == "run":
        run(a.n, a.rep, a.by)
    elif a.cmd == "calibrate":
        calibrate()
    else:
        report()


if __name__ == "__main__":
    main()
