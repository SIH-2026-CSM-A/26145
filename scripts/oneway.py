"""Strict one-way replay: rewrite a capture so it holds one direction of the boundary only, then run
it through the real pipeline (docs/ONEWAY.md).

    uv run python scripts/oneway.py rewrite IN|OUT CAPTURE OUT.pcap   # one capture
    uv run python scripts/oneway.py table --json OUT.json              # demo + 12 benign, both variants

IN keeps only packets from an external source to an internal destination; OUT keeps only
internal -> external. "Internal" is NetworkPolicy.from_env() (SIH26145_INTERNAL_CIDRS). Packets
between two internal hosts, between two external hosts, and non-IP frames cross no boundary and
are dropped from both variants. Timestamps, frames and original (wire) lengths are kept as they
were: truncated records stay truncated.
"""

import argparse
import asyncio
import collections
import json
import os
import socket
import struct
import tempfile

import dpkt

from sih26145.features.directional import NetworkPolicy
from sih26145.ingest.reader import capture_records
from sih26145.orchestrator import ThreatDetectionPipeline
from sih26145.utils.benign_scenarios import BENIGN_SCENARIOS, write_benign

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DEMO_CIDRS = "147.32.0.0/16,10.0.0.0/8,192.168.0.0/16,172.16.0.0/12"  # as scripts/demo.sh
PS = {"THREAT_DDOS_VOLUME": "a", "THREAT_C2_BEACON": "b", "THREAT_DNS_DGA": "c", "THREAT_DNS_TUNNEL": "c",
      "THREAT_ENCRYPTED_ANOMALY": "d", "THREAT_RECON_PORTSCAN": "e", "THREAT_EXFILTRATION": "f"}


def _endpoints(buf: bytes):
    try:
        ip = dpkt.ethernet.Ethernet(buf).data
    except (dpkt.UnpackError, IndexError, struct.error):
        return None
    if isinstance(ip, dpkt.ip.IP):
        return socket.inet_ntop(socket.AF_INET, ip.src), socket.inet_ntop(socket.AF_INET, ip.dst)
    if isinstance(ip, dpkt.ip6.IP6):
        return socket.inet_ntop(socket.AF_INET6, ip.src), socket.inet_ntop(socket.AF_INET6, ip.dst)
    return None


def rewrite(variant: str, src_path: str, out_path: str, policy: NetworkPolicy) -> dict:
    kept = total = 0
    with open(src_path, "rb") as fin, open(out_path, "wb") as fout:
        fout.write(struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1))  # classic pcap, Ethernet
        for ts, buf, wirelen in capture_records(fin):
            total += 1
            ends = _endpoints(buf)
            if ends is None:
                continue
            src_in, dst_in = policy.is_internal(ends[0]), policy.is_internal(ends[1])
            if (variant == "IN" and not src_in and dst_in) or (variant == "OUT" and src_in and not dst_in):
                sec = int(ts)
                fout.write(struct.pack("<IIII", sec, min(int((ts - sec) * 1e6), 999_999), len(buf), wirelen) + buf)
                kept += 1
    return {"packets": total, "kept": kept}


async def _alerts(path: str) -> list:
    p = ThreatDetectionPipeline(":memory:")
    try:
        return await p.process_pcap(path)
    finally:
        await p.storage.close()


def _summary(alerts) -> list:
    return [{"ps": PS.get(a.threat_class, "ml"), "class": a.threat_class,
             "rule": a.detection["rule_matches"][0] if a.detection["rule_matches"] else a.detector["name"],
             "provisional": a.provisional, "observability_state": a.observability_state,
             "substitutions": [s["unavailable_on_this_flow"] for s in a.substitutions],
             "severity": a.severity, "src": a.flow["src_ip"], "dst": a.flow["dst_ip"],
             "host": a.detection.get("correlation", {}).get("host")} for a in alerts]


def run_variants(name: str, capture: str, cidrs, tmp: str) -> dict:
    if cidrs:
        os.environ["SIH26145_INTERNAL_CIDRS"] = cidrs
    else:
        os.environ.pop("SIH26145_INTERNAL_CIDRS", None)
    policy, out = NetworkPolicy.from_env(), {"cidrs": cidrs or "default (RFC1918 + fc00::/7)"}
    out["both"] = {"alerts": _summary(asyncio.run(_alerts(capture)))}
    for v in ("IN", "OUT"):
        path = os.path.join(tmp, f"{name}-{v}.pcap")
        out[v] = rewrite(v, capture, path, policy)
        out[v]["alerts"] = _summary(asyncio.run(_alerts(path))) if out[v]["kept"] else []
    return out


def table(args) -> dict:
    tmp = tempfile.mkdtemp()
    res = {"demo": run_variants("demo", os.path.join(ROOT, "demo", "demo.pcap"), DEMO_CIDRS, tmp)}
    for name in BENIGN_SCENARIOS:
        path = os.path.join(tmp, f"{name}.pcap")
        write_benign(name, path)
        res[name] = run_variants(name, path, None, tmp)  # the benign tests run with the default CIDRs
    for name, r in res.items():
        line = [f"{name}:"]
        for v in ("both", "IN", "OUT"):
            c = collections.Counter(f"{a['ps']}{'*' if a['provisional'] else ''}" for a in r[v]["alerts"])
            kept = f" kept {r[v]['kept']}/{r[v]['packets']}" if v != "both" else ""
            line.append(f"{v}{kept} {dict(sorted(c.items()))}")
        print(" | ".join(line))
    return res


def main():
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    sub = ap.add_subparsers(dest="cmd", required=True)
    rw = sub.add_parser("rewrite")
    rw.add_argument("variant", choices=["IN", "OUT"])
    rw.add_argument("capture")
    rw.add_argument("out")
    tb = sub.add_parser("table")
    tb.add_argument("--json")
    args = ap.parse_args()
    if args.cmd == "rewrite":
        print(json.dumps(rewrite(args.variant, args.capture, args.out, NetworkPolicy.from_env())))
        return
    res = table(args)
    if args.json:
        with open(args.json, "w") as fh:
            json.dump(res, fh, indent=2)


if __name__ == "__main__":
    main()
