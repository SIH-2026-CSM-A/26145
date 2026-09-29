"""Baseline on the same captures: Suricata (default ET Open, untuned), Zeek if installed, and SAAKSHI,
on demo/demo.pcap and its outbound-only variant (docs/BASELINE.md).

    uv run python scripts/baseline.py run      # runs every tool, printing each exact command
    uv run python scripts/baseline.py report   # attributes alerts to the 7 generated attacks

Attack manifest: built from the generator itself, with the same calls, times and re-addressing as
scripts/build_demo_capture.attacks() (checked to be identical). An alert belongs to an attack when its
endpoints are that attack's IP pair (the flood: its target) and its event time lies in
[first packet - 5 s, last packet + 120 s]; the slack covers flow timeouts (15 s idle, 60 s active).
Alerts touching a CTU-13 normal host are "background"; Suricata decoder events on packets it could not
decode carry no addresses and are counted as "no address"; anything else is "other".
"""

import argparse
import collections
import hashlib
import json
import os
import shutil
import socket
import sqlite3
import struct
import subprocess
import sys
from datetime import datetime
from pathlib import Path

import dpkt

sys.path.insert(0, str(Path(__file__).resolve().parent))
import build_demo_capture as demo  # noqa: E402
from sih26145.ingest.reader import capture_records  # noqa: E402
from sih26145.storage.chain import canonical_json  # noqa: E402
from sih26145.utils import attack_scenarios as atk  # noqa: E402
from sih26145.utils.benign_scenarios import T0  # noqa: E402

ROOT = Path(__file__).resolve().parents[1]
DATA = Path.home() / "NewProjects/26145-data/baseline"
CIDRS = demo.INTERNAL_CIDRS
HOME_NET = f"[{CIDRS}]"
FLOOD_TARGET = "10.50.0.10"
PRE, POST = 5.0, 120.0
ZEEK = shutil.which("zeek") or next((p for p in ["/opt/zeek/bin/zeek"] if os.path.exists(p)), None)
CAPTURES = {"both": ROOT / "demo/demo.pcap", "out": DATA / "demo-out.pcap",
            "both-sv": DATA / "demo-streamvalid.pcap", "out-sv": DATA / "demo-streamvalid-out.pcap"}
# Fields that differ between two identical runs: alert_id is uuid4, confirms names a provisional alert's id.
VOLATILE = ("alert_id", "record_hash", "confirms")


def manifest() -> dict:
    def h(pkts, src):
        return atk.readdress(pkts, {src: demo.HOST})

    parts = {"(e) recon: port scan": h(atk.port_sweep(T0 + 120), "192.168.1.52"),
             "(b) C2 beacon": h(atk.c2_beacon(T0 + 150, period=15.0), "192.168.1.70"),
             "(d) rare-JA4 TLS": h(atk.tls_beacon(T0 + 300), "192.168.1.90"),
             "(c) DGA lookups": h(atk.dga_lookups(T0 + 420), "192.168.1.80"),
             "(c) DNS tunnel": h(atk.dns_tunnel(T0 + 480), "192.168.1.81"),
             "(f) exfil upload": h(atk.exfil_upload(T0 + 560), "192.168.1.51"),
             "(a) SYN flood": atk.syn_flood(T0 + 600)}
    flat = sorted((t, len(b)) for p in parts.values() for t, b in p)
    assert flat == sorted((t, n) for t, _, n in demo.attacks()), "manifest drifted from build_demo_capture"
    out = {}
    for name, pkts in parts.items():
        pairs = set()
        for _, frame in pkts:
            ip = dpkt.ethernet.Ethernet(frame).data
            pairs.add(frozenset((socket.inet_ntoa(ip.src), socket.inet_ntoa(ip.dst))))
        ts = [t for t, _ in pkts]
        out[name] = {"pairs": pairs, "first": min(ts), "last": max(ts), "packets": len(pkts)}
    return out


def _isn(end) -> int:
    """Deterministic initial sequence number for one endpoint (ip bytes, port)."""
    return 1_000_000 + int.from_bytes(hashlib.blake2b(end[0] + end[1].to_bytes(2, "big"), digest_size=2).digest(), "big") * 1000


def stream_valid(src: Path, dst: Path) -> dict:
    """Copy of `src` in which the generated TCP packets (any endpoint is the demo host or the flood
    target) carry consistent sequence and acknowledgement numbers. The generator writes seq=1000,
    ack=2000 on every TCP packet (utils/pcap_generator.py), so a stream-reassembling IDS rejects
    those sessions. Timestamps, sizes, flags and payloads are unchanged; background packets are
    copied byte for byte."""
    gen = {socket.inet_aton(demo.HOST), socket.inet_aton(FLOOD_TARGET)}
    conns, rewritten = {}, 0
    with open(src, "rb") as fin, open(dst, "wb") as fout:
        fout.write(fin.read(24))
        fin.seek(0)
        for ts, buf, wirelen in capture_records(fin):
            eth = dpkt.ethernet.Ethernet(buf)
            ip, tcp = eth.data, getattr(eth.data, "data", None)
            if isinstance(ip, dpkt.ip.IP) and isinstance(tcp, dpkt.tcp.TCP) and (ip.src in gen or ip.dst in gen):
                me, peer = (ip.src, tcp.sport), (ip.dst, tcp.dport)
                key = frozenset((me, peer))
                syn, ack = tcp.flags & dpkt.tcp.TH_SYN, tcp.flags & dpkt.tcp.TH_ACK
                if key not in conns or (syn and not ack):  # new connection (or a retransmitted SYN)
                    conns[key] = {}
                nxt = conns[key]
                nxt.setdefault(me, _isn(me))
                tcp.seq = nxt[me]
                tcp.ack = nxt.get(peer, 0) if ack else 0
                nxt[me] = (nxt[me] + len(tcp.data) + bool(syn) + bool(tcp.flags & dpkt.tcp.TH_FIN)) & 0xFFFFFFFF
                ip.sum = tcp.sum = 0  # dpkt recomputes the TCP checksum only when the IP one is zeroed too
                buf = bytes(eth)
                rewritten += 1
            sec = int(ts)
            fout.write(struct.pack("<IIII", sec, min(round((ts - sec) * 1e6), 999_999), len(buf), wirelen) + buf)
    return {"tcp_packets_rewritten": rewritten, "connections": len(conns)}


def digest(db: Path) -> dict:
    """Content digest of an alert log: sha256 over each alert's canonical JSON without VOLATILE."""
    con = sqlite3.connect(db)
    rows = [json.loads(r[0]) for r in con.execute("SELECT json_data FROM alerts ORDER BY seq")]
    hashes = [r[0] for r in con.execute("SELECT record_hash FROM alerts ORDER BY seq")]
    con.close()
    per = [hashlib.sha256(canonical_json({k: v for k, v in a.items() if k not in VOLATILE}).encode()).hexdigest()
           for a in rows]
    # Storage order can differ between runs (fast-lane and flow-lane alerts race), so both digests.
    return {"alerts": len(rows), "content_sha256_ordered": hashlib.sha256("".join(per).encode()).hexdigest(),
            "content_sha256_sorted": hashlib.sha256("".join(sorted(per)).encode()).hexdigest(),
            "chain_head": hashes[-1] if hashes else None}


def sh(cmd, **kw):
    print("$", " ".join(map(str, cmd)), flush=True)
    return subprocess.run(list(map(str, cmd)), check=True, **kw)


def run():
    DATA.mkdir(parents=True, exist_ok=True)
    env = {**os.environ, "SIH26145_INTERNAL_CIDRS": CIDRS}
    print("stream-valid copy:", stream_valid(CAPTURES["both"], CAPTURES["both-sv"]), flush=True)
    for a, b in (("both", "out"), ("both-sv", "out-sv")):
        sh([ROOT / ".venv/bin/python", ROOT / "scripts/oneway.py", "rewrite", "OUT", CAPTURES[a], CAPTURES[b]], env=env)
    for cap, pcap in CAPTURES.items():
        d = DATA / cap
        for tool in ("suricata-exact", "suricata-matched", "saakshi"):
            shutil.rmtree(d / tool, ignore_errors=True)
            (d / tool).mkdir(parents=True)
        sh(["suricata", "-r", pcap, "-k", "none", "-l", d / "suricata-exact"])
        sh(["suricata", "-r", pcap, "-k", "none", "-l", d / "suricata-matched",
            "--set", f"vars.address-groups.HOME_NET={HOME_NET}"])
        sh([ROOT / ".venv/bin/sih26145", "analyze", pcap, "--db", d / "saakshi/alerts.db"], env=env,
           stdout=subprocess.DEVNULL)
        if ZEEK:
            shutil.rmtree(d / "zeek", ignore_errors=True)
            (d / "zeek").mkdir()
            sh([ZEEK, "-C", "-r", pcap], cwd=d / "zeek")


def _t(iso: str) -> float:
    return datetime.fromisoformat(iso).timestamp()


def suricata_alerts(d: Path) -> list:
    out = []
    with open(d / "eve.json") as fh:
        for line in fh:
            e = json.loads(line)
            if e.get("event_type") == "alert":
                out.append({"t": _t(e["timestamp"]), "src": e.get("src_ip"), "dst": e.get("dest_ip"),
                            "name": e["alert"]["signature"], "sid": e["alert"]["signature_id"]})
    return out


def saakshi_alerts(db: Path) -> list:
    con = sqlite3.connect(db)
    rows = [json.loads(r[0]) for r in con.execute("SELECT json_data FROM alerts ORDER BY seq")]
    con.close()
    return [{"t": _t(a["timestamp"]), "src": a["flow"]["src_ip"], "dst": a["flow"]["dst_ip"],
             "name": (a["detection"].get("rule_matches") or [a["detector"]["name"]])[0]
             + (" (provisional)" if a.get("provisional") else "")} for a in rows]


def attribute(alerts: list, man: dict, normal: set) -> dict:
    caught = {k: collections.Counter() for k in man}
    background, other = collections.Counter(), collections.Counter()
    no_addr = collections.Counter()
    for a in alerts:
        if a["src"] is None:  # decoder event on a packet Suricata could not decode: no addresses
            no_addr[a["name"]] += 1
            continue
        pair = frozenset((a["src"], a["dst"]))
        # DGA and tunnel share endpoints and their slack windows overlap: take the nearest window.
        hits = [(max(m["first"] - a["t"], a["t"] - m["last"], 0.0), k) for k, m in man.items()
                if (FLOOD_TARGET in pair if "flood" in k else pair in m["pairs"])
                and m["first"] - PRE <= a["t"] <= m["last"] + POST]
        if hits:
            caught[min(hits)[1]][a["name"]] += 1
        elif pair & normal:
            background[a["name"]] += 1
        else:
            other[a["name"]] += 1
    return {"total": len(alerts), "attacks": {k: dict(v) for k, v in caught.items()},
            "caught": sum(bool(v) for v in caught.values()),
            "background": sum(background.values()), "background_by_name": dict(background.most_common()),
            "other": sum(other.values()), "other_by_name": dict(other.most_common()),
            "no_address": sum(no_addr.values()), "no_address_by_name": dict(no_addr.most_common())}


def zeek_counts(d: Path) -> dict:
    def n(f):
        p = d / f
        return sum(1 for line in open(p) if not line.startswith("#")) if p.exists() else 0

    return {"notice": n("notice.log"), "weird": n("weird.log")}


def report() -> dict:
    man, normal = manifest(), demo.normal_hosts()
    res = {"manifest": {k: {"pairs": sorted(sorted(p) for p in m["pairs"])[:3], "n_pairs": len(m["pairs"]),
                            "first": m["first"] - T0, "last": m["last"] - T0, "packets": m["packets"]}
                        for k, m in man.items()}}
    for cap in CAPTURES:
        d = DATA / cap
        r = {}
        for tool in ("suricata-exact", "suricata-matched"):
            al = suricata_alerts(d / tool)
            r[tool] = attribute(al, man, normal)
            r[tool]["et_open"] = sum(a["name"].startswith("ET ") for a in al)
            r[tool]["engine_events"] = sum(a["name"].startswith("SURICATA ") for a in al)
            r[tool]["attacks_with_et_open_alert"] = sum(any(n.startswith("ET ") for n in v)
                                                        for v in r[tool]["attacks"].values())
            r[tool]["top_signatures"] = collections.Counter(a["name"] for a in al).most_common(15)
        r["saakshi"] = attribute(saakshi_alerts(d / "saakshi/alerts.db"), man, normal)
        r["saakshi"]["digest"] = digest(d / "saakshi/alerts.db")
        if (d / "zeek").exists():
            r["zeek"] = zeek_counts(d / "zeek")
        res[cap] = r
    print(json.dumps(res, indent=2, default=str))
    (DATA / "report.json").write_text(json.dumps(res, indent=2, default=str))
    return res


if __name__ == "__main__":
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("cmd", choices=("run", "report", "digest"))
    ap.add_argument("db", nargs="*", help="digest: alert databases")
    a = ap.parse_args()
    if a.cmd == "digest":
        for db in a.db:
            print(db, json.dumps(digest(Path(db))))
    else:
        {"run": run, "report": report}[a.cmd]()
