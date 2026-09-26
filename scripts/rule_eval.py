"""Rule precision on labelled real traffic (docs/RULES.md).

  run   <scen> --tag T   real pipeline (ml on, as shipped) over the CTU-13-Extended truncated pcap;
                         every alert -> 26145-data/rule-eval/T/s<scen>.alerts.jsonl
  join  --tag T          label every alert against the labelled dump -> docs/rule_metrics.json
  sweep                  offline re-evaluation of existing thresholds from the full dumps

Labels: an alert's flow is joined on (community_id, flow start ±1 s) to the labelled dump
(From-Botnet = TP, From-Normal = FP). An entity-level rule alert whose flow is not labelled falls
back to its entity IPs: an infected host from the scenario README = TP, a From-Normal source =
FP. Everything else is unknown and scored as neither.
"""

import argparse
import asyncio
import csv
import gzip
import json
import os
import sys
import time
from collections import Counter, defaultdict
from datetime import datetime
from pathlib import Path

DATA = Path.home() / "NewProjects/26145-data"
OUT = DATA / "rule-eval"
FEATURES = DATA / "features"
PCAPS = {1: "capture20110810.truncated.pcap", 5: "capture20110815-2.truncated.pcap",
         6: "capture20110816.truncated.pcap", 11: "capture20110818-2.truncated.pcap",
         12: "capture20110819.truncated.pcap"}
# Scenario READMEs, "Infected Machines" (s1 README.html; the others list the same hosts per scenario)
INFECTED = {1: {"147.32.84.165"}, 5: {"147.32.84.165"}, 6: {"147.32.84.165"},
            11: {"147.32.84.165", "147.32.84.191", "147.32.84.192"},
            12: {"147.32.84.165", "147.32.84.191", "147.32.84.192"}}
TUNE, HELD_OUT = (1, 5, 6), (11, 12)
CIDRS = "147.32.0.0/16"
TOL = 1.0


def binetflow(scen: int) -> Path:
    return next((DATA / f"extracted/CTU-13-Dataset/{scen}").glob("*.binetflow"))


async def run(scen: int, tag: str) -> None:
    os.environ["SIH26145_INTERNAL_CIDRS"] = CIDRS
    from sih26145.orchestrator import ThreatDetectionPipeline
    from sih26145.streaming import run_stream
    out = OUT / tag
    out.mkdir(parents=True, exist_ok=True)
    pipeline = ThreatDetectionPipeline(":memory:")
    await pipeline.init()
    t0 = time.perf_counter()
    with open(out / f"s{scen}.alerts.jsonl", "w") as fh:
        m = await run_stream(pipeline, str(DATA / "ctu13-extended" / PCAPS[scen]),
                             on_alert=lambda a: fh.write(json.dumps(a.to_dict()) + "\n"))
    await pipeline.storage.close()
    (out / f"s{scen}.run.json").write_text(json.dumps(
        {"scenario": scen, "flows": m.flows_scored, "alerts": m.alerts, "packets": m.packets,
         "wall_s": round(time.perf_counter() - t0, 1)}))


def labelled_index(scen: int):
    """community_id -> sorted [(start_time, code)] for From-Botnet / From-Normal flows."""
    idx = defaultdict(list)
    with gzip.open(FEATURES / f"ctu13-s{scen}.labelled.csv.gz", "rt", newline="") as fh:
        for r in csv.DictReader(fh):
            idx[r["community_id"]].append((float(r["start_time"]), r["label_code"]))
    return idx


def normal_hosts(scen: int) -> set:
    with open(binetflow(scen), newline="") as fh:
        return {r["SrcAddr"] for r in csv.DictReader(fh) if r["Label"].startswith("flow=From-Normal")}


def entity_ips(alert: dict) -> list:
    """The IPs an entity-level rule alert names (see RuleHit.entity per detector)."""
    f, cls = alert["flow"], alert["threat_class"]
    if cls == "THREAT_DDOS_VOLUME":
        return [f["dst_ip"], f["src_ip"]]  # victim (reflection may name the src side)
    if cls in ("THREAT_C2_BEACON", "THREAT_ENCRYPTED_ANOMALY", "THREAT_RECON_PORTSCAN",
               "THREAT_DNS_DGA", "THREAT_DNS_TUNNEL"):
        return [f["src_ip"], f["dst_ip"]]
    return []


def detector_key(alert: dict) -> str:
    rules = alert["detection"]["rule_matches"]
    return rules[0] if rules else alert["detector"]["name"]


def label_alert(alert: dict, idx, infected: set, normal: set) -> tuple:
    """(outcome, via): outcome in tp/fp/unknown, via in flow/entity/-."""
    start = datetime.fromisoformat(alert["flow"]["window_start"]).timestamp()
    for s, code in idx.get(alert["flow_id"], ()):
        if abs(s - start) <= TOL:
            if code == "botnet":
                return "tp", "flow"
            if code == "normal":
                return "fp", "flow"
    if alert["detection"]["rule_matches"]:
        ips = entity_ips(alert)
        if any(ip in infected for ip in ips):
            return "tp", "entity"
        if any(ip in normal for ip in ips):
            return "fp", "entity"
    return "unknown", "-"


def score(alerts, flows: int, idx, infected, normal) -> dict:
    per = defaultdict(Counter)
    for a in alerts:
        outcome, via = label_alert(a, idx, infected, normal)
        c = per[detector_key(a)]
        c["alerts"] += 1
        c[outcome] += 1
        if outcome != "unknown":
            c[f"{outcome}_{via}"] += 1
    return {k: summarise(c, flows) for k, c in sorted(per.items())}


def summarise(c: Counter, flows: int) -> dict:
    known = c["tp"] + c["fp"]
    return {"alerts": c["alerts"], "tp": c["tp"], "fp": c["fp"], "unknown": c["unknown"],
            "tp_flow": c["tp_flow"], "tp_entity": c["tp_entity"], "fp_flow": c["fp_flow"],
            "fp_entity": c["fp_entity"],
            "precision_known": round(c["tp"] / known, 4) if known else None,
            "unknown_share": round(c["unknown"] / c["alerts"], 4) if c["alerts"] else None,
            "per_10k_flows": round(c["alerts"] * 1e4 / flows, 2) if flows else None}


def join(tag: str) -> dict:
    res = {}
    for scen in PCAPS:
        path = OUT / tag / f"s{scen}.alerts.jsonl"
        if not (OUT / tag / f"s{scen}.run.json").exists():
            continue  # run not finished
        flows = json.loads((OUT / tag / f"s{scen}.run.json").read_text())["flows"]
        alerts = [json.loads(line) for line in path.open()]
        res[f"s{scen}"] = {"flows": flows, "split": "tune" if scen in TUNE else "held_out",
                           "detectors": score(alerts, flows, labelled_index(scen), INFECTED[scen],
                                              normal_hosts(scen))}
    return res


# ---- sweep: offline re-evaluation of existing thresholds from the full dumps -------------------
SWEEP_COLS = ["src_ip", "dst_ip", "community_id", "start_time", "last_time", "is_tcp", "reverse_seen",
              "egress_bytes", "outbound_inbound_byte_ratio", "off_hours", "src_distinct_dsts_w",
              "src_distinct_dst_ports_w", "src_syn_only_ratio_w", "src_periodic_dsts_w", "src_egress_bytes_z",
              "dst_flows_w", "dst_bytes_w", "dst_distinct_srcs_w", "dst_src_ip_entropy_w", "dst_syn_only_ratio_w",
              "dst_reflector_flows_w", "dst_reflector_bytes_w", "dst_reflector_mean_pkt_w",
              "dst_bytes_vs_baseline", "dst_flows_vs_baseline", "dst_distinct_srcs_longterm",
              "pair_iat_mean", "pair_iat_cv", "pair_iat_n"]


def load_dump(scen: int):
    """Numeric columns as float arrays (NaN = None), identity as lists, label code per row."""
    import numpy as np
    cache = OUT / "sweep-cache" / f"s{scen}.npz"
    if cache.exists():
        z = np.load(cache, allow_pickle=True)
        return {k: z[k] for k in z.files}
    from array import array
    idx = labelled_index(scen)
    num = [c for c in SWEEP_COLS if c not in ("src_ip", "dst_ip", "community_id")]
    cols = {c: array("d") for c in num}
    ips = {"src_ip": [], "dst_ip": []}
    code = array("b")  # 1 botnet, 2 normal, 0 other
    with gzip.open(FEATURES / f"ctu13-s{scen}.csv.gz", "rt", newline="") as fh:
        rd = csv.reader(fh)
        head = next(rd)
        pos = [(c, head.index(c)) for c in num]
        si, di, ci, ti = (head.index(c) for c in ("src_ip", "dst_ip", "community_id", "start_time"))
        for r in rd:
            for c, i in pos:
                v = r[i]
                cols[c].append(float(v) if v not in ("None", "") else float("nan"))
            ips["src_ip"].append(sys.intern(r[si]))
            ips["dst_ip"].append(sys.intern(r[di]))
            st, k = float(r[ti]), 0
            for s, lab in idx.get(r[ci], ()):
                if abs(s - st) <= TOL:
                    k = 1 if lab == "botnet" else 2 if lab == "normal" else 0
                    break
            code.append(k)
    d = {c: np.frombuffer(a, dtype=np.float64) for c, a in cols.items()}
    d.update({k: np.array(v, dtype=object) for k, v in ips.items()})
    d["code"] = np.frombuffer(code, dtype=np.int8)
    cache.parent.mkdir(parents=True, exist_ok=True)
    np.savez(cache, **d)
    return d


def rule_masks(d, t):
    """Hit mask and entity per rule for thresholds t, mirroring detectors.py."""
    import numpy as np

    def ge(a, b):  # NaN (undefined) never passes a lower bound
        return np.nan_to_num(a, nan=-np.inf) >= b

    def le(a, b):  # nor an upper bound
        return np.nan_to_num(a, nan=np.inf) <= b

    out = {}
    c2 = (ge(d["pair_iat_n"], t["C2_MIN_GAPS"]) & le(d["pair_iat_cv"], t["C2_MAX_CV"])
          & ge(d["pair_iat_mean"], t["C2_MIN_PERIOD"]) & ~ge(d["src_periodic_dsts_w"], t["C2_POLLER"]))
    out["RULE_C2_PERIODIC_FLOWS"] = (c2, "pair")
    fan = np.fmax(d["src_distinct_dsts_w"], d["src_distinct_dst_ports_w"])
    recon = ((d["is_tcp"] == 1) & ge(fan, t["RECON_MIN_FANOUT"]) & ge(d["src_syn_only_ratio_w"], t["RECON_MIN_SYN_ONLY"])
             & ~ge(d["dst_distinct_srcs_w"], t["RECON_SHARED"]))
    out["RULE_RECON_FANOUT_SYN_ONLY"] = (recon, "src")
    egress = np.nan_to_num(d["egress_bytes"])
    ratio = d["outbound_inbound_byte_ratio"]
    has_ratio = ~np.isnan(ratio) & (d["reverse_seen"] == 1)
    out["RULE_EXFIL_OUTBOUND_RATIO"] = ((egress > 0) & has_ratio & (egress >= t["EXFIL_MIN_BYTES"])
                                        & ge(ratio, t["EXFIL_MIN_RATIO"]), None)
    out["RULE_EXFIL_EGRESS_BASELINE"] = ((egress > 0) & ~has_ratio & ge(d["src_egress_bytes_z"], t["EXFIL_MIN_Z"])
                                         & (np.round(np.nan_to_num(d["dst_distinct_srcs_longterm"])) <= t["EXFIL_MAX_DST_SRCS"]),
                                         None)
    syn = (ge(d["dst_distinct_srcs_w"], t["DDOS_MIN_SRCS"]) & ge(d["dst_src_ip_entropy_w"], 5.0)
           & ge(d["dst_syn_only_ratio_w"], 0.8))
    refl = ge(d["dst_reflector_flows_w"], 50) & ge(d["dst_reflector_mean_pkt_w"], 400) & ge(d["dst_reflector_bytes_w"], 1e6)
    by = np.fmax(d["dst_bytes_vs_baseline"], d["dst_flows_vs_baseline"])
    vol = (~np.isnan(d["dst_bytes_vs_baseline"]) & ge(by, t["DDOS_BASELINE_MULT"])
           & le(d["dst_distinct_srcs_w"], t["DDOS_MAX_FEW_SRCS"])
           & (ge(d["dst_bytes_w"], 10_000_000) | ge(d["dst_flows_w"], 100)))
    out["RULE_DDOS_SYN_FLOOD"] = (syn, "dst")
    out["RULE_DDOS_UDP_REFLECTION"] = (refl & ~syn, "dst")
    out["RULE_DDOS_VOLUME_BASELINE"] = (vol & ~syn & ~refl, "dst")
    return out


DDOS_RULES = ("RULE_DDOS_SYN_FLOOD", "RULE_DDOS_UDP_REFLECTION", "RULE_DDOS_VOLUME_BASELINE")


def sweep_score(d, t, infected, normal, flows):
    """Per rule: alerts after the suite's 300 s (detector, entity) dedupe, labelled like join()."""
    import numpy as np
    per = {}
    last = {}
    masks = rule_masks(d, t)
    ddos_any = np.zeros(len(d["code"]), dtype=bool)
    for r in DDOS_RULES:
        ddos_any |= masks[r][0]
    for rule, (mask, ent) in masks.items():
        c = Counter()
        det = "ddos" if rule in DDOS_RULES else rule
        for i in np.flatnonzero(mask):
            src, dst, t_last = d["src_ip"][i], d["dst_ip"][i], d["last_time"][i]
            if ent is not None:
                key = (det, {"pair": f"{src}>{dst}", "src": src, "dst": dst}[ent])
                prev = last.get(key)
                if prev is not None and abs(t_last - prev) < 300:
                    continue
                last[key] = t_last
            c["alerts"] += 1
            code = d["code"][i]
            if code in (1, 2):
                c["tp" if code == 1 else "fp"] += 1
                c[("tp" if code == 1 else "fp") + "_flow"] += 1
            elif ent is not None and (src in infected or dst in infected):
                c.update(("tp", "tp_entity"))
            elif ent is not None and (src in normal or dst in normal):
                c.update(("fp", "fp_entity"))
            else:
                c["unknown"] += 1
        per[rule] = summarise(c, flows)
    return per


CURRENT = {"C2_MIN_GAPS": 8, "C2_MAX_CV": 0.35, "C2_MIN_PERIOD": 1.0, "C2_POLLER": 10,
           "RECON_MIN_FANOUT": 20, "RECON_MIN_SYN_ONLY": 0.6, "RECON_SHARED": 20,
           "EXFIL_MIN_BYTES": 1_000_000, "EXFIL_MIN_RATIO": 10.0, "EXFIL_MIN_Z": 3.0, "EXFIL_MAX_DST_SRCS": 2,
           "DDOS_MIN_SRCS": 100, "DDOS_BASELINE_MULT": 10.0, "DDOS_MAX_FEW_SRCS": 10}


GROUPS = {  # detector -> (its rules, grid over its existing thresholds)
    "c2": (("RULE_C2_PERIODIC_FLOWS",),
           {"C2_MIN_GAPS": [6, 8, 10, 12, 16, 20], "C2_MAX_CV": [0.1, 0.15, 0.2, 0.25, 0.3, 0.35, 0.4],
            "C2_MIN_PERIOD": [1.0, 5.0, 10.0, 30.0, 60.0], "C2_POLLER": [3, 5, 10]}),
    "recon": (("RULE_RECON_FANOUT_SYN_ONLY",),
              {"RECON_MIN_FANOUT": [10, 20, 30, 50, 100], "RECON_MIN_SYN_ONLY": [0.4, 0.5, 0.6, 0.7, 0.8, 0.9],
               "RECON_SHARED": [5, 10, 20, 50]}),
    "exfil": (("RULE_EXFIL_OUTBOUND_RATIO", "RULE_EXFIL_EGRESS_BASELINE"),
              {"EXFIL_MIN_BYTES": [1e6, 5e6, 1e7, 5e7], "EXFIL_MIN_RATIO": [5.0, 10.0, 20.0, 50.0],
               "EXFIL_MIN_Z": [3.0, 5.0, 8.0, 12.0, 20.0], "EXFIL_MAX_DST_SRCS": [0, 1, 2, 5]}),
    "ddos": (DDOS_RULES,
             {"DDOS_MIN_SRCS": [50, 100, 200, 500], "DDOS_BASELINE_MULT": [5.0, 10.0, 20.0, 50.0, 100.0],
              "DDOS_MAX_FEW_SRCS": [3, 5, 10, 20]}),
}


def pooled(results, rules):
    c = Counter()
    for per, flows in results:
        c["flows"] += flows
        for r in rules:
            for k in ("alerts", "tp", "fp", "unknown"):
                c[k] += per[r][k]
    known = c["tp"] + c["fp"]
    return {"alerts": c["alerts"], "tp": c["tp"], "fp": c["fp"], "unknown": c["unknown"],
            "per_10k_flows": round(c["alerts"] * 1e4 / c["flows"], 3),
            "precision_known": round(c["tp"] / known, 4) if known else None}


def sweep(groups, scens) -> dict:
    """Objective (docs/RULES.md, fixed before the sweep): among candidates keeping >= 90% of the
    detector's tuning-set TP at the current thresholds, the lowest alerts per 10k flows; ties on
    precision over known."""
    import itertools
    data = {s: (load_dump(s), INFECTED[s], normal_hosts(s),
                json.loads((FEATURES / f"ctu13-s{s}.dump.json").read_text())["flows"]) for s in scens}
    out = {}
    for g in groups:
        rules, grid = GROUPS[g]
        rows = []
        for combo in itertools.product(*grid.values()):
            t = {**CURRENT, **dict(zip(grid, combo))}
            res = [(sweep_score(d, t, inf, nor, fl), fl) for d, inf, nor, fl in data.values()]
            rows.append({"thresholds": {k: t[k] for k in grid}, **pooled(res, rules)})
        base = next(r for r in rows if r["thresholds"] == {k: CURRENT[k] for k in grid})
        ok = [r for r in rows if r["tp"] >= 0.9 * base["tp"]]
        ok.sort(key=lambda r: (r["per_10k_flows"], -(r["precision_known"] or 0)))
        out[g] = {"current": base, "ranked": ok, "candidates": len(rows), "eligible": len(ok)}
        print(g, json.dumps(out[g]["current"]), "->", json.dumps(ok[0]), flush=True)
    return out


ATTRS = {"C2_MIN_GAPS": ("C2BeaconDetector", "MIN_GAPS"), "C2_MAX_CV": ("C2BeaconDetector", "MAX_CV"),
         "C2_MIN_PERIOD": ("C2BeaconDetector", "MIN_PERIOD"), "C2_POLLER": ("C2BeaconDetector", "POLLER_PERIODIC_DSTS"),
         "RECON_MIN_FANOUT": ("ReconPortScanDetector", "MIN_FANOUT"),
         "RECON_MIN_SYN_ONLY": ("ReconPortScanDetector", "MIN_SYN_ONLY"),
         "RECON_SHARED": ("ReconPortScanDetector", "SHARED_INFRA_SRCS"),
         "EXFIL_MIN_BYTES": ("ExfiltrationDetector", "MIN_OUTBOUND_BYTES"),
         "EXFIL_MIN_RATIO": ("ExfiltrationDetector", "MIN_RATIO"),
         "EXFIL_MIN_Z": ("ExfiltrationDetector", "MIN_EGRESS_Z"),
         "EXFIL_MAX_DST_SRCS": ("ExfiltrationDetector", "MAX_DST_SOURCES"),
         "DDOS_MIN_SRCS": ("DDoSVolumeDetector", "MIN_SRCS"), "DDOS_BASELINE_MULT": ("DDoSVolumeDetector", "BASELINE_MULT"),
         "DDOS_MAX_FEW_SRCS": ("DDoSVolumeDetector", "MAX_FEW_SRCS")}
CONSTRAINT_TESTS = ["tests/regression/test_benign_captures.py", "tests/detectors/test_attack_captures.py",
                    "tests/detectors/test_exfil_branches.py"]


def pick(sweep_path: str) -> dict:
    """First ranked candidate per detector that keeps the constraint tests green (docs/RULES.md §1)."""
    import pytest
    import sih26145.detectors.rules.detectors as det
    ranked = json.loads(Path(sweep_path).read_text())
    chosen = {}
    for g, res in ranked.items():
        for i, cand in enumerate(res["ranked"]):
            saved = {k: getattr(getattr(det, ATTRS[k][0]), ATTRS[k][1]) for k in cand["thresholds"]}
            for k, v in cand["thresholds"].items():
                setattr(getattr(det, ATTRS[k][0]), ATTRS[k][1], type(saved[k])(v))
            ok = pytest.main(["-q", "-p", "no:cacheprovider", *CONSTRAINT_TESTS]) == 0
            for k, v in saved.items():
                setattr(getattr(det, ATTRS[k][0]), ATTRS[k][1], v)
            print(f"{g} rank {i}: {cand['thresholds']} constraints {'PASS' if ok else 'FAIL'}", flush=True)
            if ok:
                chosen[g] = {"rank": i, **cand, "skipped_for_constraints": i}
                break
        else:
            chosen[g] = None
    return chosen


RULES_DOC = Path(__file__).resolve().parents[1] / "docs" / "RULES.md"
START, END = "<!-- rule-table:start -->", "<!-- rule-table:end -->"
CHANGED = {  # threshold -> (before, after); the detectors.py constants are the source of truth
    "C2 MIN_GAPS": (8, 16), "C2 MAX_CV": (0.35, 0.40), "C2 MIN_PERIOD (s)": (1.0, 10.0),
    "Recon MIN_SYN_ONLY": (0.6, 0.8), "Recon SHARED_INFRA_SRCS": (20, 5),
    "Exfil MIN_RATIO": (10.0, 50.0), "Exfil MAX_DST_SOURCES": (2, 1),
    "DDoS MIN_SRCS": (100, 200), "DDoS BASELINE_MULT": (10.0, 100.0),
}


def _pct(x):
    return "—" if x is None else f"{x:.3f}"


def report(before_tag: str, after_tag: str) -> str:
    """rule_metrics.json + the markdown tables between the RULES.md markers."""
    import sih26145.detectors.rules.detectors as det
    live = {"C2 MIN_GAPS": det.C2BeaconDetector.MIN_GAPS, "C2 MAX_CV": det.C2BeaconDetector.MAX_CV,
            "C2 MIN_PERIOD (s)": det.C2BeaconDetector.MIN_PERIOD,
            "Recon MIN_SYN_ONLY": det.ReconPortScanDetector.MIN_SYN_ONLY,
            "Recon SHARED_INFRA_SRCS": det.ReconPortScanDetector.SHARED_INFRA_SRCS,
            "Exfil MIN_RATIO": det.ExfiltrationDetector.MIN_RATIO, "Exfil MAX_DST_SOURCES": det.ExfiltrationDetector.MAX_DST_SOURCES,
            "DDoS MIN_SRCS": det.DDoSVolumeDetector.MIN_SRCS, "DDoS BASELINE_MULT": det.DDoSVolumeDetector.BASELINE_MULT}
    assert {k: v[1] for k, v in CHANGED.items()} == live, "CHANGED drifted from detectors.py"
    before, after = join(before_tag), join(after_tag)
    metrics = {"before": before, "after": after, "changed_thresholds": CHANGED,
               "split": {"tune": [f"s{s}" for s in TUNE], "held_out": [f"s{s}" for s in HELD_OUT]}}
    (RULES_DOC.parent / "rule_metrics.json").write_text(json.dumps(metrics, indent=1) + "\n")
    lines = ["| Scenario | Split | Flows | Detector | Alerts | TP (flow / entity) | FP (flow / entity) | Unknown | "
             "Precision over known | Unknown share | Alerts per 10k flows |", "|---" * 11 + "|"]
    for scen in [f"s{s}" for s in (*TUNE, *HELD_OUT)]:
        if scen not in before or scen not in after:
            continue
        dets = sorted(set(before[scen]["detectors"]) | set(after[scen]["detectors"]))
        for d in dets:
            b = before[scen]["detectors"].get(d) or summarise(Counter(), before[scen]["flows"])
            a = after[scen]["detectors"].get(d) or summarise(Counter(), after[scen]["flows"])

            def arrow(k, f=str, b=b, a=a):
                return f"{f(b[k])} → {f(a[k])}" if b[k] != a[k] else f(a[k])
            lines.append(
                f"| {scen} | {'tune' if int(scen[1:]) in TUNE else '**held out**'} | {after[scen]['flows']:,} | `{d}` "
                f"| {arrow('alerts')} | {a['tp_flow']} / {a['tp_entity']} (was {b['tp_flow']} / {b['tp_entity']}) "
                f"| {a['fp_flow']} / {a['fp_entity']} (was {b['fp_flow']} / {b['fp_entity']}) | {arrow('unknown')} "
                f"| {arrow('precision_known', _pct)} | {arrow('unknown_share', _pct)} | {arrow('per_10k_flows')} |")
    return "\n".join(lines)


def main():
    ap = argparse.ArgumentParser()
    sub = ap.add_subparsers(dest="cmd", required=True)
    r = sub.add_parser("run")
    r.add_argument("scenario", type=int, choices=sorted(PCAPS))
    r.add_argument("--tag", required=True)
    j = sub.add_parser("join")
    j.add_argument("--tag", required=True)
    j.add_argument("--out", default=None)
    w = sub.add_parser("sweep")
    w.add_argument("--groups", default="c2,recon,exfil,ddos")
    w.add_argument("--scenarios", default="1,5,6")
    w.add_argument("--check", action="store_true", help="score the current thresholds per scenario")
    w.add_argument("--out", default=None)
    rp = sub.add_parser("report")
    rp.add_argument("--before", default="before")
    rp.add_argument("--after", default="after")
    rp.add_argument("--write", action="store_true", help="replace the table in docs/RULES.md")
    k = sub.add_parser("pick")
    k.add_argument("--sweep", required=True)
    k.add_argument("--out", required=True)
    args = ap.parse_args()
    if args.cmd == "run":
        asyncio.run(run(args.scenario, args.tag))
    elif args.cmd == "join":
        res = join(args.tag)
        text = json.dumps(res, indent=1)
        (Path(args.out).write_text(text) if args.out else sys.stdout.write(text + "\n"))
    elif args.cmd == "report":
        table = report(args.before, args.after)
        if args.write:
            doc = RULES_DOC.read_text()
            i, j = doc.index(START) + len(START), doc.index(END)
            RULES_DOC.write_text(doc[:i] + "\n" + table + "\n" + doc[j:])
        else:
            print(table)
    elif args.cmd == "pick":
        Path(args.out).write_text(json.dumps(pick(args.sweep), indent=1))
    elif args.cmd == "sweep":
        scens = [int(x) for x in args.scenarios.split(",")]
        if args.check:
            for sc in scens:
                fl = json.loads((FEATURES / f"ctu13-s{sc}.dump.json").read_text())["flows"]
                print(f"s{sc}", json.dumps(sweep_score(load_dump(sc), CURRENT, INFECTED[sc], normal_hosts(sc), fl)))
            return
        res = sweep(args.groups.split(","), scens)
        if args.out:
            Path(args.out).write_text(json.dumps(res, indent=1))


if __name__ == "__main__":
    main()
