"""Build labelled training files from feature dumps (sih26145 dump-features).

    # CTU-13(-Extended) scenario: join a dump to the scenario's binetflow labels
    uv run python scripts/build_dataset.py ctu --scenario 12 --dump DUMP.csv.gz \
        --binetflow .../12/capture20110819.binetflow --out ctu13-s12.labelled.csv.gz
    # generated attack captures, dumped through the same pipeline and labelled by construction
    uv run python scripts/build_dataset.py generated --outdir ~/NewProjects/26145-data/features

Only rows with a training label (From-Botnet = 1, From-Normal = 0, generated) are written;
the coverage JSON next to the output counts everything, including what was excluded.
"""

import argparse
import asyncio
import csv
import gzip
import json
import os
from collections import Counter

from sih26145.features.dump import dump_features
from sih26145.training.labels import GENERATED, SCENARIOS, FlowLabels, generated_label, train_label
from sih26145.utils.attack_scenarios import write_attack

EXTRA = ["label", "label_code", "class_name", "group"]


def rows(path):
    with gzip.open(path, "rt", newline="") as fh:
        yield from csv.DictReader(fh)


def write(path, fieldnames, labelled):
    with gzip.open(path, "wt", newline="") as fh:
        w = csv.DictWriter(fh, fieldnames=fieldnames + EXTRA)
        w.writeheader()
        w.writerows(labelled)


def ctu(args):
    labels, codes, out, fields = FlowLabels.from_file(args.binetflow), Counter(), [], None
    group = f"ctu13-s{args.scenario}"
    for r in rows(args.dump):
        fields = fields or list(r)
        code = labels.label(r["protocol"], r["src_ip"], r["src_port"] or None, r["dst_ip"], r["dst_port"],
                            float(r["start_time"]), float(r["last_time"]))
        codes[code] += 1
        if (y := train_label(code)) is not None:
            out.append({**r, "label": y, "label_code": code, "group": group,
                        "class_name": f"ctu13-s{args.scenario}-{SCENARIOS[args.scenario]}" if y else "benign-ctu13"})
    write(args.out, fields, out)
    report = {"group": group, "dump": args.dump, "binetflow": args.binetflow, **labels.coverage(codes),
              "training_rows": dict(Counter(r["label"] for r in out))}
    json.dump(report, open(args.out.replace(".csv.gz", ".coverage.json"), "w"), indent=2)
    print(json.dumps(report, indent=2))


def generated(args):
    for name in GENERATED:
        pcap = os.path.join(args.outdir, f"gen-{name}.pcap")
        dump = os.path.join(args.outdir, f"gen-{name}.csv.gz")
        write_attack(name, pcap)
        print(json.dumps(asyncio.run(dump_features(pcap, dump))))
        out, fields = [], None
        for r in rows(dump):
            fields = fields or list(r)
            y, cls = generated_label(name, r["src_ip"], r["dst_ip"])
            out.append({**r, "label": y, "label_code": "attack" if y else "baseline", "class_name": cls,
                        "group": f"gen-{name}"})
        write(os.path.join(args.outdir, f"gen-{name}.labelled.csv.gz"), fields, out)
        print(name, dict(Counter((r["label"], r["class_name"]) for r in out)))


def main():
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    sub = ap.add_subparsers(dest="cmd", required=True)
    c = sub.add_parser("ctu")
    c.add_argument("--scenario", type=int, required=True, choices=sorted(SCENARIOS))
    c.add_argument("--dump", required=True)
    c.add_argument("--binetflow", required=True)
    c.add_argument("--out", required=True)
    g = sub.add_parser("generated")
    g.add_argument("--outdir", required=True)
    args = ap.parse_args()
    ctu(args) if args.cmd == "ctu" else generated(args)


if __name__ == "__main__":
    main()
