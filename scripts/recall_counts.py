"""Print the counts behind MODELS.md's "28%" (LightGBM recall at the alert budget) straight from
docs/model_metrics.json, so the doc quotes counts rather than re-deriving them by hand.

    uv run python scripts/recall_counts.py
"""

import json
from pathlib import Path

m = json.loads((Path(__file__).resolve().parents[1] / "docs" / "model_metrics.json").read_text())
t = m["thresholds"]["lgbm"]
print(f"Threshold rule: allowed false positives = floor({t['budget_per_10k']:g} x {t['n_benign']:,} / 10,000) = "
      f"{t['allowed_fp']} out-of-fold benign flows; threshold {t['threshold']:.8f} leaves {t['fp_at_threshold']} above it.\n")
print("| Held-out part | Unit | Malicious flows caught (TP) / malicious flows | Recall | Benign flows above threshold (FP) / benign flows | FP per 10k benign | PR-AUC |")
print("|---|---|---|---|---|---|---|")
parts = [("pooled, all five", m["out_of_fold"]["pooled"]["lgbm"])]
parts += [(g, v["lgbm"]) for g, v in sorted(m["out_of_fold"]["by_group"].items()) if g.startswith("ctu13")]
for name, r in parts:
    pr = "—" if r["pr_auc"] is None else f"{r['pr_auc']:.4f}"
    print(f"| {name} | flows | {r['tp']:,} / {r['positives']:,} | {r['recall']:.4f} | {r['fp']:,} / {r['benign']:,} | "
          f"{r['fp_per_10k_benign']} | {pr} |")
