"""Train and validate the flow models on labelled feature dumps (scripts/build_dataset.py).

    F=~/NewProjects/26145-data/features
    uv run python scripts/train_models.py $F/ctu13-s*.labelled.csv.gz \
        --holdout $F/gen-*.labelled.csv.gz --report docs/model_metrics.json   # validate, fit, save
    uv run python scripts/train_models.py FILES --split random --report /tmp/random.json --no-save

Validation: leave-one-capture-out over the training files (each CTU-13 scenario), plus a
time-ordered split inside each CTU-13 scenario; `--holdout` files (the generated attack
captures) are never trained on and are scored by the final models. Thresholds come from the pooled out-of-fold
benign scores under the alert budget (training/evaluate.py). `--split random` replaces the
capture split with shuffled rows; it exists only to show what that leak does to the numbers.
"""

import argparse
import hashlib
import json
import os
import platform
from importlib.metadata import version

import joblib
import lightgbm
import numpy as np
from sklearn.ensemble import IsolationForest
from sklearn.model_selection import KFold

from sih26145.models.anomaly import impute
from sih26145.models.schemas import ML_MODEL_VERSION
from sih26145.training.dataset import load
from sih26145.training.evaluate import (
    budget_threshold, calibration, fold_groups_disjoint, logo_folds, metrics, time_split)

ARTIFACTS = os.path.join(os.path.dirname(__file__), "..", "src", "sih26145", "models", "artifacts")
LGBM_PARAMS = dict(n_estimators=300, learning_rate=0.05, num_leaves=31, min_child_samples=50,
                   num_threads=1, deterministic=True, force_row_wise=True, random_state=42, verbose=-1)
IF_PARAMS = dict(n_estimators=100, max_samples=256, random_state=42, n_jobs=1)
# The IsolationForest flags novelty, not maliciousness. At the budget threshold its out-of-fold
# recall is near zero and it fires on a benign one-way download that no CTU normal host
# resembles (docs/MODELS.md §4.5), so it raises no alert on its own: its score attaches to
# rule alerts and, on agreement, raises their severity. LightGBM may alert alone (capped).
IF_ALERTS_ALONE = False


def fit_lgbm(X, y):
    return lightgbm.LGBMClassifier(**LGBM_PARAMS).fit(X, y)


def fit_iforest(X_benign):
    return IsolationForest(**IF_PARAMS).fit(impute(X_benign))


def if_score(model, X):
    return -model.score_samples(impute(X))  # higher = more anomalous


def out_of_fold(ds, folds):
    p, s = np.full(len(ds.y), np.nan), np.full(len(ds.y), np.nan)
    for name, tr, te in folds:
        if len(set(ds.y[tr])) < 2:
            print(f"skip fold {name}: training side has one class")
            continue
        p[te] = fit_lgbm(ds.X[tr], ds.y[tr]).predict_proba(ds.X[te])[:, 1]
        s[te] = if_score(fit_iforest(ds.X[tr[ds.y[tr] == 0]]), ds.X[te])
        print(f"fold {name}: {len(te)} rows")
    return p, s


def breakdown(ds, idx, p, s, th):
    """Metrics for both models over idx, pooled, per capture and per class."""
    def both(i):
        return {"lgbm": metrics(ds.y[i], p[i], th["lgbm"]["threshold"]),
                "iforest": metrics(ds.y[i], s[i], th["iforest"]["threshold"])}
    ctu = idx[np.char.startswith(ds.groups[idx].astype(str), "ctu13")]
    return {"pooled": both(idx), "pooled_ctu13": both(ctu) if len(ctu) else None,
            "by_group": {g: both(idx[ds.groups[idx] == g]) for g in sorted(set(ds.groups[idx]))},
            "by_class": {c: both(idx[(ds.classes[idx] == c)]) for c in sorted(set(ds.classes[idx]))}}


def time_ordered(ds, th):
    tr, te = time_split(ds.groups, ds.start)
    p, s = np.full(len(ds.y), np.nan), np.full(len(ds.y), np.nan)
    p[te] = fit_lgbm(ds.X[tr], ds.y[tr]).predict_proba(ds.X[te])[:, 1]
    s[te] = if_score(fit_iforest(ds.X[tr[ds.y[tr] == 0]]), ds.X[te])
    return {"train_rows": int(len(tr)), "train_positives": int(ds.y[tr].sum()),
            "note": "thresholds are the capture-split ones", **breakdown(ds, te, p, s, th)}


def sha256(path):
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def save(ds, th, files, if_benign_oof, lgbm_model, if_model):
    os.makedirs(ARTIFACTS, exist_ok=True)
    lgbm_path, if_path = os.path.join(ARTIFACTS, "lgbm.txt"), os.path.join(ARTIFACTS, "iforest.joblib")
    lgbm_model.booster_.save_model(lgbm_path)
    joblib.dump(if_model, if_path)
    manifest = {
        "version": ML_MODEL_VERSION, "features": ds.features,
        "lgbm": {"file": "lgbm.txt", "sha256": sha256(lgbm_path), "params": LGBM_PARAMS, "alerts_alone": True,
                 **th["lgbm"]},
        "iforest": {"file": "iforest.joblib", "sha256": sha256(if_path), "params": IF_PARAMS,
                    "nan_sentinel": -1.0, "score": "negated score_samples (higher = more anomalous)",
                    "alerts_alone": IF_ALERTS_ALONE,
                    # confidence = percentile of a score among out-of-fold benign scores
                    "benign_score_quantiles": np.quantile(if_benign_oof, np.linspace(0, 1, 1001)).round(6).tolist(),
                    **th["iforest"]},
        "training_files": {os.path.basename(f): sha256(f) for f in files},
        "training_rows": int(len(ds.y)), "training_positives": int(ds.y.sum()),
        "libs": {p: version(p) for p in ("lightgbm", "scikit-learn", "numpy", "joblib")},
        "python": platform.python_version(),
    }
    with open(os.path.join(ARTIFACTS, "manifest.json"), "w") as fh:
        json.dump(manifest, fh, indent=2)


def main():
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("files", nargs="+")
    ap.add_argument("--holdout", nargs="*", default=[],
                    help="labelled files never trained on, scored by the final models (generated captures)")
    ap.add_argument("--split", choices=["scenario", "random"], default="scenario")
    ap.add_argument("--report", required=True)
    ap.add_argument("--no-save", action="store_true")
    args = ap.parse_args()

    ds = load(args.files)
    print(f"{len(ds.y)} rows, {int(ds.y.sum())} malicious, {int((ds.y == 0).sum())} benign, groups {sorted(set(ds.groups))}")
    if args.split == "random":
        kf = KFold(5, shuffle=True, random_state=0)
        folds = [(f"random-{k}", tr, te) for k, (tr, te) in enumerate(kf.split(ds.X))]
    else:
        folds = list(logo_folds(ds.groups))
    assert args.split == "random" or fold_groups_disjoint(ds.groups, folds)
    p, s = out_of_fold(ds, folds)
    scored = np.flatnonzero(~np.isnan(p))
    benign = scored[ds.y[scored] == 0]
    th = {"lgbm": budget_threshold(p[benign]), "iforest": budget_threshold(s[benign])}
    report = {"split": args.split, "rows": int(len(ds.y)), "positives": int(ds.y.sum()),
              "thresholds": th, "out_of_fold": breakdown(ds, scored, p, s, th),
              "calibration_lgbm_oof": calibration(ds.y[scored], p[scored]),
              "calibration_lgbm_oof_ctu13": calibration(
                  ds.y[scored][np.char.startswith(ds.groups[scored].astype(str), "ctu13")],
                  p[scored][np.char.startswith(ds.groups[scored].astype(str), "ctu13")])}
    if args.split == "scenario":
        report["time_ordered"] = time_ordered(ds, th)
    lgbm_model, if_model = fit_lgbm(ds.X, ds.y), fit_iforest(ds.X[ds.y == 0])
    if args.holdout:
        ho = load(args.holdout)
        report["holdout"] = breakdown(ho, np.arange(len(ho.y)), lgbm_model.predict_proba(ho.X)[:, 1],
                                      if_score(if_model, ho.X), th)
    with open(args.report, "w") as fh:
        json.dump(report, fh, indent=2)
    print(json.dumps({"thresholds": th, "pooled": report["out_of_fold"]["pooled"]}, indent=2))
    if not args.no_save and args.split == "scenario":
        save(ds, th, args.files, s[benign], lgbm_model, if_model)


if __name__ == "__main__":
    main()
