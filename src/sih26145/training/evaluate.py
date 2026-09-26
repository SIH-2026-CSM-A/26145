"""Scenario and time splits, the alert-budget threshold, and the reported metrics.

No accuracy figure is computed anywhere: at realistic base rates it says nothing.
"""

import math
from typing import Dict, Iterator, List, Optional, Tuple

import numpy as np
from sklearn.metrics import average_precision_score

BUDGET_PER_10K = 1.0     # ML-only false positives allowed per 10,000 benign flows, per model
MIN_EXPECTED_FP = 3      # below this many allowed FPs the pooled benign set cannot resolve the budget


def logo_folds(groups: np.ndarray) -> Iterator[Tuple[str, np.ndarray, np.ndarray]]:
    """Leave one capture out: each group is tested by a model that never saw any of it."""
    for g in sorted(set(groups)):
        yield g, np.flatnonzero(groups != g), np.flatnonzero(groups == g)


def fold_groups_disjoint(groups: np.ndarray, folds) -> bool:
    return all(not set(groups[tr]) & set(groups[te]) for _, tr, te in folds)


def time_split(groups: np.ndarray, start: np.ndarray, prefix: str = "ctu13", frac: float = 0.7):
    """Within each capture, the first `frac` of flows by start time train, the rest test."""
    train, test = [], []
    for g in sorted(set(groups)):
        if not g.startswith(prefix):
            continue
        idx = np.flatnonzero(groups == g)
        idx = idx[np.argsort(start[idx], kind="stable")]
        cut = int(len(idx) * frac)
        train.append(idx[:cut])
        test.append(idx[cut:])
    return np.concatenate(train), np.concatenate(test)


def budget_threshold(benign_scores: np.ndarray) -> Dict[str, float]:
    """Lowest threshold (alert when score > threshold) that keeps benign false positives within
    the budget. With too few benign flows to resolve 1/10k, the budget widens to the tightest
    the data supports: MIN_EXPECTED_FP allowed false positives in the pooled set."""
    n = len(benign_scores)
    rate = BUDGET_PER_10K / 1e4
    if n * rate < MIN_EXPECTED_FP:
        rate = MIN_EXPECTED_FP / n
    allowed = int(math.floor(rate * n + 1e-9))
    ranked = np.sort(benign_scores)[::-1]
    threshold = float(ranked[min(allowed, n - 1)])
    return {"threshold": threshold, "n_benign": n, "budget_per_10k": round(rate * 1e4, 4),
            "allowed_fp": allowed, "fp_at_threshold": int((benign_scores > threshold).sum())}


def metrics(y: np.ndarray, score: np.ndarray, threshold: float) -> Dict[str, Optional[float]]:
    alert = score > threshold
    pos, neg = int(y.sum()), int((y == 0).sum())
    tp, fp = int((alert & (y == 1)).sum()), int((alert & (y == 0)).sum())
    return {
        "n": int(len(y)), "positives": pos, "benign": neg,
        "positive_share": round(pos / len(y), 4) if len(y) else None,
        "pr_auc": round(float(average_precision_score(y, score)), 4) if pos and neg else None,
        "precision": round(tp / (tp + fp), 4) if tp + fp else None,
        "recall": round(tp / pos, 4) if pos else None,
        "tp": tp, "fp": fp,
        "fp_per_10k_benign": round(1e4 * fp / neg, 2) if neg else None,
    }


def calibration(y: np.ndarray, prob: np.ndarray, bins: int = 10) -> Dict[str, object]:
    """Reliability table (mean predicted vs observed malicious share per bin) and Brier score."""
    edges = np.linspace(0, 1, bins + 1)
    table: List[Dict[str, float]] = []
    for lo, hi in zip(edges[:-1], edges[1:]):
        m = (prob >= lo) & ((prob < hi) if hi < 1 else (prob <= hi))
        if m.any():
            table.append({"bin": f"{lo:.1f}-{hi:.1f}", "n": int(m.sum()),
                          "mean_predicted": round(float(prob[m].mean()), 4),
                          "observed_malicious": round(float(y[m].mean()), 4)})
    return {"brier": round(float(np.mean((prob - y) ** 2)), 5), "reliability": table}
