"""Labelled feature dumps -> model matrices, behind a leakage check."""

import csv
import gzip
from dataclasses import dataclass
from typing import Iterable, List

import numpy as np

from sih26145.contract import load_contract
from sih26145.models.features import ML_FEATURES

# Never model inputs: they identify hosts, services or the moment of capture, so a model
# reading them learns the dataset instead of the behaviour.
IDENTITY = {"src_ip", "dst_ip", "src_port", "dst_port", "community_id", "start_time", "last_time",
            "flow_key_str", "entity", "group", "label", "label_code", "class_name", "off_hours"}


def check_leakage(features: Iterable[str]) -> List[str]:
    """Why this feature list is unsafe to train on (empty = safe)."""
    features = list(features)
    declared = set(load_contract().consumer("ml_flow_models").reads)
    errors = [f"{f}: identity, exact port or capture time" for f in features if f in IDENTITY]
    errors += [f"{f}: not declared for ml_flow_models" for f in features if f not in declared and f not in IDENTITY]
    if len(set(features)) != len(features):
        errors.append("duplicate features")
    return errors


@dataclass
class Dataset:
    X: np.ndarray            # (n, len(features)); NaN = undefined for that flow
    y: np.ndarray            # 1 malicious, 0 benign
    groups: np.ndarray       # capture the row came from: ctu13-s<N> or gen-<scenario>
    classes: np.ndarray      # scenario class name (benign rows: benign-*)
    start: np.ndarray        # flow start, epoch seconds (for the time-ordered split only)
    features: List[str]


def load(paths: Iterable[str], features: List[str] = ML_FEATURES) -> Dataset:
    errors = check_leakage(features)
    if errors:
        raise ValueError("leakage check failed: " + "; ".join(errors))
    X, y, g, c, t = [], [], [], [], []
    for path in paths:
        with gzip.open(path, "rt", newline="") as fh:
            for r in csv.DictReader(fh):
                X.append([float(r[f]) for f in features])
                y.append(int(r["label"]))
                g.append(r["group"])
                c.append(r["class_name"])
                t.append(float(r["start_time"]))
    return Dataset(np.array(X, dtype=np.float64).reshape(-1, len(features)), np.array(y), np.array(g),
                   np.array(c), np.array(t), list(features))
