"""The trained flow models load offline from the verified bundle and score in batches."""

import json
import math

import numpy as np
import pytest

from sih26145.models import MLModelSuite
from sih26145.models.features import ML_FEATURES, dst_port_class, ml_matrix
from sih26145 import bundle


def row(**overrides):
    base = {f: 0.0 for f in ML_FEATURES}
    base.update(duration=2.0, total_packets=6.0, total_bytes=900.0, pps=3.0, bps=450.0, is_tcp=1.0,
                has_syn=1.0, has_fin=1.0, dst_port_class=1.0, reverse_seen=1.0, pair_iat_cv=math.nan)
    base.update(overrides)
    return base


@pytest.fixture(scope="module")
def suite():
    return MLModelSuite()


def test_manifest_matches_the_code(suite):
    manifest = json.loads(bundle.load_verified()["models/manifest.json"])
    assert manifest["features"] == ML_FEATURES
    assert manifest["lgbm"]["params"]["num_threads"] == 1 and manifest["iforest"]["params"]["n_jobs"] == 1
    assert suite.classifier.threshold == manifest["lgbm"]["threshold"]


def test_batch_equals_one_at_a_time(suite):
    rows = [row(), row(total_packets=400.0, pps=200.0, src_distinct_dsts_w=90.0), row(is_tcp=0.0, is_udp=1.0)]
    batch = suite.predict_batch(rows)
    single = [suite.predict(r) for r in rows]
    assert [[p.anomaly_score for p in preds] for preds in batch] == \
        [[p.anomaly_score for p in preds] for preds in single]
    assert all(len(preds) == 2 for preds in batch)


def test_nan_stays_nan_into_the_matrix():
    X = ml_matrix([row()])
    assert X.shape == (1, len(ML_FEATURES)) and np.isnan(X[0, ML_FEATURES.index("pair_iat_cv")])


def test_port_class_is_coarse():
    assert [dst_port_class(p, "TCP") for p in (80, 8080, 51000)] == [1.0, 2.0, 3.0]
    assert dst_port_class(0, "ICMP") == 0.0


def test_isolation_forest_loads_through_skops_not_pickle(suite):
    import sklearn.ensemble
    assert isinstance(suite.anomaly.model, sklearn.ensemble.IsolationForest)
    manifest = json.loads(bundle.load_verified()["models/manifest.json"])
    assert manifest["iforest"]["file"].endswith(".skops")
