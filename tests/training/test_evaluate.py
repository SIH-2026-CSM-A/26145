"""Leakage check, scenario-disjoint folds, time split and the alert-budget threshold."""

import numpy as np
import pytest

from sih26145.models.features import ML_FEATURES
from sih26145.training.dataset import check_leakage
from sih26145.training.evaluate import budget_threshold, fold_groups_disjoint, logo_folds, metrics, time_split


def test_model_features_pass_the_leakage_check():
    assert check_leakage(ML_FEATURES) == []


@pytest.mark.parametrize("bad", ["src_ip", "dst_ip", "dst_port", "src_port", "start_time", "off_hours"])
def test_leakage_check_rejects_identity_ports_and_time(bad):
    assert check_leakage(ML_FEATURES + [bad])


def test_validation_folds_never_share_a_scenario():
    groups = np.array(["ctu13-s1"] * 5 + ["ctu13-s5"] * 5 + ["gen-syn_flood"] * 3)
    folds = list(logo_folds(groups))
    assert len(folds) == 3 and fold_groups_disjoint(groups, folds)
    rng = np.random.default_rng(0)  # a random row split mixes captures across the fold boundary
    perm = rng.permutation(len(groups))
    assert not fold_groups_disjoint(groups, [("r", perm[:9], perm[9:])])


def test_time_split_trains_on_the_earlier_flows_of_each_capture():
    groups = np.array(["ctu13-s1"] * 10 + ["gen-x"] * 4)
    start = np.array([9, 8, 7, 6, 5, 4, 3, 2, 1, 0] + [0, 1, 2, 3], dtype=float)
    train, test = time_split(groups, start)
    assert set(start[train]) == set(range(7)) and set(start[test]) == {7, 8, 9}


def test_budget_widens_when_the_benign_set_cannot_resolve_one_in_ten_thousand():
    small = budget_threshold(np.arange(1000, dtype=float))   # 1/10k of 1,000 = 0.1 expected FP
    assert small["allowed_fp"] == 3 and small["fp_at_threshold"] == 3 and small["budget_per_10k"] == 30.0
    big = budget_threshold(np.arange(50_000, dtype=float))   # 1/10k of 50,000 = 5
    assert big["allowed_fp"] == 5 and big["budget_per_10k"] == 1.0


def test_metrics_leave_undefined_values_undefined():
    m = metrics(np.array([1, 1, 1]), np.array([0.9, 0.2, 0.8]), 0.5)
    assert m["pr_auc"] is None and m["fp_per_10k_benign"] is None and m["recall"] == round(2 / 3, 4)
