"""Sketch accuracy and invariants."""

import math

import numpy as np

from sih26145.features.sketches import CountMinSketch, HyperLogLog, bucket_entropy, bucket_of


def test_hll_estimate_within_three_sigma():
    hll = HyperLogLog(p=10)
    n = 20_000
    for i in range(n):
        hll.add(f"10.{i >> 16}.{(i >> 8) & 255}.{i & 255}")
        hll.add(f"10.{i >> 16}.{(i >> 8) & 255}.{i & 255}")  # duplicates must not count
    sigma = 1.04 / math.sqrt(1024)
    assert abs(hll.count() - n) / n < 3 * sigma


def test_hll_small_cardinality_and_merge():
    a, b = HyperLogLog(p=8), HyperLogLog(p=8)
    for i in range(10):
        a.add(f"a{i}")
    for i in range(5, 15):
        b.add(f"a{i}")
    assert round(a.count()) == 10
    a.merge(b)
    assert round(a.count()) == 15


def test_count_min_never_underestimates_and_bounds_error():
    cms = CountMinSketch(width=512, depth=4)
    true = {f"k{i}": (i % 37) + 1 for i in range(3000)}
    for k, c in true.items():
        cms.add(k, c)
    total = sum(true.values())
    errors = [cms.estimate(k) - c for k, c in true.items()]
    assert min(errors) >= 0
    bound = math.e / 512 * total
    assert np.mean([e <= bound for e in errors]) > 1 - math.exp(-4)


def test_count_min_halving_decays():
    cms = CountMinSketch(width=64, depth=2)
    cms.add("x", 10)
    cms.halve()
    assert cms.estimate("x") == 5


def test_bucket_entropy_extremes():
    one = np.zeros(128, dtype=np.uint32)
    one[bucket_of("10.0.0.1", 128)] = 1000
    assert bucket_entropy(one) == 0.0
    spread = np.zeros(128, dtype=np.uint32)
    for i in range(50_000):
        spread[bucket_of(f"src{i}", 128)] += 1
    assert 6.9 < bucket_entropy(spread) <= 7.0
    assert bucket_entropy(np.zeros(128)) == 0.0
