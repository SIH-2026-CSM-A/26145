"""Fixed-memory streaming sketches (numpy + stdlib blake2b; deterministic across runs).

Python's built-in hash() is salted per process, so it is not used: two replays of the same
PCAP must produce the same sketch state.
"""

import hashlib
import math
from typing import Tuple

import numpy as np


def hash64(item: str) -> int:
    return int.from_bytes(hashlib.blake2b(item.encode(), digest_size=8).digest(), "big")


def hash128(item: str) -> Tuple[int, int]:
    d = hashlib.blake2b(item.encode(), digest_size=16).digest()
    return int.from_bytes(d[:8], "big"), int.from_bytes(d[8:], "big")


# ---- HyperLogLog ------------------------------------------------------------------------------

def hll_alpha(m: int) -> float:
    return {16: 0.673, 32: 0.697, 64: 0.709}.get(m, 0.7213 / (1 + 1.079 / m))


def hll_add(registers: np.ndarray, item: str) -> None:
    """Add `item` to a HyperLogLog register row (uint8, length 2**p), in place."""
    m = registers.shape[-1]
    p = m.bit_length() - 1
    h = hash64(item)
    idx = h >> (64 - p)
    w = h & ((1 << (64 - p)) - 1)
    rank = (64 - p) - w.bit_length() + 1
    if rank > registers[idx]:
        registers[idx] = rank


def hll_count(registers: np.ndarray) -> float:
    """Cardinality estimate of one register row (standard error ~1.04 / sqrt(m))."""
    m = registers.shape[-1]
    est = hll_alpha(m) * m * m / float(np.sum(np.ldexp(1.0, -registers.astype(np.int32))))
    zeros = int(np.count_nonzero(registers == 0))
    if est <= 2.5 * m and zeros:
        est = m * math.log(m / zeros)  # linear counting for small cardinalities
    return est


class HyperLogLog:
    """Standalone HLL. The FeatureStore packs many register rows into one array instead."""

    def __init__(self, p: int = 10):
        self.registers = np.zeros(1 << p, dtype=np.uint8)

    def add(self, item: str) -> None:
        hll_add(self.registers, item)

    def count(self) -> float:
        return hll_count(self.registers)

    def merge(self, other: "HyperLogLog") -> None:
        np.maximum(self.registers, other.registers, out=self.registers)


# ---- Count-Min ------------------------------------------------------------------------------

class CountMinSketch:
    """Count-Min with conservative update. Never underestimates; overestimates by at most
    e/width * total with probability 1 - e**-depth. halve() gives exponential decay."""

    def __init__(self, width: int = 4096, depth: int = 4):
        self.width, self.depth = width, depth
        self.table = np.zeros((depth, width), dtype=np.uint64)
        self._rows = np.arange(depth)

    def _cols(self, item: str) -> np.ndarray:
        h1, h2 = hash128(item)
        return np.array([(h1 + i * h2) % self.width for i in range(self.depth)])

    def add(self, item: str, count: int = 1) -> None:
        cols = self._cols(item)
        cells = self.table[self._rows, cols]
        target = np.uint64(int(cells.min()) + count)
        self.table[self._rows, cols] = np.maximum(cells, target)

    def estimate(self, item: str) -> int:
        return int(self.table[self._rows, self._cols(item)].min())

    def halve(self) -> None:
        self.table >>= np.uint64(1)

    @property
    def nbytes(self) -> int:
        return self.table.nbytes


# ---- Bucketed entropy --------------------------------------------------------------------------

def bucket_of(item: str, buckets: int) -> int:
    return hash64(item) % buckets


def bucket_entropy(counts: np.ndarray) -> float:
    """Shannon entropy (bits) of a hashed histogram. Saturates at log2(len(counts));
    hash collisions merge items and bias the estimate low."""
    total = counts.sum()
    if total == 0:
        return 0.0
    p = counts[counts > 0] / total
    return float(-(p * np.log2(p)).sum())
