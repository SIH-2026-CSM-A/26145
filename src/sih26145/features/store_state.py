"""State containers and configuration for the FeatureStore (fixed-size, numpy-backed)."""

from collections import OrderedDict
from dataclasses import dataclass
from typing import Tuple

import numpy as np

# host counters / HLL rows, dst counters (index 0 = current window, 1 = previous)
H_FLOWS, H_TCP, H_SYN_ONLY, H_DNS_Q, H_HIGH_ENT, H_QLEN, H_DNS_RESP, H_DNS_NX, H_DNS_RESP_FLOWS = range(9)
HLL_DSTS, HLL_PORTS, HLL_QNAMES, HLL_JA4, HLL_PERIODIC = range(5)
D_FLOWS, D_BYTES, D_TCP, D_SYN_ONLY, D_REFL_FLOWS, D_REFL_BYTES, D_REFL_PKTS = range(7)
# UDP services abused for reflection/amplification: DNS, NTP, SSDP, memcached, CLDAP,
# chargen, SNMP, portmapper.
REFLECTOR_PORTS = frozenset({53, 123, 1900, 11211, 389, 19, 161, 111})
# Per-entry Python object overhead (instance, array headers, dict/OrderedDict node, key).
# ponytail: a measured-then-padded constant; tests/features checks the total under tracemalloc.
ENTRY_OVERHEAD, PAIR_OVERHEAD = 1024, 512


@dataclass(frozen=True)
class StoreConfig:
    window: float = 60.0
    max_hosts: int = 4096
    max_dsts: int = 4096
    max_pairs: int = 32768
    hll_p: int = 8                        # 256 registers, ~6.5% standard error
    entropy_buckets: int = 128            # entropy saturates at 7 bits
    cms_width: int = 8192
    cms_depth: int = 4
    cms_halve_every: float = 86400.0      # long-horizon counts decay by half daily
    egress_bucket: float = 60.0
    egress_buckets: int = 60              # 1 hour of 1-minute egress buckets
    ewma_alpha: float = 0.1
    min_baseline_buckets: int = 5
    high_entropy_label_bits: float = 3.5  # first-label entropy counted as "high"
    periodic_cv: float = 0.35             # pair inter-flow CV at or below this is "periodic"
    periodic_min_gaps: int = 3            # gaps before a pair counts toward src_periodic_dsts_w
    dst_baseline_windows: int = 5         # closed windows before dst_*_vs_baseline is served
    work_hours: Tuple[int, int] = (9, 18)
    work_days: Tuple[int, ...] = (0, 1, 2, 3, 4)
    utc_offset_hours: float = 5.5         # enclave local time (IST default)


class _Host:
    __slots__ = ("wid", "counts", "hll", "egress", "egress_bid", "mean", "var", "baseline_n")

    def __init__(self, cfg: StoreConfig, wid: int, bid: int):
        self.wid, self.egress_bid = wid, bid
        self.counts = np.zeros((2, 9))
        self.hll = np.zeros((2, 5, 1 << cfg.hll_p), dtype=np.uint8)
        self.egress = np.zeros(cfg.egress_buckets)
        self.mean = self.var = 0.0
        self.baseline_n = 0


class _Dst:
    __slots__ = ("wid", "counts", "hll", "ent", "longterm", "base_flows", "base_bytes", "base_n")

    def __init__(self, cfg: StoreConfig, wid: int):
        self.wid = wid
        self.base_flows = self.base_bytes = 0.0  # EWMA of closed-window totals
        self.base_n = 0
        self.counts = np.zeros((2, 7))
        self.hll = np.zeros((2, 1 << cfg.hll_p), dtype=np.uint8)
        self.ent = np.zeros((2, cfg.entropy_buckets), dtype=np.uint32)
        self.longterm = np.zeros(1 << cfg.hll_p, dtype=np.uint8)


class _Pair:
    __slots__ = ("wid", "flows", "last_start", "n", "mean", "m2")

    def __init__(self, wid: int):
        self.wid, self.flows, self.last_start = wid, [0, 0], None
        self.n, self.mean, self.m2 = 0, 0.0, 0.0


def _roll(state, wid: int, *arrays) -> None:
    """Advance a state's tumbling window to `wid` (row 0 = current, row 1 = previous)."""
    if wid <= state.wid:
        return
    for a in arrays:
        a[1] = a[0] if wid == state.wid + 1 else 0
        a[0] = 0
    state.wid = wid


def _lru_get(table: OrderedDict, key, cap: int, factory):
    state = table.get(key)
    if state is None:
        if len(table) >= cap:
            table.popitem(last=False)
        state = table[key] = factory()
    else:
        table.move_to_end(key)
    return state


class _LinkView:
    def __init__(self, store):
        self.store = store

    def roll(self, wid: int) -> None:
        s = self.store
        if wid > s.link_wid:
            s.link[1] = s.link[0] if wid == s.link_wid + 1 else 0
            s.link[0] = 0
            s.link_wid = wid
