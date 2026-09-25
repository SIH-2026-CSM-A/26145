"""Readers for every feature the FeatureStore serves, keyed by contract feature name."""

import math
from typing import Optional

import numpy as np

from sih26145.contract import UnavailableFeatureError
from sih26145.features.sketches import bucket_entropy, hll_count
from sih26145.features.store_state import (
    D_BYTES, D_FLOWS, D_REFL_BYTES, D_REFL_FLOWS, D_REFL_PKTS, D_SYN_ONLY, D_TCP, H_DNS_NX, H_DNS_Q,
    H_DNS_RESP, H_DNS_RESP_FLOWS, H_FLOWS, H_HIGH_ENT, H_QLEN, H_SYN_ONLY, H_TCP, HLL_DSTS, HLL_JA4,
    HLL_PERIODIC, HLL_PORTS, HLL_QNAMES, _LinkView,
)


def _hc(i):
    return lambda s, ip: float(h.counts[:, i].sum()) if (h := s._host_view(ip)) else 0.0


def _hll_host(row):
    return lambda s, ip: hll_count(np.maximum(h.hll[0, row], h.hll[1, row])) if (h := s._host_view(ip)) else 0.0


def _ratio(num, den):
    return lambda s, ip: (float(h.counts[:, num].sum() / d) if (h := s._host_view(ip)) is not None
                          and (d := h.counts[:, den].sum()) else None)


def _nxdomain_rate(s, ip: str) -> Optional[float]:
    h = s._host_view(ip)
    if h is None or not h.counts[:, H_DNS_RESP_FLOWS].sum():
        raise UnavailableFeatureError("src_nxdomain_rate_w: no resolver responses observed for this host in the window")
    resp = h.counts[:, H_DNS_RESP].sum()
    return float(h.counts[:, H_DNS_NX].sum() / resp) if resp else None


def _egress(minutes: int):
    def read(s, ip: str) -> float:
        h = s._host_view(ip)
        if h is None:
            return 0.0
        B, bid = s.cfg.egress_buckets, h.egress_bid
        return float(sum(h.egress[(bid - i) % B] for i in range(min(minutes, B))))
    return read


def _egress_z(s, ip: str) -> Optional[float]:
    """Current 1-minute egress vs the host's EWMA baseline; None until warmed up."""
    h = s._host_view(ip)
    if h is None or h.baseline_n < s.cfg.min_baseline_buckets:
        return None
    current = h.egress[h.egress_bid % s.cfg.egress_buckets]
    # ponytail: std floored at 10% of the mean (and 1 byte) so a perfectly steady baseline
    # does not turn a small wobble into a huge z; tune if hosts are bursty by nature.
    return float((current - h.mean) / max(math.sqrt(h.var), 0.1 * h.mean, 1.0))


def _dc(i):
    return lambda s, ip: float(d.counts[:, i].sum()) if (d := s._dst_view(ip)) else 0.0


def _refl_mean_pkt(s, ip: str) -> Optional[float]:
    d = s._dst_view(ip)
    pkts = d.counts[:, D_REFL_PKTS].sum() if d is not None else 0
    return float(d.counts[:, D_REFL_BYTES].sum() / pkts) if pkts else None


def _vs_baseline(i: int, attr: str):
    """Current-window total / the destination's EWMA of past window totals; None while warming up."""
    def read(s, ip: str) -> Optional[float]:
        d = s._dst_view(ip)
        if d is None or d.base_n < s.cfg.dst_baseline_windows:
            return None
        return float(d.counts[0, i] / max(getattr(d, attr), 1.0))
    return read


def _pair_iat_cv(s, k) -> Optional[float]:
    p = s._pair_view(k)
    if p is None or p.n < 2 or p.mean <= 0:
        return None
    return math.sqrt(p.m2 / (p.n - 1)) / p.mean


def _visibility(s, _key) -> Optional[float]:
    _LinkView(s).roll(int(s.now // s.cfg.window))
    flows = s.link[:, 0].sum()
    return float(s.link[:, 1].sum() / flows) if flows else None


READERS = {
    "src_flows_w": _hc(H_FLOWS),
    "src_distinct_dsts_w": _hll_host(HLL_DSTS),
    "src_distinct_dst_ports_w": _hll_host(HLL_PORTS),
    "src_syn_only_ratio_w": _ratio(H_SYN_ONLY, H_TCP),
    "src_dns_queries_w": _hc(H_DNS_Q),
    "src_distinct_qnames_w": _hll_host(HLL_QNAMES),
    "src_high_entropy_qnames_w": _hc(H_HIGH_ENT),
    "src_qname_len_sum_w": _hc(H_QLEN),
    "src_nxdomain_rate_w": _nxdomain_rate,
    "src_distinct_ja4_w": _hll_host(HLL_JA4),
    "src_periodic_dsts_w": _hll_host(HLL_PERIODIC),
    "src_egress_bytes_1m": _egress(1),
    "src_egress_bytes_5m": _egress(5),
    "src_egress_bytes_1h": _egress(60),
    "src_egress_bytes_z": _egress_z,
    "dst_flows_w": _dc(D_FLOWS),
    "dst_bytes_w": _dc(D_BYTES),
    "dst_distinct_srcs_w": lambda s, ip: hll_count(np.maximum(d.hll[0], d.hll[1])) if (d := s._dst_view(ip)) else 0.0,
    "dst_src_ip_entropy_w": lambda s, ip: bucket_entropy(d.ent.sum(axis=0)) if (d := s._dst_view(ip)) else 0.0,
    "dst_syn_only_ratio_w": lambda s, ip: (float(d.counts[:, D_SYN_ONLY].sum() / t)
                                           if (d := s._dst_view(ip)) is not None and (t := d.counts[:, D_TCP].sum()) else None),
    "dst_reflector_flows_w": _dc(D_REFL_FLOWS),
    "dst_reflector_bytes_w": _dc(D_REFL_BYTES),
    "dst_reflector_mean_pkt_w": _refl_mean_pkt,
    "dst_bytes_vs_baseline": _vs_baseline(D_BYTES, "base_bytes"),
    "dst_flows_vs_baseline": _vs_baseline(D_FLOWS, "base_flows"),
    "dst_distinct_srcs_longterm": lambda s, ip: hll_count(d.longterm) if (d := s._dst_view(ip)) else 0.0,
    "pair_flows_w": lambda s, k: float(sum(p.flows)) if (p := s._pair_view(k)) else 0.0,
    "pair_iat_mean": lambda s, k: p.mean if (p := s._pair_view(k)) and p.n else None,
    "pair_iat_cv": _pair_iat_cv,
    "pair_iat_n": lambda s, k: p.n if (p := s._pair_view(k)) else 0,
    "pair_history_count": lambda s, k: s.pair_history.estimate(f"{k[0]}|{k[1]}"),
    "ja4_prevalence": lambda s, ja4: s.ja4_seen.estimate(ja4),
    "off_hours": lambda s, t: s.off_hours(t),
    "link_reverse_visibility_w": _visibility,
}
