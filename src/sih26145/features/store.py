"""Tier-2 feature store: windowed per-host, per-destination and per-pair rollups.

Updated once per flushed flow, on event time (flow timestamps), so replays are deterministic.
Windowed ("_w") values cover the current and previous tumbling window, i.e. the last W..2W
seconds. Memory is bounded: key tables are LRU-capped and every per-key structure is a
fixed-size numpy array; memory_ceiling_bytes() states the bound for a configuration.
Every feature served here is declared in feature_contract.toml.
"""

import math
from collections import OrderedDict
from datetime import datetime, timedelta, timezone
from typing import Any, Optional

import numpy as np

from sih26145.contract import UnavailableFeatureError, load_contract
from sih26145.features.directional import NetworkPolicy, egress_bytes
from sih26145.features.extractor import entropy_of_string
from sih26145.features.sketches import CountMinSketch, bucket_entropy, bucket_of, hll_add, hll_count
from sih26145.features.store_state import (
    D_BYTES, D_FLOWS, D_SYN_ONLY, D_TCP, ENTRY_OVERHEAD, H_DNS_NX, H_DNS_Q, H_DNS_RESP,
    H_DNS_RESP_FLOWS, H_FLOWS, H_HIGH_ENT, H_QLEN, H_SYN_ONLY, H_TCP, HLL_DSTS, HLL_JA4,
    HLL_PORTS, HLL_QNAMES, PAIR_OVERHEAD, StoreConfig, _Dst, _Host, _lru_get, _Pair, _roll,
)
from sih26145.flow.models import FlowRecord

_SYN, _ACK = 0x02, 0x10

def _syn_only(flow: FlowRecord) -> bool:
    """Initiator sent SYN but never ACKed: no SYN-ACK arrived, or none was captured."""
    flags = flow.rev_tcp_flags if flow.fwd_is_responder else flow.fwd_tcp_flags
    return bool(flags & _SYN) and not flags & _ACK


class FeatureStore:
    def __init__(self, config: Optional[StoreConfig] = None, policy: Optional[NetworkPolicy] = None):
        self.cfg = config or StoreConfig()
        self.policy = policy or NetworkPolicy.from_env()
        self.hosts: OrderedDict = OrderedDict()
        self.dsts: OrderedDict = OrderedDict()
        self.pairs: OrderedDict = OrderedDict()
        self.pair_history = CountMinSketch(self.cfg.cms_width, self.cfg.cms_depth)
        self.ja4_seen = CountMinSketch(self.cfg.cms_width, self.cfg.cms_depth)
        self.link = np.zeros((2, 2))  # [window][flows, reverse_seen flows]
        self.link_wid = 0
        self.now = 0.0
        self._halved_at: Optional[float] = None

    # ---- update --------------------------------------------------------------------------
    def update(self, flow: FlowRecord) -> None:
        cfg, t = self.cfg, flow.last_time
        self.now = max(self.now, t)
        wid = int(t // cfg.window)
        key = flow.flow_key
        tcp = key.protocol == "TCP"
        syn_only = tcp and _syn_only(flow)

        link = _LinkView(self)
        link.roll(wid)
        self.link[0] += (1, int(flow.reverse_seen))

        host = self._host(key.src_ip, t)
        _roll(host, wid, host.counts, host.hll)
        c, h = host.counts[0], host.hll[0]
        c[H_FLOWS] += 1
        c[H_TCP] += tcp
        c[H_SYN_ONLY] += syn_only
        hll_add(h[HLL_DSTS], key.dst_ip)
        hll_add(h[HLL_PORTS], str(key.dst_port))
        for ja4 in flow.tls_ja4:
            hll_add(h[HLL_JA4], ja4)
            self.ja4_seen.add(ja4)
        self._dns(flow, t, wid)

        out = egress_bytes(flow, self.policy)
        if out:
            inside = key.src_ip if self.policy.is_internal(key.src_ip) else key.dst_ip
            egress_host = self._host(inside, t)
            egress_host.egress[int(t // cfg.egress_bucket) % cfg.egress_buckets] += out

        dst = _lru_get(self.dsts, key.dst_ip, cfg.max_dsts, lambda: _Dst(cfg, wid))
        _roll(dst, wid, dst.counts, dst.hll, dst.ent)
        dst.counts[0] += (1, flow.total_bytes, tcp, syn_only)
        hll_add(dst.hll[0], key.src_ip)
        hll_add(dst.longterm, key.src_ip)
        dst.ent[0, bucket_of(key.src_ip, cfg.entropy_buckets)] += 1

        pair = _lru_get(self.pairs, (key.src_ip, key.dst_ip), cfg.max_pairs, lambda: _Pair(wid))
        if wid > pair.wid:
            pair.flows = [0, pair.flows[0] if wid == pair.wid + 1 else 0]
            pair.wid = wid
        pair.flows[0] += 1
        if pair.last_start is not None and flow.start_time >= pair.last_start:
            gap = flow.start_time - pair.last_start
            pair.n += 1
            delta = gap - pair.mean
            pair.mean += delta / pair.n
            pair.m2 += delta * (gap - pair.mean)
        pair.last_start = flow.start_time if pair.last_start is None else max(pair.last_start, flow.start_time)
        self.pair_history.add(f"{key.src_ip}|{key.dst_ip}")
        self._decay(t)

    def _dns(self, flow: FlowRecord, t: float, wid: int) -> None:
        if not flow.dns_queries and not flow.dns_responses:
            return
        key = flow.flow_key
        client = self._host(key.dst_ip if flow.fwd_is_responder else key.src_ip, t)
        _roll(client, wid, client.counts, client.hll)
        c = client.counts[0]
        for q in flow.dns_queries:
            c[H_DNS_Q] += 1
            c[H_QLEN] += len(q)
            c[H_HIGH_ENT] += entropy_of_string(q.split(".")[0]) >= self.cfg.high_entropy_label_bits
            hll_add(client.hll[0, HLL_QNAMES], q)
        if flow.responder_seen:
            c[H_DNS_RESP_FLOWS] += 1
            c[H_DNS_RESP] += flow.dns_responses
            c[H_DNS_NX] += flow.dns_nxdomain

    def _host(self, ip: str, t: float) -> _Host:
        cfg = self.cfg
        host = _lru_get(self.hosts, ip, cfg.max_hosts,
                        lambda: _Host(cfg, int(t // cfg.window), int(t // cfg.egress_bucket)))
        self._advance_egress(host, int(t // cfg.egress_bucket))
        return host

    def _advance_egress(self, host: _Host, bid: int) -> None:
        """Close finished 1-minute egress buckets into the EWMA baseline."""
        cfg, a = self.cfg, self.cfg.ewma_alpha
        steps = min(bid - host.egress_bid, cfg.egress_buckets)
        for i in range(steps):
            closing = (host.egress_bid + i) % cfg.egress_buckets
            x = host.egress[closing]
            diff = x - host.mean
            host.mean += a * diff
            host.var = (1 - a) * (host.var + a * diff * diff)
            host.baseline_n += 1
            host.egress[(closing + 1) % cfg.egress_buckets] = 0.0
        if bid - host.egress_bid > cfg.egress_buckets:
            host.egress[:] = 0.0
        host.egress_bid = max(host.egress_bid, bid)

    def _decay(self, t: float) -> None:
        if self._halved_at is None:
            self._halved_at = t
        elif t - self._halved_at >= self.cfg.cms_halve_every:
            self.pair_history.halve()
            self.ja4_seen.halve()
            self._halved_at = t

    # ---- read ----------------------------------------------------------------------------
    def get(self, feature: str, key: Any = None) -> Any:
        """Contract-checked read. `key`: host IP, dst IP, (src, dst) pair, JA4, or epoch
        seconds for off_hours; None for link features."""
        load_contract().require(feature)
        if feature not in _READERS:
            raise KeyError(f"{feature!r} is not served by the FeatureStore")
        return _READERS[feature](self, key)

    def off_hours(self, t: float) -> bool:
        local = datetime.fromtimestamp(t, tz=timezone(timedelta(hours=self.cfg.utc_offset_hours)))
        start, end = self.cfg.work_hours
        return local.weekday() not in self.cfg.work_days or not (start <= local.hour < end)

    def _host_view(self, ip: str) -> Optional[_Host]:
        host = self.hosts.get(ip)
        if host is not None:
            _roll(host, int(self.now // self.cfg.window), host.counts, host.hll)
            self._advance_egress(host, int(self.now // self.cfg.egress_bucket))
        return host

    def _dst_view(self, ip: str) -> Optional[_Dst]:
        dst = self.dsts.get(ip)
        if dst is not None:
            _roll(dst, int(self.now // self.cfg.window), dst.counts, dst.hll, dst.ent)
        return dst

    def _pair_view(self, pair_key) -> Optional[_Pair]:
        pair = self.pairs.get(tuple(pair_key))
        wid = int(self.now // self.cfg.window)
        if pair is not None and wid > pair.wid:
            pair.flows = [0, pair.flows[0] if wid == pair.wid + 1 else 0]
            pair.wid = wid
        return pair

    def memory_ceiling_bytes(self) -> int:
        """Upper bound on store memory for this configuration, at full occupancy."""
        cfg, m = self.cfg, 1 << self.cfg.hll_p
        host = 2 * 9 * 8 + 2 * 4 * m + cfg.egress_buckets * 8 + ENTRY_OVERHEAD
        dst = 2 * 4 * 8 + 2 * m + 2 * cfg.entropy_buckets * 4 + m + ENTRY_OVERHEAD
        sketches = self.pair_history.nbytes + self.ja4_seen.nbytes + self.link.nbytes
        return cfg.max_hosts * host + cfg.max_dsts * dst + cfg.max_pairs * PAIR_OVERHEAD + sketches


class _LinkView:
    def __init__(self, store: FeatureStore):
        self.store = store

    def roll(self, wid: int) -> None:
        s = self.store
        if wid > s.link_wid:
            s.link[1] = s.link[0] if wid == s.link_wid + 1 else 0
            s.link[0] = 0
            s.link_wid = wid


def _hc(i):
    return lambda s, ip: float(h.counts[:, i].sum()) if (h := s._host_view(ip)) else 0.0


def _hll_host(row):
    return lambda s, ip: hll_count(np.maximum(h.hll[0, row], h.hll[1, row])) if (h := s._host_view(ip)) else 0.0


def _ratio(num, den):
    return lambda s, ip: (float(h.counts[:, num].sum() / d) if (h := s._host_view(ip)) is not None
                          and (d := h.counts[:, den].sum()) else None)


def _nxdomain_rate(s: FeatureStore, ip: str) -> Optional[float]:
    h = s._host_view(ip)
    if h is None or not h.counts[:, H_DNS_RESP_FLOWS].sum():
        raise UnavailableFeatureError("src_nxdomain_rate_w: no resolver responses observed for this host in the window")
    resp = h.counts[:, H_DNS_RESP].sum()
    return float(h.counts[:, H_DNS_NX].sum() / resp) if resp else None


def _egress(minutes: int):
    def read(s: FeatureStore, ip: str) -> float:
        h = s._host_view(ip)
        if h is None:
            return 0.0
        B, bid = s.cfg.egress_buckets, h.egress_bid
        return float(sum(h.egress[(bid - i) % B] for i in range(min(minutes, B))))
    return read


def _egress_z(s: FeatureStore, ip: str) -> Optional[float]:
    """Current 1-minute egress vs the host's EWMA baseline; None until warmed up."""
    h = s._host_view(ip)
    if h is None or h.baseline_n < s.cfg.min_baseline_buckets:
        return None
    current = h.egress[h.egress_bid % s.cfg.egress_buckets]
    return float((current - h.mean) / max(math.sqrt(h.var), 1.0))  # ponytail: 1-byte std floor


def _dc(i):
    return lambda s, ip: float(d.counts[:, i].sum()) if (d := s._dst_view(ip)) else 0.0


def _pair_iat_cv(s: FeatureStore, k) -> Optional[float]:
    p = s._pair_view(k)
    if p is None or p.n < 2 or p.mean <= 0:
        return None
    return math.sqrt(p.m2 / (p.n - 1)) / p.mean


def _visibility(s: FeatureStore, _key) -> Optional[float]:
    _LinkView(s).roll(int(s.now // s.cfg.window))
    flows = s.link[:, 0].sum()
    return float(s.link[:, 1].sum() / flows) if flows else None


_READERS = {
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
