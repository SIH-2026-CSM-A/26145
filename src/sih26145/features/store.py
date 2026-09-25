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

from sih26145.contract import load_contract
from sih26145.features.directional import NetworkPolicy, egress_bytes
from sih26145.features.extractor import entropy_of_string
from sih26145.features.sketches import CountMinSketch, bucket_of, hll_add
from sih26145.features.store_state import (
    D_BYTES, D_FLOWS, D_REFL_BYTES, D_REFL_FLOWS, D_REFL_PKTS, D_SYN_ONLY, D_TCP, ENTRY_OVERHEAD,
    H_DNS_NX, H_DNS_Q, H_DNS_RESP, H_DNS_RESP_FLOWS, H_FLOWS, H_HIGH_ENT, H_QLEN, H_SYN_ONLY, H_TCP,
    HLL_DSTS, HLL_JA4, HLL_PERIODIC, HLL_PORTS, HLL_QNAMES, PAIR_OVERHEAD, REFLECTOR_PORTS, StoreConfig,
    _Dst, _Host, _LinkView, _lru_get, _Pair, _roll,
)
from sih26145.flow.models import FlowRecord
from sih26145.features.store_readers import READERS

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

        dst = self._dst(key.dst_ip, wid)
        dst.counts[0, [D_FLOWS, D_BYTES, D_TCP, D_SYN_ONLY]] += (1, flow.total_bytes, tcp, syn_only)
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
            if pair.n >= cfg.periodic_min_gaps and pair.mean > 0 and \
                    math.sqrt(pair.m2 / (pair.n - 1)) / pair.mean <= cfg.periodic_cv:
                hll_add(host.hll[0, HLL_PERIODIC], key.dst_ip)
        pair.last_start = flow.start_time if pair.last_start is None else max(pair.last_start, flow.start_time)
        self.pair_history.add(f"{key.src_ip}|{key.dst_ip}")
        self._reflection(flow, wid)
        self._decay(t)

    def _reflection(self, flow: FlowRecord, wid: int) -> None:
        """UDP from a reflector port toward an endpoint that sent nothing on that 5-tuple:
        the endpoint never asked, so the traffic is unsolicited (reflection/amplification)."""
        key = flow.flow_key
        if key.protocol != "UDP":
            return
        if key.src_port in REFLECTOR_PORTS:
            victim, victim_pkts, refl_pkts, refl_bytes = key.dst_ip, flow.rev_packets, flow.fwd_packets, flow.fwd_bytes
        elif key.dst_port in REFLECTOR_PORTS:
            victim, victim_pkts, refl_pkts, refl_bytes = key.src_ip, flow.fwd_packets, flow.rev_packets, flow.rev_bytes
        else:
            return
        if victim_pkts or not refl_pkts:
            return  # the endpoint initiated or answered on this 5-tuple: solicited
        dst = self._dst(victim, wid)
        dst.counts[0, [D_REFL_FLOWS, D_REFL_BYTES, D_REFL_PKTS]] += (1, refl_bytes, refl_pkts)

    def _dst(self, ip: str, wid: int) -> _Dst:
        cfg = self.cfg
        dst = _lru_get(self.dsts, ip, cfg.max_dsts, lambda: _Dst(cfg, wid))
        self._roll_dst(dst, wid)
        return dst

    def _roll_dst(self, dst: _Dst, wid: int) -> None:
        """Close finished windows into the destination's EWMA baseline, then roll."""
        if wid <= dst.wid:
            return
        a = self.cfg.ewma_alpha
        skipped = min(wid - dst.wid - 1, self.cfg.egress_buckets)  # silent windows count as zero
        for flows, nbytes in [tuple(dst.counts[0, [D_FLOWS, D_BYTES]])] + [(0.0, 0.0)] * skipped:
            if dst.base_n == 0:
                dst.base_flows, dst.base_bytes = flows, nbytes
            else:
                dst.base_flows += a * (flows - dst.base_flows)
                dst.base_bytes += a * (nbytes - dst.base_bytes)
            dst.base_n += 1
        _roll(dst, wid, dst.counts, dst.hll, dst.ent)

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
            if host.baseline_n == 0:
                host.mean, host.var = x, 0.0  # seed from the first closed minute
            else:
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
        if feature not in READERS:
            raise KeyError(f"{feature!r} is not served by the FeatureStore")
        return READERS[feature](self, key)

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
            self._roll_dst(dst, int(self.now // self.cfg.window))
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
        host = 2 * 9 * 8 + 2 * 5 * m + cfg.egress_buckets * 8 + ENTRY_OVERHEAD
        dst = 2 * 7 * 8 + 2 * m + 2 * cfg.entropy_buckets * 4 + m + ENTRY_OVERHEAD
        sketches = self.pair_history.nbytes + self.ja4_seen.nbytes + self.link.nbytes
        return cfg.max_hosts * host + cfg.max_dsts * dst + cfg.max_pairs * PAIR_OVERHEAD + sketches
