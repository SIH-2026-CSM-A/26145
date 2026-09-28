"""Fast lane: 1-second packet counters ahead of flow assembly, for floods (a) and scans (e).

The flow lane scores a flow when it closes (15 s idle, 60 s active), so a flood or a scan is
reported tens of seconds after it starts. The fast lane counts packets as they are parsed, in
tumbling 1-s windows of event time, per destination and per source. When a window closes, the
detector below reads its counters and may raise a hit. The orchestrator turns a hit into a
**provisional** alert, and the flow-lane alert for the same entity later confirms it.

What is counted, per window:
- toward a destination: packets, SYNs (SYN without ACK), the distinct sources that sent SYNs and
  how many of them also sent an ACK-bearing packet (a completed handshake), SYN-source entropy,
  the TTL spread of the SYNs, and unsolicited UDP from REFLECTOR_PORTS (distinct reflectors,
  bytes, packets);
- from a source: distinct (destination, port) SYN targets and how many it ACKed, and its
  distinct destination hosts and ports.

Per-packet cost is the s12 throughput budget, so the common path is one dict lookup. Tables
are created only by a SYN or a reflector-port UDP packet. Distinct counts are exact sets capped
at SET_CAP members (they saturate there; the rules only need "at least N"). HLL was not used:
a blake2b hash per packet costs about the whole 5% budget.
"""

import math
from typing import Dict, List, Optional, Tuple

from sih26145.detectors.models import RuleHit
from sih26145.features.store_state import REFLECTOR_PORTS

SYN, ACK = 0x02, 0x10
WINDOW_S = 1.0
SET_CAP = 4096      # members kept per distinct-count set; the count saturates here
MAX_KEYS = 65536    # entities per table per window; more are counted in `overflow`, not tracked
LANE = "fast lane, 1-s window"


class _Dst:
    __slots__ = ("pkts", "syns", "syn_srcs", "acked", "ttl_min", "ttl_max", "refl")

    def __init__(self):
        self.pkts = self.syns = 0
        self.syn_srcs: Dict[str, list] = {}   # src -> [SYN count, sport, dport]
        self.acked = set()                    # SYN sources that also sent an ACK-bearing packet
        self.ttl_min, self.ttl_max = 255, 0
        self.refl: Dict[str, list] = {}       # reflector -> [packets, sport, dport, bytes]


class _Src:
    __slots__ = ("targets", "acked", "dsts", "ports")

    def __init__(self):
        self.targets: Dict[tuple, int] = {}   # (dst, dport) -> SYN count
        self.acked = set()
        self.dsts, self.ports = set(), set()


class Window:
    """One closed 1-s window. Features are read through store_feature(name, key) with a literal
    name, like the flow lane's detectors, so tests/contract scans them the same way."""

    def __init__(self, start: float, dsts: Dict[str, _Dst], srcs: Dict[str, _Src], queried: set):
        self.start, self.dsts, self.srcs, self.queried = start, dsts, srcs, queried

    def _unsolicited(self, dst: str, d: _Dst) -> Dict[str, list]:
        return {r: v for r, v in d.refl.items() if (dst, r) not in self.queried}

    def store_feature(self, name: str, key: str):
        d, s = self.dsts.get(key), self.srcs.get(key)
        if name == "fl_dst_packets_1s":
            return d.pkts
        if name == "fl_dst_syns_1s":
            return d.syns
        if name == "fl_dst_syn_srcs_1s":
            return len(d.syn_srcs)
        if name == "fl_dst_syn_only_share_1s":
            return 1.0 - len(d.acked) / len(d.syn_srcs) if d.syn_srcs else None
        if name == "fl_dst_src_entropy_1s":
            return _entropy([v[0] for v in d.syn_srcs.values()])
        if name == "fl_dst_ttl_spread_1s":
            return d.ttl_max - d.ttl_min if d.syns else None
        if name == "fl_dst_refl_srcs_1s":
            return len(self._unsolicited(key, d))
        if name == "fl_dst_refl_bytes_1s":
            return sum(v[3] for v in self._unsolicited(key, d).values())
        if name == "fl_dst_refl_mean_pkt_1s":
            rows = self._unsolicited(key, d).values()
            n = sum(v[0] for v in rows)
            return sum(v[3] for v in rows) / n if n else None
        if name == "fl_src_syn_targets_1s":
            return len(s.targets)
        if name == "fl_src_syn_only_share_1s":
            return 1.0 - len(s.acked) / len(s.targets) if s.targets else None
        if name == "fl_src_distinct_dsts_1s":
            return len(s.dsts)
        if name == "fl_src_distinct_ports_1s":
            return len(s.ports)
        raise KeyError(name)

    def packets(self, scope: str, key: str) -> int:
        """Packets toward the destination, or SYNs sent by the source, in this window."""
        return self.dsts[key].pkts if scope == "dst" else sum(self.srcs[key].targets.values())

    def contributing(self, scope: str, key: str, n: int = 5) -> List[Tuple]:
        """(proto, src, dst, sport, dport) of the top-n contributing 5-tuples by packets."""
        if scope == "dst":
            d = self.dsts[key]
            rows = [(v[0], "TCP", src, key, v[1], v[2]) for src, v in d.syn_srcs.items()]
            rows += [(v[0], "UDP", r, key, v[1], v[2]) for r, v in self._unsolicited(key, d).items()]
        else:
            rows = [(c, "TCP", key, dst, 0, port) for (dst, port), c in self.srcs[key].targets.items()]
        rows.sort(key=lambda r: -r[0])
        return [r[1:] for r in rows[:n]]


def _entropy(counts) -> Optional[float]:
    total = sum(counts)
    if not total:
        return None
    return -sum(c / total * math.log2(c / total) for c in counts if c)


def _threshold(value, baseline):
    return {"value": value, "baseline": baseline, "baseline_source": "rule_threshold"}


class FastLaneDetector:
    """Rules over one closed window. Thresholds are per second, set before any capture was run
    through the fast lane (docs/ARCHITECTURE.md §9a); the flow lane keeps its own."""
    name = "fastlane_detector"
    MIN_SYN_SRCS, MIN_SYN_ONLY = 50, 0.8
    MIN_REFL_SRCS, MIN_REFL_MEAN_PKT, MIN_REFL_BYTES = 20, 400.0, 500_000
    MIN_SCAN_TARGETS, MIN_SCAN_SYN_ONLY = 20, 0.8

    def detect(self, win: Window) -> List[Tuple[str, RuleHit]]:
        """[(scope, hit)] for every destination and source in the window that crosses a rule."""
        out = []
        for dst in win.dsts:
            srcs = win.store_feature("fl_dst_syn_srcs_1s", dst)
            share = win.store_feature("fl_dst_syn_only_share_1s", dst)
            if srcs >= self.MIN_SYN_SRCS and share is not None and share >= self.MIN_SYN_ONLY:
                out.append(("dst", self._hit("RULE_FAST_SYN_FLOOD", "THREAT_DDOS_VOLUME", "HIGH", 0.7, dst, {
                    "fl_dst_syn_srcs_1s": _threshold(srcs, self.MIN_SYN_SRCS),
                    "fl_dst_syn_only_share_1s": _threshold(share, self.MIN_SYN_ONLY),
                    "fl_dst_syns_1s": win.store_feature("fl_dst_syns_1s", dst),
                    "fl_dst_packets_1s": win.store_feature("fl_dst_packets_1s", dst),
                    "fl_dst_src_entropy_1s": win.store_feature("fl_dst_src_entropy_1s", dst),
                    "fl_dst_ttl_spread_1s": win.store_feature("fl_dst_ttl_spread_1s", dst)})))
            refl = win.store_feature("fl_dst_refl_srcs_1s", dst)
            if refl >= self.MIN_REFL_SRCS:
                mean = win.store_feature("fl_dst_refl_mean_pkt_1s", dst)
                nbytes = win.store_feature("fl_dst_refl_bytes_1s", dst)
                if mean >= self.MIN_REFL_MEAN_PKT and nbytes >= self.MIN_REFL_BYTES:
                    out.append(("dst", self._hit("RULE_FAST_UDP_REFLECTION", "THREAT_DDOS_VOLUME", "HIGH", 0.7, dst, {
                        "fl_dst_refl_srcs_1s": _threshold(refl, self.MIN_REFL_SRCS),
                        "fl_dst_refl_mean_pkt_1s": _threshold(mean, self.MIN_REFL_MEAN_PKT),
                        "fl_dst_refl_bytes_1s": _threshold(nbytes, self.MIN_REFL_BYTES),
                        "fl_dst_packets_1s": win.store_feature("fl_dst_packets_1s", dst)})))
        for src in win.srcs:
            targets = win.store_feature("fl_src_syn_targets_1s", src)
            share = win.store_feature("fl_src_syn_only_share_1s", src)
            if targets >= self.MIN_SCAN_TARGETS and share is not None and share >= self.MIN_SCAN_SYN_ONLY:
                out.append(("src", self._hit("RULE_FAST_SCAN", "THREAT_RECON_PORTSCAN", "MEDIUM", 0.6, src, {
                    "fl_src_syn_targets_1s": _threshold(targets, self.MIN_SCAN_TARGETS),
                    "fl_src_syn_only_share_1s": _threshold(share, self.MIN_SCAN_SYN_ONLY),
                    "fl_src_distinct_dsts_1s": win.store_feature("fl_src_distinct_dsts_1s", src),
                    "fl_src_distinct_ports_1s": win.store_feature("fl_src_distinct_ports_1s", src)})))
        return out

    def _hit(self, rule_id, threat_class, severity, confidence, entity, evidence) -> RuleHit:
        return RuleHit(self.name, threat_class, rule_id, severity, confidence, evidence, entity=entity)


class FastLane:
    """Feeds packets into the current window; a packet of a later second closes it."""

    def __init__(self):
        self.detector = FastLaneDetector()
        self.overflow = 0          # entities not tracked because a table was full
        self.windows_closed = 0
        self._wid: Optional[int] = None
        self._prev_queried: set = set()
        self._reset()

    def _reset(self):
        self.dsts: Dict[str, _Dst] = {}
        self.srcs: Dict[str, _Src] = {}
        self.queried: set = set()  # (client, reflector) pairs that asked on a reflector port

    def observe(self, pkt) -> Optional[Tuple[Window, list]]:
        """Count one packet. Returns (closed window, hits) when this packet starts a new second."""
        wid = int(pkt.timestamp)
        # a packet stamped earlier than the open second (reordering) is counted in it
        closed = self._close(wid) if self._wid is None or wid > self._wid else None
        dst = pkt.dst_ip
        flags = pkt.tcp_flags
        d = self.dsts.get(dst)
        if d is not None:
            d.pkts += 1
        if flags is not None:
            src = pkt.src_ip
            if flags & SYN and not flags & ACK:
                if d is None:
                    d = self._new(self.dsts, dst, _Dst)
                    if d is None:
                        return closed
                    d.pkts = 1
                d.syns += 1
                row = d.syn_srcs.get(src)
                if row is not None:
                    row[0] += 1
                elif len(d.syn_srcs) < SET_CAP:
                    d.syn_srcs[src] = [1, pkt.src_port, pkt.dst_port]
                ttl = pkt.ttl or 0
                if ttl < d.ttl_min:
                    d.ttl_min = ttl
                if ttl > d.ttl_max:
                    d.ttl_max = ttl
                s = self.srcs.get(src) or self._new(self.srcs, src, _Src)
                if s is not None:
                    target = (dst, pkt.dst_port)
                    if target in s.targets:
                        s.targets[target] += 1
                    elif len(s.targets) < SET_CAP:
                        s.targets[target] = 1
                        s.dsts.add(dst)
                        s.ports.add(pkt.dst_port)
            elif flags & ACK:
                if d is not None and src in d.syn_srcs:
                    d.acked.add(src)
                s = self.srcs.get(src)
                if s is not None and (dst, pkt.dst_port) in s.targets:
                    s.acked.add((dst, pkt.dst_port))
        elif pkt.protocol == "UDP":
            if pkt.src_port in REFLECTOR_PORTS:
                if d is None:
                    d = self._new(self.dsts, dst, _Dst)
                    if d is None:
                        return closed
                    d.pkts = 1
                src = pkt.src_ip
                row = d.refl.get(src)
                if row is not None:
                    row[0] += 1
                    row[3] += pkt.packet_len
                elif len(d.refl) < SET_CAP:
                    d.refl[src] = [1, pkt.src_port, pkt.dst_port, pkt.packet_len]
            if pkt.dst_port in REFLECTOR_PORTS and len(self.queried) < MAX_KEYS:
                self.queried.add((pkt.src_ip, dst))
        return closed

    def _new(self, table, key, factory):
        if len(table) >= MAX_KEYS:
            self.overflow += 1
            return None
        v = table[key] = factory()
        return v

    def _close(self, wid: Optional[int]) -> Optional[Tuple[Window, list]]:
        """Close the current window (wid=None: end of input) and start `wid`."""
        prev, self._wid = self._wid, wid
        if prev is None:
            return None
        win = Window(float(prev), self.dsts, self.srcs, self.queried | self._prev_queried)
        # a query in the previous second may be answered in this one
        self._prev_queried = self.queried if wid == prev + 1 else set()
        self._reset()
        self.windows_closed += 1
        return win, self.detector.detect(win)

    def expire(self, now: float) -> Optional[Tuple[Window, list]]:
        """Close the open window once `now` (replay clock) has passed its end with no packet."""
        if self._wid is not None and now >= self._wid + WINDOW_S:
            return self._close(int(now))
        return None

    def flush(self) -> Optional[Tuple[Window, list]]:
        """End of input: close the open window."""
        return self._close(None)
