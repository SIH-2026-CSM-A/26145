"""Campaign correlation and observed host stage (alert v2 `campaign_id`, `host_stage`).

Pivots of an alert, taken from its flow: `host:` the internal endpoint, `dst:` the other endpoint,
`ja4:` TLS client fingerprints, `name:` DNS query names and TLS SNI, `port:` the destination port
class (models.features.dst_port_class).

Rarity is inverse document frequency over the pivot sets of the last N = WINDOW alerts:
    idf(p) = ln((N + PRIOR) / (df(p) + 1)),  rare  <=>  idf(p) >= IDF_MIN = ln(10)
PRIOR = 1000 pseudo-alerts stand in for a full window, so a pivot is common when it appears in
roughly 10% or more of recent alerts (at least ~100 of them). The prior keeps a
host with most of a small demo's alerts from counting as common just because few alerts exist.

Join rule: an alert joins the live campaign it shares the most rare pivots with, if it shares at
least 2 rare pivots, or 1 rare pivot and the campaign's last alert is at most PROXIMITY_S earlier
in event time. The port class supports a join but is never the only rare pivot. Ties go to the
older campaign. Campaigns never merge with each other.

Common infrastructure never merges: an IP pivot is refused when it is a shared resolver (port-53
destination with >= RESOLVER_FAN_IN distinct sources ever seen) or among the TOP_K destinations by
fan-in seen in alerts (fan-in >= MIN_TOP_FAN_IN). A refused destination takes its port class with
it. A join that only the refused pivot would have made is recorded on the alert
(detection.correlation.not_merged, e.g. "shared resolver 10.0.0.53").

host_stage is the MITRE ATT&CK tactic of the alert's class: observed history only. Nothing
predicts a next stage. Deterministic for a given alert order; memory is bounded by WINDOW,
MAX_CAMPAIGNS and MAX_FAN_IN.
"""

import hashlib
import math
from collections import Counter, OrderedDict, deque
from typing import Dict, List, Optional

from sih26145.models.features import dst_port_class

WINDOW, PRIOR, IDF_MIN = 1000, 1000, math.log(10)
PROXIMITY_S = 900.0
RESOLVER_FAN_IN, TOP_K, MIN_TOP_FAN_IN = 5, 10, 5
MAX_CAMPAIGNS, MAX_FAN_IN, MAX_PIVOTS = 512, 4096, 64

# ATT&CK tactic per threat class (enterprise matrix). DDoS names the internal host as the target.
TACTICS = {
    "THREAT_RECON_PORTSCAN": ("TA0007", "Discovery"),
    "THREAT_C2_BEACON": ("TA0011", "Command and Control"),
    "THREAT_DNS_DGA": ("TA0011", "Command and Control"),
    "THREAT_DNS_TUNNEL": ("TA0011", "Command and Control"),
    "THREAT_ENCRYPTED_ANOMALY": ("TA0011", "Command and Control"),
    "THREAT_EXFILTRATION": ("TA0010", "Exfiltration"),
    "THREAT_DDOS_VOLUME": ("TA0040", "Impact"),
}
UNCLASSIFIED = ("unclassified", "Unclassified")


def tactic(threat_class: str):
    return TACTICS.get(threat_class, UNCLASSIFIED)


class _Campaign:
    __slots__ = ("cid", "order", "last_t", "pivots")

    def __init__(self, cid: str, order: int, t: float):
        self.cid, self.order, self.last_t, self.pivots = cid, order, t, set()


class Correlator:
    def __init__(self):
        self.window: deque = deque()
        self.df: Counter = Counter()
        self.campaigns: "OrderedDict[str, _Campaign]" = OrderedDict()
        self.index: Dict[str, set] = {}  # pivot -> campaign ids
        self.fan_in: "OrderedDict[str, float]" = OrderedDict()
        self._top: set = set()
        self._since_top = 0
        self._order = 0

    # ---- pivots ------------------------------------------------------------------------------
    def _pivots(self, ctx) -> Dict[str, str]:
        """pivot -> kind ('ip', 'port', 'other'); records destination fan-in as a side effect."""
        flow, key = ctx.flow, ctx.flow.flow_key
        src_in, dst_in = ctx.policy.is_internal(key.src_ip), ctx.policy.is_internal(key.dst_ip)
        host, other = (key.src_ip, key.dst_ip) if src_in or not dst_in else (key.dst_ip, key.src_ip)
        if src_in and dst_in and self._common(key.src_ip, ctx) and not self._common(key.dst_ip, ctx):
            host, other = key.dst_ip, key.src_ip  # e.g. a resolver's answer: the client is the host
        piv = {f"host:{host}": "ip", f"dst:{other}": "ip",
               f"port:{key.protocol}/{int(dst_port_class(key.dst_port, key.protocol))}": "port"}
        for j in flow.tls_ja4:
            piv[f"ja4:{j}"] = "other"
        for n in list(flow.dns_queries) + list(flow.tls_snis):
            piv[f"name:{n.lower().rstrip('.')}"] = "other"
        return piv

    def _observe_fan_in(self, ip: str, ctx) -> float:
        n = ctx.store_feature("dst_distinct_srcs_longterm", ip)
        self.fan_in[ip] = n
        self.fan_in.move_to_end(ip)
        if len(self.fan_in) > MAX_FAN_IN:
            self.fan_in.popitem(last=False)
        self._since_top += 1
        if self._since_top >= 256 or not self._top:
            # ponytail: top-k refreshed every 256 observations, not per flow
            self._top = {k for k, v in sorted(self.fan_in.items(), key=lambda kv: (-kv[1], kv[0]))[:TOP_K]
                         if v >= MIN_TOP_FAN_IN}
            self._since_top = 0
        return n

    def _common(self, ip: str, ctx) -> Optional[str]:
        """Reason an IP is common infrastructure, or None."""
        n = self._observe_fan_in(ip, ctx)
        key = ctx.flow.flow_key
        if ip == key.dst_ip and key.dst_port == 53 and n >= RESOLVER_FAN_IN:
            return f"shared resolver {ip}"
        if n >= MIN_TOP_FAN_IN and ip in self._top:
            return f"high fan-in destination {ip} ({round(n)} sources)"
        return None

    def _rare(self, p: str) -> bool:
        return math.log((len(self.window) + PRIOR) / (self.df[p] + 1)) >= IDF_MIN

    # ---- assignment --------------------------------------------------------------------------
    def observe(self, ctx):
        """Pivots and refusals of one flow, read at the flow's own scoring time (right after its
        store update), so the result does not depend on how flows were batched."""
        piv = self._pivots(ctx)
        refused: Dict[str, str] = {}
        for p, kind in piv.items():
            if kind == "ip":
                why = self._common(p.split(":", 1)[1], ctx)
                if why:
                    refused[p] = why
        dst_why = next((why for p, why in refused.items() if p.startswith("dst:")), None)
        if dst_why:  # the refused server's port class describes the same server
            refused.update({p: dst_why for p, k in piv.items() if k == "port"})
        return piv, refused, ctx.flow.last_time

    def assign(self, alerts: List, prepared) -> None:
        """Set campaign_id, host_stage and detection['correlation'] on each alert of one flow."""
        for alert in alerts:
            self._assign(alert, *prepared)

    def _assign(self, alert, piv: Dict[str, str], refused: Dict[str, str], t: float) -> None:
        rare = {p for p in piv if self._rare(p)}

        best, notes = None, []
        for cid in sorted({c for p in rare for c in self.index.get(p, ())},
                          key=lambda c: self.campaigns[c].order):
            camp = self.campaigns[cid]
            shared = rare & camp.pivots
            usable = {p for p in shared if p not in refused}
            if self._joins(usable, piv, camp, t):
                if best is None or len(usable) > len(best[1]):
                    best = (camp, usable)
            elif self._joins(shared, piv, camp, t) and len(notes) < 3:
                notes.append({"campaign_id": cid, "reason": "not merged: " + "; ".join(
                    sorted({refused[p] for p in shared if p in refused}))})

        if best is None:
            camp = self._new_campaign(alert, t)
            joined_on: List[str] = []
        else:
            camp, joined_on = best[0], sorted(best[1])
            self.campaigns.move_to_end(camp.cid)
        camp.last_t = max(camp.last_t, t)
        for p in piv:  # refused pivots are kept too, so a refused merge can be reported later
            if len(camp.pivots) < MAX_PIVOTS:
                camp.pivots.add(p)
                self.index.setdefault(p, set()).add(camp.cid)
        self._remember(piv)

        tid, tname = tactic(alert.threat_class)
        host = next(p for p in piv if p.startswith("host:")).split(":", 1)[1]
        alert.campaign_id = camp.cid
        alert.host_stage = tid
        alert.detection["correlation"] = {
            "campaign_id": camp.cid, "host": host, "tactic": tname, "joined_on": joined_on,
            "not_merged": notes, "refused_pivots": sorted(refused)}

    @staticmethod
    def _joins(shared: set, piv: Dict[str, str], camp: _Campaign, t: float) -> bool:
        strong = [p for p in shared if piv[p] != "port"]
        if not strong:
            return False  # a port class alone never joins
        return len(shared) >= 2 or abs(t - camp.last_t) <= PROXIMITY_S

    def _new_campaign(self, alert, t: float) -> _Campaign:
        seed = f"{alert.flow_id}|{alert.timestamp}|{alert.threat_class}".encode()
        cid = "camp-" + hashlib.sha256(seed).hexdigest()[:12]
        camp = self.campaigns.get(cid) or _Campaign(cid, self._order, t)
        self._order += 1
        self.campaigns[cid] = camp
        if len(self.campaigns) > MAX_CAMPAIGNS:
            _, old = self.campaigns.popitem(last=False)
            for p in old.pivots:
                ids = self.index.get(p)
                if ids is not None:
                    ids.discard(old.cid)
                    if not ids:
                        del self.index[p]
        return camp

    def _remember(self, piv: Dict[str, str]) -> None:
        self.window.append(tuple(piv))
        self.df.update(list(piv))  # a dict would add its values, not count its keys
        if len(self.window) > WINDOW:
            old = self.window.popleft()
            self.df.subtract(old)
            for p in old:
                if self.df[p] <= 0:
                    del self.df[p]
