"""The seven rule detectors, PS (a)-(f). Every feature read is declared in
feature_contract.toml (tests/contract scans this module). Thresholds are hand-set, not tuned."""

from typing import Optional

from sih26145.contract import UnavailableFeatureError, load_contract
from sih26145.features.models import FeatureVector
from sih26145.detectors.models import RuleHit
from sih26145.detectors.rules.base import BaseRuleDetector
from sih26145.detectors.lists import in_networks, list_path, load_list, load_networks


def _threshold(value, baseline):
    return {"value": value, "baseline": baseline, "baseline_source": "rule_threshold"}


class DDoSVolumeDetector(BaseRuleDetector):
    """PS (a): many sources SYN-flooding one destination, UDP reflection/amplification toward
    one destination, or a few sources pushing a destination far above its own baseline."""
    name = "ddos_volume_detector"
    threat_class = "THREAT_DDOS_VOLUME"
    MIN_SRCS, MIN_SRC_ENTROPY, MIN_SYN_ONLY = 100, 5.0, 0.8
    MIN_REFL_FLOWS, MIN_REFL_MEAN_PKT, MIN_REFL_BYTES = 50, 400.0, 1_000_000
    BASELINE_MULT, MAX_FEW_SRCS, MIN_FLOOD_BYTES, MIN_FLOOD_FLOWS = 10.0, 10, 10_000_000, 100

    def detect(self, fv: FeatureVector, ctx=None) -> Optional[RuleHit]:
        if ctx is None:
            return None
        return self._syn_flood(ctx) or self._reflection(ctx) or self._volume(ctx)

    def _syn_flood(self, ctx) -> Optional[RuleHit]:
        srcs = ctx.store_feature("dst_distinct_srcs_w", ctx.dst)
        entropy = ctx.store_feature("dst_src_ip_entropy_w", ctx.dst)
        syn_only = ctx.store_feature("dst_syn_only_ratio_w", ctx.dst)
        if srcs < self.MIN_SRCS or entropy < self.MIN_SRC_ENTROPY or syn_only is None or syn_only < self.MIN_SYN_ONLY:
            return None
        return self._hit("RULE_DDOS_SYN_FLOOD", "CRITICAL", 0.9, ctx.dst, {
            "dst_distinct_srcs_w": _threshold(srcs, self.MIN_SRCS),
            "dst_src_ip_entropy_w": _threshold(entropy, self.MIN_SRC_ENTROPY),
            "dst_syn_only_ratio_w": _threshold(syn_only, self.MIN_SYN_ONLY)})

    def _reflection(self, ctx) -> Optional[RuleHit]:
        # The victim is whichever endpoint received from the reflector port.
        for victim in (ctx.dst, ctx.src):
            flows = ctx.store_feature("dst_reflector_flows_w", victim)
            mean_pkt = ctx.store_feature("dst_reflector_mean_pkt_w", victim)
            nbytes = ctx.store_feature("dst_reflector_bytes_w", victim)
            if flows >= self.MIN_REFL_FLOWS and mean_pkt and mean_pkt >= self.MIN_REFL_MEAN_PKT \
                    and nbytes >= self.MIN_REFL_BYTES:
                return self._hit("RULE_DDOS_UDP_REFLECTION", "CRITICAL", 0.9, victim, {
                    "dst_reflector_flows_w": _threshold(flows, self.MIN_REFL_FLOWS),
                    "dst_reflector_mean_pkt_w": _threshold(mean_pkt, self.MIN_REFL_MEAN_PKT),
                    "dst_reflector_bytes_w": _threshold(nbytes, self.MIN_REFL_BYTES)})
        return None

    def _volume(self, ctx) -> Optional[RuleHit]:
        by_bytes = ctx.store_feature("dst_bytes_vs_baseline", ctx.dst)
        by_flows = ctx.store_feature("dst_flows_vs_baseline", ctx.dst)
        if by_bytes is None or max(by_bytes, by_flows) < self.BASELINE_MULT:
            return None  # still warming up, or within the destination's normal range
        nbytes = ctx.store_feature("dst_bytes_w", ctx.dst)
        flows = ctx.store_feature("dst_flows_w", ctx.dst)
        srcs = ctx.store_feature("dst_distinct_srcs_w", ctx.dst)
        if srcs > self.MAX_FEW_SRCS or (nbytes < self.MIN_FLOOD_BYTES and flows < self.MIN_FLOOD_FLOWS):
            return None  # many sources = a crowd; the SYN and reflection rules cover floods
        return self._hit("RULE_DDOS_VOLUME_BASELINE", "HIGH", 0.8, ctx.dst, {
            "dst_bytes_vs_baseline": {"value": by_bytes, "baseline": 1.0, "baseline_source": "dst_ewma"},
            "dst_flows_vs_baseline": {"value": by_flows, "baseline": 1.0, "baseline_source": "dst_ewma"},
            "dst_bytes_w": nbytes, "dst_flows_w": flows, "dst_distinct_srcs_w": srcs})

    def _hit(self, rule_id, severity, confidence, entity, evidence) -> RuleHit:
        return RuleHit(self.name, self.threat_class, rule_id, severity, confidence, evidence, entity=entity)


class C2BeaconDetector(BaseRuleDetector):
    """PS (b): separate connections from one host to one peer at a regular interval."""
    name = "c2_beacon_detector"
    threat_class = "THREAT_C2_BEACON"
    # MIN_PERIOD: flow starts less than a second apart at a fixed rate are a rate-limited tool
    # (scanner, retry loop), not a check-in; beacons sleep for seconds to hours.
    MIN_GAPS, MAX_CV, MIN_PERIOD, POLLER_PERIODIC_DSTS = 8, 0.35, 1.0, 10

    def __init__(self):
        self.allowlist = load_networks(list_path("SIH26145_POLLER_ALLOWLIST", "poller_allowlist.txt"))

    def detect(self, fv: FeatureVector, ctx=None) -> Optional[RuleHit]:
        if ctx is None:
            return None
        n = ctx.store_feature("pair_iat_n", ctx.pair)
        cv = ctx.store_feature("pair_iat_cv", ctx.pair)
        if n < self.MIN_GAPS or cv is None or cv > self.MAX_CV or in_networks(ctx.src, self.allowlist):
            return None
        period = ctx.store_feature("pair_iat_mean", ctx.pair)
        if period < self.MIN_PERIOD:
            return None
        # A poller contacts dozens of peers on a schedule; a beacon has one or two.
        periodic = ctx.store_feature("src_periodic_dsts_w", ctx.src)
        if periodic >= self.POLLER_PERIODIC_DSTS:
            return None
        return RuleHit(self.name, self.threat_class, "RULE_C2_PERIODIC_FLOWS", "HIGH", 0.8, {
            "pair_iat_cv": _threshold(cv, self.MAX_CV), "pair_iat_n": n,
            "pair_iat_mean": _threshold(period, self.MIN_PERIOD),
            "src_periodic_dsts_w": _threshold(periodic, self.POLLER_PERIODIC_DSTS)},
            entity=f"{ctx.src}>{ctx.dst}")


class DGALexicalDetector(BaseRuleDetector):
    """PS (c): one host asking for many distinct high-entropy names; NXDOMAIN rate when the
    resolver's answers were captured."""
    name = "dga_lexical_detector"
    threat_class = "THREAT_DNS_DGA"
    MIN_HIGH_ENTROPY_QNAMES, MIN_NXDOMAIN_RATE = 20, 0.5

    def detect(self, fv: FeatureVector, ctx=None) -> Optional[RuleHit]:
        if ctx is None or not fv.dns_query_count:
            return None
        host = ctx.dns_client()
        high = ctx.store_feature("src_high_entropy_qnames_w", host)
        distinct = ctx.store_feature("src_distinct_qnames_w", host)
        if high < self.MIN_HIGH_ENTROPY_QNAMES or distinct < self.MIN_HIGH_ENTROPY_QNAMES:
            return None
        evidence = {"src_high_entropy_qnames_w": _threshold(high, self.MIN_HIGH_ENTROPY_QNAMES),
                    "src_distinct_qnames_w": distinct}
        try:
            nx = ctx.store_feature("src_nxdomain_rate_w", host)
        except UnavailableFeatureError:
            return RuleHit(self.name, self.threat_class, "RULE_DGA_HIGH_ENTROPY_QNAMES", "MEDIUM", 0.6, evidence,
                           substitutions=({"unavailable_on_this_flow": "src_nxdomain_rate_w",
                                           "reason": "no resolver responses captured for this host in the window",
                                           "substituted_by": ["src_high_entropy_qnames_w", "src_distinct_qnames_w"]},),
                           entity=host)
        if nx is None or nx < self.MIN_NXDOMAIN_RATE:
            return None  # the names resolve: CDN-style hostnames, not a DGA
        evidence["src_nxdomain_rate_w"] = _threshold(nx, self.MIN_NXDOMAIN_RATE)
        return RuleHit(self.name, self.threat_class, "RULE_DGA_NXDOMAIN_HIGH_ENTROPY", "HIGH", 0.9, evidence,
                       entity=host)


class DNSTunnelDetector(BaseRuleDetector):
    """PS (c): sustained query volume with long names from one host."""
    name = "dns_tunnel_detector"
    threat_class = "THREAT_DNS_TUNNEL"
    MIN_QUERIES, MIN_MEAN_QNAME_LEN = 50, 40.0

    def detect(self, fv: FeatureVector, ctx=None) -> Optional[RuleHit]:
        if ctx is None or not fv.dns_query_count:
            return None
        host = ctx.dns_client()
        queries = ctx.store_feature("src_dns_queries_w", host)
        if queries < self.MIN_QUERIES:
            return None
        mean_len = ctx.store_feature("src_qname_len_sum_w", host) / queries
        if mean_len < self.MIN_MEAN_QNAME_LEN:
            return None
        return RuleHit(self.name, self.threat_class, "RULE_DNS_TUNNEL_VOLUME_LENGTH", "HIGH", 0.85, {
            "src_dns_queries_w": _threshold(queries, self.MIN_QUERIES),
            "mean_qname_len": _threshold(round(mean_len, 1), self.MIN_MEAN_QNAME_LEN)}, entity=host)


class EncryptedAnomalyDetector(BaseRuleDetector):
    """PS (d), from cleartext handshake metadata only: a known-bad JA4, or a JA4 seen almost
    nowhere but this pair, used for repeated small, short sessions."""
    name = "encrypted_anomaly_detector"
    threat_class = "THREAT_ENCRYPTED_ANOMALY"
    MAX_FOREIGN_SIGHTINGS, MIN_PAIR_FLOWS, MAX_BYTES, MAX_DURATION = 2, 5, 8192, 10.0

    def __init__(self):
        self.known_bad = load_list(list_path("SIH26145_JA4_KNOWN_BAD", "ja4_known_bad.txt"))

    def detect(self, fv: FeatureVector, ctx=None) -> Optional[RuleHit]:
        ja4 = ctx.flow_feature("tls_ja4") if ctx is not None else None
        if not ja4:
            return None
        entity = f"{ctx.src}>{ctx.dst}"
        if ja4 in self.known_bad:
            return RuleHit(self.name, self.threat_class, "RULE_TLS_KNOWN_BAD_JA4", "HIGH", 0.95,
                           {"tls_ja4": ja4}, entity=entity)
        prevalence = ctx.store_feature("ja4_prevalence", ja4)
        on_pair = ctx.store_feature("pair_history_count", ctx.pair)
        if prevalence - on_pair > self.MAX_FOREIGN_SIGHTINGS:
            return None  # the fingerprint is common elsewhere in the enclave
        flows = ctx.store_feature("pair_flows_w", ctx.pair)
        if flows < self.MIN_PAIR_FLOWS or fv.total_bytes > self.MAX_BYTES or fv.duration > self.MAX_DURATION:
            return None
        return RuleHit(self.name, self.threat_class, "RULE_TLS_RARE_JA4_REPEATED", "MEDIUM", 0.65, {
            "tls_ja4": ja4, "ja4_prevalence": prevalence, "pair_history_count": on_pair,
            "pair_flows_w": _threshold(flows, self.MIN_PAIR_FLOWS),
            "total_bytes": _threshold(fv.total_bytes, self.MAX_BYTES),
            "duration": _threshold(fv.duration, self.MAX_DURATION)}, entity=entity)


class ReconPortScanDetector(BaseRuleDetector):
    """PS (e): one source touching many hosts or ports, mostly with unanswered SYNs."""
    name = "recon_portscan_detector"
    threat_class = "THREAT_RECON_PORTSCAN"
    MIN_FANOUT, MIN_SYN_ONLY, SHARED_INFRA_SRCS = 20, 0.6, 20

    def detect(self, fv: FeatureVector, ctx=None) -> Optional[RuleHit]:
        if ctx is None or not fv.is_tcp:
            return None
        dsts = ctx.store_feature("src_distinct_dsts_w", ctx.src)
        ports = ctx.store_feature("src_distinct_dst_ports_w", ctx.src)
        if max(dsts, ports) < self.MIN_FANOUT:
            return None
        syn_only = ctx.store_feature("src_syn_only_ratio_w", ctx.src)
        if syn_only is None or syn_only < self.MIN_SYN_ONLY:
            return None
        # ponytail: shared infrastructure is skipped per flow, not subtracted from the HLL
        # fan-out; a separate HLL of non-shared destinations would do that if it matters.
        if ctx.store_feature("dst_distinct_srcs_w", ctx.dst) >= self.SHARED_INFRA_SRCS:
            return None
        return RuleHit(self.name, self.threat_class, "RULE_RECON_FANOUT_SYN_ONLY", "MEDIUM", 0.8, {
            "src_distinct_dsts_w": _threshold(dsts, self.MIN_FANOUT),
            "src_distinct_dst_ports_w": _threshold(ports, self.MIN_FANOUT),
            "src_syn_only_ratio_w": _threshold(syn_only, self.MIN_SYN_ONLY)}, entity=ctx.src)


class ExfiltrationDetector(BaseRuleDetector):
    """PS (f): data leaving the enclave.

    Uses the outbound/inbound byte ratio when this flow captured both halves. When it did
    not, the ratio is unavailable (never estimated) and the detector substitutes the host's
    egress baseline, destination rarity and off-hours, and says so on the alert.
    """
    name = "exfiltration_detector"
    threat_class = "THREAT_EXFILTRATION"
    MIN_OUTBOUND_BYTES = 1_000_000
    MIN_RATIO = 10.0
    MIN_EGRESS_Z = 3.0
    MAX_DST_SOURCES = 2  # "rare": at most this many internal hosts have ever talked to it

    def detect(self, fv: FeatureVector, ctx=None) -> Optional[RuleHit]:
        if ctx is None:
            return None  # no direction policy, no notion of "leaving"
        egress = ctx.flow_feature("egress_bytes")
        if not egress:
            return None
        try:
            ratio = ctx.flow_feature("outbound_inbound_byte_ratio")
        except UnavailableFeatureError:
            return self._egress_baseline_path(ctx, egress)
        if ratio is None or egress < self.MIN_OUTBOUND_BYTES or ratio < self.MIN_RATIO:
            return None
        return RuleHit(
            detector_name=self.name,
            threat_class=self.threat_class,
            rule_id="RULE_EXFIL_OUTBOUND_RATIO",
            severity="HIGH",
            confidence=0.85,
            evidence={
                "outbound_inbound_byte_ratio": {"value": ratio, "baseline": self.MIN_RATIO,
                                                "baseline_source": "rule_threshold"},
                "egress_bytes": egress,
            },
        )

    def _egress_baseline_path(self, ctx, egress: int) -> Optional[RuleHit]:
        host, external = ctx.internal_and_external()
        z = ctx.store_feature("src_egress_bytes_z", host)
        sources = ctx.store_feature("dst_distinct_srcs_longterm", external)
        off = ctx.store_feature("off_hours", ctx.flow.last_time)
        if z is None or z < self.MIN_EGRESS_Z or round(sources) > self.MAX_DST_SOURCES:
            return None
        return RuleHit(
            detector_name=self.name,
            threat_class=self.threat_class,
            rule_id="RULE_EXFIL_EGRESS_BASELINE",
            severity="HIGH" if off else "MEDIUM",
            confidence=0.85 if off else 0.75,
            evidence={
                "src_egress_bytes_z": {"value": z, "baseline": 0.0, "baseline_source": "host_ewma"},
                "dst_distinct_srcs_longterm": sources,
                "off_hours": off,
                "egress_bytes": egress,
            },
            substitutions=({
                "unavailable_on_this_flow": "outbound_inbound_byte_ratio",
                "reason": f"reverse direction not observed on this flow ({ctx.flow.observability_state})",
                "substituted_by": list(load_contract().feature("outbound_inbound_byte_ratio").substitutes),
            },),
        )
