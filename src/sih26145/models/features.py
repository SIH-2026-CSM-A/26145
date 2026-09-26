"""Model input rows, built once per flow at scoring time.

`model_row` feeds both the feature dump (training data) and the runtime models, so the rows a
model was trained on and the rows it scores come from the same code at the same moment: right
after the flow's FeatureStore update. Every read here is declared in feature_contract.toml
(consumer `feature_dump`); the models use the `ML_FEATURES` subset (consumer `ml_flow_models`).
"""

import dataclasses
import math
from typing import Any, Dict, List, Optional

import numpy as np

from sih26145.contract import UnavailableFeatureError

# Tier-1 flow fields and tier-2 behaviour features the models read. Excluded on purpose:
# IPs, exact ports and host identity (leakage); DNS/TLS/JA4 fields (the CTU-13-Extended
# training captures are header-only, so they are always zero there); off_hours (the capture's
# time of day); egress features (they depend on the deployment's internal-CIDR policy).
ML_FEATURES: List[str] = [
    "duration", "total_packets", "total_bytes", "pps", "bps",
    "pkt_size_min", "pkt_size_max", "pkt_size_mean", "pkt_size_std",
    "pkt_size_q25", "pkt_size_q50", "pkt_size_q75",
    "iat_mean", "iat_var", "iat_min", "iat_max", "jitter", "burstiness_ratio", "small_pkt_ratio",
    "is_tcp", "is_udp", "is_icmp", "has_syn", "has_fin", "has_rst", "dst_port_class", "reverse_seen",
    "src_flows_w", "src_distinct_dsts_w", "src_distinct_dst_ports_w", "src_syn_only_ratio_w",
    "src_periodic_dsts_w", "dst_flows_w", "dst_bytes_w", "dst_distinct_srcs_w", "dst_src_ip_entropy_w",
    "dst_syn_only_ratio_w", "dst_reflector_flows_w", "dst_reflector_bytes_w", "dst_reflector_mean_pkt_w",
    "dst_bytes_vs_baseline", "dst_flows_vs_baseline", "dst_distinct_srcs_longterm",
    "pair_flows_w", "pair_iat_mean", "pair_iat_cv", "pair_iat_n", "pair_history_count",
]


def dst_port_class(port: int, protocol: str) -> float:
    """Coarse service class instead of the exact port: 0 none (ICMP/other), 1 well-known
    (< 1024), 2 registered (1024-49151), 3 dynamic (>= 49152)."""
    if protocol not in ("TCP", "UDP"):
        return 0.0
    return 1.0 if port < 1024 else 2.0 if port < 49152 else 3.0


def _num(value: Any) -> float:
    """Store readers return None when a value is undefined (warm-up, < 2 gaps): NaN, never 0."""
    return math.nan if value is None else float(value)


def _reverse(read) -> float:
    try:
        return _num(read())
    except UnavailableFeatureError:
        return math.nan  # reverse half not observed: missing, never defaulted


def store_features(ctx) -> Dict[str, float]:
    """Every tier-2 and flow-context feature the detectors read, keyed as the detectors key it."""
    src, dst, pair, client = ctx.src, ctx.dst, ctx.pair, ctx.dns_client()
    ja4: Optional[str] = ctx.flow.tls_ja4[0] if ctx.flow.tls_ja4 else None
    return {
        "reverse_seen": _num(ctx.flow_feature("reverse_seen")),
        "egress_bytes": _num(ctx.flow_feature("egress_bytes")),
        "outbound_inbound_byte_ratio": _reverse(lambda: ctx.flow_feature("outbound_inbound_byte_ratio")),
        "off_hours": _num(ctx.store_feature("off_hours", ctx.flow.last_time)),
        "src_flows_w": _num(ctx.store_feature("src_flows_w", src)),
        "src_distinct_dsts_w": _num(ctx.store_feature("src_distinct_dsts_w", src)),
        "src_distinct_dst_ports_w": _num(ctx.store_feature("src_distinct_dst_ports_w", src)),
        "src_syn_only_ratio_w": _num(ctx.store_feature("src_syn_only_ratio_w", src)),
        "src_periodic_dsts_w": _num(ctx.store_feature("src_periodic_dsts_w", src)),
        "src_egress_bytes_z": _num(ctx.store_feature("src_egress_bytes_z", src)),
        "src_dns_queries_w": _num(ctx.store_feature("src_dns_queries_w", client)),
        "src_distinct_qnames_w": _num(ctx.store_feature("src_distinct_qnames_w", client)),
        "src_high_entropy_qnames_w": _num(ctx.store_feature("src_high_entropy_qnames_w", client)),
        "src_qname_len_sum_w": _num(ctx.store_feature("src_qname_len_sum_w", client)),
        "src_nxdomain_rate_w": _reverse(lambda: ctx.store_feature("src_nxdomain_rate_w", client)),
        "dst_flows_w": _num(ctx.store_feature("dst_flows_w", dst)),
        "dst_bytes_w": _num(ctx.store_feature("dst_bytes_w", dst)),
        "dst_distinct_srcs_w": _num(ctx.store_feature("dst_distinct_srcs_w", dst)),
        "dst_src_ip_entropy_w": _num(ctx.store_feature("dst_src_ip_entropy_w", dst)),
        "dst_syn_only_ratio_w": _num(ctx.store_feature("dst_syn_only_ratio_w", dst)),
        "dst_reflector_flows_w": _num(ctx.store_feature("dst_reflector_flows_w", dst)),
        "dst_reflector_bytes_w": _num(ctx.store_feature("dst_reflector_bytes_w", dst)),
        "dst_reflector_mean_pkt_w": _num(ctx.store_feature("dst_reflector_mean_pkt_w", dst)),
        "dst_bytes_vs_baseline": _num(ctx.store_feature("dst_bytes_vs_baseline", dst)),
        "dst_flows_vs_baseline": _num(ctx.store_feature("dst_flows_vs_baseline", dst)),
        "dst_distinct_srcs_longterm": _num(ctx.store_feature("dst_distinct_srcs_longterm", dst)),
        "pair_flows_w": _num(ctx.store_feature("pair_flows_w", pair)),
        "pair_iat_mean": _num(ctx.store_feature("pair_iat_mean", pair)),
        "pair_iat_cv": _num(ctx.store_feature("pair_iat_cv", pair)),
        "pair_iat_n": _num(ctx.store_feature("pair_iat_n", pair)),
        "pair_history_count": _num(ctx.store_feature("pair_history_count", pair)),
        "ja4_prevalence": _num(ctx.store_feature("ja4_prevalence", ja4)) if ja4 else math.nan,
    }


def model_row(fv, ctx) -> Dict[str, float]:
    """The whole FeatureVector, the port class, and every store feature, as floats."""
    row = {k: float(v) for k, v in dataclasses.asdict(fv).items() if k != "flow_key_str"}
    row["dst_port_class"] = dst_port_class(fv.dst_port, ctx.flow.flow_key.protocol)
    row.update(store_features(ctx))
    return row


def ml_matrix(rows: List[Dict[str, float]]) -> np.ndarray:
    """Rows -> (n, len(ML_FEATURES)) float matrix; NaN stays NaN."""
    return np.array([[row[f] for f in ML_FEATURES] for row in rows], dtype=np.float64).reshape(-1, len(ML_FEATURES))
