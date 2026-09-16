"""Feature Extraction Engine for SIH26145."""

import math
from collections import Counter
from typing import List, Tuple
import numpy as np

from sih26145.flow.models import FlowRecord
from sih26145.features.models import FeatureVector


def entropy_of_string(s: str) -> float:
    """Calculate Shannon Entropy (in bits) for a given text string."""
    if not s:
        return 0.0
    length = len(s)
    counts = Counter(s)
    entropy = 0.0
    for count in counts.values():
        p = count / length
        entropy -= p * math.log2(p)
    return float(entropy)


class FeatureExtractor:
    """Extracts numerical FeatureVector from a windowed FlowRecord."""

    def extract(self, flow: FlowRecord) -> FeatureVector:
        """Convert FlowRecord telemetry into normalized FeatureVector."""
        duration = flow.duration
        total_packets = flow.packet_count
        total_bytes = flow.total_bytes

        pps = (total_packets / duration) if duration > 0 else float(total_packets)
        bps = (total_bytes / duration) if duration > 0 else float(total_bytes)

        # Packet Size Stats
        sizes = np.array(flow.packet_sizes if flow.packet_sizes else [0], dtype=np.float64)
        pkt_size_min = float(np.min(sizes))
        pkt_size_max = float(np.max(sizes))
        pkt_size_mean = float(np.mean(sizes))
        pkt_size_std = float(np.std(sizes))
        pkt_size_q25 = float(np.percentile(sizes, 25))
        pkt_size_q50 = float(np.percentile(sizes, 50))
        pkt_size_q75 = float(np.percentile(sizes, 75))

        # IAT Stats
        if flow.inter_arrival_times:
            iats = np.array(flow.inter_arrival_times, dtype=np.float64)
            iat_mean = float(np.mean(iats))
            iat_var = float(np.var(iats))
            iat_min = float(np.min(iats))
            iat_max = float(np.max(iats))
            # Jitter as mean absolute difference between consecutive IATs
            jitter = float(np.mean(np.abs(np.diff(iats)))) if len(iats) > 1 else 0.0
        else:
            iat_mean = 0.0
            iat_var = 0.0
            iat_min = 0.0
            iat_max = 0.0
            jitter = 0.0

        # Burstiness ratio (std / (mean + eps))
        burstiness_ratio = pkt_size_std / (pkt_size_mean + 1e-6)

        # Small packet ratio (<64 bytes)
        small_pkts = np.sum(sizes < 64)
        small_pkt_ratio = float(small_pkts / total_packets) if total_packets > 0 else 0.0

        # Protocol Indicators
        proto = flow.flow_key.protocol.upper() if flow.flow_key.protocol else ""
        is_tcp = 1.0 if "TCP" in proto else 0.0
        is_udp = 1.0 if "UDP" in proto else 0.0
        is_icmp = 1.0 if "ICMP" in proto else 0.0

        dst_port = flow.flow_key.dst_port

        # DNS Metadata
        dns_query_count = len(flow.dns_queries)
        dns_max_domain_entropy = 0.0
        dns_max_subdomain_depth = 0
        if flow.dns_queries:
            entropies = [entropy_of_string(q) for q in flow.dns_queries]
            dns_max_domain_entropy = float(max(entropies))
            depths = [q.count(".") for q in flow.dns_queries]
            dns_max_subdomain_depth = int(max(depths))

        # TLS Metadata
        tls_client_hello_count = len(flow.tls_snis)
        tls_max_sni_entropy = 0.0
        tls_max_sni_length = 0
        if flow.tls_snis:
            entropies = [entropy_of_string(sni) for sni in flow.tls_snis]
            tls_max_sni_entropy = float(max(entropies))
            lengths = [len(sni) for sni in flow.tls_snis]
            tls_max_sni_length = int(max(lengths))

        # TCP Flags
        has_syn = 1.0 if getattr(flow, "has_syn", False) else 0.0
        has_fin = 1.0 if getattr(flow, "has_fin", False) else 0.0
        has_rst = 1.0 if getattr(flow, "has_rst", False) else 0.0

        return FeatureVector(
            flow_key_str=str(flow.flow_key),
            duration=duration,
            total_packets=total_packets,
            total_bytes=total_bytes,
            pps=pps,
            bps=bps,
            pkt_size_min=pkt_size_min,
            pkt_size_max=pkt_size_max,
            pkt_size_mean=pkt_size_mean,
            pkt_size_std=pkt_size_std,
            pkt_size_q25=pkt_size_q25,
            pkt_size_q50=pkt_size_q50,
            pkt_size_q75=pkt_size_q75,
            iat_mean=iat_mean,
            iat_var=iat_var,
            iat_min=iat_min,
            iat_max=iat_max,
            jitter=jitter,
            burstiness_ratio=burstiness_ratio,
            small_pkt_ratio=small_pkt_ratio,
            is_tcp=is_tcp,
            is_udp=is_udp,
            is_icmp=is_icmp,
            dst_port=dst_port,
            dns_query_count=dns_query_count,
            dns_max_domain_entropy=dns_max_domain_entropy,
            dns_max_subdomain_depth=dns_max_subdomain_depth,
            tls_client_hello_count=tls_client_hello_count,
            tls_max_sni_entropy=tls_max_sni_entropy,
            tls_max_sni_length=tls_max_sni_length,
            has_syn=has_syn,
            has_fin=has_fin,
            has_rst=has_rst,
        )
