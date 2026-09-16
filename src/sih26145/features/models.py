"""Feature Vector Data Model for SIH26145."""

from dataclasses import dataclass


@dataclass(frozen=True)
class FeatureVector:
    """Normalized numerical feature vector extracted from a FlowRecord.
    
    Covers the 11 feature families defined in docs/ARCHITECTURE.md Section 7:
    Packet size, IAT, Rate, Duration, Packet counts, Protocol distribution,
    Port diversity, DNS unencrypted lexical features, TLS ClientHello SNI metadata.
    """
    flow_key_str: str
    duration: float
    total_packets: int
    total_bytes: int
    pps: float
    bps: float

    # Packet Size Statistics
    pkt_size_min: float
    pkt_size_max: float
    pkt_size_mean: float
    pkt_size_std: float
    pkt_size_q25: float
    pkt_size_q50: float
    pkt_size_q75: float

    # Inter-Arrival Time (IAT) Statistics
    iat_mean: float
    iat_var: float
    iat_min: float
    iat_max: float
    jitter: float

    # Count & Protocol Ratios
    burstiness_ratio: float
    small_pkt_ratio: float
    is_tcp: float
    is_udp: float
    is_icmp: float
    dst_port: int

    # DNS Observable Lexical Metadata
    dns_query_count: int
    dns_max_domain_entropy: float
    dns_max_subdomain_depth: int

    # TLS Observable Metadata
    tls_client_hello_count: int
    tls_max_sni_entropy: float
    tls_max_sni_length: int

    # TCP Connection Flags
    has_syn: float = 0.0
    has_fin: float = 0.0
    has_rst: float = 0.0
