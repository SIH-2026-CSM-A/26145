"""Normalized Packet Metadata Contract for SIH26145."""

from dataclasses import dataclass, field
from typing import Optional, List


@dataclass(frozen=True)
class PacketMetadata:
    """Normalized, observable metadata representation of a single network packet.
    
    Encrypted application payloads are strictly NOT INSPECTED, NOT DECRYPTED,
    and NOT INTERPRETED. No raw payload or packet bytes are exposed.
    """
    # Core
    timestamp: float
    captured_len: int
    packet_len: int

    # Network
    ip_version: Optional[int] = None
    src_ip: Optional[str] = None
    dst_ip: Optional[str] = None
    protocol: Optional[str] = None
    ttl: Optional[int] = None

    # Transport
    src_port: Optional[int] = None
    dst_port: Optional[int] = None
    tcp_flags: Optional[int] = None
    tcp_seq: Optional[int] = None
    tcp_ack: Optional[int] = None
    icmp_type: Optional[int] = None
    icmp_code: Optional[int] = None

    # Application - DNS (Observable unencrypted query metadata)
    dns_query_name: Optional[str] = None
    dns_query_type: Optional[int] = None
    dns_is_response: Optional[bool] = None  # QR bit; None when not DNS
    dns_rcode: Optional[int] = None         # set on responses only (3 = NXDOMAIN)

    # Application - TLS (Observable unencrypted ClientHello metadata)
    tls_version: Optional[str] = None
    tls_sni: Optional[str] = None
    tls_cipher_suites: Optional[List[int]] = None
