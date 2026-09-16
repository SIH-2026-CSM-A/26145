"""Security and Payload Boundary Tests for SIH26145 Ingestion Subsystem."""

import os
import socket
import tempfile
import dpkt

from sih26145.ingest import PacketParser, PcapReader, PacketMetadata


def test_payload_not_exposed():
    """Verify that sensitive application payload data is NEVER exposed in PacketMetadata."""
    secret_payload = b"SUPER_SECRET_APPLICATION_PAYLOAD_1234567890"
    
    ip = dpkt.ip.IP(
        src=socket.inet_aton("192.168.1.100"),
        dst=socket.inet_aton("10.0.0.200"),
        p=dpkt.ip.IP_PROTO_TCP,
        data=dpkt.tcp.TCP(
            sport=443,
            dport=55555,
            data=secret_payload
        )
    )
    eth = dpkt.ethernet.Ethernet(
        type=dpkt.ethernet.ETH_TYPE_IP,
        data=ip
    )
    frame_bytes = bytes(eth)
    
    parser = PacketParser()
    meta = parser.parse_packet(1700000000.0, frame_bytes)
    
    # 1. Verify PacketMetadata dataclass attributes
    for attr, val in meta.__dict__.items():
        assert val != secret_payload, f"Attribute {attr} contained raw secret payload!"
        if isinstance(val, str):
            assert "SUPER_SECRET" not in val
        elif isinstance(val, bytes):
            assert secret_payload not in val
            
    # 2. Verify PacketMetadata has no 'payload' or 'data' field
    assert not hasattr(meta, "payload")
    assert not hasattr(meta, "raw_data")
    assert not hasattr(meta, "data")


def test_deterministic_parsing():
    """Verify repeated parsing of the same frame yields identical PacketMetadata."""
    secret_payload = b"DETERMINISTIC_TEST_DATA"
    ip = dpkt.ip.IP(
        src=socket.inet_aton("1.2.3.4"),
        dst=socket.inet_aton("5.6.7.8"),
        p=dpkt.ip.IP_PROTO_UDP,
        data=dpkt.udp.UDP(sport=111, dport=222, data=secret_payload)
    )
    eth = dpkt.ethernet.Ethernet(type=dpkt.ethernet.ETH_TYPE_IP, data=ip)
    frame_bytes = bytes(eth)
    
    parser = PacketParser()
    meta1 = parser.parse_packet(100.0, frame_bytes)
    meta2 = parser.parse_packet(100.0, frame_bytes)
    
    assert meta1 == meta2
