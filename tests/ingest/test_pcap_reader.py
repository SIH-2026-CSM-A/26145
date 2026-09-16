"""Unit tests for PcapReader, PacketParser, and protocol metadata extraction."""

import os
import socket
import struct
import tempfile
import pytest
import dpkt

from sih26145.ingest import PcapReader, PacketParser, PacketMetadata


def create_synthetic_pcap(packets: list[bytes]) -> str:
    """Helper to generate a temporary PCAP file with given raw packet buffers."""
    fd, path = tempfile.mkstemp(suffix=".pcap")
    os.close(fd)
    
    with open(path, "wb") as f:
        writer = dpkt.pcap.Writer(f)
        for i, pkt_buf in enumerate(packets):
            writer.writepkt(pkt_buf, ts=1700000000.0 + i * 0.1)
            
    return path


def create_synthetic_pcapng(packets: list[bytes]) -> str:
    """Helper to generate a temporary PCAPNG file with given raw packet buffers."""
    fd, path = tempfile.mkstemp(suffix=".pcapng")
    os.close(fd)
    
    with open(path, "wb") as f:
        writer = dpkt.pcapng.Writer(f)
        for i, pkt_buf in enumerate(packets):
            writer.writepkt(pkt_buf, ts=1700000000.0 + i * 0.1)
            
    return path


def build_ipv4_tcp_packet(src_ip="192.168.1.10", dst_ip="10.0.0.1", src_port=12345, dst_port=80, payload=b"GET / HTTP/1.1\r\n\r\n"):
    ip = dpkt.ip.IP(
        src=socket.inet_aton(src_ip),
        dst=socket.inet_aton(dst_ip),
        p=dpkt.ip.IP_PROTO_TCP,
        ttl=64,
        data=dpkt.tcp.TCP(
            sport=src_port,
            dport=dst_port,
            flags=dpkt.tcp.TH_SYN,
            seq=1000,
            ack=0,
            data=payload
        )
    )
    eth = dpkt.ethernet.Ethernet(
        src=b"\x00\x11\x22\x33\x44\x55",
        dst=b"\xAA\xBB\xCC\xDD\xEE\xFF",
        type=dpkt.ethernet.ETH_TYPE_IP,
        data=ip
    )
    return bytes(eth)


def build_ipv6_udp_packet(src_ip="2001:db8::1", dst_ip="2001:db8::2", src_port=54321, dst_port=53, payload=b""):
    dns_pkt = dpkt.dns.DNS(
        id=1,
        qd=[dpkt.dns.DNS.Q(name="example.com", type=dpkt.dns.DNS_A)]
    )
    ip6 = dpkt.ip6.IP6(
        src=socket.inet_pton(socket.AF_INET6, src_ip),
        dst=socket.inet_pton(socket.AF_INET6, dst_ip),
        nxt=dpkt.ip.IP_PROTO_UDP,
        hlim=128,
        data=dpkt.udp.UDP(
            sport=src_port,
            dport=dst_port,
            data=bytes(dns_pkt)
        )
    )
    eth = dpkt.ethernet.Ethernet(
        src=b"\x00\x11\x22\x33\x44\x55",
        dst=b"\xAA\xBB\xCC\xDD\xEE\xFF",
        type=dpkt.ethernet.ETH_TYPE_IP6,
        data=ip6
    )
    return bytes(eth)


def build_icmp_packet():
    icmp = dpkt.icmp.ICMP(type=8, code=0)
    ip = dpkt.ip.IP(
        src=socket.inet_aton("192.168.1.50"),
        dst=socket.inet_aton("8.8.8.8"),
        p=dpkt.ip.IP_PROTO_ICMP,
        ttl=118,
        data=icmp
    )
    eth = dpkt.ethernet.Ethernet(
        type=dpkt.ethernet.ETH_TYPE_IP,
        data=ip
    )
    return bytes(eth)


def test_basic_pcap_reader():
    pkt1 = build_ipv4_tcp_packet()
    pkt2 = build_ipv6_udp_packet()
    pcap_path = create_synthetic_pcap([pkt1, pkt2])
    
    try:
        reader = PcapReader(pcap_path)
        records = list(reader)
        
        assert len(records) == 2
        
        # Check Packet 1 (IPv4 / TCP)
        r1 = records[0]
        assert r1.ip_version == 4
        assert r1.src_ip == "192.168.1.10"
        assert r1.dst_ip == "10.0.0.1"
        assert r1.protocol == "TCP"
        assert r1.src_port == 12345
        assert r1.dst_port == 80
        assert r1.ttl == 64
        assert r1.tcp_flags == dpkt.tcp.TH_SYN
        
        # Check Packet 2 (IPv6 / UDP / DNS)
        r2 = records[1]
        assert r2.ip_version == 6
        assert r2.src_ip == "2001:db8::1"
        assert r2.dst_ip == "2001:db8::2"
        assert r2.protocol == "UDP"
        assert r2.dst_port == 53
        assert r2.dns_query_name == "example.com"
        assert r2.dns_query_type == dpkt.dns.DNS_A
    finally:
        if os.path.exists(pcap_path):
            os.remove(pcap_path)


def test_icmp_parsing():
    pkt = build_icmp_packet()
    pcap_path = create_synthetic_pcap([pkt])
    try:
        reader = PcapReader(pcap_path)
        records = list(reader)
        assert len(records) == 1
        r = records[0]
        assert r.ip_version == 4
        assert r.protocol == "ICMP"
        assert r.icmp_type == 8
        assert r.icmp_code == 0
    finally:
        if os.path.exists(pcap_path):
            os.remove(pcap_path)


def test_malformed_truncated_packet():
    # Truncated buffer
    parser = PacketParser()
    meta = parser.parse_packet(1700000000.0, b"\x00\x11\x22\x33")
    assert meta.timestamp == 1700000000.0
    assert meta.captured_len == 4
    assert meta.ip_version is None
    assert meta.src_ip is None


def test_empty_pcap():
    fd, path = tempfile.mkstemp(suffix=".pcap")
    os.close(fd)
    try:
        reader = PcapReader(path)
        records = list(reader)
        assert len(records) == 0
    finally:
        if os.path.exists(path):
            os.remove(path)


def test_missing_file():
    reader = PcapReader("/tmp/non_existent_file_sih26145.pcap")
    with pytest.raises(FileNotFoundError):
        list(reader)


def test_pcapng_reader():
    """Verify that PcapReader successfully reads PCAPNG files."""
    pkt1 = build_ipv4_tcp_packet()
    pkt2 = build_ipv6_udp_packet()
    pcapng_path = create_synthetic_pcapng([pkt1, pkt2])
    
    try:
        reader = PcapReader(pcapng_path)
        records = list(reader)
        
        assert len(records) == 2
        
        # Check Packet 1 (IPv4 / TCP)
        r1 = records[0]
        assert r1.ip_version == 4
        assert r1.src_ip == "192.168.1.10"
        assert r1.dst_ip == "10.0.0.1"
        assert r1.protocol == "TCP"
        assert r1.src_port == 12345
        assert r1.dst_port == 80
        
        # Check Packet 2 (IPv6 / UDP / DNS)
        r2 = records[1]
        assert r2.ip_version == 6
        assert r2.src_ip == "2001:db8::1"
        assert r2.dst_ip == "2001:db8::2"
        assert r2.protocol == "UDP"
        assert r2.dns_query_name == "example.com"
        assert r2.dns_query_type == dpkt.dns.DNS_A
    finally:
        if os.path.exists(pcapng_path):
            os.remove(pcapng_path)
