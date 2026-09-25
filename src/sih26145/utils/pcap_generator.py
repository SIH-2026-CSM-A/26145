"""Synthetic PCAP Generator for SIH26145 Threat Class Testing."""

import time
import socket
import dpkt
from typing import List, Tuple


def create_ethernet_ip_packet(
    src_ip: str = "192.168.1.100",
    dst_ip: str = "10.0.0.53",
    src_port: int = 49152,
    dst_port: int = 53,
    proto: str = "UDP",
    payload: bytes = b"",
    tcp_flags: int = dpkt.tcp.TH_ACK,
) -> bytes:
    """Construct standard Ethernet II / IPv4 / UDP|TCP|ICMP packet."""
    eth = dpkt.ethernet.Ethernet(
        src=b"\x00\x11\x22\x33\x44\x55",
        dst=b"\x66\x77\x88\x99\xaa\xbb",
        type=dpkt.ethernet.ETH_TYPE_IP,
    )

    ip = dpkt.ip.IP(
        src=socket.inet_aton(src_ip),
        dst=socket.inet_aton(dst_ip),
        id=12345,
        ttl=64,
    )

    if proto.upper() == "UDP":
        ip.p = dpkt.ip.IP_PROTO_UDP
        udp = dpkt.udp.UDP(
            sport=src_port,
            dport=dst_port,
            data=payload,
        )
        udp.ulen = len(udp)
        ip.data = udp
    elif proto.upper() == "TCP":
        ip.p = dpkt.ip.IP_PROTO_TCP
        tcp = dpkt.tcp.TCP(
            sport=src_port,
            dport=dst_port,
            flags=tcp_flags,
            seq=1000,
            ack=2000,
            win=8192,
            data=payload,
        )
        ip.data = tcp
    elif proto.upper() == "ICMP":
        ip.p = dpkt.ip.IP_PROTO_ICMP
        icmp = dpkt.icmp.ICMP(
            type=dpkt.icmp.ICMP_ECHO,
            code=0,
            data=dpkt.icmp.ICMP.Echo(id=1, seq=1, data=payload),
        )
        ip.data = icmp

    ip.len = len(ip)
    eth.data = ip
    return bytes(eth)


def make_tls_client_hello(sni_str: str) -> bytes:
    """Construct a valid TLS 1.2 ClientHello record with SNI extension."""
    import struct
    sni_bytes = sni_str.encode("ascii")
    server_name_list = struct.pack("!H", len(sni_bytes) + 3) + b"\x00" + struct.pack("!H", len(sni_bytes)) + sni_bytes
    ext_sni = struct.pack("!HH", 0, len(server_name_list)) + server_name_list
    extensions = struct.pack("!H", len(ext_sni)) + ext_sni
    random_bytes = b"\x00" * 32
    ciphers = struct.pack("!H", 2) + struct.pack("!H", 0x002f)
    comp = b"\x01\x00"
    body = b"\x03\x03" + random_bytes + b"\x00" + ciphers + comp + extensions
    handshake = b"\x01" + struct.pack("!I", len(body))[1:] + body
    record = b"\x16\x03\x01" + struct.pack("!H", len(handshake)) + handshake
    return record


def generate_threat_pcap(output_file: str) -> int:
    """Generate PCAP file containing background traffic and threat patterns for all 6 PS threat categories."""
    packets: List[Tuple[float, bytes]] = []
    ts = time.time()

    # 1. Background Normal DNS/HTTP traffic (Benign control)
    for i in range(10):
        pkt = create_ethernet_ip_packet("192.168.1.10", "10.0.0.1", 50000 + i, 80, "TCP", b"GET / HTTP/1.1\r\n\r\n")
        packets.append((ts + i * 0.1, pkt))

    # 2. Category 1: THREAT_DDOS_VOLUME (Volumetric packet burst: 120 packets from single 5-tuple over 0.005s -> pps > 10,000)
    for i in range(120):
        pkt_ddos = create_ethernet_ip_packet("192.168.1.100", "10.0.0.5", 49152, 80, "UDP", b"VOLUMETRIC_FLOOD_PAYLOAD_BURST_DATA")
        packets.append((ts + 1.0 + i * 0.00004, pkt_ddos))

    # 3. Category 2: THREAT_C2_BEACON (Periodic beaconing over 1.0s interval)
    for i in range(15):
        pkt_c2 = create_ethernet_ip_packet("192.168.1.101", "10.0.0.6", 45000, 443, "TCP", b"BEACON_HEARTBEAT_DATA", tcp_flags=dpkt.tcp.TH_ACK)
        packets.append((ts + 2.0 + i * 1.0, pkt_c2))

    # 4. Category 3: THREAT_DNS_TUNNEL (High entropy subdomain query with 4 subdomain levels)
    dns_payload = b"\x12\x34\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00"
    dns_payload += b"\x02a1\x02b2\x02c3\x02d4\x05exfil\x03com\x00\x00\x10\x00\x01"
    pkt_dns = create_ethernet_ip_packet("192.168.1.50", "10.0.0.53", 53535, 53, "UDP", dns_payload)
    for i in range(5):
        packets.append((ts + 18.0 + i * 0.05, pkt_dns))

    # 5. Category 4: THREAT_ENCRYPTED_ANOMALY (Valid TLS ClientHello with high SNI entropy over port 8443)
    tls_payload = make_tls_client_hello("x99z88y77w66v55u44t33s22r11.malicious.io")
    pkt_tls = create_ethernet_ip_packet("192.168.1.102", "10.0.0.7", 48000, 8443, "TCP", tls_payload, tcp_flags=dpkt.tcp.TH_PUSH | dpkt.tcp.TH_ACK)
    for i in range(3):
        packets.append((ts + 19.0 + i * 0.1, pkt_tls))

    # 6. Category 5: THREAT_RECON_PORTSCAN (SYN scan across 25 distinct dst ports)
    for port in range(100, 125):
        pkt_sweep = create_ethernet_ip_packet("192.168.1.52", "10.0.0.200", 40000, port, "TCP", tcp_flags=dpkt.tcp.TH_SYN)
        packets.append((ts + 20.0 + (port - 100) * 0.01, pkt_sweep))

    # 7. Category 6: THREAT_EXFILTRATION — internal host uploads ~1.2 MB to an external
    # (TEST-NET-3) address; the capture holds both halves, so the server's small ACKs are
    # present and the outbound/inbound ratio is measurable.
    packets += _upload(ts + 21.0, "192.168.1.51", "203.0.113.99", 51515, 800, bidirectional=True)

    return _write(output_file, packets)


def _write(output_file: str, packets: List[Tuple[float, bytes]]) -> int:
    packets.sort(key=lambda x: x[0])
    with open(output_file, "wb") as f:
        writer = dpkt.pcap.Writer(f)
        for p_ts, p_buf in packets:
            writer.writepkt(p_buf, p_ts)
    return len(packets)


def _upload(t0: float, client: str, server: str, sport: int, segments: int,
            bidirectional: bool, seg_size: int = 1460, spacing: float = 0.0025) -> List[Tuple[float, bytes]]:
    """Client -> server bulk upload over TCP/443; with bidirectional, the server ACKs every 10 segments."""
    out = []
    for i in range(segments):
        out.append((t0 + i * spacing, create_ethernet_ip_packet(
            client, server, sport, 443, "TCP", b"U" * seg_size, tcp_flags=dpkt.tcp.TH_PUSH | dpkt.tcp.TH_ACK)))
        if bidirectional and i % 10 == 9:
            out.append((t0 + i * spacing + 0.0005, create_ethernet_ip_packet(
                server, client, 443, sport, "TCP", tcp_flags=dpkt.tcp.TH_ACK)))
    return out


def _small_https(t0: float, client: str, server: str, sport: int, bidirectional: bool) -> List[Tuple[float, bytes]]:
    """A routine HTTPS exchange: ~1.8 KB up; with bidirectional, ~2.9 KB down."""
    out = [(t0 + i * 0.01, create_ethernet_ip_packet(client, server, sport, 443, "TCP", b"R" * 600,
                                                     tcp_flags=dpkt.tcp.TH_PUSH | dpkt.tcp.TH_ACK)) for i in range(3)]
    if bidirectional:
        out += [(t0 + 0.05 + i * 0.01, create_ethernet_ip_packet(server, client, 443, sport, "TCP", b"S" * 1400,
                                                                 tcp_flags=dpkt.tcp.TH_PUSH | dpkt.tcp.TH_ACK)) for i in range(2)]
    return out


def generate_exfil_pcap(output_file: str, bidirectional: bool, start: float = 1_790_000_000.0) -> int:
    """Exfiltration scenario for detector (f), captured with both halves or with one.

    192.168.1.60 makes one routine HTTPS exchange per minute with a popular external
    service (also used by three other hosts) for seven minutes, building its egress
    baseline; in minute eight it uploads ~1 MB to an external address no one else uses.
    """
    host, popular, rare = "192.168.1.60", "203.0.113.10", "198.51.100.77"
    packets: List[Tuple[float, bytes]] = []
    for minute in range(7):
        t = start + minute * 60 + 5
        packets += _small_https(t, host, popular, 50000 + minute, bidirectional)
        for peer in range(3):
            packets += _small_https(t + 1 + peer, f"192.168.1.{61 + peer}", popular, 50100 + minute * 10 + peer, bidirectional)
    packets += _upload(start + 7 * 60 + 5, host, rare, 51000, 700, bidirectional)
    return _write(output_file, packets)
