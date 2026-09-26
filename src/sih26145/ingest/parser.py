"""Deterministic Packet Parser for SIH26145."""

import socket
from typing import Optional, Tuple, List
import dpkt

from sih26145.ingest.models import PacketMetadata
from sih26145.ingest.tls_fingerprint import ja3, ja3s, ja4, parse_hello


class PacketParser:
    """Safely extracts observable header metadata from raw frame bytes."""

    def parse_packet(self, timestamp: float, buf: bytes, wire_len: Optional[int] = None) -> PacketMetadata:
        """Parse raw link-layer frame buffer into normalized PacketMetadata.
        
        Guarantees that malformed, truncated, or unsupported frames are handled
        gracefully without raising unhandled exceptions. Payload bytes are
        never exposed. `wire_len` is the original length from the capture record header;
        a snaplen-truncated record keeps its true size for byte counts (AUDIT A8).
        """
        captured_len = len(buf)
        packet_len = max(wire_len or 0, captured_len)

        # Defaults
        ip_ver: Optional[int] = None
        src_ip: Optional[str] = None
        dst_ip: Optional[str] = None
        proto_str: Optional[str] = None
        ttl: Optional[int] = None

        src_port: Optional[int] = None
        dst_port: Optional[int] = None
        tcp_flags: Optional[int] = None
        tcp_seq: Optional[int] = None
        tcp_ack: Optional[int] = None
        icmp_type: Optional[int] = None
        icmp_code: Optional[int] = None

        dns_name: Optional[str] = None
        dns_qtype: Optional[int] = None
        dns_is_response: Optional[bool] = None
        dns_rcode: Optional[int] = None

        tls_ver: Optional[str] = None
        tls_sni: Optional[str] = None
        tls_ciphers: Optional[List[int]] = None
        tls_ja3: Optional[str] = None
        tls_ja4: Optional[str] = None
        tls_ja3s: Optional[str] = None

        try:
            link, ip_obj = self._unpack_link(buf)
        except Exception:
            # Failed to parse link layer or raw buffer
            return PacketMetadata(
                timestamp=timestamp,
                captured_len=captured_len,
                packet_len=packet_len,
            )

        if ip_obj is None:
            return PacketMetadata(
                timestamp=timestamp,
                captured_len=captured_len,
                packet_len=packet_len,
            )

        # Parse IP Layer
        try:
            if isinstance(ip_obj, dpkt.ip.IP):
                ip_ver = 4
                src_ip = socket.inet_ntop(socket.AF_INET, ip_obj.src)
                dst_ip = socket.inet_ntop(socket.AF_INET, ip_obj.dst)
                ttl = ip_obj.ttl
                l4_obj = ip_obj.data
                p_num = ip_obj.p
            elif isinstance(ip_obj, dpkt.ip6.IP6):
                ip_ver = 6
                src_ip = socket.inet_ntop(socket.AF_INET6, ip_obj.src)
                dst_ip = socket.inet_ntop(socket.AF_INET6, ip_obj.dst)
                ttl = ip_obj.hlim
                l4_obj = ip_obj.data
                p_num = ip_obj.nxt
            else:
                l4_obj = None
                p_num = -1
        except Exception:
            l4_obj = None
            p_num = -1

        # Transport Layer Parsing
        if l4_obj is not None:
            if isinstance(l4_obj, dpkt.tcp.TCP) or p_num == 6:
                proto_str = "TCP"
                try:
                    src_port = l4_obj.sport
                    dst_port = l4_obj.dport
                    tcp_flags = l4_obj.flags
                    tcp_seq = l4_obj.seq
                    tcp_ack = l4_obj.ack
                    
                    # Cleartext TLS ClientHello / ServerHello on any TCP port
                    hello = parse_hello(l4_obj.data) if l4_obj.data else None
                    if hello is not None and hello.is_client:
                        tls_ver, tls_sni, tls_ciphers = hello.version_name, hello.sni, hello.ciphers
                        tls_ja3, tls_ja4 = ja3(hello), ja4(hello)
                    elif hello is not None:
                        tls_ja3s = ja3s(hello)
                except Exception:
                    pass

            elif isinstance(l4_obj, dpkt.udp.UDP) or p_num == 17:
                proto_str = "UDP"
                try:
                    src_port = l4_obj.sport
                    dst_port = l4_obj.dport
                    
                    # Extract DNS Query if present
                    if dst_port == 53 or src_port == 53:
                        dns_name, dns_qtype, dns_is_response, dns_rcode = self._parse_dns_query(l4_obj.data)
                except Exception:
                    pass

            elif isinstance(l4_obj, dpkt.icmp.ICMP) or p_num == 1:
                proto_str = "ICMP"
                try:
                    icmp_type = l4_obj.type
                    icmp_code = l4_obj.code
                except Exception:
                    pass

            elif isinstance(l4_obj, dpkt.icmp6.ICMP6) or p_num == 58:
                proto_str = "ICMPv6"
                try:
                    icmp_type = l4_obj.type
                    icmp_code = l4_obj.code
                except Exception:
                    pass
            else:
                proto_str = f"OTHER_{p_num}"

        return PacketMetadata(
            timestamp=timestamp,
            captured_len=captured_len,
            packet_len=packet_len,
            ip_version=ip_ver,
            src_ip=src_ip,
            dst_ip=dst_ip,
            protocol=proto_str,
            ttl=ttl,
            src_port=src_port,
            dst_port=dst_port,
            tcp_flags=tcp_flags,
            tcp_seq=tcp_seq,
            tcp_ack=tcp_ack,
            icmp_type=icmp_type,
            icmp_code=icmp_code,
            dns_query_name=dns_name,
            dns_query_type=dns_qtype,
            dns_is_response=dns_is_response,
            dns_rcode=dns_rcode,
            tls_version=tls_ver,
            tls_sni=tls_sni,
            tls_cipher_suites=tls_ciphers,
            tls_ja3=tls_ja3,
            tls_ja4=tls_ja4,
            tls_ja3s=tls_ja3s,
        )

    def _unpack_link(self, buf: bytes) -> Tuple[Optional[str], Optional[object]]:
        """Unpack link layer header (Ethernet, Linux Cooked SLL, or Raw IP)."""
        if not buf:
            return None, None

        # Try Ethernet
        try:
            eth = dpkt.ethernet.Ethernet(buf)
            if eth.type == dpkt.ethernet.ETH_TYPE_IP:
                return "ETH", eth.data
            elif eth.type == dpkt.ethernet.ETH_TYPE_IP6:
                return "ETH", eth.data
        except Exception:
            pass

        # Try Linux Cooked Capture (SLL)
        try:
            sll = dpkt.sll.SLL(buf)
            if sll.ethtype == dpkt.ethernet.ETH_TYPE_IP or sll.ethtype == dpkt.ethernet.ETH_TYPE_IP6:
                return "SLL", sll.data
        except Exception:
            pass

        # Try Raw IPv4
        try:
            ip = dpkt.ip.IP(buf)
            if ip.v == 4:
                return "RAW", ip
        except Exception:
            pass

        # Try Raw IPv6
        try:
            ip6 = dpkt.ip6.IP6(buf)
            if ip6.v == 6:
                return "RAW", ip6
        except Exception:
            pass

        return None, None

    def _parse_dns_query(self, payload: bytes) -> Tuple[Optional[str], Optional[int], Optional[bool], Optional[int]]:
        """Safely parse unencrypted DNS header + question: (qname, qtype, is_response, rcode)."""
        if not payload:
            return None, None, None, None
        try:
            dns = dpkt.dns.DNS(payload)
            is_response = dns.qr == dpkt.dns.DNS_R
            rcode = dns.rcode if is_response else None
            if dns.qd:
                q = dns.qd[0]
                return q.name, q.type, is_response, rcode
            return None, None, is_response, rcode
        except Exception:
            pass
        return None, None, None, None
