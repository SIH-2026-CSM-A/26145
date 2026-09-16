"""Deterministic Packet Parser for SIH26145."""

import socket
import struct
from typing import Optional, Tuple, List
import dpkt

from sih26145.ingest.models import PacketMetadata


class PacketParser:
    """Safely extracts observable header metadata from raw frame bytes."""

    def parse_packet(self, timestamp: float, buf: bytes) -> PacketMetadata:
        """Parse raw link-layer frame buffer into normalized PacketMetadata.
        
        Guarantees that malformed, truncated, or unsupported frames are handled
        gracefully without raising unhandled exceptions. Payload bytes are
        never exposed.
        """
        captured_len = len(buf)
        packet_len = captured_len

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

        tls_ver: Optional[str] = None
        tls_sni: Optional[str] = None
        tls_ciphers: Optional[List[int]] = None

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
                    
                    # Extract TLS ClientHello if present on TCP payload
                    if dst_port == 443 or src_port == 443 or (hasattr(l4_obj, 'data') and l4_obj.data):
                        tls_ver, tls_sni, tls_ciphers = self._parse_tls_client_hello(l4_obj.data)
                except Exception:
                    pass

            elif isinstance(l4_obj, dpkt.udp.UDP) or p_num == 17:
                proto_str = "UDP"
                try:
                    src_port = l4_obj.sport
                    dst_port = l4_obj.dport
                    
                    # Extract DNS Query if present
                    if dst_port == 53 or src_port == 53:
                        dns_name, dns_qtype = self._parse_dns_query(l4_obj.data)
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
            tls_version=tls_ver,
            tls_sni=tls_sni,
            tls_cipher_suites=tls_ciphers,
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

    def _parse_dns_query(self, payload: bytes) -> Tuple[Optional[str], Optional[int]]:
        """Safely parse unencrypted DNS query payload."""
        if not payload:
            return None, None
        try:
            dns = dpkt.dns.DNS(payload)
            if dns.qd:
                q = dns.qd[0]
                return q.name, q.type
        except Exception:
            pass
        return None, None

    def _parse_tls_client_hello(self, payload: str | bytes) -> Tuple[Optional[str], Optional[str], Optional[List[int]]]:
        """Safely parse unencrypted TLS ClientHello metadata (SNI, Ciphers)."""
        if not payload or not isinstance(payload, bytes):
            return None, None, None

        # Check TLS Record Header: ContentType == 22 (Handshake), Version == 0x0300..0x0304
        if len(payload) < 5 or payload[0] != 22:
            return None, None, None

        try:
            # Parse record header
            record_ver_major = payload[1]
            record_ver_minor = payload[2]
            record_len = struct.unpack("!H", payload[3:5])[0]

            if len(payload) < 5 + record_len:
                # Truncated record
                handshake_data = payload[5:]
            else:
                handshake_data = payload[5:5 + record_len]

            if not handshake_data or handshake_data[0] != 1:
                # HandshakeType != ClientHello (1)
                return None, None, None

            # Parse ClientHello body
            pos = 1
            if len(handshake_data) < 4:
                return None, None, None
            msg_len = (handshake_data[1] << 16) | (handshake_data[2] << 8) | handshake_data[3]
            pos += 3

            client_ver_major = handshake_data[pos]
            client_ver_minor = handshake_data[pos + 1]
            pos += 2

            tls_ver_str = f"{client_ver_major}.{client_ver_minor}"
            if client_ver_major == 3 and client_ver_minor == 3:
                tls_ver_str = "TLS 1.2"
            elif client_ver_major == 3 and client_ver_minor == 1:
                tls_ver_str = "TLS 1.0"
            elif client_ver_major == 3 and client_ver_minor == 2:
                tls_ver_str = "TLS 1.1"

            # Skip Random (32 bytes)
            pos += 32
            if len(handshake_data) < pos + 1:
                return tls_ver_str, None, None

            # Session ID
            sess_id_len = handshake_data[pos]
            pos += 1 + sess_id_len

            # Cipher Suites
            if len(handshake_data) < pos + 2:
                return tls_ver_str, None, None
            cipher_len = struct.unpack("!H", handshake_data[pos:pos + 2])[0]
            pos += 2

            ciphers = []
            if len(handshake_data) >= pos + cipher_len:
                for i in range(0, cipher_len, 2):
                    ciphers.append(struct.unpack("!H", handshake_data[pos + i:pos + i + 2])[0])
            pos += cipher_len

            # Compression Methods
            if len(handshake_data) < pos + 1:
                return tls_ver_str, None, ciphers
            comp_len = handshake_data[pos]
            pos += 1 + comp_len

            # Extensions
            sni_name = None
            if len(handshake_data) >= pos + 2:
                ext_total_len = struct.unpack("!H", handshake_data[pos:pos + 2])[0]
                pos += 2
                ext_end = min(len(handshake_data), pos + ext_total_len)

                while pos + 4 <= ext_end:
                    ext_type = struct.unpack("!H", handshake_data[pos:pos + 2])[0]
                    ext_len = struct.unpack("!H", handshake_data[pos + 2:pos + 4])[0]
                    pos += 4

                    if ext_type == 0:  # server_name extension
                        if pos + ext_len <= ext_end and ext_len >= 5:
                            # ServerNameList length (2), ServerNameType (1), ServerName length (2)
                            list_len = struct.unpack("!H", handshake_data[pos:pos + 2])[0]
                            name_type = handshake_data[pos + 2]
                            if name_type == 0:  # host_name
                                name_len = struct.unpack("!H", handshake_data[pos + 3:pos + 5])[0]
                                if pos + 5 + name_len <= ext_end:
                                    sni_bytes = handshake_data[pos + 5:pos + 5 + name_len]
                                    try:
                                        sni_name = sni_bytes.decode("ascii")
                                    except Exception:
                                        pass
                    pos += ext_len

            return tls_ver_str, sni_name, ciphers
        except Exception:
            return None, None, None
