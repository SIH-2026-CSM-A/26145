"""JA3 / JA4 / JA3S from cleartext hellos, checked against the published JA4 example."""

import hashlib
import struct

from sih26145.ingest.parser import PacketParser
from sih26145.ingest.tls_fingerprint import is_grease, ja3, ja3_string, ja3s, ja4, parse_hello
from sih26145.utils.pcap_generator import create_ethernet_ip_packet

GREASE = 0x3A3A
# The JA4 spec example (FoxIO technical_details/JA4.md): 15 ciphers, 16 extensions, ALPN h2
SPEC_CIPHERS = [0x1301, 0x1302, 0x1303, 0xC02B, 0xC02F, 0xC02C, 0xC030, 0xCCA9, 0xCCA8,
                0xC013, 0xC014, 0x009C, 0x009D, 0x002F, 0x0035]
SPEC_EXTS = [0x001B, 0x0000, 0x0033, 0x0010, 0x4469, 0x0017, 0x002D, 0x000D, 0x0005,
             0x0023, 0x0012, 0x002B, 0xFF01, 0x000B, 0x000A, 0x0015]
SPEC_SIGS = [0x0403, 0x0804, 0x0401, 0x0503, 0x0805, 0x0501, 0x0806, 0x0601]


def u16s(values):
    return b"".join(struct.pack("!H", v) for v in values)


def ext_body(ext):
    if ext == 0x0000:
        name = b"example.com"
        return struct.pack("!HBH", len(name) + 3, 0, len(name)) + name
    if ext == 0x0010:
        return struct.pack("!HB", 3, 2) + b"h2"
    if ext == 0x000D:
        return struct.pack("!H", 2 * len(SPEC_SIGS)) + u16s(SPEC_SIGS)
    if ext == 0x002B:
        return bytes([6]) + u16s([GREASE, 0x0304, 0x0303])
    if ext == 0x000A:
        return struct.pack("!H", 8) + u16s([GREASE, 0x001D, 0x0017, 0x0018])
    if ext == 0x000B:
        return bytes([1, 0])
    return b""


def record(handshake_type, body):
    hs = bytes([handshake_type]) + struct.pack("!I", len(body))[1:] + body
    return b"\x16\x03\x01" + struct.pack("!H", len(hs)) + hs


def client_hello():
    exts = [GREASE] + SPEC_EXTS + [GREASE]
    ext_bytes = b"".join(struct.pack("!HH", e, len(ext_body(e))) + ext_body(e) for e in exts)
    ciphers = [GREASE] + SPEC_CIPHERS
    body = (b"\x03\x03" + b"\x00" * 32 + b"\x00" + struct.pack("!H", 2 * len(ciphers)) + u16s(ciphers)
            + b"\x01\x00" + struct.pack("!H", len(ext_bytes)) + ext_bytes)
    return record(1, body)


def server_hello():
    exts = struct.pack("!HH", 0x002B, 2) + u16s([0x0304]) + struct.pack("!HH", 0x0033, 0)
    body = b"\x03\x03" + b"\x11" * 32 + b"\x00" + u16s([0x1301]) + b"\x00" + struct.pack("!H", len(exts)) + exts
    return record(2, body)


def test_grease_detection():
    assert all(is_grease(v) for v in (0x0A0A, 0x3A3A, 0xFAFA))
    assert not any(is_grease(v) for v in (0x0A1A, 0x1301, 0x0000))


def test_ja4_matches_the_published_example():
    assert ja4(parse_hello(client_hello())) == "t13d1516h2_8daaf6152771_e5627efa2ab1"


def test_ja4_hash_parts_match_the_spec_raw_strings():
    h12 = lambda s: hashlib.sha256(s.encode()).hexdigest()[:12]  # noqa: E731
    assert h12("002f,0035,009c,009d,1301,1302,1303,c013,c014,c02b,c02c,c02f,c030,cca8,cca9") == "8daaf6152771"
    assert h12("0005,000a,000b,000d,0012,0015,0017,001b,0023,002b,002d,0033,4469,ff01") == "6d807ffa2a79"


def test_ja3_string_drops_grease_and_keeps_wire_order():
    h = parse_hello(client_hello())
    expected = ("771,"
                + "-".join(str(c) for c in SPEC_CIPHERS) + ","
                + "-".join(str(e) for e in SPEC_EXTS) + ","
                + "29-23-24,0")
    assert ja3_string(h) == expected
    assert ja3(h) == hashlib.md5(expected.encode()).hexdigest()
    assert h.sni == "example.com" and h.alpn == [b"h2"]


def test_ja3s_from_server_hello():
    h = parse_hello(server_hello())
    assert not h.is_client
    assert ja3s(h) == hashlib.md5(b"771,4865,43-51").hexdigest()


def test_truncated_or_non_handshake_payloads():
    assert parse_hello(b"GET / HTTP/1.1\r\n") is None
    assert parse_hello(b"") is None
    truncated = parse_hello(client_hello()[:60])
    assert truncated is not None and truncated.is_client and truncated.sni is None


def test_parser_attaches_fingerprints_to_packet_metadata():
    parser = PacketParser()
    ch = parser.parse_packet(1.0, create_ethernet_ip_packet("192.168.1.5", "203.0.113.9", 50000, 993, "TCP", client_hello()))
    assert ch.tls_sni == "example.com"
    assert ch.tls_ja4 == "t13d1516h2_8daaf6152771_e5627efa2ab1"
    assert ch.tls_ja3 is not None and ch.tls_ja3s is None
    sh = parser.parse_packet(1.1, create_ethernet_ip_packet("203.0.113.9", "192.168.1.5", 993, 50000, "TCP", server_hello()))
    assert sh.tls_ja3s is not None and sh.tls_ja4 is None


def test_fingerprint_pair_needs_both_hellos_on_one_flow():
    import pytest
    from sih26145.contract import UnavailableFeatureError
    from sih26145.features.directional import NetworkPolicy, flow_feature
    from sih26145.flow import FlowTracker

    parser, policy = PacketParser(), NetworkPolicy()
    ch = parser.parse_packet(1.0, create_ethernet_ip_packet("192.168.1.5", "203.0.113.9", 50000, 443, "TCP", client_hello()))
    sh = parser.parse_packet(1.1, create_ethernet_ip_packet("203.0.113.9", "192.168.1.5", 443, 50000, "TCP", server_hello()))

    one_sided = FlowTracker()
    one_sided.process_packet(ch)
    (flow,) = one_sided.flush_expired(100.0)
    assert flow_feature(flow, "tls_ja4", policy) == ch.tls_ja4
    with pytest.raises(UnavailableFeatureError):
        flow_feature(flow, "tls_client_server_fp_pair", policy)

    both = FlowTracker()
    both.process_packet(ch)
    both.process_packet(sh)
    (flow,) = both.flush_expired(100.0)
    assert flow_feature(flow, "tls_client_server_fp_pair", policy) == f"{ch.tls_ja4}|{sh.tls_ja3s}"
