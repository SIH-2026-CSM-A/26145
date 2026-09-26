"""AUDIT A8: a snaplen-truncated capture keeps each packet's wire length, and header-only
frames (CTU-13-Extended: TCP cut at 54 bytes, UDP at 42) still yield ports and flags."""

import struct

import dpkt

from sih26145.ingest import PcapReader
from sih26145.utils.pcap_generator import create_ethernet_ip_packet as pkt


def write_truncated(path, frames, snap):
    """Classic pcap written the way editcap -s does it: caplen = snap, wirelen = full."""
    with open(path, "wb") as f:
        f.write(struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1))
        for i, (frame, s) in enumerate(zip(frames, snap)):
            cut = frame[:s]
            f.write(struct.pack("<IIII", 1_700_000_000 + i, 250_000, len(cut), len(frame)) + cut)


def test_truncated_records_report_wire_length_and_parse_headers(tmp_path):
    tcp = pkt("10.0.0.1", "203.0.113.5", 40000, 443, "TCP", b"x" * 1000, dpkt.tcp.TH_ACK | dpkt.tcp.TH_PUSH)
    udp = pkt("10.0.0.1", "10.0.0.53", 40001, 53, "UDP", b"y" * 200)
    path = str(tmp_path / "trunc.pcap")
    write_truncated(path, [tcp, udp], [54, 42])

    first, second = list(PcapReader(path))
    assert (first.captured_len, first.packet_len) == (54, len(tcp))
    assert (first.src_port, first.dst_port, first.protocol) == (40000, 443, "TCP")
    assert first.tcp_flags == dpkt.tcp.TH_ACK | dpkt.tcp.TH_PUSH
    assert first.timestamp == 1_700_000_000.25
    assert (second.captured_len, second.packet_len) == (42, len(udp))
    assert (second.src_port, second.dst_port, second.protocol) == (40001, 53, "UDP")


def test_truncated_pcapng_blocks_report_wire_length(tmp_path):
    """CTU-13-Extended's header-only captures are pcapng: the original length lives in each
    Enhanced Packet Block."""
    tcp = pkt("10.0.0.1", "203.0.113.5", 40000, 443, "TCP", b"x" * 1000, dpkt.tcp.TH_ACK)
    path = str(tmp_path / "trunc.pcapng")
    ts = 1_700_000_000_500_000  # microseconds
    block = bytearray(bytes(dpkt.pcapng.EnhancedPacketBlockLE(pkt_data=tcp[:54], ts_high=ts >> 32, ts_low=ts & 0xFFFFFFFF)))
    block[24:28] = struct.pack("<I", len(tcp))  # original length; dpkt's writer always sets it to caplen
    with open(path, "wb") as f:
        dpkt.pcapng.Writer(f)  # section + interface headers
        f.write(bytes(block))
    (first,) = list(PcapReader(path))
    assert (first.captured_len, first.packet_len) == (54, len(tcp))
    assert (first.src_port, first.dst_port, first.timestamp) == (40000, 443, 1_700_000_000.5)
