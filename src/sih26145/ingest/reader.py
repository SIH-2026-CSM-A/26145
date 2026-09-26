"""Stream-based PCAP Reader for SIH26145."""

import os
import struct
from typing import BinaryIO, Iterator, Optional, Tuple

import dpkt

from sih26145.ingest.models import PacketMetadata
from sih26145.ingest.parser import PacketParser

# Classic pcap magic -> (struct byte order, timestamp fraction divisor)
_MAGIC = {
    b"\xd4\xc3\xb2\xa1": ("<", 1e6), b"\xa1\xb2\xc3\xd4": (">", 1e6),   # microsecond
    b"\x4d\x3c\xb2\xa1": ("<", 1e9), b"\xa1\xb2\x3c\x4d": (">", 1e9),   # nanosecond
}


def pcap_records(f: BinaryIO) -> Optional[Iterator[Tuple[float, bytes, int]]]:
    """(timestamp, captured bytes, original wire length) per classic-pcap record, or None if
    the file is not classic pcap. dpkt's reader drops the record header's original length,
    which a snaplen-truncated capture needs for byte counts (AUDIT A8)."""
    head = f.read(24)
    fmt = _MAGIC.get(head[:4]) if len(head) == 24 else None
    if fmt is None:
        return None
    endian, divisor = fmt

    def records():
        while len(rec := f.read(16)) == 16:
            sec, frac, caplen, wirelen = struct.unpack(endian + "IIII", rec)
            buf = f.read(caplen)
            if len(buf) < caplen:
                return  # the file ends mid-record
            yield sec + frac / divisor, buf, wirelen
    return records()


class _PcapngReader(dpkt.pcapng.Reader):
    """dpkt's pcapng reader, also yielding each packet block's original length, which dpkt
    parses and drops. CTU-13-Extended's header-only captures are pcapng."""

    def records(self) -> Iterator[Tuple[float, bytes, int]]:
        # ponytail: reads dpkt's private file handle and byte order (dpkt 1.9.8, pinned in
        # uv.lock); re-check on a dpkt upgrade, or parse the blocks here if it changes.
        f, le, png = self._Reader__f, self._Reader__le, dpkt.pcapng
        while len(buf := f.read(8)) == 8:
            blk_type, blk_len = struct.unpack("<II" if le else ">II", buf)
            buf += f.read(blk_len - 8)
            if blk_type == png.PCAPNG_BT_EPB:
                block = (png.EnhancedPacketBlockLE if le else png.EnhancedPacketBlock)(buf)
            elif blk_type == png.PCAPNG_BT_PB:
                block = (png.PacketBlockLE if le else png.PacketBlock)(buf)
            else:
                continue
            yield self._tsoffset + ((block.ts_high << 32) | block.ts_low) / self._divisor, block.pkt_data, block.pkt_len


def capture_records(f: BinaryIO) -> Iterator[Tuple[float, bytes, int]]:
    """(timestamp, captured bytes, wire length) for every packet of a classic pcap or pcapng
    file; nothing for an unreadable header."""
    records = pcap_records(f)
    if records is not None:
        return records
    f.seek(0)
    try:
        return _PcapngReader(f).records()
    except Exception:
        return iter(())  # malformed, unsupported, or empty capture header


class PcapReader:
    """Stream-based PCAP file reader yielding normalized PacketMetadata."""

    def __init__(self, filepath: str):
        self.filepath = filepath
        self.parser = PacketParser()

    def __iter__(self) -> Iterator[PacketMetadata]:
        """Yield PacketMetadata iteratively for each packet record in PCAP."""
        if not os.path.exists(self.filepath):
            raise FileNotFoundError(f"PCAP file not found: {self.filepath}")

        with open(self.filepath, "rb") as f:
            for ts, buf, wirelen in capture_records(f):
                yield self.parser.parse_packet(ts, buf, wirelen)
