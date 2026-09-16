"""Stream-based PCAP Reader for SIH26145."""

import os
from typing import Iterator
import dpkt

from sih26145.ingest.models import PacketMetadata
from sih26145.ingest.parser import PacketParser


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
            reader = None
            try:
                reader = dpkt.pcap.Reader(f)
            except Exception:
                f.seek(0)
                try:
                    reader = dpkt.pcapng.Reader(f)
                except Exception:
                    # Malformed, unsupported, or empty capture header
                    return

            for ts, buf in reader:
                yield self.parser.parse_packet(ts, buf)
