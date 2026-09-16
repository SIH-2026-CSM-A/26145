"""Flow Key and Flow Record Data Models for SIH26145."""

from dataclasses import dataclass, field
from typing import Optional, List, Tuple


@dataclass(frozen=True)
class FlowKey:
    """Represents a unidirectional flow aggregation key.
    
    Supports both 5-Tuple (src_ip, src_port, dst_ip, dst_port, protocol)
    and 4-Tuple (src_ip, dst_ip, dst_port, protocol) for behavioral aggregation.
    """
    src_ip: str
    dst_ip: str
    dst_port: int
    protocol: str
    src_port: Optional[int] = None  # None when in 4-tuple mode

    def to_tuple(self) -> Tuple:
        if self.src_port is not None:
            return (self.src_ip, self.src_port, self.dst_ip, self.dst_port, self.protocol)
        return (self.src_ip, self.dst_ip, self.dst_port, self.protocol)

    def __str__(self) -> str:
        if self.src_port is not None:
            return f"{self.src_ip}:{self.src_port}->{self.dst_ip}:{self.dst_port}/{self.protocol}"
        return f"{self.src_ip}->{self.dst_ip}:{self.dst_port}/{self.protocol}"


@dataclass
class FlowRecord:
    """Accumulated telemetry state for a single unidirectional flow window."""
    flow_key: FlowKey
    start_time: float
    last_time: float
    packet_count: int = 0
    total_bytes: int = 0
    packet_sizes: List[int] = field(default_factory=list)
    inter_arrival_times: List[float] = field(default_factory=list)
    tcp_flags_seen: int = 0
    dns_queries: List[str] = field(default_factory=list)
    tls_snis: List[str] = field(default_factory=list)
    is_active_expired: bool = False
    is_idle_expired: bool = False
    is_evicted: bool = False

    @property
    def duration(self) -> float:
        return max(0.0, self.last_time - self.start_time)

    @property
    def has_syn(self) -> bool:
        return bool(self.tcp_flags_seen & 0x02)

    @property
    def has_fin(self) -> bool:
        return bool(self.tcp_flags_seen & 0x01)

    @property
    def has_rst(self) -> bool:
        return bool(self.tcp_flags_seen & 0x04)

    @property
    def is_terminated(self) -> bool:
        return self.has_fin or self.has_rst
