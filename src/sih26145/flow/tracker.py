"""Unidirectional Flow Tracker and State Engine for SIH26145."""

from collections import OrderedDict
from typing import List, Optional, Dict, Tuple
from sih26145.ingest.models import PacketMetadata
from sih26145.flow.models import FlowKey, FlowRecord


class FlowTracker:
    """Manages unidirectional active flow state tables, timeouts, and eviction."""

    def __init__(
        self,
        mode: str = "5tuple",
        active_timeout: float = 60.0,
        idle_timeout: float = 15.0,
        max_flows: int = 100000,
    ):
        if mode not in ("5tuple", "4tuple"):
            raise ValueError("FlowTracker mode must be '5tuple' or '4tuple'")
        self.mode = mode
        self.active_timeout = active_timeout
        self.idle_timeout = idle_timeout
        self.max_flows = max_flows
        
        # OrderedDict used as LRU table: key -> FlowRecord
        self._active_flows: OrderedDict[Tuple, FlowRecord] = OrderedDict()

    def process_packet(self, pkt: PacketMetadata) -> List[FlowRecord]:
        """Ingest single PacketMetadata into active flow state table.
        
        Returns a list of flushed FlowRecords (e.g. triggered by Active Timeout or LRU Eviction).
        """
        if not pkt.src_ip or not pkt.dst_ip or not pkt.protocol:
            return []

        src_port = pkt.src_port or 0
        dst_port = pkt.dst_port or 0

        # Construct FlowKey based on configured mode
        if self.mode == "5tuple":
            key_obj = FlowKey(
                src_ip=pkt.src_ip,
                src_port=src_port,
                dst_ip=pkt.dst_ip,
                dst_port=dst_port,
                protocol=pkt.protocol,
            )
        else:
            key_obj = FlowKey(
                src_ip=pkt.src_ip,
                dst_ip=pkt.dst_ip,
                dst_port=dst_port,
                protocol=pkt.protocol,
            )

        key_tuple = key_obj.to_tuple()
        flushed_records: List[FlowRecord] = []

        if key_tuple in self._active_flows:
            # Move to end (mark as recently used)
            flow = self._active_flows[key_tuple]
            self._active_flows.move_to_end(key_tuple)

            # Check Active Timeout
            if (pkt.timestamp - flow.start_time) >= self.active_timeout:
                flow.is_active_expired = True
                flushed_records.append(flow)
                
                # Start new flow window for same key
                flow = FlowRecord(flow_key=key_obj, start_time=pkt.timestamp, last_time=pkt.timestamp)
                self._active_flows[key_tuple] = flow
            else:
                # Calculate Inter-Arrival Time
                iat = max(0.0, pkt.timestamp - flow.last_time)
                flow.inter_arrival_times.append(iat)
                flow.last_time = max(flow.last_time, pkt.timestamp)

        else:
            # Check LRU Eviction capacity bound
            if len(self._active_flows) >= self.max_flows:
                evicted_key, evicted_flow = self._active_flows.popitem(last=False)
                evicted_flow.is_evicted = True
                flushed_records.append(evicted_flow)

            flow = FlowRecord(flow_key=key_obj, start_time=pkt.timestamp, last_time=pkt.timestamp)
            self._active_flows[key_tuple] = flow

        # Accumulate metrics
        flow.packet_count += 1
        flow.total_bytes += pkt.packet_len
        flow.packet_sizes.append(pkt.packet_len)

        if pkt.tcp_flags is not None:
            flow.tcp_flags_seen |= pkt.tcp_flags

        if pkt.dns_query_name and pkt.dns_query_name not in flow.dns_queries:
            flow.dns_queries.append(pkt.dns_query_name)

        if pkt.tls_sni and pkt.tls_sni not in flow.tls_snis:
            flow.tls_snis.append(pkt.tls_sni)

        return flushed_records

    def flush_expired(self, current_time: float) -> List[FlowRecord]:
        """Flush active flows that have exceeded the Idle Timeout threshold."""
        expired_keys = []
        flushed_records = []

        for key_tuple, flow in list(self._active_flows.items()):
            if (current_time - flow.last_time) >= self.idle_timeout:
                flow.is_idle_expired = True
                flushed_records.append(flow)
                expired_keys.append(key_tuple)

        for key_tuple in expired_keys:
            del self._active_flows[key_tuple]

        return flushed_records

    def get_active_flow_count(self) -> int:
        return len(self._active_flows)
