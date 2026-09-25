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

        In 5-tuple mode a packet whose reversed 5-tuple matches an active flow is attached
        to that flow as its reverse direction, so each flow measures whether both halves of
        the conversation are visible. 4-tuple keys carry no source port and cannot be
        reversed; those flows only ever see one direction.

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
        is_rev = False
        if self.mode == "5tuple" and key_tuple not in self._active_flows:
            rev_tuple = (pkt.dst_ip, dst_port, pkt.src_ip, src_port, pkt.protocol)
            if rev_tuple in self._active_flows:
                key_tuple, is_rev = rev_tuple, True

        flushed_records: List[FlowRecord] = []

        if key_tuple in self._active_flows:
            # Move to end (mark as recently used)
            flow = self._active_flows[key_tuple]
            self._active_flows.move_to_end(key_tuple)

            # Check Active Timeout
            if (pkt.timestamp - flow.start_time) >= self.active_timeout:
                flow.is_active_expired = True
                flushed_records.append(flow)

                # Start new flow window for same key, keeping the original orientation
                flow = FlowRecord(
                    flow_key=flow.flow_key, start_time=pkt.timestamp, last_time=pkt.timestamp,
                    fwd_is_responder=flow.fwd_is_responder,
                    icmp_type=flow.icmp_type, icmp_code=flow.icmp_code,
                )
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

            flow = FlowRecord(
                flow_key=key_obj, start_time=pkt.timestamp, last_time=pkt.timestamp,
                fwd_is_responder=_looks_like_responder(pkt),
                icmp_type=pkt.icmp_type, icmp_code=pkt.icmp_code,
            )
            self._active_flows[key_tuple] = flow

        # Accumulate metrics
        flow.packet_count += 1
        flow.total_bytes += pkt.packet_len
        flow.packet_sizes.append(pkt.packet_len)
        _accumulate_direction(flow, pkt, is_rev)

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


_SYN, _ACK = 0x02, 0x10
_ICMP_REPLY_TYPES = {0, 14, 16, 18}   # echo, timestamp, info, address-mask replies
_ICMP6_REPLY_TYPES = {129}             # echo reply


def _looks_like_responder(pkt: PacketMetadata) -> bool:
    """Heuristic: does the packet that opened a flow come from the responder side?

    ponytail: header heuristics only; a mid-stream capture between two ephemeral ports
    defaults to "initiator". Only affects the forward_only/reverse_only label of one-sided
    flows, never whether reverse_seen is true.
    """
    if pkt.tcp_flags is not None and pkt.tcp_flags & _SYN:
        return bool(pkt.tcp_flags & _ACK)
    if pkt.dns_is_response is not None:
        return pkt.dns_is_response
    if pkt.protocol == "ICMP" and pkt.icmp_type is not None:
        return pkt.icmp_type in _ICMP_REPLY_TYPES
    if pkt.protocol == "ICMPv6" and pkt.icmp_type is not None:
        return pkt.icmp_type in _ICMP6_REPLY_TYPES
    if pkt.src_port is not None and pkt.dst_port is not None:
        return pkt.src_port < 1024 <= pkt.dst_port
    return False


def _accumulate_direction(flow: FlowRecord, pkt: PacketMetadata, is_rev: bool) -> None:
    """Per-direction counters, handshake timing and DNS response codes."""
    flags = pkt.tcp_flags or 0
    if is_rev:
        flow.rev_packets += 1
        flow.rev_bytes += pkt.packet_len
        flow.rev_tcp_flags |= flags
    else:
        flow.fwd_packets += 1
        flow.fwd_bytes += pkt.packet_len
        flow.fwd_tcp_flags |= flags

    if flags & _SYN and not flags & _ACK and flow.syn_ts is None:
        flow.syn_ts, flow.syn_rev = pkt.timestamp, is_rev
    if flags & _SYN and flags & _ACK and flow.synack_ts is None:
        flow.synack_ts, flow.synack_rev = pkt.timestamp, is_rev

    if pkt.dns_is_response:
        flow.dns_responses += 1
        if pkt.dns_rcode == 3:  # NXDOMAIN
            flow.dns_nxdomain += 1
