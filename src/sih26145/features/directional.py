"""Direction policy and flow-level features whose availability depends on what was captured.

Every accessor here is declared in feature_contract.toml. Reverse-dependent features check
the flow's runtime observability and raise UnavailableFeatureError instead of guessing.
"""

import ipaddress
import os
from typing import Any, Callable, Dict, Iterable, Optional

from sih26145.contract import UnavailableFeatureError, load_contract
from sih26145.flow.models import FlowRecord

DEFAULT_INTERNAL_CIDRS = ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "fc00::/7")
INTERNAL_CIDRS_ENV = "SIH26145_INTERNAL_CIDRS"


class NetworkPolicy:
    """Which addresses are inside the monitored enclave. Outbound = internal -> external."""

    def __init__(self, internal_cidrs: Optional[Iterable[str]] = None):
        cidrs = DEFAULT_INTERNAL_CIDRS if internal_cidrs is None else tuple(internal_cidrs)
        self.networks = tuple(ipaddress.ip_network(c.strip(), strict=False) for c in cidrs if c.strip())

    @classmethod
    def from_env(cls) -> "NetworkPolicy":
        raw = os.getenv(INTERNAL_CIDRS_ENV)
        return cls(raw.split(",") if raw else None)

    def is_internal(self, ip: str) -> bool:
        addr = ipaddress.ip_address(ip)
        return any(addr.version == n.version and addr in n for n in self.networks)


def flow_direction(flow: FlowRecord, policy: NetworkPolicy) -> str:
    """outbound | inbound | internal | external, for the flow key's src -> dst."""
    src_in = policy.is_internal(flow.flow_key.src_ip)
    dst_in = policy.is_internal(flow.flow_key.dst_ip)
    if src_in and not dst_in:
        return "outbound"
    if dst_in and not src_in:
        return "inbound"
    return "internal" if src_in else "external"


def egress_bytes(flow: FlowRecord, policy: NetworkPolicy) -> int:
    """Bytes observed leaving the enclave in this flow, whichever half carried them."""
    direction = flow_direction(flow, policy)
    if direction == "outbound":
        return flow.fwd_bytes
    if direction == "inbound":
        return flow.rev_bytes
    return 0


def _need_both_halves(flow: FlowRecord, name: str) -> None:
    if not flow.reverse_seen:
        raise UnavailableFeatureError(
            f"{name}: reverse direction not observed on this flow ({flow.observability_state})"
        )


def outbound_inbound_byte_ratio(flow: FlowRecord, policy: NetworkPolicy) -> Optional[float]:
    """Outbound / inbound bytes. None for flows that do not cross the enclave boundary."""
    _need_both_halves(flow, "outbound_inbound_byte_ratio")
    direction = flow_direction(flow, policy)
    if direction == "outbound":
        return flow.fwd_bytes / flow.rev_bytes
    if direction == "inbound":
        return flow.rev_bytes / flow.fwd_bytes
    return None


def tcp_handshake_completed(flow: FlowRecord, policy: NetworkPolicy) -> Optional[bool]:
    _need_both_halves(flow, "tcp_handshake_completed")
    if flow.flow_key.protocol != "TCP":
        return None
    return (flow.syn_ts is not None and flow.synack_ts is not None
            and flow.syn_rev != flow.synack_rev)


def tcp_rtt(flow: FlowRecord, policy: NetworkPolicy) -> Optional[float]:
    """Tap-observed SYN -> SYN-ACK delay; None if the handshake was not captured."""
    if not tcp_handshake_completed(flow, policy):
        return None
    return max(0.0, flow.synack_ts - flow.syn_ts)


def dns_nxdomain_rate(flow: FlowRecord, policy: NetworkPolicy) -> Optional[float]:
    if not flow.responder_seen:
        raise UnavailableFeatureError(
            f"dns_nxdomain_rate: resolver responses not observed on this flow ({flow.observability_state})"
        )
    return flow.dns_nxdomain / flow.dns_responses if flow.dns_responses else None


def tls_client_server_fp_pair(flow: FlowRecord, policy: NetworkPolicy) -> Optional[str]:
    """"<ja4>|<ja3s>" when both hellos were captured on this flow."""
    _need_both_halves(flow, "tls_client_server_fp_pair")
    if not flow.tls_ja4 or not flow.tls_ja3s:
        return None
    return f"{flow.tls_ja4[0]}|{flow.tls_ja3s[0]}"


FLOW_FEATURES: Dict[str, Callable[[FlowRecord, NetworkPolicy], Any]] = {
    "reverse_seen": lambda flow, policy: flow.reverse_seen,
    "flow_direction": flow_direction,
    "egress_bytes": egress_bytes,
    "outbound_inbound_byte_ratio": outbound_inbound_byte_ratio,
    "tcp_handshake_completed": tcp_handshake_completed,
    "tcp_rtt": tcp_rtt,
    "dns_nxdomain_rate": dns_nxdomain_rate,
    "tls_client_server_fp_pair": tls_client_server_fp_pair,
    "tls_ja3": lambda flow, policy: flow.tls_ja3[0] if flow.tls_ja3 else None,
    "tls_ja4": lambda flow, policy: flow.tls_ja4[0] if flow.tls_ja4 else None,
    "tls_ja3s": lambda flow, policy: flow.tls_ja3s[0] if flow.tls_ja3s else None,
}


def flow_feature(flow: FlowRecord, name: str, policy: NetworkPolicy) -> Any:
    """Contract-checked access to a flow-level feature."""
    load_contract().require(name)
    if name not in FLOW_FEATURES:
        raise KeyError(f"{name!r} is not a flow-level feature")
    return FLOW_FEATURES[name](flow, policy)
