"""Community ID v1 flow hash (https://github.com/corelight/community-id-spec).

Symmetric: A->B and B->A hash identically, so an alert's flow_id joins directly to the
`community_id` column Zeek and Suricata emit.
"""

import base64
import hashlib
import ipaddress
import struct
from typing import Optional

PROTO_NUMBERS = {"ICMP": 1, "TCP": 6, "UDP": 17, "ICMPv6": 58, "SCTP": 132}

# ICMP type -> counterpart type (Zeek's ICMP4_counterpart / ICMP6_counterpart).
_ICMP4_PAIRS = {8: 0, 0: 8, 13: 14, 14: 13, 15: 16, 16: 15, 10: 9, 9: 10, 17: 18, 18: 17}
_ICMP6_PAIRS = {128: 129, 129: 128, 133: 134, 134: 133, 135: 136, 136: 135,
                130: 131, 131: 130, 139: 140, 140: 139, 144: 145, 145: 144}


def community_id(
    proto: str, src_ip: str, dst_ip: str,
    src_port: Optional[int] = None, dst_port: Optional[int] = None, seed: int = 0,
) -> str:
    """Community ID v1 string. For ICMP/ICMPv6 pass type as src_port and code as dst_port."""
    proto_num = PROTO_NUMBERS.get(proto)
    if proto_num is None:
        proto_num = int(proto.removeprefix("OTHER_")) if proto.startswith("OTHER_") else 0
    saddr = ipaddress.ip_address(src_ip).packed
    daddr = ipaddress.ip_address(dst_ip).packed
    has_ports = proto_num in (1, 6, 17, 58, 132)
    sport, dport = src_port or 0, dst_port or 0

    one_way = False
    if proto_num in (1, 58):
        pairs = _ICMP4_PAIRS if proto_num == 1 else _ICMP6_PAIRS
        if sport in pairs:
            dport = pairs[sport]
        else:
            one_way = True  # sport = type, dport = code, keep direction

    if not one_way and (saddr, sport) > (daddr, dport):
        saddr, daddr, sport, dport = daddr, saddr, dport, sport

    data = struct.pack("!H", seed) + saddr + daddr + struct.pack("!BB", proto_num, 0)
    if has_ports:
        data += struct.pack("!HH", sport, dport)
    return "1:" + base64.b64encode(hashlib.sha1(data).digest()).decode("ascii")
