"""Attack captures, one per detector, and the composed demo capture.

Addresses: victims and attackers inside the enclave use RFC1918 space; external peers use
the documentation ranges; spoofed flood sources are random public addresses.
"""

import base64
import random
from typing import Callable, Dict, List, Tuple

import dpkt

from sih26145.utils.benign_scenarios import T0, _web
from sih26145.utils.pcap_generator import (
    _upload, _write, create_ethernet_ip_packet as pkt, dns_message, tcp_session, tls_client_hello, tls_server_hello,
)

Packets = List[Tuple[float, bytes]]
SYN, RST_ACK = dpkt.tcp.TH_SYN, dpkt.tcp.TH_RST | dpkt.tcp.TH_ACK
RESOLVER = "10.0.0.53"


def ramnit_dga(seed: int, count: int) -> List[str]:
    """The Ramnit DGA (J. Bader, "The DGA of Ramnit", bin.re): a Park-Miller LCG draws a
    length of 8-19 and that many letters a-y; the next domain's seed is derived from the
    two LCG states around the length draw. Seed 0x79159C10 yields the published example
    list: knpqxlxcwtlvgrdyhd.com, nvlyffua.com, hgyudheedieibxy.com, ..."""
    state, domains = seed, []

    def draw(modulus: int) -> int:
        nonlocal state
        state = (16807 * (state % 127773) - 2836 * (state // 127773)) & 0xFFFFFFFF
        return state % modulus

    for _ in range(count):
        before = state
        length = draw(12) + 8
        after = state
        domains.append("".join(chr(ord("a") + draw(25)) for _ in range(length)) + ".com")
        product = before * after
        state = (product + product // 2**32) % 2**32
    return domains


def _public_ip(rng: random.Random) -> str:
    while True:
        a = rng.randrange(11, 223)
        if a not in (100, 127, 169, 172, 192, 198, 203):
            return f"{a}.{rng.randrange(256)}.{rng.randrange(256)}.{rng.randrange(1, 255)}"


def syn_flood(t0: float = T0) -> Packets:
    """500 spoofed sources SYN-flood one web server within 10 s; nothing answers."""
    rng, victim, out = random.Random(1), "10.50.0.10", []
    for i in range(500):
        src, t = _public_ip(rng), t0 + rng.uniform(0, 9)
        out += [(t + dt, pkt(src, victim, 1024 + i, 80, "TCP", b"", SYN)) for dt in (0.0, 1.0)]
    return out


def spoofed_flood(t0: float = T0) -> Packets:
    """hping3 --rand-source style: one machine sends 5,000 SYNs in 1 s to one web server, each
    from a new random public address and port. One sender, so every packet has the same TTL."""
    rng, victim = random.Random(10), "10.50.0.11"
    return [(t0 + i / 5000, pkt(_public_ip(rng), victim, rng.randrange(1024, 65536), 80, "TCP", b"", SYN))
            for i in range(5000)]


def udp_reflection(t0: float = T0) -> Packets:
    """200 open DNS/NTP/memcached reflectors send ~8 MB of unsolicited large responses to one
    internal host in 10 s (the attacker spoofed the victim's address in its requests)."""
    rng, victim, out = random.Random(2), "10.50.0.20", []
    for i in range(200):
        refl, port = _public_ip(rng), (53, 123, 11211)[i % 3]
        out += [(t0 + rng.uniform(0, 10), pkt(refl, victim, port, 3074, "UDP", b"R" * 1400)) for _ in range(30)]
    return out


def single_source_flood(t0: float = T0) -> Packets:
    """A web server with ~10 sessions/min for 6 min, then one external source sends ~15 MB of
    UDP at it in 20 s."""
    rng, srv, out = random.Random(9), "10.30.0.90", []
    for minute in range(6):
        for k in range(10):  # independent visit times: ordinary use has no schedule
            out += _web(t0 + minute * 60 + rng.uniform(0, 58), f"10.40.1.{k % 5 + 1}", srv, 43000 + minute * 10 + k)
    return out + [(t0 + 365 + i * 0.00187, pkt("198.51.100.66", srv, 40000, 9999, "UDP", b"F" * 1400))
                  for i in range(10700)]


def c2_beacon(t0: float = T0, jitter: float = 0.2, seed: int = 3, period: float = 30.0) -> Packets:
    """20 check-ins to one external server, each a new connection, every `period` seconds with
    uniform +/-`jitter` on each interval (coefficient of variation = jitter / sqrt(3))."""
    rng, bot, cnc, out, t = random.Random(seed), "192.168.1.70", "203.0.113.66", [], t0
    for i in range(20):
        out += tcp_session(t, bot, cnc, 45000 + i, 443, [b"GET /updates HTTP/1.1\r\n\r\n"], [b"c" * 300])
        t += period * (1 + rng.uniform(-jitter, jitter))
    return out


def dga_lookups(t0: float = T0, with_responses: bool = True) -> Packets:
    """An infected host tries 200 Ramnit DGA domains in under a minute; the resolver answers
    NXDOMAIN (when its responses are in the capture)."""
    rng, bot, out = random.Random(4), "192.168.1.80", []
    names = ramnit_dga(0x79159C10, 200)
    for i, t in enumerate(sorted(t0 + rng.uniform(0, 50) for _ in range(200))):
        name = names[i]
        out.append((t, pkt(bot, RESOLVER, 20000 + i, 53, "UDP", dns_message(name, qid=i))))
        if with_responses:
            out.append((t + 0.01, pkt(RESOLVER, bot, 53, 20000 + i, "UDP",
                                      dns_message(name, qid=i, response=True, rcode=3))))
    return out


def dns_tunnel(t0: float = T0) -> Packets:
    """iodine-style tunnel: 200 queries with 48-character base32 labels under one domain."""
    rng, host, out = random.Random(6), "192.168.1.81", []
    for i, t in enumerate(sorted(t0 + rng.uniform(0, 50) for _ in range(200))):
        label = base64.b32encode(rng.randbytes(30)).decode().lower()
        name = f"{label}.t.tunnel.example.org"
        out.append((t, pkt(host, RESOLVER, 25000 + i, 53, "UDP", dns_message(name, qid=i, qtype=dpkt.dns.DNS_TXT))))
        out.append((t + 0.01, pkt(RESOLVER, host, 53, 25000 + i, "UDP", dns_message(
            name, qid=i, qtype=dpkt.dns.DNS_TXT, response=True, answer_bytes=120))))
    return out


RARE_HELLO = dict(sni="cdn-update.example.com", ciphers=[0x002F, 0x0035, 0x000A, 0x0005],
                  extensions=[0x0000, 0x000A, 0x000B])


def tls_beacon(t0: float = T0) -> Packets:
    """30 short TLS sessions to one server, every ~10 s, from a client library no one else in
    the enclave uses (a rare JA4)."""
    rng, bot, srv, out, t = random.Random(8), "192.168.1.90", "203.0.113.77", [], t0
    for i in range(30):
        out += tcp_session(t, bot, srv, 46000 + i, 443,
                           [tls_client_hello(**RARE_HELLO), b"\x17\x03\x03" + b"e" * 200],
                           [tls_server_hello(0x002F), b"\x17\x03\x03" + b"f" * 300])
        t += 10 * (1 + rng.uniform(-0.1, 0.1))
    return out


def port_sweep(t0: float = T0, target: str = "10.0.0.200") -> Packets:
    """SYN scan of ports 1-100 on one host; closed ports answer RST/ACK."""
    scanner, out = "192.168.1.52", []
    for port in range(1, 101):
        t = t0 + port * 0.005
        out.append((t, pkt(scanner, target, 40000, port, "TCP", b"", SYN)))
        out.append((t + 0.0005, pkt(target, scanner, port, 40000, "TCP", b"", RST_ACK)))
    return out


def exfil_upload(t0: float = T0) -> Packets:
    return _upload(t0, "192.168.1.51", "203.0.113.99", 51515, 800, bidirectional=True)


ATTACK_SCENARIOS: Dict[str, Callable[..., Packets]] = {
    "syn_flood": syn_flood,
    "spoofed_flood": spoofed_flood,
    "udp_reflection": udp_reflection,
    "single_source_flood": single_source_flood,
    "c2_beacon": c2_beacon,
    "dga_lookups": dga_lookups,
    "dns_tunnel": dns_tunnel,
    "tls_beacon": tls_beacon,
    "port_sweep": port_sweep,
    "exfil_upload": exfil_upload,
}


def demo_packets() -> Packets:
    """Every attack scenario in one ~11-minute capture, staggered in time."""
    offsets = {"single_source_flood": 0, "c2_beacon": 10, "syn_flood": 30, "udp_reflection": 60,
               "dga_lookups": 90, "dns_tunnel": 150, "tls_beacon": 200, "port_sweep": 300, "exfil_upload": 400}
    return sum((ATTACK_SCENARIOS[name](T0 + dt) for name, dt in offsets.items()), [])


def readdress(packets: Packets, mapping: Dict[str, str]) -> Packets:
    """The same packets with IPv4 addresses swapped per `mapping` (checksums recomputed)."""
    import socket
    raw = {socket.inet_aton(a): socket.inet_aton(b) for a, b in mapping.items()}
    out = []
    for t, frame in packets:
        eth = dpkt.ethernet.Ethernet(frame)
        ip = eth.data
        if isinstance(ip, dpkt.ip.IP) and (ip.src in raw or ip.dst in raw):
            ip.src, ip.dst = raw.get(ip.src, ip.src), raw.get(ip.dst, ip.dst)
            ip.sum = 0
            if isinstance(ip.data, (dpkt.tcp.TCP, dpkt.udp.UDP)):
                ip.data.sum = 0
            frame = bytes(eth)
        out.append((t, frame))
    return out


def one_host_chain(t0: float = T0, host: str = "192.168.1.66") -> Packets:
    """Recon, then C2, then exfiltration, all from one internal host: the scripted campaign."""
    return (readdress(port_sweep(t0), {"192.168.1.52": host})
            + readdress(c2_beacon(t0 + 60), {"192.168.1.70": host})
            + readdress(exfil_upload(t0 + 700), {"192.168.1.51": host}))


def write_attack(name: str, path: str, **kwargs) -> int:
    return _write(path, ATTACK_SCENARIOS[name](**kwargs))
