"""Benign captures that the audit showed tripping detectors (AUDIT A1-A4, D3, D4), plus the
counterexamples each rewired rule needs. Every scenario must raise zero alerts.

Internal hosts use RFC1918 space; "external" hosts use the documentation ranges
203.0.113.0/24 and 198.51.100.0/24. T0 sits on a 60 s window boundary so windowed
features line up with the scenario's minutes.
"""

import random
from typing import Callable, Dict, List, Tuple

import dpkt

from sih26145.utils.pcap_generator import (
    _write, create_ethernet_ip_packet as pkt, dns_message, tcp_session, tls_client_hello, tls_server_hello,
)

T0 = 1_790_000_040.0  # divisible by 60
Packets = List[Tuple[float, bytes]]
A, PA = dpkt.tcp.TH_ACK, dpkt.tcp.TH_PUSH | dpkt.tcp.TH_ACK

# A mail/stub client hello: common ciphers, no GREASE; a browser-like one for web sessions.
CLIENT_CIPHERS = [0x1301, 0x1302, 0x1303, 0xC02B, 0xC02F, 0xC02C, 0xC030, 0xCCA9, 0xCCA8, 0xC013, 0xC014]
CLIENT_EXTS = [0x0000, 0x0017, 0xFF01, 0x000A, 0x000B, 0x0023, 0x0010, 0x000D, 0x002B, 0x0033]


def ping_c6() -> Packets:
    """`ping -c 6`: six 98-byte echo requests one second apart, each answered."""
    c, s, out = "192.168.1.20", "203.0.113.53", []
    for i in range(6):
        out.append((T0 + i, pkt(c, s, 0, 0, "ICMP", b"p" * 56, icmp_seq=i + 1)))
        out.append((T0 + i + 0.02, pkt(s, c, 0, 0, "ICMP", b"p" * 56, icmp_type=0, icmp_seq=i + 1)))
    return out


def rtp_stream() -> Packets:
    """One 10 s G.711 RTP stream: a 172-byte payload every 20 ms (AUDIT A2)."""
    a, b = "192.168.1.21", "203.0.113.40"
    return [(T0 + i * 0.02, pkt(a, b, 16384, 16386, "UDP", b"r" * 172)) for i in range(500)]


def dns_lookups() -> Packets:
    """One www.google.com lookup and one CDN-style hostname lookup, both answered."""
    c, r, out = "192.168.1.22", "10.0.0.53", []
    for i, name in enumerate(("www.google.com", "d1a2b3c4e5f6g7.cloudfront.net")):
        out.append((T0 + i, pkt(c, r, 53001 + i, 53, "UDP", dns_message(name, qid=i + 1))))
        out.append((T0 + i + 0.01, pkt(r, c, 53, 53001 + i, "UDP", dns_message(name, qid=i + 1, response=True))))
    return out


def tls_mail_and_dot() -> Packets:
    """IMAPS (993), SMTPS (465) and DNS-over-TLS (853) sessions to an external provider."""
    c, s, out = "192.168.1.23", "203.0.113.25", []
    for i, (port, sni, alpn) in enumerate(((993, "imap.example.net", b""), (465, "smtp.example.net", b""),
                                           (853, "dns.example.net", b"dot"))):
        hello = tls_client_hello(sni, CLIENT_CIPHERS, CLIENT_EXTS, alpn)
        out += tcp_session(T0 + i * 5, c, s, 50200 + i, port, [hello, b"\x17\x03\x03" + b"a" * 300],
                           [tls_server_hello(), b"\x17\x03\x03" + b"b" * 1200, b"\x17\x03\x03" + b"b" * 400])
    return out


def back_to_back() -> Packets:
    """Two full-size HTTPS segments 100 microseconds apart (AUDIT A1: pps = 20,000)."""
    s, c = "203.0.113.80", "192.168.1.24"
    return [(T0 + i * 0.0001, pkt(s, c, 443, 50555, "TCP", b"d" * 1460, PA)) for i in range(2)]


def one_way_download() -> Packets:
    """Only the server->client half of a 1.5 MB HTTPS download at 1.5 MB/s (AUDIT A3)."""
    s, c = "203.0.113.90", "192.168.1.25"
    return [(T0 + i * 0.001, pkt(s, c, 443, 51000, "TCP", b"d" * 1460, PA)) for i in range(1000)]


def failed_tcp() -> Packets:
    """One connection attempt that is never answered: SYN plus two retransmits."""
    c, s = "192.168.1.26", "203.0.113.99"
    return [(T0 + dt, pkt(c, s, 52000, 443, "TCP", b"", dpkt.tcp.TH_SYN)) for dt in (0.0, 1.0, 3.0)]


def monitoring_poller() -> Packets:
    """A metrics server scraping 50 hosts on TCP 9100 every 30 s, 12 rounds, new connection each."""
    mon, out = "10.10.0.5", []
    for rnd in range(12):
        for h in range(50):
            t = T0 + rnd * 30 + h * 0.5
            out += tcp_session(t, mon, f"10.20.0.{h + 1}", 40000 + rnd * 50 + h, 9100,
                               [b"GET /metrics HTTP/1.1\r\n\r\n"], [b"m" * 1400, b"m" * 1400, b"m" * 600])
    return out


def flash_crowd() -> Packets:
    """An internal web server with a steady ~10 sessions/min for 6 min, then 150 distinct
    clients complete sessions within one minute (legitimate surge, not a flood)."""
    rng, srv, out = random.Random(3), "10.30.0.80", []
    for minute in range(6):
        for k in range(10):  # independent visit times: ordinary use has no schedule
            out += _web(T0 + minute * 60 + rng.uniform(0, 58), f"10.40.0.{k + 1}", srv, 41000 + minute * 10 + k)
    for k in range(150):
        out += _web(T0 + 360 + 5 + k * 0.3, f"10.41.{k // 200}.{k % 200 + 1}", srv, 42000 + k)
    return out


def _web(t: float, client: str, srv: str, sport: int) -> Packets:
    return tcp_session(t, client, srv, sport, 443, [b"q" * 500], [b"s" * 1400, b"s" * 1400, b"s" * 800])


def busy_resolver() -> Packets:
    """An internal resolver sends ~2,000 queries to 300 upstream servers in one minute and
    receives DNSSEC-sized (~1.2 KB) answers. Both halves captured: every answer is solicited."""
    rng, res, out = random.Random(7), "10.0.0.53", []
    words = ("www", "mail", "api", "cdn", "static", "img", "login", "docs", "news", "shop")
    for i in range(2000):
        up = f"{'198.51.100' if i % 2 else '203.0.113'}.{rng.randrange(1, 151)}"
        name, t = f"{words[i % 10]}.site{i}.com", T0 + rng.uniform(0, 59)
        out.append((t, pkt(res, up, 20000 + i, 53, "UDP", dns_message(name, qid=i))))
        out.append((t + 0.02, pkt(up, res, 53, 20000 + i, "UDP",
                                  dns_message(name, qid=i, response=True, answer_bytes=1100))))
    return out


def mail_ptr_burst() -> Packets:
    """A mail server checks 60 connecting IPs with PTR lookups in one minute. Lookups follow
    SMTP connections, so they arrive at random times, not on a clock."""
    rng, mta, res, out = random.Random(11), "10.0.0.25", "10.0.0.53", []
    for i, t in enumerate(sorted(T0 + rng.uniform(0, 55) for _ in range(60))):
        ip = [rng.randrange(1, 255) for _ in range(4)]
        name = ".".join(map(str, reversed(ip))) + ".in-addr.arpa"
        out.append((t, pkt(mta, res, 30000 + i, 53, "UDP", dns_message(name, qid=i, qtype=dpkt.dns.DNS_PTR))))
        out.append((t + 0.01, pkt(res, mta, 53, 30000 + i, "UDP",
                                  dns_message(name, qid=i, qtype=dpkt.dns.DNS_PTR, response=True))))
    return out


def cdn_heavy_browsing() -> Packets:
    """A browser resolving 50 distinct CDN-style hostnames (random-looking first labels) while
    loading pages; every one resolves. Counterexample for the DGA rule's NXDOMAIN branch."""
    rng, c, r, out = random.Random(5), "192.168.1.27", "10.0.0.53", []
    alphabet = "abcdefghijklmnopqrstuvwxyz0123456789"
    for i, t in enumerate(sorted(T0 + rng.uniform(0, 40) for _ in range(50))):
        name = "".join(rng.choice(alphabet) for _ in range(14)) + (".cloudfront.net" if i % 2 else ".akamaized.net")
        out.append((t, pkt(c, r, 54000 + i, 53, "UDP", dns_message(name, qid=i))))
        out.append((t + 0.01, pkt(r, c, 53, 54000 + i, "UDP", dns_message(name, qid=i, response=True))))
    return out


BENIGN_SCENARIOS: Dict[str, Callable[[], Packets]] = {
    "ping_c6": ping_c6,
    "rtp_stream": rtp_stream,
    "dns_lookups": dns_lookups,
    "tls_mail_and_dot": tls_mail_and_dot,
    "back_to_back": back_to_back,
    "one_way_download": one_way_download,
    "failed_tcp": failed_tcp,
    "monitoring_poller": monitoring_poller,
    "flash_crowd": flash_crowd,
    "busy_resolver": busy_resolver,
    "mail_ptr_burst": mail_ptr_burst,
    "cdn_heavy_browsing": cdn_heavy_browsing,
}


def write_benign(name: str, path: str) -> int:
    return _write(path, BENIGN_SCENARIOS[name]())
