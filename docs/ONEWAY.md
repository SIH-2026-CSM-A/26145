# Strict one-way replay

What SAAKSHI still detects when the capture holds **one direction of the boundary only**.
Measured on 2026-09-28 with `scripts/oneway.py`, after the fast lane was added. The numbers are
reported as they came out. No threshold was changed because of them.

## Method

`scripts/oneway.py rewrite IN|OUT` copies a capture and keeps only:
- **IN:** packets from an external source to an internal destination;
- **OUT:** packets from an internal source to an external destination.

"Internal" is the configured `SIH26145_INTERNAL_CIDRS` (`NetworkPolicy`):
- for `demo/demo.pcap`, the demo's own list `147.32.0.0/16,10.0.0.0/8,192.168.0.0/16,172.16.0.0/12`
  (as `scripts/demo.sh`);
- for the 12 benign captures, the default (RFC1918 + `fc00::/7`), as their tests use.

A packet between two internal hosts, or between two external ones, crosses no boundary and is in
neither variant. Timestamps, frames and wire lengths are kept, so a truncated CTU-13 record stays
truncated. Each variant, and the original ("both"), runs through the full pipeline (`process_pcap`:
fast lane, flow lane, models, correlation). Raw results: `26145-data/oneway/table.json`.

Reproduce: `uv run python scripts/oneway.py table --json table.json`.

## demo.pcap, per threat class

`demo/demo.pcap` holds 102,333 packets. IN keeps 39,663 and OUT keeps 23,372. The rest are between
internal hosts, mostly the CTU-13 background inside 147.32.0.0/16 plus the demo's internal resolver
and scan target. Only alerts on the demo's attack endpoints are counted here; the CTU-13 normal
hosts are in the next section. `*` = a provisional fast-lane alert.

| PS | Attack in the demo | Both directions | IN only | OUT only |
|---|---|---|---|---|
| (a) DDoS | SYN flood on 10.50.0.10 from spoofed external sources | **fires**: `RULE_DDOS_SYN_FLOOD` (forward_only) + `RULE_FAST_SYN_FLOOD`* | **fires**: the same two alerts, same states | **does not fire**: the flood is inbound only, so none of it is in OUT |
| (b) C2 | beacon 192.168.1.66 ↔ 203.0.113.66 | **fires**: `RULE_C2_PERIODIC_FLOWS` (bidirectional) | **fires** on the server's replies alone: `RULE_C2_PERIODIC_FLOWS` (reverse_only) | **fires**: `RULE_C2_PERIODIC_FLOWS` (forward_only) |
| (c) DGA, DNS tunnel | 192.168.1.66 via the internal resolver 10.0.0.53 | **fires**: `RULE_DGA_NXDOMAIN_HIGH_ENTROPY`, `RULE_DNS_TUNNEL_VOLUME_LENGTH` (bidirectional) | **does not fire**: host and resolver are both internal, so none of it crosses the boundary | **does not fire**: same reason |
| (d) Encrypted | rare-JA4 TLS sessions 192.168.1.66 → 203.0.113.77 | **fires**: `RULE_TLS_RARE_JA4_REPEATED` (bidirectional) | **does not fire**: the ClientHello (client half) is outbound; the JA4 is absent | **fires**: `RULE_TLS_RARE_JA4_REPEATED` (forward_only) |
| (e) Recon | SYN scan 192.168.1.66 → 10.0.0.200 | **fires**: `RULE_RECON_FANOUT_SYN_ONLY` + `RULE_FAST_SCAN`* | **does not fire**: both hosts internal | **does not fire**: both hosts internal |
| (f) Exfiltration | 1.2 MB upload 192.168.1.66 → 203.0.113.99 | **fires**: `RULE_EXFIL_OUTBOUND_RATIO` (bidirectional) | **does not fire**: the upload is the egress half, absent from IN | **degraded**: `RULE_EXFIL_EGRESS_BASELINE` (forward_only), substituting for the unavailable ratio (`substitutions` names it). It also fired 3 times on the TLS beacon's flows to 203.0.113.77: the right host, the wrong class |

Observability of every alert above: "both" 6 bidirectional, 1 forward_only (the SYN flood) and
2 provisional (null, since the fast lane has no flows); IN 1 forward_only, 1 reverse_only, 1
provisional; OUT 6 forward_only.

**Reading it:**
- Nothing fired in a variant that did not carry the attack's packets. Every "does not fire"
  above is an attack whose packets are not in that direction. For (c) and (e) the traffic never
  crosses the boundary in this capture. That is a property of the demo's layout (internal
  resolver, internal scan target), not a claim that DGA or scans are invisible one-way.
- Where the attack's own packets were present, it was detected: (a) IN, (b) both variants,
  (d) OUT and (f) OUT. (f) fired on its substitute path, as designed for one-sided flows.

## Alerts on the CTU-13 normal hosts (real background)

The demo's background is every packet to or from the hand-checked **normal** hosts of CTU-13
scenario 5, so any alert on those hosts is a false alarm by the CTU labels.

| Variant | Alerts on 147.32.x normal hosts |
|---|---|
| Both | 3: `RULE_C2_PERIODIC_FLOWS` (bidirectional) |
| IN | 9: `RULE_C2_PERIODIC_FLOWS` (7 reverse_only, 2 forward_only) |
| OUT | **94**: 3 `RULE_C2_PERIODIC_FLOWS` (forward_only), and **91 `RULE_EXFIL_EGRESS_BASELINE`** (forward_only) on three hosts (46 on 147.32.84.134, 29 on .164, 16 on .170) |

The exfiltration substitute path (egress z-score ≥ 3 toward a destination no other internal host
has used) is **noisy on an outbound-only capture of real traffic**. With both halves, these flows
take the ratio path and stay quiet. With only the outbound half, ordinary uploads by three
workstations raise 91 HIGH alerts in about 11 minutes of capture. The rule raises one alert per
flow (it has no entity dedupe). This is a measured weakness, listed in TODO. It was not tuned
here.

## The 12 benign captures

Several benign captures run entirely between internal hosts, so a variant can be empty ("kept 0").
Alerts in "both" are 0 for all twelve (the regression tests).

| Capture | Packets | IN kept | IN alerts | OUT kept | OUT alerts |
|---|---|---|---|---|---|
| `ping_c6` | 12 | 6 | 0 | 6 | 0 |
| `rtp_stream` | 500 | 0 | 0 | 500 | 0 |
| `dns_lookups` | 4 | 0 | 0 | 0 | 0 |
| `tls_mail_and_dot` | 33 | 15 | 0 | 18 | 0 |
| `back_to_back` | 2 | 2 | 0 | 0 | 0 |
| `one_way_download` | 1,000 | 1,000 | 0 | 0 | 0 |
| `failed_tcp` | 3 | 0 | 0 | 3 | 0 |
| `monitoring_poller` | 6,000 | 0 | 0 | 0 | 0 |
| `flash_crowd` | 2,100 | 0 | 0 | 0 | 0 |
| `busy_resolver` | 4,000 | 2,000 | **1**: `RULE_DDOS_UDP_REFLECTION` (reverse_only) | 2,000 | 0 |
| `mail_ptr_burst` | 120 | 0 | 0 | 0 | 0 |
| `cdn_heavy_browsing` | 100 | 0 | 0 | 0 | 0 |

**One false alarm in 24 benign runs.** `busy_resolver` IN keeps only the upstream servers' answers
to the internal resolver 10.0.0.53. Its queries were outbound, so they are gone, and the answers
look unsolicited. The flow lane's reflection rule fires once. Its contract row
(`dst_reflector_flows_w`, degraded) already states this: "on a capture holding only inbound halves
genuine answers are counted too". This run measures it. The fast lane's reflection rule did not
fire: about 33 answers per second is 40 kB/s, far under its 500 kB/s floor.

## What this does not cover

- Captures where the resolver or the scan target is external. The demo has none, so (c) and (e)
  are untested one-way here.
- Live asymmetric routing, where one link mixes one-sided and two-sided flows. Each variant here
  is one-sided for every flow.
