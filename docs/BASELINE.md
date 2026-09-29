# Baseline: Suricata on the same captures

This page compares SAAKSHI with a standard receive-side IDS on the same two captures. Measured on
2026-09-29 on the development laptop (docs/BENCHMARK.md), with `scripts/baseline.py`. **Suricata
ran untuned, with the default ET Open ruleset.** Nothing in SAAKSHI or Suricata was changed because
of these numbers. Suricata ran on the development machine only; it is not part of the sensor.

## Versions

| | |
|---|---|
| Suricata | 8.0.3 RELEASE, Ubuntu 26.04 `apt` package (`suricata 1:8.0.3-1`) |
| Ruleset | ET Open via `suricata-update` 1.3.7, default sources, no enable/disable/modify files. Downloaded 2026-09-29 10:44 UTC; newest rule `updated_at 2026_09_28`. `suricata.rules` sha256 `046ee71cd044daca383161a44006c07f3ab0146e5369f66a400d33e5156af04f` |
| Rules loaded | 53,015 (0 failed): the enabled ET Open rules plus Suricata's own decoder, stream and app-layer event rules, which `suricata-update` merges into the same file |
| Suricata config | `/etc/suricata/suricata.yaml` as installed |
| SAAKSHI | this repository at the commit that adds this page; models `ctu13x5-lgbm-if-1.0.0`, ruleset 2.1.0 |
| Zeek | **not run.** The official OBS repository has `zeek-lts` 8.0.10 for xUbuntu 26.04, but it was not installed within the 20-minute limit set for it (15:31–15:51 UTC; the install needs sudo). No Zeek figure is claimed |

## Captures

1. **`demo/demo.pcap`**, 11 minutes (sha256 in `demo/ATTRIBUTION.md`):
   - real background: every packet of the CTU-13 scenario 5 normal hosts, header-only as published;
   - 7 generated attacks: 6 stages from one enclave host (192.168.1.66), plus a SYN flood on
     10.50.0.10.
2. **Outbound-only:** `scripts/oneway.py rewrite OUT` of (1), internal → external packets only
   (`docs/ONEWAY.md`).

**Why there are two versions of each.** The attack generator writes every TCP packet with a
fixed `seq=1000, ack=2000` (`src/sih26145/utils/pcap_generator.py`). SAAKSHI does not read
sequence numbers. Suricata's stream engine does: it rejects those sessions, so its application-layer
parsers, and the ET Open rules that sit on them, never see the C2, TLS or exfiltration payloads. On
`demo.pcap` as-is Suricata logged no TLS and no HTTP event. That is unfair to Suricata.

So `baseline.py` also writes a **stream-valid copy**:
- it rewrites only the generated TCP packets (2,540 packets in 651 connections, identified by the
  demo host 192.168.1.66 or the flood target 10.50.0.10);
- each gets consistent per-connection sequence and acknowledgement numbers and a recomputed
  checksum;
- timestamps, sizes, flags and payloads are unchanged, and background packets are copied byte for
  byte.

Its outbound-only variant is made from it the same way. **The stream-valid pair is the main
comparison.** The as-is pair follows, second.

Two things the stream-valid copy does not fix, both from the generator's simplified payloads:
- the C2 sessions carry HTTP-like text with no `Host` header;
- the TLS sessions' application-data records have a malformed length, so Suricata reports
  `INVALID_RECORD_LENGTH` on the server half.

## Commands

```bash
DEMO=147.32.0.0/16,10.0.0.0/8,192.168.0.0/16,172.16.0.0/12      # the demo's internal list (scripts/demo.sh)
uv run python scripts/baseline.py run      # everything below, printing each command
uv run python scripts/baseline.py report   # attribution -> 26145-data/baseline/report.json

# per capture X (demo.pcap, demo-out.pcap, demo-streamvalid.pcap, demo-streamvalid-out.pcap):
suricata -r X -k none -l OUT/suricata-exact                                                 # exact, untouched
suricata -r X -k none -l OUT/suricata-matched --set "vars.address-groups.HOME_NET=[$DEMO]"  # matched HOME_NET
SIH26145_INTERNAL_CIDRS=$DEMO .venv/bin/sih26145 analyze X --db OUT/saakshi/alerts.db
SIH26145_INTERNAL_CIDRS=$DEMO uv run python scripts/oneway.py rewrite OUT demo/demo.pcap demo-out.pcap
```

Two Suricata rows per capture:
- **Exact:** the command as given, with the default `HOME_NET` (RFC1918 only).
- **Matched HOME_NET:** `HOME_NET` set to the same internal list SAAKSHI is given, which adds
  147.32.0.0/16. That is site configuration, not rule tuning.

On every capture the two rows gave identical output.

**How alerts are attributed.** The 7 attacks are rebuilt from the generator with the same calls,
times and re-addressing as `scripts/build_demo_capture.py`, and checked to give the same packets.
Each attack's IP pairs and its first and last packet time are recorded.

An alert (Suricata `eve.json` `event_type=alert`, or a SAAKSHI alert log row) counts for an attack
when:
- its endpoints are that attack's pair (the flood: its target 10.50.0.10);
- its event time is within [first packet − 5 s, last packet + 120 s]. The slack covers flow
  timeouts.

DGA and the DNS tunnel share endpoints, so an alert goes to the nearer of the two windows. Alerts
are then sorted into:
- **background:** the alert touches a CTU-13 normal host;
- **no address:** Suricata decoder events on packets it could not decode carry no IP addresses;
- **other:** anything else. It was 0 everywhere.

## Main comparison: stream-valid captures

"ET Open" counts alerts whose signature starts with `ET `. "Engine" counts Suricata's own
`SURICATA …` protocol-anomaly events.

| Capture | Tool | Total alerts | ET Open alerts | Attacks alerted (of 7) | Alerts on background hosts | No-address alerts |
|---|---|---|---|---|---|---|
| both directions | Suricata, exact | 97,319 | **0** | **0 by ET Open.** 1 by an engine event only: C2 (20 `HTTP missing Host header`, 20 `Applayer Detect protocol only one direction`) | 0 | 97,279 `IPv4 truncated packet` |
| both directions | Suricata, matched HOME_NET | 97,319 | **0** | same as exact | 0 | 97,279 |
| both directions | **SAAKSHI** | **12** | — | **7 of 7:** recon, C2, TLS, DGA, DNS tunnel, exfiltration, SYN flood | **3** (`RULE_C2_PERIODIC_FLOWS`) | — |
| outbound only | Suricata, exact | 21,901 | **0** | **0** | 0 | 21,901 `IPv4 truncated packet` |
| outbound only | Suricata, matched HOME_NET | 21,901 | **0** | 0 | 0 | 21,901 |
| outbound only | **SAAKSHI** | **100** | — | **3 of 7:** C2, TLS, exfiltration. These are the only 3 of the 7 with packets in an outbound-only capture | **94** (91 `RULE_EXFIL_EGRESS_BASELINE`, 3 `RULE_C2_PERIODIC_FLOWS`) | — |

SAAKSHI per attack on the stream-valid capture:

| Attack | Both directions | Outbound only |
|---|---|---|
| (e) recon | `RULE_FAST_SCAN`* + `RULE_RECON_FANOUT_SYN_ONLY` | none: scanner and target are both internal |
| (b) C2 | `RULE_C2_PERIODIC_FLOWS` | `RULE_C2_PERIODIC_FLOWS` |
| (d) rare-JA4 TLS | `RULE_TLS_RARE_JA4_REPEATED` | `RULE_TLS_RARE_JA4_REPEATED`, plus 3 `RULE_EXFIL_EGRESS_BASELINE` on the same pair (right host, wrong class) |
| (c) DGA | `RULE_DGA_NXDOMAIN_HIGH_ENTROPY` | none: the resolver is internal |
| (c) DNS tunnel | `RULE_DNS_TUNNEL_VOLUME_LENGTH` | none: the resolver is internal |
| (f) exfiltration | `RULE_EXFIL_OUTBOUND_RATIO` | `RULE_EXFIL_EGRESS_BASELINE`, the one-sided substitute (`substitutions` names it) |
| (a) SYN flood | `RULE_FAST_SYN_FLOOD`* + `RULE_DDOS_SYN_FLOOD` | none: the flood is inbound only |

`*` = provisional fast-lane alert. Of the 12 alerts, 10 are flow-lane and 2 are fast-lane.

**The stream-valid copy does not change SAAKSHI's output.** Its alerts on the stream-valid copy
have the same content as on the original. The check is a digest of each alert's canonical JSON
without `alert_id`, `record_hash` and `confirms`, which differ between any two runs:

| Captures | Alerts | Digest, sorted | Digest, in storage order |
|---|---|---|---|
| `demo.pcap` / stream-valid | 12 / 12 | `5e0315d4…` / `5e0315d4…`, **equal** | `0ec4a132…` / `4c0d521c…`, differ |
| outbound-only / its stream-valid copy | 100 / 100 | `4ea4d17d…` / `4ea4d17d…`, **equal** | `642c86a0…` / `642c86a0…`, equal |

The ordered digests differ on the both-directions pair because two alerts were stored in the
opposite order: the fast-lane SYN-flood alert and one C2 alert. Which is published first depends on
how the producer (fast lane) and the consumer (flow lane) interleave. The alert content does not
depend on it. `docs/ONEWAY-ACCEPTANCE.md` shows the same effect between two normal runs.

## Second table: captures as-is (fixed TCP sequence numbers)

| Capture | Tool | Total alerts | ET Open alerts | Attacks alerted (of 7) | Alerts on background hosts | No-address alerts |
|---|---|---|---|---|---|---|
| both directions | Suricata, exact | 97,529 | **0** | **0 by ET Open.** 3 by engine events only, **caused by the generator's fixed sequence numbers**: recon (100 `STREAM Packet with invalid ack` + 100 `STREAM SHUTDOWN RST invalid ack`), C2 (20 `3way handshake SYNACK with wrong ack`), TLS (30, same) | 0 | 97,279 |
| both directions | Suricata, matched HOME_NET | 97,529 | **0** | same as exact | 0 | 97,279 |
| both directions | SAAKSHI | 12 | — | 7 of 7 | 3 | — |
| outbound only | Suricata, exact | 21,901 | **0** | 0 | 0 | 21,901 |
| outbound only | Suricata, matched HOME_NET | 21,901 | **0** | 0 | 0 | 21,901 |
| outbound only | SAAKSHI | 100 | — | 3 of 7 | 94 | — |

The engine events on recon, C2 and TLS here are not detections of those attacks. They are Suricata
correctly reporting that the generated TCP handshakes are inconsistent. They disappear on the
stream-valid copy.

## What each tool caught and missed

**Suricata** with default ET Open raised no ET Open alert on either capture, in either version,
with either `HOME_NET`.
- **Not seen:** the 7 generated attacks, including the ones whose payloads it parsed on the
  stream-valid copy (800 DNS records for the DGA and tunnel, 20 HTTP transactions for the C2).
- **Why:** these attacks are synthetic behaviours (periodic check-ins, NXDOMAIN-heavy random
  names, long TXT-style queries, a rare TLS client, a large upload, a fan-out scan, a spoofed SYN
  flood). No real malware family and no known indicator is involved, so a signature ruleset has
  nothing to match unless it has a threshold rule for that behaviour.
- **Engine events:** its own protocol-anomaly events fired on the malformed parts of our synthetic
  payloads.
- **The background:** it is header-only, and Suricata could not decode it: 97,279 `IPv4 truncated
  packet` events with no addresses. So these captures say nothing about Suricata's false-alarm rate
  on real traffic with payloads, and the "0 on background hosts" is not a precision figure.

**SAAKSHI** alerted on all 7 attacks with both directions captured. With only the outbound half it
alerted on the 3 whose packets that half contains. On the outbound-only capture it also raised 94
alerts on the three CTU-13 normal hosts: 91 from the exfiltration rule's one-sided substitute path.
That is the known weakness in `docs/ONEWAY.md` and `TODO.md`, and it was not tuned here.

**What this comparison shows:** behavioural detection from flow and header features found generated
attack behaviour that an untuned signature IDS with default ET Open did not. **What it does not
show:**
- ET Open's coverage of real, known malware;
- either tool's false-alarm rate on full-payload traffic.

The attacks are generated, and the real background is header-only.

Raw outputs (`eve.json`, `suricata.log`, alert databases, `report.json`) are in
`26145-data/baseline/`.
