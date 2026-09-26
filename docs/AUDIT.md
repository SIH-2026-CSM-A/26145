# Intake Audit — baseline `baseline-antigravity` (5dff4f1)

Auditor: Claude Code (Opus 5.5), 2026-09-25. Baseline test suite: 71 passed.

Every finding below was checked against the code. Findings marked **probe** were reproduced
by running the real detectors/models on hand-built `FlowRecord`s shaped like ordinary
traffic (`uv run python`, no code changed). Each finding lists the PS pass/fail constraint
it threatens and where it is (or will be) fixed.

PS constraints referenced: **RO** read-only ingest / no return path · **ND** no payload
decryption · **SL** streaming with bounded latency · **TP** stated and demonstrated
throughput · **AS** structured alert schema · **(a)–(f)** the six threat classes.

---

## Findings from the intake brief (all confirmed)

### D1 — The ML models are not trained models (confirmed, wider than stated)
- `models/classifier.py:28` `fit_synthetic_baseline()` fits the RandomForest on
  `rng.normal(0, 0.1, 32)` vectors with a handful of hand-set columns. `predict()` calls it
  implicitly on first use (`classifier.py:122`).
- **Also:** `models/anomaly.py:81` does the same for the IsolationForest — on first
  `predict()` it fits on 60 dummy vectors. Neither model has ever seen real traffic.
- **Probe:** the RF labels a lookup of `www.google.com` as `THREAT_DNS_DGA` with p=0.86. Its
  synthetic "DGA" class is every UDP/53 flow with one query, so the model learned "port 53 =
  DGA". The IsolationForest flags a SYN with two retransmits, a normal ping, an IMAPS session and a `www.google.com` lookup as
  anomalies.
- Threatens: (a)–(f) credibility; any accuracy claim. Fix: LightGBM + IsolationForest
  trained on labelled captures (TODO Next). `model_version` in alert v2 (Part 4) says
  `synthetic-baseline` so no alert overstates this.

### D2 — No per-host or per-destination state (confirmed)
- Every detector's signature is `detect(fv: FeatureVector)` (`detectors/rules/base.py:23`);
  `FeatureVector` is built from one `FlowRecord` (`features/extractor.py:28`).
- Source-IP entropy toward a destination, fan-out, destination cardinality, and per-host
  egress baselines cannot be computed. A distributed flood of many small flows, a
  horizontal scan, or a slow exfiltration across many connections is invisible.
- Threatens: (a), (b), (e), (f). Fix: two-tier `FeatureStore` (Part 5 this session).

### D3 — No JA3/JA4 (confirmed)
- The parser extracts SNI and the cipher list (`ingest/parser.py:210`), then `FlowTracker`
  keeps only SNI strings; ciphers are discarded. Extensions, curves, point formats, ALPN and
  signature algorithms are never read.
- `EncryptedAnomalyDetector` (`detectors/rules/detectors.py:99`) fires on SNI entropy > 4.0
  or any TLS on a port other than 443/8443.
- **Probe:** a TLS session to IMAPS (993) fires `THREAT_ENCRYPTED_ANOMALY`. SMTPS (465),
  DoT (853), LDAPS (636) would too.
- Threatens: (d). Fix: JA3/JA4/JA3S in `ingest/tls_fingerprint.py` (Part 5); detector
  rewrite TODO Now.

### D4 — Recon detector fires on every failed connection (confirmed)
- `ReconPortScanDetector` (`detectors.py:120`): TCP, ≥80% packets < 64 B, ≤ 5 packets,
  duration < 1 s. It never looks at how many ports or hosts the source touched.
- **Probe:** a single 54-byte SYN to 443 fires `THREAT_RECON_PORTSCAN`. The demo PCAP's
  25-port sweep produces 25 separate recon alerts, one per port.
- Threatens: (e) and alert volume. Fix: `src_distinct_dst_ports_w` / `src_distinct_dsts_w`
  (HLL) and `src_syn_only_ratio_w` in the store; detector rewrite TODO Now.

### D5 — Benchmark reports packets/sec, and the number is wrong (confirmed, worse than stated)
- `scripts/benchmark.py:35` computes packets/sec; the PS asks for flows/sec or Mbps.
- **The reported figure is inflated 50×.** `benchmark.py:23` calls
  `generate_threat_pcap(pcap_path)` 50 times on the same path; each call opens the file
  `"wb"` (`utils/pcap_generator.py:131`) and overwrites it. Verified: the loop reports
  9,200 packets, the file holds 184. The pipeline processed 184 packets and the script
  divided 9,200 by the elapsed time. The "2167.45 Packets/Sec" in the 2026-09-16
  SESSION-LOG entry is therefore invalid.
- The PCAP is also tiny (184 packets, ~20 KB), so fixed start-up cost (model fitting on first
  predict) dominates the measurement.
- Threatens: **TP** directly. Fix: TODO Now — flows/sec and Mbps on a large replay, measured
  and reported with hardware. No throughput number is claimed anywhere until then.

### D6 — README and code disagree on the threat taxonomy (confirmed)
- README lists `THREAT_DNS_TUNNEL, THREAT_EXFIL_DNS, THREAT_EXFIL_ICMP, THREAT_BEACON_C2,
  THREAT_SLOWLORIS_DOS, THREAT_PORT_SWEEP, THREAT_ANOMALOUS_BURST`.
- Code emits `THREAT_DDOS_VOLUME, THREAT_C2_BEACON, THREAT_DNS_DGA, THREAT_DNS_TUNNEL,
  THREAT_ENCRYPTED_ANOMALY, THREAT_RECON_PORTSCAN, THREAT_EXFILTRATION`, plus
  `THREAT_UNSUPERVISED_ANOMALY` from the IsolationForest. Only `THREAT_DNS_TUNNEL` overlaps.
  None of the README's other six exist in code.
- Threatens: **AS** and demo credibility. Fixed: README now lists the code taxonomy mapped
  to PS (a)–(f) (Part 2).

---

## Additional findings

### A1 — DDoS rule fires on any two back-to-back packets
- `features/extractor.py:34` computes `pps = packets / duration`. Two packets 100 µs apart
  gives pps = 20,000 > 10,000 → `THREAT_DDOS_VOLUME` (`detectors.py:14`). At 20 µs spacing
  the severity is CRITICAL.
- **Probe:** two 1514-byte HTTPS segments 100 µs apart → DDoS alert. Every bulk transfer's
  first flush window can do this.
- `burstiness_ratio` (`extractor.py:64`) is the coefficient of variation of *packet size*,
  not temporal burstiness, yet the DDoS rule treats `> 5.0` as a volumetric signal.
- A volumetric DDoS is many sources → one destination; a per-flow rule cannot see it (D2).
- Threatens: (a). Fix: destination-tier features (`dst_flows_w`, `dst_distinct_srcs_w`,
  `dst_src_ip_entropy_w`, `dst_syn_only_ratio_w`); detector rewrite TODO Now.

### A2 — C2 rule fires on VoIP and ping
- `C2BeaconDetector` (`detectors.py:36`): ≥ 5 packets, ≥ 5 s, `iat_var < 0.01`, pps < 100.
- **Probe:** a 10-second RTP stream (20 ms spacing) fires C2; so does `ping -c 6`. Any
  isochronous media or keepalive matches. Real beacons are usually *separate connections* at
  a period; per-flow IAT misses them entirely.
- Threatens: (b). Fix: `pair_iat_mean/cv/n` across flows per (src, dst) in the store;
  detector rewrite TODO Now.

### A3 — Exfiltration rule fires on ping and on downloads
- `ExfiltrationDetector` (`detectors.py:141`): `bps > 500 kB/s` or (ICMP and ≥ 500 bytes),
  with duration ≥ 1 s.
- **Probe:** `ping -c 6` (6 × 98 B = 588 B) fires EXFILTRATION. A one-way view of an HTTPS
  *download* at 1.5 MB/s fires EXFILTRATION. The code has no notion of internal vs external,
  so it cannot tell data leaving from data arriving.
- Threatens: (f). **Fix: this session, Part 5**: detector (f) now needs internal→external
  bytes under a configured CIDR policy, uses the outbound/inbound ratio when the reverse
  direction was observed, and uses per-host egress baseline + destination rarity +
  off-hours when it was not. Every exfil alert names the path it took.

### A4 — DGA rule and DGA model misfire on normal DNS
- `DGALexicalDetector` (`detectors.py:58`): any UDP/53 query with Shannon entropy > 4.2.
  Entropy of a *whole FQDN* rises with length, so long CDN names trip it.
- **Probe:** `d1a2b3c4e5f6g7.cloudfront.net` fires the rule; `www.google.com` is labelled DGA
  by the RF at 0.86 (D1).
- No DGA scenario exists in `utils/pcap_generator.py`. The e2e test's `THREAT_DNS_DGA`
  requirement is satisfied by the *tunnel* fixture tripping the model, not by a DGA sample.
- DNS query type is parsed (`parser.py:111`) and then dropped by `FlowTracker`, so the
  TXT/NULL ratio promised in the old ARCHITECTURE §7 is not computable. DNS response codes
  are never parsed, so NXDOMAIN rate — the strongest passive DGA signal — was unavailable.
- Threatens: (c). Fix: per-host DNS rollups + NXDOMAIN rate when responses are observed
  (Part 5); detector rewrite and a real DGA sample TODO Now.

### A5 — `/api/v1/metrics` returns hardcoded numbers
- `api/app.py:140-142` returns `active_flows: 12, packets_per_sec: 45.2,
  bytes_per_sec: 12450.0` regardless of anything. The dashboard renders them as live
  telemetry. This is fake data in a demoed path.
- Threatens: demo honesty, **TP**. **Fix: this session, Part 4**: unmeasured fields
  return `null` until the pipeline is wired to the API.

### A6 — Pipeline and API are not connected
- The API's storage defaults to `:memory:` (`api/app.py:49`) unless `SIH26145_DB_PATH` is
  set; the pipeline writes to its own `AlertStorage` (`orchestrator.py:24`) whose default is
  a different path. Nothing in `src/` calls `publish_alert` (`api/app.py:53`), so the SSE
  broadcaster never receives a pipeline alert. The dashboard only shows alerts from a
  separately-populated DB.
- Threatens: **SL**, **AS** end-to-end. Fix: TODO Now.

### A7 — Latency is unbounded; no backpressure
- `FlowTracker.flush_expired` (`flow/tracker.py:105`) is called only once, at end of file
  (`orchestrator.py:61`). A flow is scored only on active timeout (60 s), LRU eviction, or
  end of input — an idle C2 session is never scored during a live run.
- `process_pcap` is `async` but iterates a synchronous reader, blocking the event loop.
- There is no bounded queue and no drop counter; `alert_queue.put` awaits an unbounded queue.
- Threatens: **SL**. Fix: asyncio bounded queue + explicit drop counter + periodic idle
  flush (ARCHITECTURE target; TODO Now).

### A8 — Byte counts wrong under snaplen truncation
- `ingest/parser.py:22` sets `packet_len = captured_len`. dpkt's pcap iterator
  (`ingest/reader.py:35`) yields only the captured buffer, so on a truncated capture every
  byte-derived feature (bps, total_bytes, sizes) undercounts.
- Threatens: (a), (f), **TP** in Mbps. **Fixed (session 3):** `ingest/reader.py` reads each
  record's original (wire) length and passes it to the parser: classic pcap from the record
  header, pcapng from each Enhanced/Packet Block (dpkt parses that field and drops it).
  Header-only captures such as CTU-13-Extended, which are pcapng with TCP cut at 54 bytes and
  UDP at 42, therefore count full sizes. `tests/ingest/test_truncated_capture.py` pins both
  formats.

### A9 — Reverse-direction packets become separate flows; visibility is never measured
- `FlowTracker` keys on the directional 5-tuple (`flow/tracker.py:41`); B→A packets of an
  A→B conversation open a second, unrelated flow (pinned by the old test
  `test_bidirectional_separate_keys`).
- The system therefore cannot tell whether it is seeing a full-duplex tap or one half of an
  asymmetric path, and cannot compute anything that needs both halves (handshake completion,
  RTT, response codes, outbound/inbound ratio).
- Threatens: (c), (d), (f), and the correctness of every "one-way" assumption.
  **Fix: this session, Part 3**: reverse packets attach to the originating flow;
  `FlowRecord.reverse_seen` and per-direction counters give a per-flow
  `observability_state` (`bidirectional` / `forward_only` / `reverse_only`).

### A10 — Alert timestamp is wall-clock, not event time
- `alerts/models.py:35` stamps `datetime.now()`. For a replayed PCAP every alert carries the
  replay time, not when the traffic happened; timelines and correlation are meaningless.
- Threatens: **AS**. **Fix: this session, Part 4**: v2 `timestamp` is the flow window end.

### A11 — Repository/documentation drift
- AGENTS.md rule 7 says the repo lives at `~/NewProjects/sih26145/`; it is at
  `~/NewProjects/26145/`. `AlertStorage`'s default DB path (`storage/database.py:15`) points
  at the non-existent `sih26145` directory and silently creates it.
- `RuleHit.severity` is documented as `"MED"` (`detectors/models.py:13`); the aggregator and
  API use `"MEDIUM"`.
- The 2026-09-16 SESSION-LOG says "zero commits or remotes" on `master`; the code is
  committed as 5dff4f1 on `main`, with an older empty `master`.
- The old ARCHITECTURE §8 promised XGBoost and JA3/JA4; neither exists.
- Fix: default DB path (Part 4); docs rewrite (Part 2).

---

## Summary

| ID | Area | Status at end of session (2026-09-25) |
|---|---|---|
| D1 | ML fitted on dummy vectors | Open (TODO Next); gated since session 2: ML scores attach to rule alerts, never create one |
| D2 | No windowed state | Fixed: all seven detectors read the store (session 2) |
| D3 | No JA3/JA4 | Fixed: detector (d) uses JA4 rarity + known-bad list, no port rule (session 2) |
| D4 | Recon on failed connections | Fixed: fan-out + SYN-only ratio; `failed_tcp` regression capture (session 2) |
| D5 | Benchmark pps, inflated 50× | Fixed: `scripts/benchmark.py` rewritten; flows/s + Mbps measured on CTU-13 scenario 12 (`docs/BENCHMARK.md`, session 2) |
| D6 | Taxonomy mismatch | Fixed |
| A1–A2 | DDoS / C2 false positives | Fixed: dst-tier DDoS rules, pair-level C2 with poller suppression; regression captures (session 2) |
| A3 | Exfil false positives | Fixed (direction-aware detector (f)) |
| A4 | DGA misfires | Fixed: host-tier DGA/tunnel rules with NXDOMAIN when answered; Ramnit DGA scenario (session 2). qtype still dropped (TODO) |
| A5 | Fake metrics | Fixed: `/metrics` reports the running pipeline; null when none is attached (session 2) |
| A6–A7 | Not wired; unbounded latency | Fixed: `serve` (pipeline + API + SSE, one process), bounded queue with drop counter, idle-flush timer (session 2) |
| A8 | Truncated byte counts | Fixed: wire length from classic-pcap record headers and pcapng packet blocks (session 3) |
| A9 | Direction never measured | Fixed |
| A10 | Wall-clock timestamps | Fixed |
| A11 | Drift | Fixed: docs, DB default path, and AGENTS.md rule 7 (owner decision, session 2) |
