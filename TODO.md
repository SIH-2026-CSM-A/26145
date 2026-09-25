# TODO

IDs in brackets refer to docs/AUDIT.md.

## Now
- [ ] Speed up ML scoring, the measured bottleneck (~93% of pipeline time, docs/BENCHMARK.md):
      score ML only on flows that already have a rule hit (the gate means scores cannot alert
      alone), or batch-predict the flows waiting in the queue. Re-run the benchmark after.
- [ ] Thresholds for detectors (a)–(f) are hand-set on generated captures (e.g. C2 CV 0.35 /
      8 gaps, DGA 20 high-entropy names / NXDOMAIN 0.5, recon fan-out 20 / SYN-only 0.6,
      DDoS 100 sources / 10x baseline, exfil 1 MB / ratio 10 / z 3). Tune on labelled real
      captures (CTU-13 binetflow labels) before quoting precision. EWMA std floor likewise.
- [ ] Consumer scheduling: under saturation the producer reads 256 packets per turn and the
      consumer scores one flow, so queued flows wait for the file to be read (unthrottled
      latency 30-57 s). Decide the live-capture policy (drain bursts, or a scoring thread).

## Next
- [ ] Replace synthetic-baseline RF/IF with LightGBM + IsolationForest trained on labelled
      captures, session-aware split [D1]. LightGBM enters pyproject in that session. Opening
      the ML gate follows from a new ML_MODEL_VERSION.
- [ ] Zeek adapter behind `FlowSource` (conn/dns/ssl logs + IAT script); dpkt stays fallback.
      Map `resp_pkts > 0` -> reverse_seen and `history` -> observability_state.
- [ ] Keep DNS qtype on FlowRecord so a TXT/NULL ratio can be declared and computed [A4].
- [ ] Read original wire length from pcap record headers [A8] (the benchmark capture had no
      truncated records; other captures may).
- [ ] Dashboard: campaign graph (Cytoscape.js). (Link visibility is shown as a number now.)
- [ ] `record_hash` chain in AlertStorage (tamper-evident log).
- [ ] Recon shared-infrastructure suppression is per flow; subtract shared destinations from
      the fan-out (separate HLL) if scans hiding among popular servers matter.
- [ ] C2 poller signature is windowed: pollers slower than the window can see need the
      allowlist, or a long-horizon periodic-destination set.

## Later
- [ ] `campaign_id` / `host_stage` correlation across alerts.
- [ ] Split flow-tier size/IAT stats per direction on bidirectional flows.
- [ ] JA4S server fingerprint once the FoxIO licence is reviewed (JA3S used meanwhile).
- [ ] Reverse-key matching in 4-tuple flow mode.

## Cut
- Next-stage kill-chain probability forecasting — the published ceiling (~67% top-3 with
  endpoint telemetry) cannot be defended from passive network data.
- Redis, TimescaleDB — operational surface a sealed enclave should not carry.
- QUIC Initial decryption for ClientHello features — PS: "never from decrypted content".
