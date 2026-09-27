# TODO

IDs in brackets refer to docs/AUDIT.md.

## Now
- [ ] Deploy the demo to the GCP VM (`DEPLOY.md`) and record the Playwright demo video.
      `dashboard/tests/demo-shots.mjs` takes the 1366×768 / 1920×1080 stills for the PPT.
- [ ] Re-measure throughput on an idle machine. The session-3 figures predate the correlator
      and the per-alert hash (docs/BENCHMARK.md scope note).
- [ ] C2 is still the noisiest rule on real traffic: about 97 alerts per 10k flows on held-out
      s12, 97% on unlabelled hosts (docs/RULES.md §4). The 90%-of-TP floor binds because CTU TPs
      are host-based. The next lever is not a threshold but a feature (e.g. a long-horizon
      periodic-destination set, or payload-size regularity), which needs a contract row.
- [ ] LightGBM cross-scenario recall at the 1/10k budget is 28%, and a benign failed TCP
      connection sits 0.39 log-odds under the threshold (docs/MODELS.md §4.5). Candidates: more
      benign diversity (more CTU-13-Extended scenarios, other normal captures), or a
      per-deployment threshold. Re-validate before any change to the budget.
- [ ] Paced replay above ~20× compresses the 1 s timer tick into many seconds of capture time,
      so idle flows reach the store out of event order and the alert mix shifts
      (docs/BENCHMARK.md). Scale the tick with `--speed`, or flush on event time when behind.
- [ ] Profile top item is now dpkt parsing (38.7%), then model-row store reads (13.6%: 30+
      contract-checked reads per flow). Cache `load_contract().require` per feature name, or
      read store views once per flow.

## Next
- [ ] Zeek adapter behind `FlowSource` (conn/dns/ssl logs + IAT script); dpkt stays fallback.
      Map `resp_pkts > 0` -> reverse_seen and `history` -> observability_state.
- [ ] Keep DNS qtype on FlowRecord so a TXT/NULL ratio can be declared and computed [A4].
- [ ] DDoS thresholds (ruleset 2.1.0) are bounded only by the generated attack captures: the
      tuning scenarios have no flood. Validate on a capture with real floods (CTU-13 s10/s11
      mixed, or a DDoS dataset with pcaps).
- [ ] Cold-start volumetric detection: no bytes ceiling separates a first-window flood from real
      bulk transfers (docs/RULES.md §6). A pps- or ICMP-share feature would need a contract row.
- [ ] Recon shared-infrastructure suppression is per flow; subtract shared destinations from
      the fan-out (separate HLL) if scans hiding among popular servers matter.
- [ ] C2 poller signature is windowed: pollers slower than the window can see need the
      allowlist, or a long-horizon periodic-destination set.

## Later
- [ ] Correlator: campaigns never merge after the fact. Two campaigns that later turn out to share
      a rare pivot stay separate (by design, for determinism); a merge view could be added.
- [ ] Split flow-tier size/IAT stats per direction on bidirectional flows.
- [ ] JA4S server fingerprint once the FoxIO licence is reviewed (JA3S used meanwhile).
- [ ] Reverse-key matching in 4-tuple flow mode.

## Cut
- Next-stage kill-chain probability forecasting — the published ceiling (~67% top-3 with
  endpoint telemetry) cannot be defended from passive network data.
- Redis, TimescaleDB — operational surface a sealed enclave should not carry.
- QUIC Initial decryption for ClientHello features — PS: "never from decrypted content".
