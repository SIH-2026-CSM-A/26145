# TODO

IDs in brackets refer to docs/AUDIT.md.

## Now
- [ ] Rule thresholds (a)–(f) are hand-set on generated captures. On real mixed traffic they
      are noisy: on CTU-13-Extended s12 (541,957 flows) the pipeline raised 7,453 C2-beacon and
      593 exfiltration alerts (docs/BENCHMARK.md). The labelled dumps in
      `26145-data/features/ctu13-s*.labelled.csv.gz` now allow rule precision/recall per
      scenario. Measure it, then tune (C2 CV 0.35 / 8 gaps first).
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
