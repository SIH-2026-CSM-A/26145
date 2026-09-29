# TODO

IDs in brackets refer to docs/AUDIT.md.

## Now
- [ ] Redeploy the VM (`saakshi-demo`) at tag `idea-deck-v4` (fast lane, signed bundle). Owner does this.
- [ ] Exfil egress-baseline substitute is noisy on outbound-only captures: 91 HIGH alerts on 3 CTU
      normal hosts in 11 min (docs/ONEWAY.md). It has no entity dedupe; consider a per-host dedupe
      and a higher z on one-sided links. Re-run rule_eval + ONEWAY after any change.
- [ ] Reflection rule counts genuine answers when only inbound halves are captured
      (busy_resolver IN, docs/ONEWAY.md). Needs a signal that does not depend on the query half.
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
- [ ] Profile top item is now dpkt parsing (36.5%), then model-row store reads (12.9%: 30+
      contract-checked reads per flow). Cache `load_contract().require` per feature name, or
      read store views once per flow.

## Next
- [ ] Multi-core: shared-nothing shards scale throughput (3,915 flows/s on 8 vCPUs) but change the
      alerts: host- and dst-tier state is split (docs/BENCHMARK.md "Multi-core scaling"). Hash by
      internal host, or share the FeatureStore windows, then re-run `scripts/shard_scale.py`.
- [ ] Generator writes fixed TCP seq/ack (1000/2000), so stream-reassembling tools reject the
      demo's TCP sessions (docs/BASELINE.md). Fix in `utils/pcap_generator.py`; it changes demo.pcap
      (rebuild + update the sha256 in its 3 places) and re-run baseline.py.
- [ ] Zeek baseline on the same captures (`zeek-lts` from OBS xUbuntu_26.04), add to BASELINE.md.
- [ ] Alert storage order depends on fast-lane / flow-lane scheduling (docs/ONEWAY-ACCEPTANCE.md);
      decide whether the chain order should be made deterministic (e.g. publish in event time).
- [ ] Sensor health NORMAL / DEGRADED / BLIND (session-7 P5, cut, not started): queue/parser
      drops, capture gaps, one-sided share, rate collapse -> OBSERVABILITY_DEGRADED + degraded=true.
- [ ] Signed chain checkpoints (session-7 P6, cut, not started): reuse bundle.py's Ed25519;
      verify-log checks them; export carries checkpoints + public key.
- [ ] Fast lane: no shared-infrastructure suppression; a scanner inside a >65k-source/s spoofed
      flood is not tracked (FastLane.overflow). Drops beyond the ceiling are modelled only: needs a
      real capture ring (AF_PACKET) to measure.
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
