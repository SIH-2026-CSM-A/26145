# TODO

IDs in brackets refer to docs/AUDIT.md.

## Now
- [ ] Rewrite detectors (a)–(e) against the FeatureStore; drop the per-flow false-positive
      rules [A1, A2, A4, D3, D4]. Each detector's contract entry is updated in the same commit.
- [ ] Benchmark: report flows/sec and Mbps on a large replay, with hardware stated; fix the
      50× overwrite bug [D5]. No figure goes into README until this runs.
- [ ] Wire pipeline → shared SQLite (WAL) → `publish_alert` → SSE; serve real
      `/metrics` values including `link_reverse_visibility_w` [A5, A6].
- [ ] asyncio bounded queue between ingest and scoring with an explicit drop counter;
      periodic idle flush so idle flows are scored during a live run [A7].
- [ ] Add a DGA scenario to the generator; the e2e DGA assertion currently rides on the
      tunnel fixture [A4].

## Next
- [ ] Replace synthetic-baseline RF/IF with LightGBM + IsolationForest trained on labelled
      captures, session-aware split [D1]. LightGBM enters pyproject in that session.
- [ ] Zeek adapter behind `FlowSource` (conn/dns/ssl logs + IAT script); dpkt stays fallback.
- [ ] Read original wire length from pcap record headers [A8].
- [ ] Dashboard: link-visibility gauge; campaign graph (Cytoscape.js).
- [ ] `record_hash` chain in AlertStorage (tamper-evident log).

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
