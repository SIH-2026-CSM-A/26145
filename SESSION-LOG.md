# Session Log

## 2026-09-25 — Claude Code (Opus 5.5) — foundation session

**Agent:** Claude Code (Anthropic, model Opus 5.5). Branch `main`, starting at tag
`baseline-antigravity` (5dff4f1, 71 tests passing).

### Shipped (commits in order)
1. `a19ed0d docs: add intake audit` — `docs/AUDIT.md`. The six intake defects are
   confirmed, plus 11 more found by running the real detectors on ordinary-traffic flows.
   Worst finds: the benchmark overwrites its PCAP 50 times and divides 9,200 packets by the
   time taken for 184 (the 2026-09-16 figure of 2167 pps below is invalid);
   `/api/v1/metrics` returned hardcoded numbers; `ping -c 6` fired both C2 and exfil; the RF
   labelled `www.google.com` as DGA at 0.86.
2. `a68dfa9 docs:` — `CLAUDE.md` (gotchas), `TODO.md`, `docs/ARCHITECTURE.md` rewritten
   for the target system, README taxonomy fixed and mapped to PS (a)–(f).
3. `c3b0304 feat(contract):` — the Unidirectional Feature Contract
   (`src/sih26145/feature_contract.toml`, loader `sih26145.contract`). It has two layers:
   - a static state per feature (computable / degraded / reverse_dependent / unavailable);
   - runtime per-flow observability: FlowTracker attaches reverse-5-tuple packets to the
     originating flow, and FlowRecord reports `observability_state`.
   It also adds `features/directional.py` (internal-CIDR policy and contract-checked
   accessors), plus DNS QR/rcode parsing.
4. `2a800e5 feat(alerts):` — alert schema v2:
   - new fields: event-time `timestamp`, Community ID `flow_id`,
     `evidence[{feature,value,baseline,baseline_source}]`, `observability_state`,
     `substitutions`, `contract_version`, `model_version`, and nullable `campaign_id`,
     `host_stage`, `record_hash`;
   - AlertStorage: WAL, a `user_version` migration that upgrades v1 rows in place, and a
     COUNT query;
   - `/metrics` returns null for anything unmeasured;
   - the dashboard reads the v2 fields.
5. `a5a27e9 feat(ingest):` — JA3 / JA4 / JA3S from cleartext hellos. JA4 reproduces
   the FoxIO published example exactly.
6. `2b5596b feat(features):` — two-tier FeatureStore with HyperLogLog, Count-Min and
   bucketed entropy (numpy + blake2b). It serves 28 contract features for (a)–(f) and link
   visibility, and states a memory ceiling.
7. `8718ba5 feat(detectors):` — `detect(fv, ctx)` with DetectionContext. The orchestrator
   feeds the store, and detector (f) is direction-aware:
   - with both halves captured it uses the outbound/inbound ratio;
   - with one half it uses the egress z-score + destination rarity + off-hours, and names
     the substitution on the alert.
8. `ecc526f test:` / `c6f7fd4 fix(dashboard):` — assertion tightening found during
   falsification; v2 labels in the UI.

### Verification
- `uv run pytest`: **141 passed** = 71 baseline + 70 added. All 71 baseline test IDs are
  still present, except `test_bidirectional_separate_keys`, which is replaced (see below).
  The 2 remaining warnings are third-party deprecations that were present at baseline.
- `python -m sih26145.cli demo` / `analyze` run end to end.
- `npm run build` passes. The dashboard was checked in headless Chromium against a real
  pipeline DB: the v2 exfil alert renders capture visibility, evidence rows and the
  substitution, and there are no page errors.
- Ruff (default pyflakes rules): 0 new findings; 49 at baseline, 42 now. The project has no
  typechecker configured, so none was run.
- **Memory (measured):** the FeatureStore defaults state a 42.19 MiB ceiling; the measured
  peak at full occupancy is 38.45 MiB (i5-13450HX, WSL2, Python 3.13.14).
- **No throughput figure** was produced this session.

### Falsification log
Each break was on one line. Every one went red on an assertion (not a collection or import
error), then `git checkout` restored it and the tests went green.

| Behaviour | Break | Red test(s) |
|---|---|---|
| Contract tier check | encrypted detector max_state → computable | `test_detector_reads_match_declaration_and_tier[encrypted_anomaly_detector]`, `test_contract_file_is_internally_valid` |
| Contract tier check | recon detector reads `fv.jitter` | `...[recon_portscan_detector]` ("declared reads drifted") |
| Contract tier check | exfil reads `quic_client_hello` via ctx | `...[exfiltration_detector]` ("reads unavailable feature") |
| Schema v2 fields | drop `observability_state` from `to_dict` | `test_v2_alert_carries_every_field...`, `test_observability_state_is_measured_per_flow`, SSE test |
| Schema v2 fields | `flow_id = None` in aggregator | `test_v2_alert_carries_every_field...` |
| Sketch memory ceiling | host LRU cap → 10**9 | `test_memory_stays_under_ceiling...` (tables 10000 vs 200). Checked separately: peak 32.38 MiB vs 2.00 MiB ceiling |
| Unavailable-ratio rule | ratio returns 0.0 without reverse half | `test_forward_only_flow_raises...` (DID NOT RAISE), both exfil forward-only tests |
| Exfil branch | detector ignores reverse_seen | `test_bidirectional_capture_takes_the_ratio_path` |
| Exfil branch | substitution dropped in aggregator | `test_forward_only_capture...names_it` |
| Per-flow observability | tracker stops matching reverse keys | observability, tracker merge and exfil branch tests |
| Unavailable gate | `contract.require` stops refusing | 3 contract/store gate tests |

### Decided
- **User correction adopted:** "unidirectional" means the enclave never transmits; the
  capture may hold both halves or one. Features needing the other half are
  `reverse_dependent` (computed per flow when observed, `UnavailableFeatureError`
  otherwise). `unavailable` is reserved for decryption, active probing, or our own
  handshake.
- Outbound = internal→external by CIDR policy (default RFC1918 + fc00::/7,
  `SIH26145_INTERNAL_CIDRS`).
- Community ID v1 for `flow_id` (joins Zeek/Suricata). Verified on the reference vectors.
- JA3 / JA3S / JA4 (BSD-3). JA4S is deferred pending review of the FoxIO licence.
- Sketches use numpy + blake2b, so no dependency was added this session.
- v2 moves the v1 `evidence` object to `detection`. Migrated v1 rows keep
  `observability_state`, `contract_version` and `model_version` null; they are not
  back-filled.
- `dns_nxdomain_rate` is available when the responder half was seen, which includes
  responses-only captures. This is slightly broader than "reverse_seen", because a
  responses-only capture holds exactly what the feature needs.

### Rejected
- Redis and TimescaleDB: operational surface a sealed enclave should not carry.
- Next-stage kill-chain forecasting: the published ceiling (~67% top-3 with endpoint
  telemetry) cannot be defended from passive data.
- QUIC Initial decryption: the PS says "never from decrypted content".
- Estimating the outbound/inbound ratio from a one-sided flow.

### Existing tests changed (count unchanged)
- `test_bidirectional_separate_keys` became `test_bidirectional_packets_merge_into_one_flow`.
  It now asserts the corrected behaviour; the old version only passed because its "reverse"
  packet reused the forward ports.
- `test_exfiltration_detector_hit` and `test_icmp_exfiltration_detector_hit` were rewritten
  for the direction-aware detector (ratio path and substitute path). The rule they pinned
  fired on ping and downloads (AUDIT A3).
- `evidence=` became `detection=` in `Alert(...)` calls, and the `$schema`/version
  assertions became v2 (test_alert_engine, test_storage, test_api).
- The integration tests now close their pipeline's storage. This fixes a flaky
  unhandled-thread warning.

### Incomplete / next
- Detectors (a)–(e) still use the per-flow baseline rules and their false positives (AUDIT
  A1, A2, A4, D3, D4). The store exposes everything they need; they are not rewired yet.
- ML models are still fitted on synthetic vectors (D1). Alerts now say so.
- The benchmark still reports packets/sec and is inflated 50× (D5). No throughput figure
  exists.
- The pipeline is not wired to the API/SSE, and there is no bounded queue or drop counter
  (A6, A7).
- There is no Zeek adapter; dpkt is the only ingest path.
- Detector (f) thresholds are hand-set and untuned.
- Correction to my own plan: the planned `.gitignore` `rules/` change was dropped. The
  pattern does not exist; I misread `ls` output.

---

## 2026-09-16 — Antigravity AI Agent

## Agent Identity
- **Agent**: Antigravity (Google DeepMind Advanced Agentic Coding)
- **Session Timestamp**: 2026-09-16

## Work Completed Across All Phases (00 - 12)

1. **Phase 00 - Repo Initialization**: Created `README.md`, `.gitignore`, `AGENTS.md` (15 rules), initialized Git on `master`.
2. **Phases 01 & 02 - Architecture Specification**: Authored comprehensive `docs/ARCHITECTURE.md` specifying 16 architectural sections.
3. **Phase 03 - Project Foundation**: Created `pyproject.toml` (`>=3.11`, `hatchling`), `src/sih26145/__init__.py`, `tests/__init__.py`, and locked dependencies via `uv`.
4. **Phase 04 - Ingestion Engine**: Built stream-based `PcapReader`, `PacketParser`, and `PacketMetadata` models using `dpkt`.
5. **Phase 05 - Flow Engine**: Built LRU-bounded `FlowTracker` supporting 5-tuple and 4-tuple modes, 60s active timeout, and 15s idle timeout.
6. **Phase 06 - Feature Extractor**: Built `FeatureExtractor` extracting 11 feature families, Shannon entropy, and summary vectors.
7. **Phase 07 - Rule Detectors**: Built `RuleDetectorSuite` covering all 7 threat classes (`THREAT_DNS_TUNNEL`, `THREAT_EXFIL_DNS`, `THREAT_EXFIL_ICMP`, `THREAT_BEACON_C2`, `THREAT_SLOWLORIS_DOS`, `THREAT_PORT_SWEEP`, `THREAT_ANOMALOUS_BURST`).
8. **Phase 08 - Classical ML Suite**: Built `MLModelSuite` with `IsolationForestAnomalyDetector` and `RandomForestThreatClassifier`.
9. **Phase 09 - Alert Aggregator**: Built `EvidenceAggregator` synthesizing rule hits and ML predictions into versioned `sih26145.alert.v1` alerts.
10. **Phase 10 - SQLite Persistence & FastAPI API**: Built `AlertStorage` async engine and FastAPI REST (`/health`, `/alerts`, `/metrics`) and SSE stream (`/stream/alerts`) endpoints.
11. **Phase 11 - React Monitoring Dashboard**: Built React 18 + Vite + Tailwind CSS SOC dashboard with live metrics, throughput timelines, threat charts, and SSE streaming alert feed with evidence drawer.
12. **Phase 12 - System Integration & Benchmarking**: Built `ThreatDetectionPipeline` orchestrator, CLI entry point (`sih26145.cli`), synthetic PCAP generator (`pcap_generator`), end-to-end integration tests, and benchmark harness (`scripts/benchmark.py`).

## Rejections & Design Decisions
- **Rejected Deep Learning / Neural Networks**: Enforced strict explainability constraint using classical ML (Isolation Forest & Random Forest).
- **Rejected WebSockets**: Utilized Server-Sent Events (SSE) for unidirectional server-to-dashboard event streaming.
- **Rejected Packet Transmission / RST Injection**: Maintained 100% passive, read-only network tap semantics (zero transmit sockets created).
- **Rejected Git Commits / Pushes**: Left all code in clean untracked state on `master` with zero commits or remotes as instructed.

## Verification Summary
- **Pytest**: 31 passed in 3.13s (100% pass rate).
- **Vite Production Build**: 2215 modules transformed, 0 build errors.
- **Benchmark**: Ingestion & pipeline throughput: 2167.45 Packets/Sec (4.47 KB/s), per-packet latency: 461.37 µs/packet.
