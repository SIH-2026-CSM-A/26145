# Session Log

## 2026-09-25 — Claude Code (Opus 5.5) — session 2: real detectors, streaming, first throughput figure

**Agent:** Claude Code (Anthropic, model Opus 5.5). Branch `main`, starting at `4505ec9`
(141 tests passing). No other agent worked on the repo during this session.

### Shipped (commits in order)
0. `d5531d8 docs:` — owner decisions:
   - contract 1.0.1 accepts the broader NXDOMAIN rule (computed whenever resolver responses
     were captured, including a responses-only capture);
   - AGENTS.md rule 7 now names `~/NewProjects/26145`.
1. `18de166 test:` — benign regression suite (`tests/regression/`). Generated pcaps run
   through the real pipeline, each asserting zero alerts:
   - the audit's list: `ping -c 6`, 10 s RTP, www.google.com and CDN lookups,
     IMAPS/SMTPS/DoT, two segments 100 µs apart, one-way HTTPS download, a failed TCP
     connection, and a 50-host poller every 30 s;
   - plus the owner-requested counterexamples: flash crowd, busy resolver, mail PTR burst.

   10 of 11 were red at this commit (strict xfail naming the AUDIT id); only the one-way
   download passed (A3, fixed in session 1).
2. `f80eeed feat(detectors):` — (a)–(e) rewritten on tier-2 store features (ruleset
   2.0.0, contract 1.1.0).
   - (a) has three rules: SYN flood; **UDP reflection/amplification** (unsolicited flows
     from reflector ports, mean packet size, reflector bytes); and a **few-source
     volumetric flood** against the destination's EWMA baseline. Owner change to the plan:
     reflection is in PS (a), so it is not a stated limitation.
   - (b) pair inter-flow CV, with poller suppression by periodic fan-out plus an allowlist
     file.
   - (c) DGA uses NXDOMAIN when answered, with a named substitution otherwise; tunnel uses
     volume × qname length.
   - (d) known-bad JA4 list (ships empty) and a rare-JA4 repeated-session rule; no port
     rule.
   - (e) fan-out + SYN-only, skipping shared infrastructure.
   - One alert per (detector, entity) per 300 s.
   - **ML gate:** synthetic RF/IF scores attach to rule alerts but never create or inflate
     one.
   - Attack scenarios cover every detector, including a Ramnit DGA.
3. `db6d8ab feat(streaming):` — `streaming.run_stream`:
   - bounded asyncio queue with an exported drop counter (paced/live; offline analysis is
     lossless);
   - idle-flush timer;
   - `sih26145 serve` runs pipeline + FastAPI + SSE in one process;
   - `/api/v1/metrics` returns live values;
   - dashboard pipeline status row.
4. `perf:` (this commit):
   - rewritten `scripts/benchmark.py`, `docs/BENCHMARK.md`, and ARCHITECTURE §13 figures;
   - tracker fix: a packet after `idle_timeout` starts a new flow, whether or not a sweep
     ran (found by the benchmark, see below);
   - docs.

### Verification
- `uv run pytest`: **177 passed**. That is 141 at session start, with 8 test IDs replaced
  (listed below) and 44 added. The 2 warnings are the third-party deprecations present at
  baseline.
- Every benign capture raises 0 alerts. Each attack capture fires its own detector exactly
  once; the TLS beacon also fires C2, as it is periodic too. C2 fires at 20% and at 40%
  uniform jitter.
- The contract AST test is green with the new reads. Ruff (default rules, `--isolated`):
  42 at session start, 40 now, no new findings. `npm run build` passes.
- **`serve` in headless Chromium** (Playwright, demo capture at 3×):
  - metrics cards were non-null while running (flows/s, Mbps, queue, latency, visibility);
  - alert rows grew over SSE without reload, reaching 11 of 11 demo alerts across all
    classes;
  - 0 console errors.

  This check found one display defect: the timeline plotted the finished-run average as a
  final spike. The timeline now plots live-window points only.
- CTU-13: `pgrep -x tar` showed no extraction running. All 52 archive members were present
  in `extracted/` at their exact listed sizes, so nothing was re-extracted and nothing was
  written under `raw/`.

### Throughput (measured; details in docs/BENCHMARK.md)
- Setup: CTU-13 scenario 12 (281.2 MiB, 352,266 packets, 8,927 flows); i5-13450HX, WSL2,
  Python 3.13.14, one core; end to end including both ML models on every flow and SQLite
  WAL.
- **Unthrottled: 120.6–124.4 flows/s, 31.3–32.2 Mbps** (3 runs).
- Paced 26× (~50% of capacity): 0 drops; alert latency p50/p95/p99 165/496/641 ms from
  flush to published.
- Overload at 104× with a 1k queue: 42.6% of flows dropped, all counted.
- Profile: IsolationForest predict 73.6%, RandomForest predict 19.1% (single-row predict
  per flow; sklearn per-tree dispatch and per-call `warnings` handling dominate), dpkt
  parsing 3.5%, feature extraction 1.4%, tracker 0.9%. Not optimised.

### Falsification log (each break on one line, red on an assertion, then restored)
| Target | Break | Red test |
|---|---|---|
| (a) SYN flood | SYN-only threshold 0.8 → 0 | `test_benign_capture_raises_no_alerts[flash_crowd]` |
| (a) reflection | drop the "endpoint never initiated/answered" check | `[busy_resolver]` |
| (a) volumetric | drop `dst_distinct_srcs_w <= 10` | `[flash_crowd]` |
| (b) C2 | poller suppression disabled | `[monitoring_poller]` (50 alerts) |
| (c) DGA | NXDOMAIN "names resolve" suppression disabled | `[cdn_heavy_browsing]` |
| (c) tunnel | mean qname length 40 → 20 | `[mail_ptr_burst]` |
| (d) encrypted | drop the `pair_flows_w >= 5` requirement | `[tls_mail_and_dot]` |
| (e) recon | fan-out threshold 20 → 1 | `[failed_tcp]` |
| (f) exfil | ratio branch never taken (ignore reverse_seen) | `test_bidirectional_capture_takes_the_ratio_path` |
| ML gate | `ml_can_alert=True` | `[ping_c6]` (IsolationForest) |
| Tracker idle split | disable the on-arrival idle check | `test_packet_after_idle_timeout_starts_a_new_flow_without_a_sweep` |

The first (c) DGA attempt did **not** go red: 30 CDN names gave only 13 labels at or above
3.5 bits, below the count threshold. The benign capture was raised to 50 CDN lookups (28
high-entropy) and the break then went red.

### Found and fixed along the way
- **Generator clockwork.** Three benign/baseline generators spaced events on an exact
  clock and so tripped C2, which says nothing about detection. They now use independent
  random times, as real traffic does:
  - PTR lookups 0.9 s apart;
  - baseline web clients sorted into even slots;
  - flash-crowd baseline clients.
- **C2 on port sweeps.** A sweep at a fixed 5 ms rate is periodic. C2 now requires a mean
  period of at least 1 s (beacons sleep; scanners don't).
- **Model version on gated alerts.** A gated ML score attached to a rule alert now marks it
  HYBRID, so `model_version` names `ml-synthetic-baseline`. Confidence and severity stay
  the rule's.
- **Tracker (found by the benchmark).** Flow boundaries depended on sweep timing: at 26×
  replay a 1 s wall tick is 26 s of capture time, so packets after a 15 s gap merged into
  stale flows. Paced runs yielded 8,606 flows against 8,917 and fewer alerts. Idle expiry
  is now decided on packet arrival. All benchmark runs were redone after the fix, and all
  runs give 8,927 flows.

### Decided
- **DGA scenario is Ramnit, not the Wikipedia/CryptoLocker example.** The Wikipedia
  example reproduces its published vectors (2014-01-07 → intgmxdeadnxuyla.com), but it
  yields only 16 distinct names over 200 dates. Ramnit (J. Bader) reproduces the published
  `example_domains.txt` from seed 0x79159C10. The reference repo is GPL-2.0, so the
  implementation here is our own from the algorithm description; no code was copied.
- **Reflection uses dedicated reflector counters.** `dst_reflector_bytes_w` and mean
  packet size are counted per victim endpoint, not `dst_bytes_w`: a victim is not the
  flow-key destination when it initiated. The contract states the degraded case: a capture
  holding only inbound halves cannot tell solicited answers from unsolicited ones.
- **Dedup:** one alert per (detector, entity) per 300 s of event time. Exfil is not
  deduplicated.
- **Rates in `/metrics`:** the last ~5 s while running, the whole run once finished, with
  `rate_window_s` saying which. `alert_latency_ms` is null until an alert exists.
- **No dependency added.** cProfile (stdlib) was used for the profile; py-spy is not
  installed and was not needed.

### Existing tests changed (8 IDs replaced)
- `tests/detectors/test_rule_detectors.py`: 7 FeatureVector-only tests pinned the old
  per-flow rules. They were replaced by 9 store-driven tests (flows fed through a
  FeatureStore in order). Replaced: `test_ddos_volume_detector_hit`,
  `test_c2_beacon_detector_hit`, `test_dga_lexical_detector_hit`,
  `test_dns_tunnel_detector_hit`, `test_recon_portscan_detector_hit`,
  `test_encrypted_anomaly_detector_hit`, `test_detector_threshold_boundaries` (now a C2
  gap-count boundary).
- `test_ml_alerts_declare_the_synthetic_model` became
  `test_alerts_carrying_ml_scores_declare_the_synthetic_model`, since under the gate an ML
  prediction alone raises nothing.
- Not renamed, but changed:
  - `test_evidence_aggregation_ml_only` and `..._hybrid...` pass `ml_can_alert=True` (the
    path a trained model takes);
  - `test_metrics_report_only_measured_values` checks the new null fields;
  - `test_pipeline_end_to_end_performance_benchmark` budget went from 5 s per file to
    2 ms per packet, because the demo capture grew from 184 to 20,640 packets;
  - `test_feature_store` imports READERS from `store_readers`.

### Incomplete / next
- ML scoring is ~93% of pipeline time. See TODO Now; it was deliberately not optimised.
- Thresholds are hand-set on generated captures; no precision/recall on real labels yet.
- Under saturation, queued flows wait for the producer to finish reading (latency 30–57 s
  unthrottled). The live-capture scheduling policy is a TODO.
- A8 (truncated byte counts) is still open; the benchmark capture is unaffected.

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
