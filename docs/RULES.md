# Rule precision on labelled real traffic

How often the rule detectors (a)–(f) are right on real mixed traffic, measured on the
CTU-13-Extended header-only captures, and how their existing thresholds were tuned. The full
numbers are in `docs/rule_metrics.json`. The commands to reproduce them are in the last section.

## 1. Declared before any number was looked at (2026-09-26)

- **Split.** Tuning uses s1, s5 and s6. s11 and s12 are **held out**, and their numbers are
  reported whatever they are.
- **What may change.** Only thresholds that already existed:
  - C2: CV, gap count, minimum period and poller fan-out;
  - exfil: bytes, ratio, z-score and destination rarity;
  - recon: fan-out, SYN-only share and the shared-infrastructure cut;
  - DDoS: distinct sources, baseline multiple and the few-source cap.

  No new features.
- **Objective.**
  - The candidates are those that keep at least 90% of the detector's tuning-set true
    positives at the old thresholds.
  - Among them, the chosen one has the **lowest alerts per 10k flows**.
  - Ties go to precision over known.
- **Constraints that must still hold.**
  - The 12 benign regression captures raise 0 alerts.
  - Every generated attack capture fires its own detector exactly once.
  - The C2 beacon is still caught at 20% and 40% jitter.

  A candidate that breaks one of these is skipped, and the next-ranked one is taken.

## 2. How an alert is scored

- **Flow join.** An alert's flow is joined on `flow_id` (Community ID) and flow start (±1 s) to
  the labelled feature dump of its scenario:
  - `From-Botnet` counts as a **TP**;
  - `From-Normal` counts as an **FP**.
- **Entity fallback.** Some alerts are entity-level (a DDoS destination, a scanning host, a C2
  pair) and their triggering flow is not labelled. For those, the entity's IPs are checked:
  - an infected host from the scenario README counts as a TP;
  - a host that started `From-Normal` flows in the scenario's binetflow counts as an FP.

  The columns say which join produced each count.
- **Unknown alerts** (Background, `To-*`, unmatched) are **scored as neither TP nor FP**. They are
  reported as the unknown share next to precision, together with alerts per 10k flows. Precision
  over known ignores them, so read the three columns together.
- **The CTU labels are host-based.** Every flow an infected host starts is `From-Botnet`,
  including its ordinary lookups. TP counts are therefore **optimistic**: a rule that fires on
  any traffic from an infected host scores a TP.
- **Header-only data.** The captures carry no DNS or TLS payload. The DGA, DNS-tunnel and
  encrypted-session rules cannot fire on them, and their precision here is **not measured**. It
  is not zero-FP.
- **LightGBM rows are in-sample.** The shipped model was trained on all five of these scenarios
  (docs/MODELS.md), so its ML-only alert counts are shown for alert volume only, not as a
  precision estimate. MODELS.md §4.1 has the held-out figures.

## 3. How the thresholds were chosen

1. **Offline sweep** (`rule_eval.py sweep`):
   - The rules are re-evaluated from each flow's dumped feature row. It is the same store
     state the detectors read at scoring time.
   - The suite's 300 s per-entity dedupe is simulated, and the sweep covers grids of the
     existing thresholds on s1, s5 and s6.
   - At the old thresholds it reproduces the pipeline's alert counts exactly: for example
     7,453 C2 alerts on s12, 1,733 on s5 and 15,793 on s6.
2. **Ranking** follows §1: keep ≥ 90% of tuning-set TP, then take the lowest alerts per 10k
   flows.
3. **Constraints** (`rule_eval.py pick`): each candidate, in rank order, is patched into the
   detectors, then the benign-regression, attack-capture and exfil-branch tests run. The first
   candidate that passes is taken. The skipped ranks are listed below.
4. **Confirmation:** every scenario, including the held-out ones, is re-run through the full
   pipeline (ML on, as shipped) with the chosen thresholds. §4 comes only from those runs.

| Detector | Threshold | Before | After | Candidates skipped for constraints | Why they were skipped |
|---|---|---|---|---|---|
| C2 beacon (b) | `MIN_GAPS` | 8 | 16 | 1 | rank 0 (min period 30 s) missed the 30 s generated beacon at 20% and 40% jitter |
| | `MAX_CV` | 0.35 | 0.40 | | |
| | `MIN_PERIOD` | 1 s | 10 s | | |
| Recon (e) | `MIN_SYN_ONLY` | 0.6 | 0.8 | 0 | |
| | `SHARED_INFRA_SRCS` | 20 | 5 | | |
| Exfiltration (f) | `MIN_RATIO` | 10 | 50 | 17 | ranks 0–16 raised `MIN_OUTBOUND_BYTES` to 5–50 MB, above the 1.2 MB generated upload |
| | `MAX_DST_SOURCES` | 2 | 1 | | |
| DDoS (a) | `MIN_SRCS` | 100 | 200 | 22 | ranks 0–21 set `MAX_FEW_SRCS` to 3 or 5, and the generated few-source flood stopped firing |
| | `BASELINE_MULT` | 10 | 100 | | |

Unchanged: C2 `POLLER_PERIODIC_DSTS` (10), recon `MIN_FANOUT` (20), exfil `MIN_OUTBOUND_BYTES`
(1 MB) and `MIN_EGRESS_Z` (3), DDoS `MAX_FEW_SRCS` (10), and the DGA, tunnel and TLS thresholds
(untestable here). The ruleset version is 2.1.0.

**Two cases the objective handles badly.**
- **DDoS.** There is no DDoS TP in the tuning set: the s1, s5 and s6 botnets do not flood. The
  90% TP floor is therefore vacuous, and "lowest alerts per 10k flows" picks the quietest
  thresholds that still fire on the generated SYN flood, reflection and few-source flood. This
  new DDoS setting is justified only by alert volume and the generated attacks, not by real
  attack traffic.
- **C2.** The TP floor binds hard. C2 TPs are host-based (any periodic flow of an infected host
  counts, §2), so keeping 90% of them keeps most of the periodic background too. The objective
  cut C2 volume by only about 17%.

Offline-sweep totals on the tuning set (s1 + s5 + s6), before → after:

| Detector | Alerts | TP | FP | Alerts per 10k flows | Precision over known |
|---|---|---|---|---|---|
| C2 beacon | 57,121 → 47,693 | 305 → 281 | 1,050 → 822 | 92.1 → 76.9 | 0.225 → 0.255 |
| Recon | 123 → 92 | 81 → 74 | 0 → 0 | 0.198 → 0.148 | 1.000 → 1.000 |
| Exfiltration (both rules) | 5,939 → 2,585 | 167 → 167 | 5 → 1 | 9.58 → 4.17 | 0.971 → 0.994 |
| DDoS (all three rules) | 84 → 40 | 0 → 0 | 2 → 0 | 0.135 → 0.065 | 0.000 → — |

## 4. Measured precision, full pipeline, before → after

Generated by `rule_eval.py report --write` from the pipeline runs. Rows with no change show
one value. "was" gives the TP/FP split before tuning.

<!-- rule-table:start -->
| Scenario | Split | Flows | Detector | Alerts | TP (flow / entity) | FP (flow / entity) | Unknown | Precision over known | Unknown share | Alerts per 10k flows |
|---|---|---|---|---|---|---|---|---|---|---|
| s1 | tune | 4,952,836 | `RULE_C2_PERIODIC_FLOWS` | 39595 → 36336 | 271 / 1 (was 292 / 3) | 431 / 179 (was 495 / 225) | 38580 → 35454 | 0.291 → 0.308 | 0.974 → 0.976 | 79.94 → 73.36 |
| s1 | tune | 4,952,836 | `RULE_DDOS_SYN_FLOOD` | 1 → 0 | 0 / 0 (was 0 / 0) | 0 / 0 (was 0 / 0) | 1 → 0 | — | 1.000 → — | 0.0 |
| s1 | tune | 4,952,836 | `RULE_DDOS_VOLUME_BASELINE` | 65 → 34 | 0 / 0 (was 0 / 0) | 0 / 0 (was 0 / 1) | 64 → 34 | 0.000 → — | 0.985 → 1.000 | 0.13 → 0.07 |
| s1 | tune | 4,952,836 | `RULE_EXFIL_EGRESS_BASELINE` | 1904 → 1862 | 136 / 0 (was 136 / 0) | 0 / 0 (was 0 / 0) | 1768 → 1726 | 1.000 | 0.929 → 0.927 | 3.84 → 3.76 |
| s1 | tune | 4,952,836 | `RULE_EXFIL_OUTBOUND_RATIO` | 994 → 125 | 0 / 0 (was 0 / 0) | 0 / 0 (was 4 / 0) | 990 → 125 | 0.000 → — | 0.996 → 1.000 | 2.01 → 0.25 |
| s1 | tune | 4,952,836 | `RULE_RECON_FANOUT_SYN_ONLY` | 85 → 57 | 48 / 0 (was 55 / 0) | 0 / 0 (was 0 / 0) | 30 → 9 | 1.000 | 0.353 → 0.158 | 0.17 → 0.12 |
| s1 | tune | 4,952,836 | `lightgbm_flow_classifier` | 54691 → 54760 | 20522 / 0 (was 20508 / 0) | 0 / 0 (was 0 / 0) | 34183 → 34238 | 1.000 | 0.625 → 0.625 | 110.42 → 110.56 |
| s5 | tune | 196,185 | `RULE_C2_PERIODIC_FLOWS` | 1733 → 943 | 0 / 0 (was 5 / 0) | 15 / 13 (was 41 / 25) | 1662 → 915 | 0.070 → 0.000 | 0.959 → 0.970 | 88.33 → 48.07 |
| s5 | tune | 196,185 | `RULE_DDOS_VOLUME_BASELINE` | 4 → 2 | 0 / 0 (was 0 / 0) | 0 / 0 (was 1 / 0) | 3 → 2 | 0.000 → — | 0.750 → 1.000 | 0.2 → 0.1 |
| s5 | tune | 196,185 | `RULE_EXFIL_EGRESS_BASELINE` | 90 → 87 | 6 / 0 (was 6 / 0) | 0 / 0 (was 0 / 0) | 84 → 81 | 1.000 | 0.933 → 0.931 | 4.59 → 4.43 |
| s5 | tune | 196,185 | `RULE_EXFIL_OUTBOUND_RATIO` | 129 → 62 | 0 / 0 (was 0 / 0) | 0 / 0 (was 0 / 0) | 129 → 62 | — | 1.000 | 6.58 → 3.16 |
| s5 | tune | 196,185 | `RULE_RECON_FANOUT_SYN_ONLY` | 2 | 2 / 0 (was 2 / 0) | 0 / 0 (was 0 / 0) | 0 | 1.000 | 0.000 | 0.1 |
| s5 | tune | 196,185 | `lightgbm_flow_classifier` | 1901 → 1906 | 37 / 0 (was 37 / 0) | 0 / 0 (was 0 / 0) | 1864 → 1869 | 1.000 | 0.981 → 0.981 | 96.9 → 97.15 |
| s6 | tune | 1,051,586 | `RULE_C2_PERIODIC_FLOWS` | 15793 → 10414 | 9 / 0 (was 5 / 0) | 84 / 100 (was 98 / 166) | 15524 → 10221 | 0.019 → 0.047 | 0.983 → 0.982 | 150.18 → 99.03 |
| s6 | tune | 1,051,586 | `RULE_DDOS_VOLUME_BASELINE` | 14 → 4 | 0 / 0 (was 0 / 0) | 0 / 0 (was 0 / 0) | 14 → 4 | — | 1.000 | 0.13 → 0.04 |
| s6 | tune | 1,051,586 | `RULE_EXFIL_EGRESS_BASELINE` | 449 → 418 | 25 / 0 (was 25 / 0) | 1 / 0 (was 1 / 0) | 423 → 392 | 0.962 | 0.942 → 0.938 | 4.27 → 3.97 |
| s6 | tune | 1,051,586 | `RULE_EXFIL_OUTBOUND_RATIO` | 2373 → 31 | 0 / 0 (was 0 / 0) | 0 / 0 (was 0 / 0) | 2373 → 31 | — | 1.000 | 22.57 → 0.29 |
| s6 | tune | 1,051,586 | `RULE_RECON_FANOUT_SYN_ONLY` | 36 → 33 | 24 / 0 (was 24 / 0) | 0 / 0 (was 0 / 0) | 12 → 9 | 1.000 | 0.333 → 0.273 | 0.34 → 0.31 |
| s6 | tune | 1,051,586 | `lightgbm_flow_classifier` | 5402 → 5403 | 3611 / 0 (was 3611 / 0) | 0 / 0 (was 0 / 0) | 1791 → 1792 | 1.000 | 0.332 → 0.332 | 51.37 → 51.38 |
| s11 | **held out** | 144,262 | `RULE_C2_PERIODIC_FLOWS` | 929 → 341 | 0 / 0 (was 0 / 0) | 9 / 5 (was 13 / 20) | 896 → 327 | 0.000 | 0.965 → 0.959 | 64.4 → 23.64 |
| s11 | **held out** | 144,262 | `RULE_DDOS_VOLUME_BASELINE` | 5 → 4 | 0 / 1 (was 0 / 1) | 0 / 0 (was 0 / 1) | 3 | 0.500 → 1.000 | 0.600 → 0.750 | 0.35 → 0.28 |
| s11 | **held out** | 144,262 | `RULE_EXFIL_EGRESS_BASELINE` | 19 | 0 / 0 (was 0 / 0) | 0 / 0 (was 0 / 0) | 19 | — | 1.000 | 1.32 |
| s11 | **held out** | 144,262 | `RULE_EXFIL_OUTBOUND_RATIO` | 57 → 16 | 0 / 0 (was 0 / 0) | 0 / 0 (was 0 / 0) | 57 → 16 | — | 1.000 | 3.95 → 1.11 |
| s11 | **held out** | 144,262 | `RULE_RECON_FANOUT_SYN_ONLY` | 2 | 0 / 1 (was 0 / 1) | 0 / 0 (was 0 / 0) | 1 | 1.000 | 0.500 | 0.14 |
| s11 | **held out** | 144,262 | `lightgbm_flow_classifier` | 425 → 426 | 0 / 0 (was 0 / 0) | 0 / 0 (was 0 / 0) | 425 → 426 | — | 1.000 | 29.46 → 29.53 |
| s12 | **held out** | 541,957 | `RULE_C2_PERIODIC_FLOWS` | 7453 → 5274 | 48 / 21 (was 58 / 26) | 63 / 26 (was 76 / 34) | 7259 → 5116 | 0.433 → 0.437 | 0.974 → 0.970 | 137.52 → 97.31 |
| s12 | **held out** | 541,957 | `RULE_DDOS_VOLUME_BASELINE` | 9 → 5 | 0 / 0 (was 0 / 0) | 0 / 0 (was 0 / 0) | 9 → 5 | — | 1.000 | 0.17 → 0.09 |
| s12 | **held out** | 541,957 | `RULE_EXFIL_EGRESS_BASELINE` | 120 → 112 | 0 / 0 (was 1 / 0) | 0 / 0 (was 0 / 0) | 119 → 112 | 1.000 → — | 0.992 → 1.000 | 2.21 → 2.07 |
| s12 | **held out** | 541,957 | `RULE_EXFIL_OUTBOUND_RATIO` | 473 → 43 | 0 / 0 (was 0 / 0) | 0 / 0 (was 0 / 0) | 473 → 43 | — | 1.000 | 8.73 → 0.79 |
| s12 | **held out** | 541,957 | `RULE_RECON_FANOUT_SYN_ONLY` | 2 → 0 | 0 / 0 (was 0 / 0) | 0 / 0 (was 0 / 0) | 2 → 0 | — | 1.000 → — | 0.04 → 0.0 |
| s12 | **held out** | 541,957 | `lightgbm_flow_classifier` | 804 → 813 | 16 / 0 (was 16 / 0) | 0 / 0 (was 0 / 0) | 788 → 797 | 1.000 | 0.980 → 0.980 | 14.84 → 15.0 |
<!-- rule-table:end -->

The confirmation runs agree with the offline sweep exactly: per rule, the alert, TP and FP counts
are equal at the new thresholds in all five scenarios. Summed over s1, s5 and s6, the pipeline
gives the sweep's totals: C2 57,121 → 47,693 alerts, TP 305 → 281.

## 5. Reading it

**Held out (s11, s12).** These were not looked at during tuning.
- **C2 beacon.**
  - s12 (NSIS.ay, P2P): 7,453 → 5,274 alerts, 137.5 → 97.3 per 10k flows. Precision over known
    is 0.433 → 0.437 (69 TP, 89 FP), and 97% of the alerts are on unlabelled hosts.
  - s11 (Rbot): 929 → 341 alerts. There are **no TP before or after**: this botnet's C2 is not
    periodic at the rule's scale, and every known C2 alert is on a normal host (14 FP).
  - The rule is quieter, not more precise.
- **Exfil outbound ratio.** On s12 it drops from 473 to 43 alerts (8.73 → 0.79 per 10k), and on s11
  from 57 to 16. Every one of those alerts, before and after, is on an unlabelled flow, so the
  cut is in volume. Nothing says whether those alerts were right or wrong.
- **Exfil egress baseline:** about the same (s12 120 → 112). Its one s12 TP was lost.
- **Recon:** s12 2 → 0 (both unknown before). s11 unchanged, with 1 TP by entity.
- **DDoS:** s11 keeps the Rbot flood TP (§6) and loses its one FP; s12 9 → 5, all unknown.

**Tuning set.** Recon keeps 74 of 81 TP and drops the unknown share on s1 from 35% to 16%.
Exfil-ratio falls from 2,373 to 31 alerts on s6. C2 loses all 5 of its s5 (Virut) TP, but the
pooled floor holds because s1 dominates the pool. That is a cost of pooling the objective, and
it is stated here instead of re-tuning per scenario.

**What this does not show.**
- **Recall.** A TP here means that an alert landed on an infected host's flow. The labels do not
  say which of the botnet's flows were C2, scanning or exfiltration.
- **Anything for DGA, tunnel or TLS** (header-only data).
- **LightGBM precision:** the model is in-sample on all five scenarios, and its counts change
  slightly only because agreement with rules changed.

## 6. The s11 ICMP flood and the warm-up limit

- **Mixed traffic.** In CTU-13-Extended s11 (all hosts) the Rbot flood **is detected**.
  `RULE_DDOS_VOLUME_BASELINE` fires at 13:53:55 on 147.32.84.191 → 147.32.96.69. The window
  held 635 MB from 4 sources, 90,397× the target's baseline, so it still fires at the tuned
  multiple of 100. The target had earlier ordinary traffic, so its baseline existed.
- **Botnet-only capture.** The miss in `docs/BENCHMARK.md` is on the public CTU-13 botnet-only
  capture. There the flood is the target's first traffic, so no baseline exists yet (warm-up).
- **Why there is no cold-start rule.** I measured whether a cold-start ceiling (bytes to one
  destination from ≤ 10 sources while no baseline exists) could separate the flood's first
  window from real traffic. It cannot. On the tuning and held-out dumps, cold-start windows
  toward ordinary destinations reach:

  | Scenario | Largest cold-start window | 99.99th percentile |
  |---|---|---|
  | s1 | 1,532 MB (one internal host to another) | 95 MB |
  | s6 | 253 MB | 243 MB |
  | s12 | 271 MB | 71 MB |

  A ceiling below the flood's 635 MB would fire on s1's bulk transfer.
- **Decision.** No cold-start path was added. The warm-up limit stays as stated for PS (a): a
  destination needs 5 closed windows of baseline before the few-source volumetric rule can
  fire. Floods from many sources are covered from the first window by the SYN-flood and
  reflection rules.

## 7. Reproduce

```bash
for s in 1 5 6 11 12; do uv run python scripts/rule_eval.py run $s --tag after & done; wait   # s1 ~70 min
uv run python scripts/rule_eval.py sweep --scenarios 1,5,6 --out sweep.json                  # tuning set only
uv run python scripts/rule_eval.py pick --sweep sweep.json --out pick.json                   # constraint tests
uv run python scripts/rule_eval.py report --before before --after after --write              # §4 + rule_metrics.json
```

The runs read `~/NewProjects/26145-data/ctu13-extended/*.truncated.pcap` and the labelled dumps
in `~/NewProjects/26145-data/features/` (docs/MODELS.md §6), with
`SIH26145_INTERNAL_CIDRS=147.32.0.0/16`.
