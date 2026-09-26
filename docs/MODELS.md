# Models

Model cards, training data, validation and the engineered-feature table for SIH26145's two ML
models. PS 26145 requires this document. Every number here was measured on the machine named in
`docs/BENCHMARK.md` and can be reproduced with the commands in §6. The full metrics are in
`docs/model_metrics.json` (capture split) and `docs/model_metrics_random_split.json` (the
falsification run in §4.4).

**What the models can and cannot see.** They were trained on header-only captures (§2), so they
read flow behaviour only: sizes, timing, flags, a coarse port class, and tier-2 host, destination
and pair behaviour. They never see DNS names, TLS fingerprints or payload. The DGA, DNS-tunnel and
encrypted-session classes, PS (c) and (d), therefore stay with the rule detectors. The models add
nothing there, and this document claims nothing for them there.

No accuracy figure appears anywhere. With 1–30% malicious flows per capture, accuracy mostly
measures the base rate.

## 1. Model cards

### 1.1 LightGBM flow classifier (`lightgbm_flow_classifier`)

| | |
|---|---|
| Purpose | Score each flow as malicious or benign from its behaviour; raise `THREAT_ML_MALICIOUS_FLOW` above the budget threshold, and raise a rule alert's severity when both agree |
| Inputs | The 48 `ML_FEATURES` of the flow's model row (`models/features.py`), taken at scoring time right after the flow's FeatureStore update. NaN = undefined (warm-up, fewer than 2 gaps); LightGBM routes missing values natively |
| Output | Probability of the malicious class. The score is **not calibrated for a new link** (§4.3) |
| Target | 1 = CTU-13 `From-Botnet` flow, 0 = `From-Normal` flow. Each malicious row carries its scenario's class name (§2.2) for per-class reporting; the model itself is binary |
| Algorithm | LightGBM 4.7.0 `LGBMClassifier`: 300 trees, learning rate 0.05, 31 leaves, min 50 rows per leaf, `num_threads=1`, deterministic, seed 42. Fixed before validation; no tuning |
| Artefact | `src/sih26145/models/artifacts/lgbm.txt` (LightGBM text model), hash-checked against `manifest.json` on load. Nothing is downloaded at runtime |
| Threshold | Probability > **0.99999974** (log-odds 15.15). This is the lowest threshold that keeps the pooled out-of-fold benign flows within the **alert budget of 1 ML-only false positive per 10,000 benign flows**: 83,035 benign flows allow 8, and 7 score above it. The budget was set before training, so that an ML-only alert stream stays reviewable on a busy link; it was not chosen for best F1 |
| Evidence | Every ML-raised or ML-agreeing alert lists the flow's top 5 features by \|`pred_contrib`\| (LightGBM's built-in TreeSHAP, log-odds units), each with its value |
| Severity | ML-only alerts are capped at MEDIUM. Agreement with a rule raises the rule alert one level |

**Why LightGBM rather than scikit-learn's HistGradientBoosting (already installed).** The brief
requires each ML alert to carry its top contributing features from a built-in method, with no new
explainability dependency. `HistGradientBoostingClassifier` has no per-prediction contribution
output. LightGBM's `predict(pred_contrib=True)` gives exact per-row TreeSHAP values. That
decided it; accuracy did not come into the choice.

### 1.2 IsolationForest (`isolation_forest_flow_model`)

| | |
|---|---|
| Purpose | Novelty: flag flows unlike the benign training flows, whatever their class; raise `THREAT_UNSUPERVISED_ANOMALY` above the budget threshold |
| Inputs | The same 48 features. NaN becomes the sentinel −1.0; every real value is ≥ 0 |
| Training data | Benign rows only (`From-Normal`, §2) |
| Output | Anomaly score = −`score_samples` (higher = more unusual). Alert confidence is the score's percentile among out-of-fold benign scores, **not a probability** |
| Algorithm | scikit-learn 1.9.1 `IsolationForest`: 100 trees, 256 samples per tree, `n_jobs=1`, seed 42 |
| Artefact | `src/sih26145/models/artifacts/iforest.joblib`, hash-checked on load |
| Threshold | Anomaly score > **0.6514**, under the same 1-per-10,000 budget (7 of 83,035 out-of-fold benign flows above it) |
| Alerts | **Corroborates only**: it never raises an alert alone (manifest `alerts_alone: false`). A flagged flow that also has a rule hit gets the forest's score attached, and the rule alert goes up one severity level. Why: §4.5 |
| Evidence | LightGBM `pred_contrib` for the same flow. The alert says so (`note`): it explains the supervised model's view, not the forest's |

### 1.3 What the models must not be used for

- **No accuracy or detection-rate claim** outside the measured numbers in §4, and none at all for
  PS (c) DGA/tunnelling or (d) encrypted-session malware. The models cannot see those signals.
- **Not a verdict on a host.** A score is about one flow. The training labels are host-based:
  every flow an infected host started is "malicious", including its ordinary lookups and updates.
- **Not a calibrated probability on a new network.** The training mix is 28% malicious. A live
  link's base rate is far lower, so read the score as a ranking and use the threshold.
- **Not evidence of absence.** Recall at the budget is well below 1 (§4). A quiet model on a flow
  says little.
- **Not against IPv6-heavy or high-bandwidth modern traffic without re-validation.** The training
  traffic is a 2011 university network (§5).

## 2. Training data

### 2.1 Sources and provenance

**CTU-13-Extended** (Stratosphere Laboratory, CTU Prague): the header-only full-traffic captures
of five CTU-13 scenarios, taken on the university's main router. They hold every host on the
link: the infected VMs, hand-checked normal hosts and unlabelled background. Payloads were cut
at 54 bytes (TCP), 42 (UDP) and 66 (ICMP), so all headers survive. The files are **pcapng**.
Their original packet lengths are read from each packet block (AUDIT A8), so byte features use
real sizes.

| Scenario | Malware (README "Probable Name"; behaviour per the CTU-13 paper) | File | sha256 (decompressed) |
|---|---|---|---|
| 1 | Neris: IRC C2, spam, click fraud | `CTU-Malware-Capture-Botnet-42/capture20110810.truncated.pcap` | `d4652b7f…4100` |
| 5 | Virut: spam, port scan, HTTP | `…-46/capture20110815-2.truncated.pcap` | `bb116165…f29e` |
| 6 | DonBot: port scan | `…-47/capture20110816.truncated.pcap` | `19ea1309…f7ad` |
| 11 | Rbot: IRC, ICMP DDoS | `…-52/capture20110818-2.truncated.pcap` | `85616ecc…036b` |
| 12 | NSIS.ay: P2P | `…-53/capture20110819.truncated.pcap` | `cae0aad9…d8d0` |

Full hashes of the downloads and the decompressed files are in
`~/NewProjects/26145-data/ctu13-extended/SHA256SUMS`. The labels are the scenario `.binetflow`
files from the CTU-13 archive already in `extracted/CTU-13-Dataset/<n>/`.

**Selection:** five scenarios with different botnet families, downloaded smallest first, none
over 1.5 GB compressed (owner decision, 2026-09-26). All five qualified.

**Licence:** the scenario READMEs say "You are free to use these files as long as you reference
this project and the authors": *Garcia, Sebastian. Malware Capture Facility Project. Retrieved
from https://stratosphereips.org*, and S. Garcia, M. Grill, J. Stiborek, A. Zunino, "An
empirical comparison of botnet detection methods", *Computers & Security* 45 (2014). The
captures and dumps stay outside this repository; only the trained artefacts are committed.

**Generated captures** (`utils/attack_scenarios.py`) are labelled by construction: a flow is
malicious when it touches the scenario's attack endpoint. They are used **only as a held-out
evaluation set**, never for training.

### 2.2 Labels and join coverage

Every capture was run through the real pipeline in dump mode (`python -m sih26145.cli
dump-features`). The dump writes one row per scored flow: the full FeatureVector plus every
FeatureStore feature the detectors read, taken at scoring time. The model reads the same row at
runtime. The dump rows were then joined to the binetflow labels
(`training/labels.py`) on protocol, both endpoints and ports (either orientation; ICMP on hosts
only) and time overlap (±1 s), with binetflow times read as Europe/Prague local time. A flow
whose overlapping rows disagree is `ambiguous`; one with no overlapping row is `unmatched`.

- **Malicious (1)** = `From-Botnet`. **Benign (0)** = `From-Normal`.
- `To-Botnet`, `To-Normal`, `Background`, ambiguous and unmatched flows are excluded from
  training. These five scenarios' label files contain no `To-Botnet` rows.
- **Class name:** each malicious flow carries its scenario's family (for example
  `ctu13-s11-rbot-irc-icmp-ddos`). The label is host-based, so the class is the host's, not the
  flow's.

| Scenario | Our flows | Malicious (From-Botnet) | Benign (From-Normal) | To-Normal | Background | Ambiguous | Unmatched | Labelled rows joined: From-Botnet / From-Normal |
|---|---|---|---|---|---|---|---|---|
| s1 | 4,952,836 | 22,928 | 49,606 | 1,220 | 4,860,972 | 0 | 18,110 | 40,961/40,961 (100.0%) / 30,245/30,258 (100.0%) |
| s5 | 196,185 | 931 | 7,062 | 164 | 187,756 | 0 | 272 | 901/901 (100.0%) / 4,657/4,660 (99.9%) |
| s6 | 1,051,586 | 4,641 | 12,327 | 497 | 1,031,640 | 1 | 2,480 | 4,630/4,630 (100.0%) / 7,466/7,471 (99.9%) |
| s11 | 144,262 | 28 | 1,016 | 75 | 142,854 | 4 | 285 | 8,164/8,164 (100.0%) / 2,709/2,709 (100.0%) |
| s12 | 541,957 | 3,137 | 13,024 | 329 | 524,060 | 1 | 1,406 | 2,165/2,168 (99.9%) / 7,612/7,615 (100.0%) |

Coverage is complete: at least 99.9% of labelled binetflow rows are matched by one of our flows.
The flow counts differ from Argus's because the flow definitions differ. Our tracker splits at
15 s idle / 60 s active and keys ICMP by host pair. In s11, the 8,164 Argus ICMP records of the
flood become 28 of our flows. The training set is 31,665 malicious and 83,035 benign flows.

### 2.3 What is not used, and why

- **CIC-IDS2017 (improved), `~/NewProjects/26145-data/extracted/cicids2017_improved`.** It is
  CICFlowMeter CSV output (`monday.csv` … `friday.csv`), with no pcaps. Our features come from
  our own flow tracker and FeatureStore, with tier-2 windows, observability state and pair
  history, at scoring time. None of that can be computed from another tool's per-flow CSV.
  Training never computes features any other way than the pipeline's own dump, so this dataset
  cannot be used.
- **The public CTU-13 `botnet-capture-*.pcap` files.** They hold only the infected hosts'
  traffic: 99.8% of scenario 12's packets touch an infected IP, and every scenario README says
  so. `From-Normal` flows have no packets there. Training on them against generated benign
  traffic would teach "real vs generated", not "malicious vs benign".
- **CTU-13 `To-Botnet`, `To-Normal` and `Background` flows.** The CTU README says `To-*` flows
  come from unknown hosts and "should not be considered malicious per se". Background is
  unlabelled. They are counted in §2.2 and never trained on.
- **Our generated attack captures.** These are evaluated as a held-out set only (§4.2). An
  earlier variant that trained on them made four of the twelve benign regression captures fire
  (§4.5). The benign regression captures themselves are never trained on.

## 3. Validation procedure

- **Leakage check first** (`training/dataset.check_leakage`). Training refuses any feature that
  is an IP, an exact port, a timestamp, a host or row identifier, or not declared for
  `ml_flow_models` in the contract. The port enters only as `dst_port_class` (4 coarse classes).
- **Scenario split: leave one CTU-13 scenario out.** For each scenario, both models are trained
  on the other four and score the held-out one, so every score in §4.1 comes from a model that
  never saw that capture. The IsolationForest is fitted on the benign rows of the other four.
  `fold_groups_disjoint` asserts that no capture is on both sides of a fold.
- **Time-ordered split:** inside each scenario, the first 70% of flows by start time train and
  the last 30% test. The splits are pooled.
- **No random row split** is used for any reported number. §4.4 shows what one would have
  claimed.
- **Threshold:** from the pooled out-of-fold benign scores (§1). The budget rule
  (`training/evaluate.budget_threshold`): allow ⌊rate × n_benign⌋ false positives. When
  n_benign × 1/10,000 < 3, the budget widens to the tightest the data supports (3 / n_benign),
  and the widened budget is stated. With 83,035 benign flows no widening was needed. No
  false-positive rate finer than 1 / 83,035 is quoted.
- **Metrics:** PR-AUC (average precision), precision and recall at the threshold, false
  positives per 10,000 benign flows, and the malicious share for context. Where a held-out
  part has only one class, PR-AUC is reported as "—", not estimated.
- **Calibration:** a 10-bin reliability table and the Brier score on out-of-fold LightGBM
  probabilities.
- **Final models** are fitted on all five scenarios with the same fixed hyperparameters. The
  thresholds come from the out-of-fold scores.

## 4. Results

### 4.1 Leave-one-scenario-out (the headline, reported as measured)

| Held-out part | Flows | Malicious | LightGBM PR-AUC | LightGBM precision / recall at threshold | LightGBM FP (per 10k benign) | IsolationForest PR-AUC | IsolationForest precision / recall at threshold | IsolationForest FP |
|---|---|---|---|---|---|---|---|---|
| **pooled, all five** | 114,700 | 31,665 | 0.9704 | 0.9992 / 0.2818 | 7 (0.84) | 0.7898 | 0.7667 / 0.0007 | 7 |
| ctu13-s1 | 72,534 | 22,928 | 0.9971 | 0.9992 / 0.3864 | 7 (1.41) | 0.7634 | 0.6875 / 0.0005 | 5 |
| ctu13-s11 | 1,044 | 28 | 0.8784 | — / 0 | 0 (0.0) | 0.2182 | — / 0 | 0 |
| ctu13-s12 | 16,161 | 3,137 | 0.7389 | 1 / 0.0057 | 0 (0.0) | 0.8703 | 1 / 0.0038 | 0 |
| ctu13-s5 | 7,993 | 931 | 0.9998 | 1 / 0.0473 | 0 (0.0) | 0.6841 | 0 / 0 | 1 |
| ctu13-s6 | 16,968 | 4,641 | 1 | — / 0 | 0 (0.0) | 0.8672 | 0 / 0 | 1 |

Per class, the malicious flows of each scenario (the recall columns above) are:
- s1 Neris: 38.6% (LightGBM) and 0.05% (IsolationForest).
- s5 Virut: 4.7% and 0.
- s12 NSIS.ay: 0.6% and 0.4%.
- s6 DonBot and s11 Rbot: 0 for both.

**Reading it honestly:**
- LightGBM *ranks* held-out scenarios well: PR-AUC 0.74–1.00 (for s6, every malicious flow
  outranks every benign one).
- At the 1-per-10k budget, cross-scenario *recall is poor*: 28% pooled, and nearly all of it
  from s1, the largest scenario. The threshold is set by the most botnet-like benign flows, all
  seven of them from s1, and the malicious flows of other families mostly score just below it.
- A deployment that wants more recall must accept a larger budget: the ranking is there, the
  margin is not.
- The IsolationForest ranks worse (PR-AUC 0.22–0.87) and catches almost nothing at the budget.

### 4.2 Generated attack captures (held out, never trained on)

| Held-out part | Flows | Malicious | LightGBM PR-AUC | LightGBM precision / recall at threshold | LightGBM FP (per 10k benign) | IsolationForest PR-AUC | IsolationForest precision / recall at threshold | IsolationForest FP |
|---|---|---|---|---|---|---|---|---|
| **pooled** | 882 | 822 | 0.9793 | — / 0 | 0 (0.0) | 0.9975 | 1 / 0.2445 | 0 |
| gen-c2_beacon | 20 | 20 | — | — / 0 | 0 (no benign) | — | — / 0 | 0 |
| gen-exfil_upload | 1 | 1 | — | — / 0 | 0 (no benign) | — | — / 0 | 0 |
| gen-port_sweep | 100 | 100 | — | — / 0 | 0 (no benign) | — | — / 0 | 0 |
| gen-single_source_flood | 61 | 1 | 0.0164 | — / 0 | 0 (0.0) | 1 | 1 / 1 | 0 |
| gen-syn_flood | 500 | 500 | — | — / 0 | 0 (no benign) | — | — / 0 | 0 |
| gen-udp_reflection | 200 | 200 | — | — / 0 | 0 (no benign) | — | 1 / 1 | 0 |

LightGBM flags **none** of the generated attacks: SYN flood, UDP reflection, few-source flood,
C2 beacon, port sweep and exfiltration all score below the threshold. The rule detectors cover
those classes, and each one fires on its capture (`tests/detectors/test_attack_captures.py`).
The IsolationForest scores every reflection flow and the few-source flood above its threshold.
Because it only corroborates, that adds severity to the rule alerts, not new alerts.

### 4.3 Calibration (LightGBM, out-of-fold)

| Predicted probability bin | Flows | Mean predicted | Observed malicious share |
|---|---|---|---|
| 0.0-0.1 | 85,614 | 0.0001 | 0.0442 |
| 0.1-0.2 | 52 | 0.1411 | 0.5769 |
| 0.2-0.3 | 32 | 0.2435 | 0.6562 |
| 0.3-0.4 | 52 | 0.3577 | 0.5769 |
| 0.4-0.5 | 46 | 0.4446 | 0.6739 |
| 0.5-0.6 | 30 | 0.5496 | 0.8000 |
| 0.6-0.7 | 33 | 0.6553 | 0.6667 |
| 0.7-0.8 | 46 | 0.7498 | 0.5652 |
| 0.8-0.9 | 50 | 0.8570 | 0.6400 |
| 0.9-1.0 | 28,745 | 0.9994 | 0.9624 |

Brier score 0.0430. The model is **overconfident at the extremes and uninformative in between**.
Flows it puts at 0.0–0.1 are 4.4% malicious (it misses held-out families), and the middle bins
hold about 0.3% of flows at a 57–80% malicious share. The scores are a ranking, not a
probability; the alert confidence shown is this raw score.

### 4.4 Time-ordered split, and the random-split falsification

Time-ordered (first 70% of each scenario trains, last 30% tests; 80,287 training flows, 20,627
malicious; thresholds from §1):

| Held-out part | Flows | Malicious | LightGBM PR-AUC | LightGBM precision / recall at threshold | LightGBM FP (per 10k benign) | IsolationForest PR-AUC | IsolationForest precision / recall at threshold | IsolationForest FP |
|---|---|---|---|---|---|---|---|---|
| **pooled** | 34,413 | 11,038 | 1 | 1 / 0.7182 | 0 (0.0) | 0.9218 | 0.8333 / 0.0005 | 1 |
| ctu13-s1 | 21,761 | 7,800 | 1 | 1 / 0.8631 | 0 (0.0) | 0.9229 | 0.75 / 0.0004 | 1 |
| ctu13-s11 | 314 | 6 | 0.9484 | — / 0 | 0 (0.0) | 0.1712 | — / 0 | 0 |
| ctu13-s12 | 4,849 | 1,159 | 1 | — / 0 | 0 (0.0) | 0.9411 | — / 0 | 0 |
| ctu13-s5 | 2,398 | 703 | 1 | 1 / 0.0043 | 0 (0.0) | 0.8934 | 1 / 0.0028 | 0 |
| ctu13-s6 | 5,091 | 1,370 | 1 | 1 / 0.8708 | 0 (0.0) | 0.9147 | — / 0 | 0 |

This split is **optimistic**: train and test share hosts and the same day. The pooled PR-AUC is
1.000, against 0.970 when a whole scenario is held out.

**Falsification: a random row split.** The same pipeline with shuffled 5-fold rows instead of
scenario folds (`--split random`, `docs/model_metrics_random_split.json`):

| Pooled out-of-fold | Scenario split (reported) | Random row split (leaky) |
|---|---|---|
| LightGBM PR-AUC | 0.9704 | **1.0000** |
| LightGBM recall at the 1/10k threshold | 0.2818 | **0.9996** |
| LightGBM threshold | 0.99999974 | 0.5792 |
| LightGBM Brier score | 0.0430 | 0.00014 |
| IsolationForest PR-AUC | 0.7898 | 0.8633 |

A random split puts flows of the same hosts and minutes on both sides of every fold. It would
have let us claim 99.96% recall at 1 false positive per 10k. The scenario split says 28%.
`tests/training/test_evaluate.py::test_validation_folds_never_share_a_scenario` goes red when
the scenario folds are replaced by random ones (§6, falsification log).

### 4.5 Benign regression captures, and why the forest only corroborates

The 12 benign regression captures (`tests/regression/`) are never trained on. With the gate open
they raise **zero alerts**. The margins are small, and they are stated here because they are the
real risk:

| Capture | Highest LightGBM score | Log-odds (threshold 15.15) | Highest forest score (threshold 0.6514) |
|---|---|---|---|
| `failed_tcp` (one SYN with retransmits) | 0.99999961 | 14.76 | 0.5310 |
| `flash_crowd` | 0.99998540 | 11.13 | 0.5995 |
| `monitoring_poller` | 0.99989678 | 9.18 | 0.5231 |
| `one_way_download` (1.5 MB/s, one direction) | 0.61715 | 0.48 | **0.6600: above** |

- A single failed TCP connection clears the LightGBM threshold by only 0.39 log-odds. In the
  CTU training data, unanswered SYNs come mostly from scanning bots. On a network where benign
  hosts often fail to connect, expect LightGBM-only alerts on them (§5).
- The forest flags the benign one-way download: no CTU normal host moved 1.5 MB/s in one
  direction.

Out of fold, the forest's recall at the budget is 0.07% (23 of 31,665 malicious flows) at
precision 0.77. So after this regression result, the forest was made **corroborate-only**. It
still attaches its score and raises severity when a rule agrees, but it raises no alert alone.
This was decided after seeing the result. The threshold was not moved, and the model was not
retrained to pass.

Earlier variants, measured this session and recorded for completeness:
1. A variant that also trained on the generated attack captures made four benign captures fire.
   With three scenarios: `rtp_stream`, `failed_tcp` (LightGBM), `one_way_download`, and
   `flash_crowd` (121 forest alerts). This is why generated data is held out.
2. The CTU-only version of the same variant made only the download fire.
3. **Both variants were fitted before a reader defect was found and fixed:** CTU-13-Extended is
   pcapng, whose original packet lengths the reader first ignored. Their byte features were
   header sizes. The final models were retrained on dumps made after the fix.

## 5. Known failure modes

- **Unanswered TCP connections look malicious.** A benign SYN retry sits 0.39 log-odds under the
  threshold (§4.5). Networks where benign hosts often fail to connect will see LightGBM-only
  alerts (MEDIUM at most).
- **Cross-family recall is low at the budget** (§4.1). A new botnet family is ranked, but
  mostly not flagged. s6 DonBot and s11 Rbot get 0 recall held out.
- **Training traffic is a 2011 university network**, with bandwidth-limited VMs and IPv4 only.
  Modern CDN-heavy, QUIC-heavy or IPv6 traffic, and higher link speeds, are outside the training
  distribution. The forest's alarm on a 1.5 MB/s download is one sign of this.
- **Few benign hosts.** `From-Normal` comes from three hand-checked workstations plus three
  servers per scenario, which the README calls "not so reliable". 83,035 flows, but little
  diversity.
- **Host-based labels:** every flow an infected host started counts as malicious, including
  ordinary DNS and web lookups. Precision against truly malicious *flows* is lower than the
  table suggests; recall on the botnet's benign-looking flows is not expected.
- **Header-only training data:** DNS, TLS and payload features are absent by construction (see the note at the top).
- **Base rate:** training is 28% malicious. On a live link the share is far lower, so precision
  at the same threshold will be lower than measured, and the raw score is not a probability
  (§4.3).
- **Tier-2 features depend on the replay:** at high paced-replay speeds, idle flows reach the
  store out of event order and windowed features shift (`docs/BENCHMARK.md`). The dumps were made
  unthrottled, the same as the offline `analyze` path.
- **Flow-table eviction:** the tracker holds 10,000 active flows. On a router capture, evicted
  flows split (`is_evicted` is in the dump). Training and runtime share this behaviour, so it
  is consistent, but the features of evicted flows are partial.

## 6. Reproduce every number

```bash
# 1. Download (resumable), decompress, hash: never under 26145-data/raw/
mkdir -p ~/NewProjects/26145-data/ctu13-extended && cd $_
B=https://mcfp.felk.cvut.cz/publicDatasets
for s in "46 capture20110815-2" "52 capture20110818-2" "53 capture20110819" "47 capture20110816" "42 capture20110810"; do
  set -- $s; wget -c "$B/CTU-Malware-Capture-Botnet-$1/$2.truncated.pcap.bz2"
  bunzip2 -k "$2.truncated.pcap.bz2"; sha256sum "$2.truncated.pcap"*; done
cd ~/NewProjects/26145

# 2. Dump features through the real pipeline, then join the labels (per scenario; s1 takes ~1 h)
F=~/NewProjects/26145-data/features; E=~/NewProjects/26145-data/extracted/CTU-13-Dataset
SIH26145_INTERNAL_CIDRS=147.32.0.0/16 uv run python -m sih26145.cli dump-features \
  ~/NewProjects/26145-data/ctu13-extended/capture20110819.truncated.pcap --out $F/ctu13-s12.csv.gz
uv run python scripts/build_dataset.py ctu --scenario 12 --dump $F/ctu13-s12.csv.gz \
  --binetflow $E/12/capture20110819.binetflow --out $F/ctu13-s12.labelled.csv.gz   # + coverage JSON
#    (same for s1 capture20110810, s5 capture20110815-2, s6 capture20110816, s11 capture20110818-2;
#     ~/NewProjects/26145-data/features/dump_ctu.sh wraps both steps)
uv run python scripts/build_dataset.py generated --outdir $F                       # held-out set

# 3. Validate, fit, write artefacts + docs/model_metrics.json (deterministic: same files every run)
uv run python scripts/train_models.py $F/ctu13-s*.labelled.csv.gz \
  --holdout $F/gen-*.labelled.csv.gz --report docs/model_metrics.json

# 4. The random-split falsification (§4.4)
uv run python scripts/train_models.py $F/ctu13-s*.labelled.csv.gz --split random \
  --report docs/model_metrics_random_split.json --no-save

# 5. Tests: leakage, folds, cap, evidence, regression captures, attack captures
uv run pytest -q
```

**Falsification log** (each break made on one line, run red on an assertion, then restored;
2026-09-26):

| Break | Red |
|---|---|
| `"src_ip"` appended to `ML_FEATURES` | `test_model_features_pass_the_leakage_check` (`src_ip: identity, exact port or capture time`); `train_models.py` refuses with the same message |
| `logo_folds` yields random row folds | `test_validation_folds_never_share_a_scenario`. The metrics change is §4.4 |
| ML-only severity cap removed (`_cap_ml_only` bypassed) | `test_ml_only_alert_is_capped_at_medium[0.8]`, `[0.99]`, `test_evidence_aggregation_ml_only` |
| pcapng reader reports captured length | `test_truncated_pcapng_blocks_report_wire_length` |

## 7. Engineered features (generated from `feature_contract.toml`)

Generated by `uv run python scripts/contract_table.py --write`;
`tests/training/test_models_doc.py` fails if this table drifts from the contract.

<!-- contract-table:start -->
Contract version 1.3.0: 82 features. `ML` = read by the models (`ml_flow_models`, 48 features).

| Feature | ML | State | Tier | Approx. | Sources | Read by | Definition and caveats |
|---|---|---|---|---|---|---|---|
| `duration` | yes | computable | flow | exact | dpkt, zeek | encrypted_anomaly_detector, feature_dump | Span of observed packets; covers both halves when both are captured. |
| `total_packets` | yes | computable | flow | exact | dpkt, zeek | feature_dump | Count of observed packets (both halves if captured). |
| `total_bytes` | yes | computable | flow | exact | dpkt, zeek | encrypted_anomaly_detector, feature_dump | Sum of observed frame lengths, taken from each record's original (wire) length (classic pcap and pcapng), so snaplen-truncated captures count full sizes (AUDIT A8, fixed). |
| `pps` | yes | computable | flow | exact | dpkt, zeek | feature_dump | total_packets / duration; meaningless for sub-millisecond flows (AUDIT A1). |
| `bps` | yes | computable | flow | exact | dpkt, zeek | feature_dump | total_bytes / duration; same caveats as pps and total_bytes. |
| `pkt_size_min` | yes | computable | flow | exact | dpkt | feature_dump | Observed frame sizes. Zeek conn.log has no size distribution. |
| `pkt_size_max` | yes | computable | flow | exact | dpkt | feature_dump | As pkt_size_min. |
| `pkt_size_mean` | yes | computable | flow | exact | dpkt | feature_dump | As pkt_size_min. |
| `pkt_size_std` | yes | computable | flow | exact | dpkt | feature_dump | As pkt_size_min. |
| `pkt_size_q25` | yes | computable | flow | exact | dpkt | feature_dump | As pkt_size_min. |
| `pkt_size_q50` | yes | computable | flow | exact | dpkt | feature_dump | As pkt_size_min. |
| `pkt_size_q75` | yes | computable | flow | exact | dpkt | feature_dump | As pkt_size_min. |
| `iat_mean` | yes | computable | flow | exact | dpkt | feature_dump | Inter-arrival over all observed packets (both halves interleaved if captured). Zeek needs the IAT script. |
| `iat_var` | yes | computable | flow | exact | dpkt | feature_dump | As iat_mean. |
| `iat_min` | yes | computable | flow | exact | dpkt | feature_dump | As iat_mean. |
| `iat_max` | yes | computable | flow | exact | dpkt | feature_dump | As iat_mean. |
| `jitter` | yes | computable | flow | exact | dpkt | feature_dump | Mean \|delta IAT\|; as iat_mean. |
| `burstiness_ratio` | yes | computable | flow | exact | dpkt | feature_dump | Coefficient of variation of packet SIZE, not temporal burstiness (AUDIT A1). |
| `small_pkt_ratio` | yes | computable | flow | exact | dpkt | feature_dump | Fraction of observed frames < 64 bytes. |
| `is_tcp` | yes | computable | flow | exact | dpkt, zeek | recon_portscan_detector, feature_dump | IP protocol header. |
| `is_udp` | yes | computable | flow | exact | dpkt, zeek | feature_dump | IP protocol header. |
| `is_icmp` | yes | computable | flow | exact | dpkt, zeek | feature_dump | IP protocol header. |
| `dst_port` |  | computable | flow | exact | dpkt, zeek | feature_dump | Destination port of the flow key (first observed packet). |
| `dst_port_class` | yes | computable | flow | exact | dpkt, zeek | feature_dump | Coarse service class of dst_port for models (0 no port, 1 < 1024, 2 1024-49151, 3 >= 49152): exact ports are a leakage risk. |
| `dns_query_count` |  | computable | flow | exact | dpkt, zeek | dga_lexical_detector, dns_tunnel_detector, feature_dump | Question section is present in both queries and responses, so either half yields it. |
| `dns_max_domain_entropy` |  | computable | flow | exact | dpkt, zeek | feature_dump | Shannon entropy of the queried name; either half. |
| `dns_max_subdomain_depth` |  | computable | flow | exact | dpkt, zeek | feature_dump | Label count of the queried name; either half. |
| `tls_client_hello_count` |  | degraded | flow | exact | dpkt, zeek | feature_dump | Needs the client half (ClientHello); absent on reverse_only flows. QUIC ClientHellos are unavailable (encrypted). |
| `tls_max_sni_entropy` |  | degraded | flow | exact | dpkt, zeek | feature_dump | Client half only; SNI replaced by the public name under ECH. |
| `tls_max_sni_length` |  | degraded | flow | exact | dpkt, zeek | feature_dump | As tls_max_sni_entropy. |
| `has_syn` | yes | computable | flow | exact | dpkt, zeek | feature_dump | OR of TCP flags over observed packets. |
| `has_fin` | yes | computable | flow | exact | dpkt, zeek | feature_dump | OR of TCP flags over observed packets. |
| `has_rst` | yes | computable | flow | exact | dpkt, zeek | feature_dump | OR of TCP flags over observed packets. |
| `tls_ja3` |  | degraded | flow | exact | dpkt, zeek | — | JA3 of the cleartext ClientHello: client half only; not available for QUIC. |
| `tls_ja4` |  | degraded | flow | exact | dpkt, zeek | encrypted_anomaly_detector | JA4 (TCP 't' variant) of the cleartext ClientHello: client half only; QUIC 'q' variant needs decryption. |
| `tls_ja3s` |  | degraded | flow | exact | dpkt, zeek | — | JA3S of the cleartext ServerHello: server half only. JA4S deferred (FoxIO licence). |
| `reverse_seen` | yes | computable | flow | exact | dpkt, zeek | feature_dump | Packets matching the reversed 5-tuple were observed (zeek: resp_pkts > 0). |
| `flow_direction` |  | computable | flow | exact | dpkt, zeek | — | outbound/inbound/internal/external from the internal-CIDR policy; no reverse half needed. |
| `egress_bytes` |  | computable | flow | exact | dpkt, zeek | exfiltration_detector, feature_dump | Bytes observed travelling internal -> external in this flow, whichever half carried them. |
| `src_flows_w` | yes | computable | host | exact | dpkt, zeek | feature_dump | Flows first observed from this host. |
| `src_distinct_dsts_w` | yes | computable | host | hll | dpkt, zeek | recon_portscan_detector, feature_dump | Fan-out: distinct destination IPs from this host (HLL p=8, ~6.5% error). |
| `src_distinct_dst_ports_w` | yes | computable | host | hll | dpkt, zeek | recon_portscan_detector, feature_dump | Distinct destination ports from this host. |
| `src_syn_only_ratio_w` | yes | degraded | host | exact | dpkt, zeek | recon_portscan_detector, feature_dump | Share of TCP flows where the initiator sent SYN and never ACKed. Proxy for failed handshakes that needs no reverse half; a SYN-ACK lost beyond the tap looks the same. |
| `src_dns_queries_w` |  | computable | host | exact | dpkt, zeek | dns_tunnel_detector, feature_dump | Queried names attributed to the DNS client side of each flow. |
| `src_distinct_qnames_w` |  | computable | host | hll | dpkt, zeek | dga_lexical_detector, feature_dump | Distinct queried names per client. |
| `src_high_entropy_qnames_w` |  | computable | host | exact | dpkt, zeek | dga_lexical_detector, feature_dump | Queried names whose first label has Shannon entropy >= 3.5 bits (configurable). |
| `src_qname_len_sum_w` |  | computable | host | exact | dpkt, zeek | dns_tunnel_detector, feature_dump | Total characters queried: a volume proxy for DNS tunnelling. |
| `src_nxdomain_rate_w` |  | reverse_dependent | host | exact | dpkt, zeek | dga_lexical_detector, feature_dump | NXDOMAIN share of resolver responses to this client. Computed whenever resolver responses were captured, including a responses-only capture; raises UnavailableFeatureError when none were. |
| `src_distinct_ja4_w` |  | degraded | host | hll | dpkt, zeek | — | Distinct JA4 client fingerprints; needs the client half. |
| `src_periodic_dsts_w` | yes | computable | host | hll | dpkt, zeek | c2_beacon_detector, feature_dump | Distinct destinations this host contacts at a regular interval (pair inter-flow CV <= 0.35 over >= 3 gaps). A beacon has one or two; a poller has dozens. |
| `src_egress_bytes_1m` |  | degraded | host | exact | dpkt, zeek | — | Internal->external bytes from this host in the current minute. Counts only captured halves: a capture holding only inbound halves sees no egress. |
| `src_egress_bytes_5m` |  | degraded | host | exact | dpkt, zeek | — | As src_egress_bytes_1m, last 5 one-minute buckets. |
| `src_egress_bytes_1h` |  | degraded | host | exact | dpkt, zeek | — | As src_egress_bytes_1m, last 60 one-minute buckets. |
| `src_egress_bytes_z` |  | degraded | host | ewma | dpkt, zeek | exfiltration_detector, feature_dump | Current-minute egress vs this host's EWMA baseline; null until 5 minutes of baseline. Same capture caveat as src_egress_bytes_1m. |
| `off_hours` |  | computable | flow | exact | dpkt, zeek | exfiltration_detector, feature_dump | Event time outside configured working hours/days (enclave local time). |
| `dst_flows_w` | yes | computable | dst | exact | dpkt, zeek | ddos_volume_detector, feature_dump | Flows toward this destination. |
| `dst_bytes_w` | yes | computable | dst | exact | dpkt, zeek | ddos_volume_detector, feature_dump | Observed bytes of flows toward this destination (both halves if captured). |
| `dst_distinct_srcs_w` | yes | computable | dst | hll | dpkt, zeek | ddos_volume_detector, recon_portscan_detector, feature_dump | Fan-in: distinct sources toward this destination. |
| `dst_src_ip_entropy_w` | yes | computable | dst | bucketed | dpkt, zeek | ddos_volume_detector, feature_dump | Entropy of source IPs toward this destination over 128 hash buckets; saturates at 7 bits, collisions bias low. |
| `dst_syn_only_ratio_w` | yes | degraded | dst | exact | dpkt, zeek | ddos_volume_detector, feature_dump | As src_syn_only_ratio_w, per destination (SYN-flood signal). |
| `dst_reflector_flows_w` | yes | degraded | dst | exact | dpkt, zeek | ddos_volume_detector, feature_dump | UDP flows toward this endpoint from a reflector source port (53, 123, 1900, 11211, 389, 19, 161, 111) on which the endpoint sent nothing: unsolicited. Needs the endpoint's own half to prove a response was solicited, so on a capture holding only inbound halves genuine answers are counted too. |
| `dst_reflector_bytes_w` | yes | degraded | dst | exact | dpkt, zeek | ddos_volume_detector, feature_dump | Bytes sent by the reflectors in dst_reflector_flows_w; same capture caveat. |
| `dst_reflector_mean_pkt_w` | yes | degraded | dst | exact | dpkt | ddos_volume_detector, feature_dump | Mean packet size sent by those reflectors (amplified responses are large); same capture caveat. Null when there are none. |
| `dst_bytes_vs_baseline` | yes | computable | dst | ewma | dpkt, zeek | ddos_volume_detector, feature_dump | Current-window bytes toward this destination / its EWMA of past window totals (silent windows count as zero). Null until 5 windows have closed: the baseline needs warm-up. |
| `dst_flows_vs_baseline` | yes | computable | dst | ewma | dpkt, zeek | ddos_volume_detector, feature_dump | As dst_bytes_vs_baseline, for flow counts. |
| `dst_distinct_srcs_longterm` | yes | computable | dst | hll | dpkt, zeek | exfiltration_detector, campaign_correlator, feature_dump | Distinct sources ever seen toward this destination while tracked (rarity). Includes the current flow: 1 = only this source. |
| `pair_flows_w` | yes | computable | pair | exact | dpkt, zeek | encrypted_anomaly_detector, feature_dump | Flows from src to dst. |
| `pair_iat_mean` | yes | computable | pair | exact | dpkt, zeek | c2_beacon_detector, feature_dump | Mean gap between successive flow starts src->dst (Welford). |
| `pair_iat_cv` | yes | computable | pair | exact | dpkt, zeek | c2_beacon_detector, feature_dump | Coefficient of variation of those gaps; low = periodic. Null below 2 gaps. |
| `pair_iat_n` | yes | computable | pair | exact | dpkt, zeek | c2_beacon_detector, feature_dump | Number of inter-flow gaps observed. |
| `pair_history_count` | yes | computable | pair | cms | dpkt, zeek | encrypted_anomaly_detector, feature_dump | Long-horizon flow count src->dst (Count-Min, halves daily). Includes the current flow: 1 = first contact. |
| `ja4_prevalence` |  | degraded | global | cms | dpkt, zeek | encrypted_anomaly_detector, feature_dump | How often this JA4 has been seen enclave-wide (Count-Min, halves daily). Client half only. |
| `link_reverse_visibility_w` |  | computable | link | exact | dpkt, zeek | — | Fraction of flows in the window with reverse_seen: the link's measured visibility. |
| `outbound_inbound_byte_ratio` |  | reverse_dependent | flow | exact | dpkt, zeek | exfiltration_detector, feature_dump | Needs bytes in both directions. Never estimated when the inbound half is missing. |
| `tcp_handshake_completed` |  | reverse_dependent | flow | exact | dpkt, zeek | — | SYN in one direction and SYN-ACK in the other. |
| `tcp_rtt` |  | reverse_dependent | flow | exact | dpkt | — | Tap-observed SYN -> SYN-ACK delay: the responder leg as seen from the tap. |
| `tls_client_server_fp_pair` |  | reverse_dependent | flow | exact | dpkt, zeek | — | JA4 of the ClientHello paired with JA3S of the ServerHello: needs both halves. |
| `dns_nxdomain_rate` |  | reverse_dependent | flow | exact | dpkt, zeek | — | Needs the resolver's responses. Computed whenever they were captured (responder_seen), including a responses-only capture that never saw the query; unavailable otherwise. |
| `quic_client_hello` |  | unavailable | flow | exact | — | — | QUIC Initial packets are AEAD-protected. The keys are public, but removing them is decryption and the PS forbids detection from decrypted content. |
| `tls13_server_certificate` |  | unavailable | flow | exact | — | — | TLS 1.3 encrypts the Certificate message; reading it needs decryption. |
| `jarm_server_fingerprint` |  | unavailable | flow | exact | — | — | JARM sends ten crafted ClientHellos: our own handshake. The enclave never transmits. |
| `service_banner_probe` |  | unavailable | flow | exact | — | — | Needs active probing of the destination. |
<!-- contract-table:end -->
