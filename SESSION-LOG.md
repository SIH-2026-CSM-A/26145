# Session Log

## 2026-09-27 — Claude Code (Opus 5.5) — session 6: a dashboard judges remember, and a narrated film

**Agent:** Claude Code (Anthropic, model Opus 5.5). Branch `main`, starting at `977301e` (236 tests).
No other agent worked on this repo. The pipeline is frozen at `idea-deck-v3`: no detection, flow,
feature, model or storage code changed.

### Owner decisions
- **Mockups first.** Two mockups were rendered from the real components on a live replay and approved.
- **Changes after review:**
  - KPI notes name the demo rate next to the tested capacity;
  - tiles show the latest real alert's evidence line;
  - the ribbon is full width;
  - the map seams are fixed;
  - the 2D fallback matches the 3D hero;
  - the case file scrolls and fits the still.
- **Plain SVG for the campaign map** (Cytoscape removed); React 19 (current fiber/drei need it).
- **Order:** A → B → C → E (stills + tag), then the narrated film.

### Shipped (commits in order)
1. `b25962d feat(dashboard): design system`:
   - tokens and bundled fonts;
   - a 14 px text floor;
   - Counter (anime.js) and Sparkline;
   - PS tile definitions.
2. `6d83f3a feat(dashboard): ...`:
   - the one-way-link hero (three.js), with a 2D fallback on `?nogl` or without WebGL;
   - six PS tiles, the KPI strip, the ribbon and the replay banner;
   - the SVG campaign map, the stage timeline, the case file (chain links + Verify) and the model card;
   - API: `GET /stats/classes` and `GET /chain/blocks`; HEAD on every GET route (the SSE stream excepted);
   - tests: `tests/api/test_dashboard_endpoints.py`; `smoke.mjs` rewritten; `smoke.sh` paces at 60×.
3. `6b29639 feat(demo): stills`:
   - `docs/media/s6-01..07`;
   - `demo-shots.mjs` rewritten;
   - `render_verify_log.py` in the new palette;
   - `demo-video.mjs` removed (it drove Cytoscape).
4. `docs:` this entry, TODO.

### Verification
- `uv run pytest -q`: 240 passed. Ruff (`--isolated --select E4,E7,E9,F`): 30 findings, none new.
- `scripts/smoke.sh` passes:
  - hero webgl;
  - tile (a) pulsed;
  - no map label overlap;
  - the case file opened and Verify recomputed the chain;
  - `?nogl` rendered;
  - no offsite request.
- Bundle: `index` 453 KB (148 KB gzip), lazy `Scene3D` 952 KB (257 KB gzip), CSS 26 KB, fonts
  bundled.
- **fps** (15 s rAF sample during a live 5× replay, as in the Performance panel's frame track):
  - native Windows Chrome, this laptop: **144 fps** (the display's refresh), p95 frame 7.1 ms,
    for both the WebGL hero and `?nogl`, at 1920×1050 device px;
  - under WSLg (D3D12 → Intel UHD): 43 fps for WebGL; the same page with the hero hidden runs at
    48 fps, and a blank page at 60. The cost is WSLg compositing, not the scene;
  - headless SwiftShader: 55 fps.
- **Benchmark re-run** (CTU-13 s12 unthrottled): **867.5 flows/s, 224.9 Mbps**, 0 drops. That is
  +0.9% vs the 859.5 mean, inside the 5% bar. Data: `26145-data/bench/s6/s12-u1.json`. Docker
  Desktop stayed up because another project's six containers were running (not ours to stop).
  They drew < 1% CPU, and the 1-min load was 0.33 before the run.

### Found along the way
- **The SYN flood's alert comes out at the capture's EOF flush.** By the time all four campaigns
  exist the replay is ending, so s6-01 is taken as its spark lands on tile (a). It was still
  `running` at that moment.
- **drei `<Html>` dropped a label under React 19.** Hero labels are now DOM, projected by the scene.
- **Map seams.** `backdrop-filter` on the glass panels left straight seams in headless stills after
  scrolling, so panel blur was removed (the panels are near-opaque anyway).
- **Shell kills.** `pkill -f`/`pgrep -f` with a pattern that is also in the shell's own command
  line kills the shell (exit 144). A bracket trick (`[p]ort 18001`) avoids it.

### Part D: the narrated film (after the tag)
- Owner picks and edits:
  - voice Kokoro `af_heart` at 0.9 speed;
  - the script edits for beats 1, 5, 7 and 8, with the cut rule "only if over 3:40".
- Length: Kokoro pads every line with ~0.9 s of silence (37.7 s in total). Trimming that to a
  0.3 s gap brought the film to **3:38.5 (218.5 s) with no sentence cut**. Neither of the owner's
  conditional cuts was needed.
- `demo/film/` holds the tooling. The mp4, WAVs and frames sit in the git-ignored `out/`.
  - `tts.py`: one WAV per line, with phoneme overrides;
  - `plan.py`: each segment lasts as long as its narration;
  - `render-scenes.mjs`: the five HTML scenes, seeked frame by frame with anime.js;
  - `film-record.mjs`: one real `serve --speed 5` replay via Chrome screencast (29 fps), with alert
    and spark-landing times logged;
  - `assemble.py`: cuts with "time skip · N s cut" badges, −16 LUFS, ASS subtitles at 1080p plus
    an `.srt`;
  - `check.py`: a contact sheet and cue/onset sync.
- **Checks on the output:**
  - H.264 1080p30 + stereo AAC 48 kHz;
  - integrated −16.4 LUFS;
  - all 44 subtitle cues within 53 ms of the speech onset;
  - the contact sheet was reviewed.
- **Found and fixed:**
  - an SRT burned through libass lays out on a 384×288 canvas, which gave one-word lines at ~135 px;
    the fix was a native 1920×1080 ASS;
  - spaCy's model download went into the product `.venv`; it was removed and put in the TTS venv;
  - the false-positive outline cut through labels, so it was re-recorded.
- The tamper scene types the real transcript. `render_verify_log.py OUT.json` runs the same real
  commands as the PNG render and writes the transcript.

### Not done / next
- The VM redeploy (owner).

## 2026-09-27 — Claude Code (Opus 5.5) — session 5: re-benchmark, PPT stills, demo video, HTTPS profile

**Agent:** Claude Code (Anthropic, model Opus 5.5). Branch `main`, starting at `0b8e954` (236 tests).
No other agent worked on the repo during this session.

### Owner decisions (at planning)
- Docker Desktop is quit before the benchmark series and started again only for Part D.
- The six stills are committed to `docs/media/` (each under 1 MB), and two are shown in the README.
- Captions say "replayed at 2× real time" and quote only numbers that are on screen or in
  BENCHMARK/MODELS/RULES. Throughput comes from the new figures.

### Shipped (commits in order)
1. `fedf71f perf:`
   - The series was re-run on an idle machine, with Docker Desktop stopped and 1-min load ≤ 1.43.
     Data is in `26145-data/bench/s5/`.
   - CTU-13 s12 botnet-only: **859.5 flows/s mean** (803.5 / 879.1 / 895.9) and ~223 Mbps.
     That is 7.6% below session 3. The repeat was 867.9, within 1.0% of the mean.
   - Paced 184× gave 0 drops, with flush → alert 6.7 / 217 / 250 ms. 736× with a 1k queue dropped
     5.6%.
   - Mixed CTU-13-Extended s12: 1,128.6 flows/s (−8.7%). s11 ran at 676.6 Mbps.
   - In the profile, the correlator is 2.2% and the chain hash rounds to 0.
   - The session-3 tables are kept as "superseded"; README and ARCHITECTURE §13/§15 are updated.
2. `f7b038e feat(demo):`
   - `demo-shots.mjs --ppt` asserts what each still shows before taking it.
   - `scripts/render_verify_log.py` is a PEP 723 script (Pillow is not a project dependency). It
     runs analyze, verify-log, a one-byte edit of alert #3's JSON with Python's sqlite3 (the CLI is
     not installed) and verify-log again, which prints "BROKEN at index 3 of 10".
   - `docs/media/` 01–06.
3. `34a19d4 feat(demo):` `dashboard/tests/demo-video.mjs` records a captioned 1920×1080
   walkthrough of `serve --speed 2 --loop`:
   - `--pause 240` only holds the final picture;
   - every caption is gated on the page or the API;
   - the recording is 5:58, H.264.
4. `3b25644 feat(deploy):`
   - A compose profile `https`: caddy:2 with `SIH_HOSTNAME=<VM-IP>.sslip.io`, and `SIH_BIND` for the
     sensor port.
   - `deploy/Caddyfile`; DEPLOY.md firewall rules and steps.
5. `docs:` this entry, TODO, ARCHITECTURE §15.

### Verification
- `uv run pytest -q`: 236 passed. `npm run build` passes; `scripts/smoke.sh` passes.
- Ruff (`--isolated --select E4,E7,E9,F`) gives 30 findings, none new.
- `docker compose config` passes with and without `--profile https`, and `caddy validate` passes on
  the Caddyfile.
- The profile was also run locally on alternate ports with `SIH_HOSTNAME=localhost`:
  - health 200 over HTTP/2;
  - HTTP 308 to HTTPS;
  - POST 405;
  - the SSE heartbeat passes through unbuffered.

  Not deployed.
- The video was reviewed frame by frame at several points. Two captions were corrected before the
  final take:
  - "scans many ports and machines" became "many ports on 10.0.0.200" (the generator sweeps 100
    ports on one host);
  - the DDoS caption no longer says "arrives", because the flood had already appeared by then.

### Found along the way
- **Title-card wording.** "Replay of a recorded capture … nothing mocked" became "a committed capture
  (real CTU-13 university traffic plus generated attack packets) … nothing on screen is mocked". The
  attacks in `demo/demo.pcap` are generated, not recorded.
- **FP count.** Only 2 of the 3 university-host C2 alerts have the university host as source. The
  third is inbound (74.125.232.214 → 147.32.84.170), so the video counts either end.
- **Beat 6.** It was cut: no "not merged" note appears in the demo run, so none is captioned.
- **Docker.** Docker Desktop restarted by itself at 08:00 UTC, 33 min after the benchmark series
  ended (07:27 UTC). No measurement overlapped it.
- **Shell kills.** `pkill -f` with a pattern that also matches the shell's own command line kills
  the shell (exit 144). Stop background servers by task, or by PID.

### Not done / next
- The GCP deployment (DEPLOY.md §1–4).
- Pre-existing and unchanged: C2 noise on real traffic, and the paced-replay tick at high `--speed`.

## 2026-09-26 — Claude Code (Opus 5.5) — session 4: rule precision, hash chain, campaigns, dashboard, demo package

**Agent:** Claude Code (Anthropic, model Opus 5.5). Branch `main`, starting at `21a3946` (204 tests).
No other agent worked on the repo during this session.

### Owner decisions (at planning)
- **Part 1 objective.** Precision over known ignores the unknown bucket. So: among candidates
  that keep ≥ 90% of tuning-set TP, take the lowest alerts per 10k flows; ties go to precision.
  Report the unknown share and alerts per 10k next to precision. Tune on s1/s5/s6, and report
  s11/s12 held out.
- **Public demo, no auth.** Only GET and SSE. A 405 test covers every route, and access is
  same-origin (CORS removed).
- **Demo capture committed to git** (< 25 MB, with attribution and a pinned sha256), so a clone
  plus `docker compose up` runs it.
- **Dashboard.** Delete old components only if nothing imports them. Check the layout at
  1366×768 and 1920×1080.

### Shipped (commits in order)
1. `f4eb2e4 feat(storage):`
   - A SHA-256 hash chain over stored alerts (genesis = 64 zeros), with schema v3 and plain
     INSERT.
   - `sih26145 verify-log` / `export`: `alerts.jsonl`, `chain_head.txt`, `manifest.json`, and a
     Section 63 BSA data sheet (Part A/Part B, "not legal advice").
   - `GET /chain/verify`.
   - Adds the `sih26145` console script.
2. `3b48655 feat(correlate):` campaign correlation (IDF pivots with a 1,000-alert prior,
   common-infrastructure refusal recorded on the alert), ATT&CK `host_stage`, `/campaigns`,
   `/hosts/{ip}/timeline`. Contract 1.3.0 declares the correlator's read.
3. `fbe65d1 feat(dashboard):` Cytoscape campaign graph, alert drawer, host timeline, facts
   strip, and a model card quoted from MODELS.md. Same-origin and read-only. No-transmit AST test
   and a Playwright smoke test (`scripts/smoke.sh`).
4. `db78f4c fix(correlate):` only destination pivots can be refused. A busy workstation had
   been split into two campaigns in the demo.
5. `2b7f569 fix(dashboard):` deterministic grid layout. cose had overlapped the campaign boxes.
6. `8d0b84b feat(eval):` `scripts/rule_eval.py` (run/join/sweep/pick/report),
   `docs/RULES.md`, `docs/rule_metrics.json`, ruleset 2.1.0.
7. `d80b5d6 feat(demo):` `demo/demo.pcap`, `serve --loop`, Dockerfile, compose, `DEPLOY.md`,
   `scripts/demo.sh`.
8. `docs:` this entry, TODO, ARCHITECTURE, README, CLAUDE.md.

### Results
- **Rule precision** (full pipeline, before → after; docs/RULES.md §4 has every row):
  - **held-out s12:** C2 137.5 → 97.3 alerts per 10k flows, precision over known 0.433 → 0.437,
    97% unknown. Exfil ratio 8.73 → 0.79 per 10k (all unknown).
  - **held-out s11:** C2 64.4 → 23.6 per 10k, 0 TP before and after. The Rbot flood is still
    caught by the baseline rule.
  - **tuning:** C2 loses all 5 s5 TP; the pooled floor holds through s1.
  - **DDoS:** the tuning is vacuous (no flood in s1/s5/s6), bounded by the generated captures.
- **Sweep fidelity.** The offline sweep equals the pipeline exactly, per rule, for alerts, TP
  and FP, before and after, in all five scenarios.
- **s11 cold start.** Cold windows of real traffic reach 1,532 MB, above the flood's 635 MB. No
  rule was added; the reason is documented.
- **Demo** (unthrottled): 10 alerts in 4 campaigns, all six PS classes.
  - Host 192.168.1.66: recon, TLS, C2, DGA, tunnel, exfil = one campaign (Discovery → C2 →
    Exfiltration).
  - DDoS on 10.50.0.10: its own campaign.
  - 3 C2 alerts on real CTU normal hosts (147.32.84.134, 147.32.84.170 ×2).
  - At 5× and 2× the alert list is identical to unthrottled: 20,857 flows, 0 dropped.
- **Docker.** The image runs with `--network none` (uid 10001, read-only rootfs). Compose on a
  free port gives 405 for POST/DELETE and no CORS headers. The clean-clone image was checked
  the same way.

### Verification
- `uv run pytest -q`: **236 passed**, also from a clean clone. The 12 benign captures give 0
  alerts, and every attack capture fires its detector.
- `npm run build` passes; `scripts/smoke.sh` passes, also from a clean clone. The dashboard was
  checked by screenshots at 1366×768 and 1920×1080 on the live demo.
- Ruff (`--isolated --select E4,E7,E9,F`): 30 findings, none new (31 at session start).
- **Falsified:**
  - an injected `sendto` in `ingest/reader.py` turns the no-transmit test red;
  - a changed model-card figure turns the facts test red;
  - the busy-host correlation test fails on the pre-fix code.

### Existing tests changed
- `test_storage.py`: a duplicate `alert_id` is now refused, not replaced (the chain).
- `test_storage_migration.py`: user_version 3.
- `test_api_endpoints.py`: the CORS test became `test_no_cross_origin_reads`; SSE queue items
  are `(event, payload)`.
- `test_streaming.py`: the same tuple change.
- `test_rule_detectors.py`: the SYN-flood and C2 boundary tests read the class constants
  instead of the literal 100 and 8.

### Found along the way
- `.gitignore`'s Python `lib/` rule hid `dashboard/src/lib/`, and the dashboard commit briefly
  lacked two files. Fixed (`/lib/`) and amended before push.
- `*.pcap` was ignored; `!demo/demo.pcap` was added.
- Port 8000 is occupied on this machine by an unrelated service (it answers with permissive
  CORS). Use `SIH_PORT` / `PORT`.

### Not done / next
- Not deployed (next session). Throughput has not been re-measured since the correlator and
  hash chain were added.
- C2 is still noisy on real traffic; the next lever is a feature, not a threshold (TODO).

## 2026-09-26 — Claude Code (Opus 5.5) — session 3: trained models, MODELS.md, batched throughput

**Agent:** Claude Code (Anthropic, model Opus 5.5). Branch `main`, starting at `08cc107`
(177 tests passing). No other agent worked on the repo during this session.

### Owner decisions (asked at planning)
- **The public CTU-13 pcaps are botnet-only.** 99.8% of scenario 12's packets touch the infected
  IPs, so `Normal` rows had nothing to join. Decision: download the CTU-13-Extended truncated
  full-traffic pcaps for five scenarios, smallest first (s5, s11, s12, s6, s1; none over
  1.5 GB bz2), into `~/NewProjects/26145-data/ctu13-extended/` with `wget -c`.
- CTU rows carry no DNS/TLS payload. The supervised model covers flow behaviour only; DGA,
  tunnel and encrypted-session detection stay with the rules.
- `To-Botnet` excluded; malicious = `From-Botnet`, benign = `From-Normal`.
- Budget rule added by the owner: when the pooled benign set is under 30,000 flows, widen to
  ≥ 3 expected false positives and say so. The final set has 83,035 benign flows, so no
  widening was needed.
- A mixed-traffic benchmark run is added on the CTU-13-Extended s12 capture.

### Shipped (commits in order)
1. `aeffee1 feat(training):`
   - A8 fixed for classic pcap **and pcapng**: the wire length comes from record headers and
     packet blocks.
   - `models/features.py` `model_row` is the single model-input function, used by both the
     dump and the runtime.
   - `dump-features` CLI; the CTU-13 label join (`training/labels.py`); `build_dataset.py`.
   - Contract 1.2.0 (`dst_port_class`, `feature_dump` consumer).
2. `a4ec46b feat(models):`
   - LightGBM + IsolationForest trained on the five scenarios. The synthetic RF/IF and
     `scripts/forensic_verification.py` are deleted.
   - Leakage check; leave-one-scenario-out and time-ordered validation; alert-budget
     threshold.
   - `pred_contrib` evidence; ML-only alerts capped at MEDIUM; agreement raises severity one
     level. Artefacts are hash-checked; `lightgbm` added to pyproject.
3. `4d57d4a perf:`
   - Batched consumer (256 flows, one predict per model per batch, `n_jobs=1` /
     `num_threads=1`).
   - Benchmark series rerun; BENCHMARK.md, ARCHITECTURE §8/§9/§13/§15, README.
4. `docs:` (this commit): `docs/MODELS.md` (model cards, data, coverage, validation, results,
   failure modes, commands, generated feature table); AUDIT D1; TODO; CLAUDE.md gotchas; this
   log.

### Data
- Five captures were dumped through the real pipeline:
  - s1: 4,952,836 flows, 63 min;
  - s5: 196,185;
  - s6: 1,051,586;
  - s11: 144,262;
  - s12: 541,957.
- Joined: 31,665 `From-Botnet` and 83,035 `From-Normal` flows; ≥ 99.9% of labelled binetflow rows
  matched a flow in every scenario. The files have no `To-Botnet` rows.
- Generated attack captures are a held-out evaluation set only.

### Results (docs/MODELS.md has every table)
- **Leave-one-scenario-out, pooled:**
  - LightGBM: PR-AUC 0.970. At the 1-per-10k budget (threshold 0.99999974), 7 false positives
    in 83,035 benign flows and **28% recall**, nearly all from s1. s6 DonBot and s11 Rbot get
    0 recall held out, although s6 ranks perfectly (PR-AUC 1.0).
  - IsolationForest: PR-AUC 0.790; recall 0.07% at the budget.
- **Random-split falsification:** LightGBM PR-AUC 1.000 and recall 99.96%. That is what a leaky
  split would have claimed. Both sets are recorded.
- **Calibration:** Brier 0.043; overconfident at the extremes, so the scores are a ranking.
- **Generated held-out attacks:** LightGBM flags none. The rules cover them.

### Throughput (docs/BENCHMARK.md)
- CTU-13 s12 botnet-only: **927.0–932.8 flows/s, 240.3–241.8 Mbps**, one core (session 2:
  ~121). A repeat run landed within 0.1%.
- Paced at ~50% (200×): 0 drops. Detection latency is flow close (15 s idle / 60 s active,
  plus ≤ 1 s tick), then flush → alert p50/p95/p99 of 6.9/265/305 ms.
- ~2× overload with a 1k queue: 1.8% dropped, all counted.
- Mixed traffic (CTU-13-Extended s12, all hosts): 1,235.5 flows/s, with Mbps from pcapng
  original lengths.
- Largest completed: s11 botnet-only, 4.07 GB at 681 Mbps. s10 (66 GB) was not run.
- New profile top five: dpkt parsing 38.7%, model-row store reads 13.6%, extraction 11.7%,
  tracker 9.3%, batched IsolationForest 6.2%.

### Verification
- `uv run pytest -q`: **204 passed** (177 at session start; tests added and changed listed
  below). The 2 warnings are the third-party deprecations present at baseline.
- All 12 benign regression captures raise 0 alerts with the ML gate open. Every attack capture
  fires its detector exactly once.
- Ruff with the rule set session 2 counted (`--isolated --select E4,E7,E9,F`): 41 findings at
  `08cc107`, 31 now, none new. The installed ruff 0.16.9 has wider defaults, so the old
  "default rules" wording no longer names the same rule set.
- `npm run build` passes.

### Falsification log (each break on one line, red on an assertion, then restored)
| Target | Break | Red test |
|---|---|---|
| Leakage check | `"src_ip"` appended to `ML_FEATURES` | `test_model_features_pass_the_leakage_check`; `train_models.py` refuses |
| Scenario split | `logo_folds` yields random row folds | `test_validation_folds_never_share_a_scenario` (metrics change: MODELS.md §4.4) |
| ML severity cap | `_cap_ml_only` bypassed | `test_ml_only_alert_is_capped_at_medium[0.8]`, `[0.99]`, `test_evidence_aggregation_ml_only` |
| A8, classic pcap | parser uses captured length | `test_truncated_records_report_wire_length_and_parse_headers` |
| A8, pcapng | reader reports captured length | `test_truncated_pcapng_blocks_report_wire_length` |

### Found and fixed along the way
- **The CTU-13-Extended files are pcapng.** The first A8 fix covered only classic pcap. The
  first training pass therefore used header sizes (54/42/66 B) for every byte feature, and the
  first mixed-traffic Mbps figure was wrong. This was found through the benchmark's capture
  facts (2 packets, a 1.1e9 s span). pcapng block original lengths are now read. All five
  scenarios were re-dumped and the models retrained. Nothing from the first pass is quoted
  except the recorded variant history in MODELS.md §4.5.
- **Dump column collision:** the FeatureVector's float `dst_port` overwrote the identity port
  ("53.0"), and the first join matched almost nothing. Identity columns now win; the parity
  test checks it.
- **A shortcut from generated data:** training on the generated attack captures made four
  benign regression captures fire (LightGBM on RTP and on a failed TCP connection). The
  generated captures are now held out; the final models are CTU-only.

### Decided (after seeing results; stated as such in MODELS.md)
- **The IsolationForest corroborates only** (manifest `alerts_alone: false`). With wire sizes,
  it flagged the benign one-way download (0.660 against a threshold of 0.651), and its
  out-of-fold recall at the budget is 0.07%. The threshold was not moved. It still attaches its
  score and raises severity on rule agreement.
- Small margins are disclosed: a benign failed TCP connection scores 14.76 log-odds against
  a LightGBM threshold of 15.15.

### Existing tests changed
- `tests/models/test_ml_models.py`: rewritten for the trained artefacts (manifest, batch =
  single, NaN kept, port class, tamper refusal).
- `tests/alerts/test_alert_engine.py`:
  - `test_evidence_aggregation_ml_only` now expects MEDIUM (the cap);
  - the hybrid test expects CRITICAL (agreement);
  - `test_synthetic_ml_cannot_create_or_inflate_an_alert` became
    `test_closed_ml_gate_cannot_create_or_inflate_an_alert`.
- `tests/alerts/test_alert_schema_v2.py`: `..._declare_the_synthetic_model` became
  `test_alerts_carrying_ml_scores_declare_the_model_version`.
- `tests/contract/test_feature_contract.py`: the ML array scan was replaced by
  `test_ml_features_match_declaration`; `test_feature_dump_reads_match_declaration` added.
- `tests/detectors/test_attack_captures.py`: rule counting ignores ML-only alerts (true
  positives on attack flows, not detector cross-fire).
- `tests/streaming/test_streaming.py`: the idle-flush spy wraps `score_batch`.

### Incomplete / next (TODO Now)
- Rule precision on real traffic is unmeasured, and the rules are noisy on mixed traffic
  (7,453 C2 alerts on s12). The labelled dumps now make this measurable.
- LightGBM cross-family recall is low, and the failed-TCP margin is small; more benign
  diversity is needed.
- Paced replay above ~20× distorts windowed features (timer tick in capture time).

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
