# Throughput benchmark

Measured throughput of SIH26145 on the current code: trained models (`docs/MODELS.md`) with
batched inference, ruleset 2.1.0, campaign correlation and the hash-chained alert log. Every figure
below was measured on 2026-09-27 on the machine named here, on an idle machine: Docker Desktop was
stopped, and no download, dump, build, browser or training job was running (checked with `pgrep`
and the load average before each run; the 1-minute load stayed at or below 1.43). The session-3
figures (2026-09-26, before correlation and the hash chain) and the session-2 figures (2026-09-25)
are kept at the end for comparison. They are superseded.

## What is measured

`scripts/benchmark.py` runs the real streaming pipeline (`streaming.run_stream`) end to end:

1. ingest: dpkt parsing, with the wire length from pcap record headers (AUDIT A8);
2. flow tracking;
3. the bounded queue;
4. the consumer, which drains up to 256 queued flows per turn. For each flow, in order, it runs:
   - the FeatureStore update;
   - the tier-1 features;
   - the seven rule detectors;
   - the model row, taken at that flow's own scoring time.

   It then makes **one** LightGBM and **one** IsolationForest predict call for the batch
   (`num_threads=1` / `n_jobs=1`), and runs the aggregator and the campaign correlator for
   each flow;
5. SQLite WAL writes to a temp file. Each stored alert gets its SHA-256 chain hash.

It reports:
- **flows/s:** flows scored ÷ wall time.
- **Mbps:** wire bytes × 8 ÷ wall time. Wire bytes come from the pcap record headers' original
  length. On the header-only mixed-traffic capture below, that is the traffic's original size,
  not the bytes on disk.
- **drop %:** flows dropped at the full queue ÷ flows flushed.

**Detection latency has two parts, and both are stated wherever latency is quoted:**
1. **Flow close:** the time from a flow's last packet to its flush. This is set by the tracker, in
   capture time: the **idle timeout (15 s)**, or the **active timeout (60 s)** for a flow that
   keeps sending, plus at most one timer tick (1 s). It is a configuration bound, not a
   measurement.
2. **Flush → alert:** the time from the flush (hand-off to the queue) to the alert being
   published, measured per alert as p50/p95/p99. A flow scored in a batch counts from its own
   flush to the end of its batch. **Flow latency** is the same span to "scored", for every flow.

## Machine and captures

| | |
|---|---|
| CPU | Intel Core i5-13450HX, 16 logical CPUs visible to WSL2; the pipeline uses one core |
| Memory | 9,943 MiB visible to WSL2 |
| OS | Linux 6.18.33.2-microsoft-standard-WSL2 (x86_64, glibc 2.43) |
| Python | 3.13.14; numpy 2.5.3, dpkt 1.9.8, scikit-learn 1.9.1, lightgbm 4.7.0, aiosqlite 0.22.1 |
| Models | `ctu13x5-lgbm-if-1.0.0` (`src/sih26145/models/artifacts/manifest.json`) |

| Capture | Size | Packets | Wire bytes | Truncated records | Span | Flows |
|---|---|---|---|---|---|---|
| CTU-13 s12, `botnet-capture-20110819-bot.pcap` (botnet hosts only; sha256 `4c66deef…eaa9c`) | 281.2 MiB | 352,266 | 289,266,098 | 0 | 3,823.5 s | 8,927 (2.33/s of capture) |
| CTU-13 s11, `botnet-capture-20110818-bot-2.pcap` (botnet hosts only; ICMP flood) | 4,066.1 MiB | 3,941,769 | 4,200,569,876 | 0 | 532.0 s | 281 |
| CTU-13-Extended s12, `capture20110819.truncated.pcap` (**mixed traffic**: every host on the university link, headers only, pcapng; sha256 `cae0aad9…a5d8d0`) | 1,089.0 MiB | 13,208,566 | 8,716,148,990 (from pcapng block original lengths) | 13,208,305 | 4,412.4 s | 541,957 |

## Results

### CTU-13 scenario 12, botnet hosts only

| Run | Flags | Wall | flows/s | Mbps | pps | Drops | Alerts | Flush → alert p50 / p95 / p99 | Flush → scored p50 / p95 / p99 |
|---|---|---|---|---|---|---|---|---|---|
| Unthrottled #1 | — | 11.11 s | 803.5 | 208.30 | 31,709 | 0 (lossless) | 91 | 162 / 717 / 747 ms | 67 / 488 / 715 ms |
| Unthrottled #2 | — | 10.16 s | 879.1 | 227.88 | 34,689 | 0 (lossless) | 91 | 336 / 1,386 / 1,388 ms | 270 / 889 / 1,206 ms |
| Unthrottled #3 | — | 9.96 s | 895.9 | 232.25 | 35,353 | 0 (lossless) | 91 | 593 / 1,473 / 1,475 ms | 531 / 916 / 1,298 ms |
| Paced, ~50% of capacity | `--speed 184` | 20.91 s | 426.9 | 110.68 | — | **0 / 8,927 (0.0%)** | 70 | **6.7 / 217 / 250 ms** | 127 / 244 / 261 ms |
| Paced, ~2× capacity, 1k queue | `--speed 736 --queue-max 1000` | 10.12 s | 832.4 | 228.60 | — | **501 / 8,927 (5.6%)** | 40 | 645 / 1,123 / 1,194 ms | 307 / 1,243 / 1,415 ms |
| Repeat (reproducibility) | — | 10.29 s | 867.9 | 224.99 | 34,249 | 0 (lossless) | 91 | 169 / 1,227 / 1,229 ms | 85 / 653 / 1,052 ms |

**Sustained capacity on this machine: about 860 flows/s (803.5–895.9 over three runs, mean 859.5)
and about 223 Mbps (208.3–232.3), on one core.** That is 7.6% below the session-3 mean of 929.8
flows/s, measured before campaign correlation and the hash chain were added. The first run of the
series was the slowest; runs 2 and 3 and the repeat lie within 3.3% of each other. The repeat run, made
after the paced and overload runs, gave 867.9 flows/s: within 1.0% of the three-run mean, inside
the 10% reproducibility check.

**Detection latency at the operating point (paced, ~50% of capacity):** flow close takes 15 s
idle or 60 s active (capture time), plus at most one 1 s tick. Then flush → alert is 6.7 ms p50,
217 ms p95 and 250 ms p99.

How to read the rows:
- **Unthrottled latency** is queueing at saturation. The producer reads ahead and flows wait until
  the consumer reaches them, so these latencies are a backlog, not a detection-latency claim.
  They vary run to run because the backlog depends on how the one core is shared between producer
  and consumer.
- **Paced 184×** offers 184 × 2.33 ≈ 429 flows/s, about half the capacity (the speed is derived
  from the measured mean as `0.5 × 859.5 ÷ 2.33`). Nothing is dropped.
- **Overload at 736×** offers about 1,715 flows/s. The producer and the consumer share one core,
  so the producer falls behind the replay clock (10.1 s wall against the 5.2 s schedule) rather
  than filling the queue quickly. 5.6% of flows were dropped, every one counted (session 3: 1.8%
  at 800× on the faster code). A capture longer than this one would keep the queue full and drop
  more.
- **Alert counts differ between paced and unthrottled runs** (70 and 91), and not only because
  of drops. At 184× a 1 s wall-clock timer tick spans 184 s of capture time. Idle flows then
  reach the FeatureStore up to ~184 s out of event order, which changes windowed features: the
  paced run raised 70 C2 alerts and no LightGBM alert, the unthrottled runs 69 C2 and 22 LightGBM
  alerts. At real-time speed a tick is 1 s of capture time. The paced rows measure latency and
  drops; their alert mix is not representative (TODO). The demo replays at 2×, where the alert
  list is identical to unthrottled (`scripts/demo_report.py`).
- Unthrottled alert counts are 91, not session 3's 106: ruleset 2.1.0 (`docs/RULES.md`) raised
  the C2 thresholds between the two series.

### Same procedure on a non-WSL Linux VM (2026-09-28)

The s12 unthrottled procedure (three runs + one repeat, `scripts/benchmark.py`, same capture,
commit `6de6a3d`, whose pipeline code is unchanged since the laptop series; models `ctu13x5-lgbm-if-1.0.0`) on a temporary
Google Cloud VM, to show the figure is not a WSL artefact. The VM was created for this run and
deleted afterwards. Data: `26145-data/bench/s7-gcp/` (JSON per run, `lscpu`, load log).

| | Laptop (session 5 series) | GCP VM `e2-standard-4` |
|---|---|---|
| CPU | Intel Core i5-13450HX (Raptor Lake, 2023) | Intel Xeon @ 2.20 GHz, family 6 model 79 (Broadwell, 2016), KVM guest |
| Cores | 16 logical visible; the pipeline uses one core | 4 vCPUs (2 cores × 2 threads); the pipeline uses one core |
| OS / kernel | WSL2, Linux 6.18.33.2-microsoft-standard-WSL2 | Ubuntu 24.04.5 LTS, Linux 7.0.0-1011-gcp |
| Python | 3.13.14 | 3.13.15 (uv-managed); numpy, dpkt, scikit-learn, lightgbm, aiosqlite at the same versions |
| Unthrottled runs, flows/s | 803.5 / 879.1 / 895.9 (mean **859.5**) | 340.1 / 345.7 / 349.4 (mean **345.1**) |
| Mbps (mean) | 222.8 | 89.5 |
| Packets/s (mean) | 33,917 | 13,618 |
| Average packet size (wire bytes ÷ packets) | 821.2 B (289,266,098 ÷ 352,266) | 821.2 B (same capture) |
| Repeat run | 867.9 flows/s (1.0% from the mean) | 335.5 flows/s (2.8% from the mean) |
| Drops / alerts | 0 (lossless) / 91 | 0 (lossless) / 91 |

The VM is 2.5× slower per core than the laptop, on the same code and capture, and raises the same
91 alerts. The pipeline is single-threaded Python, so per-core speed decides it: a 2016 Broadwell
vCPU at 2.2 GHz against a 2023 laptop core rated up to 4.6 GHz. The CPUs differ, so this run does
not isolate any WSL2 effect; it shows the pipeline runs and gives identical detections on native
Linux. **Capacity is machine-dependent**: size a deployment from a run on its own
hardware, using this procedure.

### Largest scenario that completes: CTU-13 scenario 11, botnet hosts only (4.07 GB)

| Run | Wall | flows/s | Mbps | pps | Drops | Alerts | Flush → alert |
|---|---|---|---|---|---|---|---|
| Unthrottled | 49.67 s | 5.7 | **676.57** | **79,361** | 0 | 1 (`THREAT_RECON_PORTSCAN`) | 71 ms (one alert) |

This capture is two infected hosts ICMP-flooding one target: 3.94 million packets in only 281
flows. It is packet-bound, so Mbps and packets/s are the meaningful figures, and it shows the
ingest path sustaining about 677 Mbps of large packets on one core (session 3: 681). **Scenario 10
(66 GB) was not run.** It is 16× the size of s11 and shows the same Rbot ICMP-flood behaviour, so
it would add wall time without adding a new traffic mix. No figure is claimed for it.

Detection note, not a throughput figure: no rule flagged the flood in this botnet-only capture.
In the mixed-traffic CTU-13-Extended s11 capture, the flood is caught (`docs/RULES.md` §6). The
few-source volumetric rule needs 5 closed windows of per-destination baseline, and the target first
appears with the attack. This is the warm-up limit stated for PS (a).

### Mixed traffic: CTU-13-Extended scenario 12, all hosts, headers only

| Run | Wall | flows/s | Mbps (wire length) | pps | Drops | Alerts | Flush → alert p50 / p95 / p99 (saturated) |
|---|---|---|---|---|---|---|---|
| Unthrottled, `SIH26145_INTERNAL_CIDRS=147.32.0.0/16` | 480.22 s | **1,128.6** | **145.20** | 27,505 | 0 (lossless) | 6,247 | 8.7 / 10.7 / 12.3 s |

This is the full university-link capture (background, normal and botnet hosts), not only the
infected hosts. **Its Mbps is computed from each pcapng block's original packet length**, the
size the traffic had on the wire. The capture is headers only (TCP cut at 54 bytes, UDP at 42,
ICMP at 66), so the pipeline parsed far fewer bytes than that figure implies. flows/s is the
comparable figure: 1,128.6, 8.7% below session 3's 1,235.5. Flows here are smaller and more numerous
than in the botnet-only capture, so flows/s is higher and Mbps lower.

Alerts: 5,274 C2-beacon, 813 LightGBM-only, 155 exfiltration and 5 DDoS, on 541,957 flows. Most
fire on unlabelled background hosts. Precision against the CTU labels is in `docs/RULES.md` §4;
this is an alert-volume observation, not a precision figure.

## Fast lane (2026-09-28)

The fast lane (`docs/ARCHITECTURE.md` §9a) counts packets in 1-s windows before flow assembly and
raises provisional alerts for floods and scans. `scripts/fastlane_bench.py` measures it. Data:
`26145-data/bench/s7-fastlane/`. Same laptop, idle (1-min load ≤ 0.36; another project's six
Docker containers stayed up, as in session 6).

### Packet → alert latency

Each generated capture is followed by 45 s of unrelated traffic at 1 packet/s, so its flows close
by idle timeout, as on a live link, and not at end of file. It is replayed at **1× real time**
through the full pipeline. Latency runs from the ingest of the capture's first attack packet to
the alert's publication. There are 20 runs per capture, each shifting the attack by 0.05 s
against the 1-s window grid; p95 and p99 are interpolated from those 20 values. Every run raised
the fast-lane alert and the flow-lane alert confirming it.

| Capture | Attack | Fast lane (provisional) p50 / p95 / p99 | Flow lane (confirming) p50 / p95 / p99 |
|---|---|---|---|
| `syn_flood` | 500 spoofed sources, 2 SYNs each, over 10 s (~110 sources/s) | **1,526 / 1,957 / 1,983 ms** | 20,057 / 20,062 / 20,065 ms |
| `spoofed_flood` | 5,000 SYNs in 1 s, a new random source per packet | **528 / 956 / 995 ms** | 15,176 / 15,203 / 15,205 ms |
| `udp_reflection` | 200 reflectors, 1,400-byte answers, over 10 s | **1,028 / 1,460 / 1,495 ms** | 25,434 / 25,446 / 25,451 ms |
| `port_sweep` | SYN scan of 100 ports in 0.5 s | **1,002 / 1,497 / 1,499 ms** | 16,070 / 16,075 / 16,076 ms |

How to read it:
- **The fast lane's latency is its window.** An alert comes out when the 1-s window in which the
  evidence crosses the threshold closes, i.e. at the first packet of the next second. The
  `syn_flood` reaches 50 distinct sources only in its second window, so it takes about 1.5 s.
- **The flow lane waits for flows to close** (15 s idle; a SYN flood source that retries after
  1 s closes 16 s after its first SYN). The reflection flows last 10 s before idling. The flow
  lane's figures are timeouts, not processing.

### Packets-per-second ceiling: parser + fast lane

These are 2,000,000 64-byte Ethernet/IPv4/TCP SYN frames to one destination, stamped at 1 GbE
line rate for 64-byte frames (1,488,095 packets/s). They are read by the real reader and parser
and fed to the fast lane, unthrottled, on one core. There are three runs; the ceiling is their
mean.

| Sources | Parser alone | Parser + fast lane (ceiling) | Runs |
|---|---|---|---|
| A new random source every packet (spoofed) | 122,696 pps | **107,959 pps** | 3 |
| 1,000 sources | 128,642 pps | **115,982 pps** | 3 |

So the fast lane costs about 10–12% of the parser's rate on a 64-byte flood. The parser itself
(dpkt) is the ceiling, at about 8% of 1 GbE line rate for minimum-size frames. With random
sources, the per-source table is full (65,536 entities per window) after the first 65,536
packets of each second: 1,868,897 source entries were not tracked (`FastLane.overflow`). The
per-destination counters, which the flood rules read, are unaffected. A scanner hidden inside a
spoofed flood of this rate would not be seen by the fast lane.

**Drops at and beyond the ceiling are modelled, not measured.** The sensor reads files, so there
is no capture ring to overflow. The model is as follows:
- a second run records each packet's service time;
- a FIFO ring of 16,384 slots in front of one core is replayed against arrivals at a fixed rate;
- a packet that finds the ring full is counted as dropped.

| Sources | Offered | Modelled drops (of 2,000,000) |
|---|---|---|
| random | 1.0× ceiling, 107,959 pps | 1,936 (0.10%) |
| random | 1.5× ceiling, 161,939 pps | 652,265 (32.6%) |
| 1,000 | 1.0× ceiling, 115,982 pps | 19,022 (0.95%) |
| 1,000 | 1.5× ceiling, 173,972 pps | 673,496 (33.7%) |

At exactly the ceiling, drops come from bursts: service time is not uniform. At 1.5×, about a
third of packets are lost, as expected for a server running at 2/3 of the offered rate.

### Cost on the s12 benchmark

The CTU-13 s12 unthrottled run with the fast lane in the producer gave **856.8 and 857.4 flows/s**
(222.1 and 222.3 Mbps), with the same 91 alerts. The session-5 mean without it is 859.5, so the
difference is 0.3%, inside run-to-run spread. Measured alone, the fast lane costs 0.15 µs per s12
packet (352,266 packets, 0.06 s).

## Profile: top five hot spots

cProfile over the unthrottled scenario-12 run: 22.7 s under the profiler against about 10 s
unprofiled, so the shares are indicative. Shares are cumulative time. cProfile sees only the main
thread; SQLite writes on aiosqlite's worker thread are not included.

| # | Where | Calls | Share | Why |
|---|---|---|---|---|
| 1 | `ingest/parser.py` `PacketParser.parse_packet` (dpkt Ethernet/IP/TCP unpack) | 352,266 | **36.5%** | Per-packet Python object construction in dpkt; the Ethernet/IP unpack alone is 25.0% |
| 2 | `models/features.py` `model_row` (`store_features`) | 8,927 | **12.9%** | 30+ contract-checked store reads per flow, each rolling its window view |
| 3 | `features/extractor.py` `FeatureExtractor.extract` | 8,927 | 11.3% | Per-flow numpy statistics on small arrays |
| 4 | `flow/tracker.py` `FlowTracker.process_packet` | 352,266 | 9.0% | Per-packet dict lookup and counter updates |
| 5 | IsolationForest `score_samples` (batched) | 210 | 8.9% | One call per batch over 100 trees; sklearn still dispatches per tree through joblib |

What session 4 added: the campaign correlator (`correlate.py` `observe`) is **2.2%**, and the
per-alert chain hash (`storage/chain.py` `record_hash`, 91 calls) rounds to 0.0%. For comparison:
rules 4.3%, `FeatureStore.update` 4.0%, LightGBM prediction 2.9% and the aggregator 1.1%. The
consumer drained smaller batches in this run than in session 3 (210 IsolationForest calls against
138), and per-call model overhead grew with them.

## Reproduce

```bash
B=~/NewProjects/26145-data/bench/s5
E=~/NewProjects/26145-data/extracted/CTU-13-Dataset
P=$E/12/botnet-capture-20110819-bot.pcap
uv run python scripts/benchmark.py $P --json $B/s12-u1.json                  # capacity (run 3 times)
uv run python scripts/benchmark.py $P --speed 184 --json $B/s12-paced.json   # ~50% of capacity
uv run python scripts/benchmark.py $P --speed 736 --queue-max 1000           # overload, drops counted
uv run python scripts/benchmark.py $P --profile $B/s12.prof                  # profile (rates not quotable)
uv run python scripts/benchmark.py $E/11/botnet-capture-20110818-bot-2.pcap  # largest completed
uv run python scripts/fastlane_bench.py latency syn_flood --runs 20 --json lat.json   # fast lane, 1x (also spoofed_flood, udp_reflection, port_sweep)
uv run python scripts/fastlane_bench.py ceiling --packets 2000000 [--sources 1000]     # parser + fast lane pps
SIH26145_INTERNAL_CIDRS=147.32.0.0/16 uv run python scripts/benchmark.py \
  ~/NewProjects/26145-data/ctu13-extended/capture20110819.truncated.pcap     # mixed traffic
```

`~/NewProjects/26145-data/bench/s5/run.sh` runs the whole series (session-3 series: `bench/final/`). It also
asserts the repeat run is within 10% of the three-run mean. It derives the
paced speeds from the measured capacity as `0.5 × flows/s ÷ (capture flows ÷ capture span)`, and
4× that for overload. Use the same rule on a different machine. The CTU-13-Extended download
commands are in `docs/MODELS.md` §6.

## Superseded: 2026-09-26 (session 3)

Measured on the session-3 code, before campaign correlation and the hash-chained alert log,
with the pre-2.1.0 rule thresholds. Same machine and captures. Kept as recorded.

#### CTU-13 scenario 12, botnet hosts only (the session-2 procedure, rerun)

| Run | Flags | Wall | flows/s | Mbps | pps | Drops | Alerts | Flush → alert p50 / p95 / p99 | Flush → scored p50 / p95 / p99 |
|---|---|---|---|---|---|---|---|---|---|
| Unthrottled #1 | — | 9.63 s | 927.0 | 240.31 | 36,581 | 0 (lossless) | 106 | 632 / 1,503 / 1,546 ms | 586 / 1,407 / 1,563 ms |
| Unthrottled #2 | — | 9.57 s | 932.8 | 241.81 | 36,809 | 0 (lossless) | 106 | 932 / 1,349 / 1,379 ms | 679 / 1,308 / 1,403 ms |
| Unthrottled #3 | — | 9.60 s | 929.5 | 240.94 | 36,677 | 0 (lossless) | 106 | 885 / 1,447 / 1,480 ms | 775 / 1,456 / 1,535 ms |
| Paced, ~50% of capacity | `--speed 200` | 19.33 s | 461.8 | 119.72 | — | **0 / 8,927 (0.0%)** | 88 | **6.9 / 265 / 305 ms** | 121 / 265 / 310 ms |
| Paced, ~2× capacity, 1k queue | `--speed 800 --queue-max 1000` | 10.10 s | 868.2 | 229.20 | — | **161 / 8,927 (1.8%)** | 62 | 657 / 1,245 / 1,302 ms | 369 / 1,239 / 1,247 ms |
| Repeat (reproducibility) | — | 9.60 s | 929.6 | 240.98 | 36,682 | 0 (lossless) | 106 | 2,612 / 3,386 / 3,549 ms | 2,611 / 3,395 / 3,559 ms |

**Sustained capacity on this machine: about 930 flows/s (927.0–932.8 over three runs) and about
241 Mbps (240.3–241.8), on one core.** That is 7.7× the session-2 figure of 121 flows/s. The
repeat run, made at the end of the series, gave 929.6 flows/s: within 0.1% of the three-run mean
(929.8), well inside the 10% reproducibility check.

**Detection latency at the operating point (paced, ~50% of capacity):** flow close takes 15 s
idle or 60 s active (capture time), plus at most one 1 s tick. Then flush → alert is 6.9 ms p50,
265 ms p95 and 305 ms p99.

How to read the rows:
- **Unthrottled latency** is queueing at saturation. The producer reads ahead and flows wait until
  the consumer reaches them, so these latencies are a backlog, not a detection-latency claim.
  They vary run to run (the repeat's p50 is 2.6 s) because the backlog depends on how the one
  core is shared between producer and consumer; throughput does not vary.
- **Paced 200×** offers 200 × 2.33 ≈ 466 flows/s, about half the capacity. Nothing is dropped.
- **Overload at 800×** offers about 1,864 flows/s. Here the producer and the consumer share
  one core, so the producer falls behind the replay clock (10.1 s wall against the 4.8 s
  schedule) rather than filling the queue quickly. 1.8% of flows were dropped, every one
  counted. Batching also helps under load: fuller batches make each predict call cheaper per
  flow. A capture longer than this one (8,927 flows) would keep the queue full and drop more.
- **Alert counts differ between paced and unthrottled runs** (88 and 106), and not only because
  of drops. At 200× a 1 s wall-clock timer tick spans 200 s of capture time. Idle flows then
  reach the FeatureStore up to ~200 s out of event order, which changes windowed features: the
  paced run raised 2 few-source volumetric DDoS alerts and no LightGBM alert, the unthrottled
  runs 22 LightGBM alerts and no DDoS alert. At real-time speed a tick is 1 s of capture time.
  The paced rows measure latency and drops; their alert mix is not representative (TODO).

#### Largest scenario that completes: CTU-13 scenario 11, botnet hosts only (4.07 GB)

| Run | Wall | flows/s | Mbps | pps | Drops | Alerts | Flush → alert |
|---|---|---|---|---|---|---|---|
| Unthrottled | 49.33 s | 5.7 | **681.28** | **79,913** | 0 | 1 (`THREAT_RECON_PORTSCAN`) | 81 ms (one alert) |

This capture is two infected hosts ICMP-flooding one target: 3.94 million packets in only 281
flows. It is packet-bound, so Mbps and packets/s are the meaningful figures, and it shows the
ingest path sustaining about 681 Mbps of large packets on one core. **Scenario 10 (66 GB) was
not run.** It is 16× the size of s11 and shows the same Rbot ICMP-flood behaviour, so it would add
wall time without adding a new traffic mix. No figure is claimed for it.

Detection note, not a throughput figure: no rule flagged the flood in this botnet-only capture.
In the mixed-traffic CTU-13-Extended s11 capture, the flood is caught (`docs/RULES.md` §6). The few-source volumetric
rule needs 5 closed windows of per-destination baseline, and the target first appears with the
attack. This is the warm-up limit stated for PS (a).

#### Mixed traffic: CTU-13-Extended scenario 12, all hosts, headers only

| Run | Wall | flows/s | Mbps (wire length) | pps | Drops | Alerts | Flush → alert p50 / p95 / p99 (saturated) |
|---|---|---|---|---|---|---|---|
| Unthrottled, `SIH26145_INTERNAL_CIDRS=147.32.0.0/16` | 438.67 s | **1,235.5** | **158.96** | 30,111 | 0 (lossless) | 8,861 | 7.7 / 10.1 / 11.2 s |

This is the full university-link capture (background, normal and botnet hosts), not only the
infected hosts. **Its Mbps is computed from each pcapng block's original packet length**, the
size the traffic had on the wire. The capture is headers only (TCP cut at 54 bytes, UDP at 42,
ICMP at 66), so the pipeline parsed far fewer bytes than that figure implies. flows/s is the
comparable figure. Flows here are smaller and more numerous than in the botnet-only capture,
so flows/s is higher (1,236 against 930) and Mbps lower.

Alerts: 7,453 C2-beacon, 804 LightGBM-only, 593 exfiltration, 9 DDoS and 2 recon, on 541,957
flows. The rules have not been tuned on real traffic, and most of these fire on background
hosts, which carry no label. This is an alert-volume observation for the TODO, not a precision
figure.

### Profile: top five hot spots (after batching)

cProfile over the unthrottled scenario-12 run: 22.2 s under the profiler against 9.6 s
unprofiled, so the shares are indicative. Shares are cumulative time. cProfile sees only the main
thread; SQLite writes on aiosqlite's worker thread are not included.

| # | Where | Calls | Share | Why |
|---|---|---|---|---|
| 1 | `ingest/parser.py` `PacketParser.parse_packet` (dpkt Ethernet/IP/TCP unpack) | 352,266 | **38.7%** | Per-packet Python object construction in dpkt; the Ethernet/IP unpack alone is 27.6% |
| 2 | `models/features.py` `model_row` (`store_features`) | 8,927 | **13.6%** | 30+ contract-checked store reads per flow, each rolling its window view |
| 3 | `features/extractor.py` `FeatureExtractor.extract` | 8,927 | 11.7% | Per-flow numpy statistics on small arrays; `np.percentile` alone is 7.1% |
| 4 | `flow/tracker.py` `FlowTracker.process_packet` | 352,266 | 9.3% | Per-packet dict lookup and counter updates |
| 5 | IsolationForest `score_samples` (batched) | 138 | 6.2% | One call per batch over 100 trees; sklearn still dispatches per tree through joblib |

For comparison: rules 4.5%, `FeatureStore.update` 4.0%, the aggregator 1.2%, and LightGBM
prediction 0.4%. Session 2's two largest items were IsolationForest (73.6%) and RandomForest
(19.1%) single-row predicts. Batching removed that per-call overhead, and packet parsing is now
the largest cost.

## Superseded: 2026-09-25 (session 2)

Single-row predicts with the synthetic RandomForest and IsolationForest, same machine and
capture: 120.6–124.4 flows/s and 31.3–32.2 Mbps unthrottled. Paced at 26× (~50%): 0 drops, flush
→ alert 165 / 496 / 641 ms. At 104× with a 1k queue: 42.6% dropped. The profile was 93% ML
predict overhead. Those numbers describe code that no longer exists; they are kept only to show
the change.
