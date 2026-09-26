# Throughput benchmark

Measured throughput of SIH26145 with the trained models (`docs/MODELS.md`) and batched ML
inference. Every figure below was measured on 2026-09-26 on the machine named here, on an idle
machine: no download, dump or training job was running (checked with `pgrep` and the load
average before each series). The 2026-09-25 figures (single-row synthetic models, ~121 flows/s)
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
   (`num_threads=1` / `n_jobs=1`), and runs the aggregator for each flow;
5. SQLite WAL writes to a temp file.

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

### CTU-13 scenario 12, botnet hosts only (the session-2 procedure, rerun)

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

### Largest scenario that completes: CTU-13 scenario 11, botnet hosts only (4.07 GB)

| Run | Wall | flows/s | Mbps | pps | Drops | Alerts | Flush → alert |
|---|---|---|---|---|---|---|---|
| Unthrottled | 49.33 s | 5.7 | **681.28** | **79,913** | 0 | 1 (`THREAT_RECON_PORTSCAN`) | 81 ms (one alert) |

This capture is two infected hosts ICMP-flooding one target: 3.94 million packets in only 281
flows. It is packet-bound, so Mbps and packets/s are the meaningful figures, and it shows the
ingest path sustaining about 681 Mbps of large packets on one core. **Scenario 10 (66 GB) was
not run.** It is 16× the size of s11 and shows the same Rbot ICMP-flood behaviour, so it would add
wall time without adding a new traffic mix. No figure is claimed for it.

Detection note, not a throughput figure: no rule flagged the flood. The few-source volumetric
rule needs 5 closed windows of per-destination baseline, and the target first appears with the
attack. This is the warm-up limit stated for PS (a).

### Mixed traffic: CTU-13-Extended scenario 12, all hosts, headers only

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

## Profile: top five hot spots (after batching)

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

## Reproduce

```bash
B=~/NewProjects/26145-data/bench/final
E=~/NewProjects/26145-data/extracted/CTU-13-Dataset
P=$E/12/botnet-capture-20110819-bot.pcap
uv run python scripts/benchmark.py $P --json $B/s12-u1.json                  # capacity (run 3 times)
uv run python scripts/benchmark.py $P --speed 200 --json $B/s12-paced.json   # ~50% of capacity
uv run python scripts/benchmark.py $P --speed 800 --queue-max 1000           # overload, drops counted
uv run python scripts/benchmark.py $P --profile $B/s12.prof                  # profile (rates not quotable)
uv run python scripts/benchmark.py $E/11/botnet-capture-20110818-bot-2.pcap  # largest completed
SIH26145_INTERNAL_CIDRS=147.32.0.0/16 uv run python scripts/benchmark.py \
  ~/NewProjects/26145-data/ctu13-extended/capture20110819.truncated.pcap     # mixed traffic
```

`~/NewProjects/26145-data/bench/final/run.sh` runs the whole series in this order. It derives the
paced speeds from the measured capacity as `0.5 × flows/s ÷ (capture flows ÷ capture span)`, and
4× that for overload. Use the same rule on a different machine. The CTU-13-Extended download
commands are in `docs/MODELS.md` §6.

## Superseded: 2026-09-25 (session 2)

Single-row predicts with the synthetic RandomForest and IsolationForest, same machine and
capture: 120.6–124.4 flows/s and 31.3–32.2 Mbps unthrottled. Paced at 26× (~50%): 0 drops, flush
→ alert 165 / 496 / 641 ms. At 104× with a 1k queue: 42.6% dropped. The profile was 93% ML
predict overhead. Those numbers describe code that no longer exists; they are kept only to show
the change.
