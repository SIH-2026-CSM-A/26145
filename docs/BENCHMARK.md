# Throughput benchmark

First measured throughput figure for SIH26145. It replaces the old `scripts/benchmark.py`
number, which was invalid (AUDIT D5). Everything below was measured on 2026-09-25 on the
machine named here. Nothing was optimised before measuring.

## What is measured

`scripts/benchmark.py` runs the real streaming pipeline (`streaming.run_stream`) end to end:

1. dpkt ingest;
2. flow tracking;
3. the bounded queue;
4. the FeatureStore;
5. the seven rule detectors;
6. both ML models (RandomForest + IsolationForest, synthetic baseline, run on every flow);
7. the aggregator;
8. SQLite WAL writes to a temp file.

It reports:

- **flows/s:** flows scored ÷ wall time.
- **Mbps:** wire bytes ingested × 8 ÷ wall time. No record in this capture is truncated,
  so captured bytes equal wire bytes; AUDIT A8 does not affect these figures.
- **drop %:** flows dropped at the full queue ÷ flows flushed.
- **Latency:**
  - **alert latency** runs from a flow's flush (hand-off to the queue) to its alert being
    published;
  - **flow latency** is the same span to scored, for every flow.

  Neither includes the wait between a flow's last packet and its flush. That wait is set by
  the tracker's idle timeout (15 s of capture time) plus one timer tick.

## Machine and capture

| | |
|---|---|
| CPU | Intel Core i5-13450HX, 16 logical CPUs visible to WSL2; the pipeline uses one core |
| Memory | 9,943 MiB visible to WSL2 |
| OS | Linux 6.18.33.2-microsoft-standard-WSL2 (x86_64, glibc 2.43) |
| Python | 3.13.14; numpy 2.5.3, dpkt 1.9.8, scikit-learn 1.9.1, aiosqlite 0.22.1 |
| Capture | CTU-13 scenario 12, `12/botnet-capture-20110819-bot.pcap`: 281.2 MiB, 352,266 packets, 289,266,098 wire bytes, 0 truncated records, 3,823.5 s span. sha256 `4c66deefb4530435c0c90de186c9350fa8b1ab8c3b8e6606c493e971796eaa9c` |
| Flows | 8,927 (5-tuple, idle timeout 15 s, active timeout 60 s), a mean of 2.33 flows/s over the capture's span |

The machine was otherwise idle (load average under 2, no other CPU-bound process). The CTU-13
archive listing had finished before any run below.

## Results

| Run | Command flags | Wall | flows/s | Mbps | pps | Drops | Alerts | Alert latency p50 / p95 / p99 | Flow latency p50 / p95 / p99 |
|---|---|---|---|---|---|---|---|---|---|
| Unthrottled #1 | — | 71.78 s | 124.4 | 32.24 | 4,908 | 0 (lossless) | 84 | 34.8 / 54.1 / 55.6 s | 29.5 / 53.6 / 56.0 s |
| Unthrottled #2 | — | 73.84 s | 120.9 | 31.34 | 4,771 | 0 (lossless) | 84 | 35.9 / 55.8 / 57.4 s | 30.3 / 55.3 / 57.8 s |
| Unthrottled #3 | — | 74.00 s | 120.6 | 31.27 | 4,760 | 0 (lossless) | 84 | 36.0 / 55.9 / 57.4 s | 30.4 / 55.3 / 57.8 s |
| Paced, ~50% of capacity | `--speed 26` | 147.53 s | 60.5 | 15.69 | — | **0 / 8,927 (0.0%)** | 84 | **165 / 496 / 641 ms** | 244 / 1,263 / 1,886 ms |
| Paced, ~2× capacity, 1k queue | `--speed 104 --queue-max 1000` | 44.37 s | 115.5 | 52.15 | — | **3,802 / 8,927 (42.6%)** | 41 | 7.9 / 8.2 / 8.4 s | 7.8 / 8.4 / 8.5 s |
| Paced, ~2× capacity, 10k queue | `--speed 104` | 74.05 s | 120.6 | 31.25 | — | 0 / 8,927 (0.0%) | 85 | 21.8 / 35.2 / 36.3 s | 19.0 / 34.9 / 36.6 s |

**Sustained capacity on this machine: about 121 flows/s (120.6–124.4 over three runs) and
about 31 Mbps (31.3–32.2), with one core.** This is a capacity figure: the unthrottled run
reads as fast as scoring allows and never drops.

How to read the rows:

- **Unthrottled latency** is queueing at saturation. The producer reads ahead and flows wait
  in the queue until they are scored, so these latencies are not a detection-latency claim.
- **The paced 26× row** is the operating point. It offers about half the capacity: 26 × 2.33
  ≈ 61 flows/s. Nothing is dropped, and alerts are published within 0.17 s at the median and
  0.64 s at p99 of a flow being flushed.
- **Overload.**
  - At 104× (about 2× capacity) with a 1,000-flow queue, 42.6% of flows are dropped. Every
    drop is counted, and alerts are lost with them (41 against 84).
  - With the default 10,000-flow queue, the whole capture (8,927 flows) fits in the queue,
    so nothing is dropped and the overload shows up as latency instead. On a sustained
    live link the queue would fill and drop.
  - The ingest Mbps in the 1k-queue row (52.15) counts bytes ingested; drops happen after
    ingest.
- **Alert counts.** Every alert on this capture is `THREAT_C2_BEACON`; no class accuracy is
  claimed (the detectors are not tuned on CTU-13, and the ML models are synthetic). The
  10k-queue overload run raised 85 alerts against 84, because under load the timer flushes
  flows in different batches, so per-pair gaps reach the store in a slightly different order.

## Reproduce

The capture comes from `CTU-13-Dataset.tar.bz2`. It was extracted into
`~/NewProjects/26145-data/extracted/`, and all 52 archive members were checked against the
archive listing by size.

```bash
P=~/NewProjects/26145-data/extracted/CTU-13-Dataset/12/botnet-capture-20110819-bot.pcap
uv run python scripts/benchmark.py $P --json unthrottled.json            # capacity (run 3 times)
uv run python scripts/benchmark.py $P --speed 26 --json paced.json         # ~50% of capacity
uv run python scripts/benchmark.py $P --speed 104 --queue-max 1000         # overload, drops counted
uv run python scripts/benchmark.py $P --profile ctu12.prof                 # profile (rates not quotable)
```

On a different machine, pick the paced speed as
`0.5 × measured flows/s ÷ (capture flows ÷ capture span)`.

## Profile: top five hot spots (not optimised this session)

The profile is cProfile over the unthrottled run on the same capture: 224.7 s under the
profiler, against 72–74 s unprofiled, so the shares are indicative. Shares are cumulative
time. cProfile sees only the main thread, so SQLite writes (on aiosqlite's worker thread)
are not in these numbers.

| # | Where | Calls | Share | Why |
|---|---|---|---|---|
| 1 | `models/anomaly.py` `IsolationForestAnomalyDetector.predict` | 8,927 | **73.6%** | One single-row `predict` per flow over 200 trees. sklearn dispatches each tree through joblib (1,785,500 `_parallel_compute_tree_depths` calls). Per-call overhead dominates: joblib's `parallel.__call__` wrapper and its per-call `warnings.filterwarnings` context (11.2M calls, 16.5% of all time) cost more than the tree traversal. |
| 2 | `models/classifier.py` `RandomForestThreatClassifier.predict` | 8,927 | **19.1%** | The same pattern: a single-row `predict_proba` per flow over 50 trees. |
| 3 | `ingest/parser.py` `PacketParser.parse_packet` (dpkt Ethernet/IP/TCP unpack) | 352,266 | 3.5% | Per-packet Python object construction in dpkt. |
| 4 | `features/extractor.py` `FeatureExtractor.extract` | 8,927 | 1.4% | Per-flow numpy statistics on small arrays. |
| 5 | `flow/tracker.py` `FlowTracker.process_packet` | 352,266 | 0.9% | Per-packet dict lookup and counter updates. |

For comparison, the new tier-2 work is small: `FeatureStore.update` takes 0.6%, the seven
rule detectors 0.6%, and the aggregator 0.3%.

The two ML models are about 93% of the time. Their scores cannot create alerts (the ML
gate), yet they run on every flow. The obvious next steps are listed in TODO, not done here:

- score ML only on flows that already have a rule hit, or batch-predict the queued flows;
- replace the synthetic models with trained ones.
