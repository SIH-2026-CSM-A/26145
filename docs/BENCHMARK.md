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

## Multi-core scaling (shared-nothing shards) (2026-09-29)

**Question:** does it scale beyond one core? The pipeline is one single-threaded Python process. It
scales out by running one independent process per core, each fed a share of the link. On a real link
a receive-only packet broker does the split, using a symmetric hash so that both directions of a
flow land in the same shard. Here `scripts/shard_scale.py` does that split once, beforehand, and
the split is **not timed**. Then N copies of the same unthrottled `scripts/benchmark.py` path run at
once, each pinned with `taskset` to its own vCPU, one shard each. Data: `26145-data/bench/s8-shard/`
(per-shard JSON, per-shard alert lists, `report.json`, `calibrate.json`, `lscpu*.txt`, `run.log`).

**Capture:** CTU-13 s12, as above (352,266 packets, 289,266,098 wire bytes, 8,927 flows).

**Split:**
- 5-tuple split: hash of the protocol and the sorted (src IP, port) / (dst IP, port) pair.
- Host-pair split: protocol and sorted IP pair, no ports.
- Shard = blake2b(key) mod N.
- The 729 non-IP frames go to shard 0; s12 has no IP fragments.

Every split's shards add up to the original packet and wire-byte totals exactly. The N=1 "shard" is
record-for-record identical to the original capture.

**Machine:**
- Same laptop as above: Intel Core i5-13450HX, which is 6 performance cores (2 threads each) + 4
  efficiency cores (1 thread each) = 10 physical cores, 16 threads.
- On AC power, Windows best-performance mode.
- Docker Desktop quit, no browser video.
- 1-minute load 0.27 before the series started.

**What WSL2 lets us pin, and what it does not.** WSL2 shows Hyper-V's virtual topology, not the
chip's: 8 cores × 2 threads, with no core type and no max frequency. `lscpu -e` inside WSL gives:

```
CPU NODE SOCKET CORE L1d:L1i:L2:L3 ONLINE
  0    0      0    0 0:0:0:0          yes
  1    0      0    0 0:0:0:0          yes
  2    0      0    1 1:1:1:0          yes
  3    0      0    1 1:1:1:0          yes
  4    0      0    2 2:2:2:0          yes
  5    0      0    2 2:2:2:0          yes
  6    0      0    3 3:3:3:0          yes
  7    0      0    3 3:3:3:0          yes
  8    0      0    4 4:4:4:0          yes
  9    0      0    4 4:4:4:0          yes
 10    0      0    5 5:5:5:0          yes
 11    0      0    5 5:5:5:0          yes
 12    0      0    6 6:6:6:0          yes
 13    0      0    6 6:6:6:0          yes
 14    0      0    7 7:7:7:0          yes
 15    0      0    7 7:7:7:0          yes
```

That is 8 "cores" of 2 threads. The real chip is 6 two-thread P-cores + 4 one-thread E-cores, so a
WSL core is **not** a physical core. Windows decides which host core runs each vCPU and can move
it. Each shard was pinned to one vCPU per virtual core, never two siblings:

| N | vCPUs used |
|---|---|
| 1 | 0 |
| 2 | 0, 2 |
| 4 | 0, 2, 4, 6 |
| 8 | 0, 2, 4, 6, 8, 10, 12, 14 |

**Whether a shard ran on a P-core or an E-core was not controlled, and cannot be named from
inside WSL.** A calibration ran the same pure-Python loop pinned to each of the 16 vCPUs in turn,
3 passes, with the rest of the machine idle (`shard_scale.py calibrate`):
- every vCPU had a median of 0.318–0.329 s;
- one outlier pass took 0.42 s on vCPU 7.

So when a single thread runs alone, no vCPU is consistently slower, and Windows gives it a fast
core. That says nothing about placement when 8 run at once: 8 busy threads cannot all sit on the 6
P-cores.

### Result: 5-tuple split (the throughput table)

Median of 3 runs per N. Every run is listed; none was dropped.
- **Flows/s** = Σ flows ÷ the wall time of the slowest shard.
- **Mbps** = Σ wire bytes × 8 ÷ the same wall.
- **Efficiency** = flows/s ÷ (N × the N=1 median, 816.0 flows/s).
- **Wall** is `benchmark.py`'s pipeline wall: model load and the capture-facts pass are outside it.
- **Load** is the 1-minute load average from `uptime` just before each run. It includes the tail of
  the previous batch, which ended 5 s earlier.

| N | vCPUs | Flows | Slowest shard wall | **Flows/s** | **Mbps** | **Efficiency** | Flows/s per run | Alerts (sum of shards) | Load before each run |
|---|---|---|---|---|---|---|---|---|---|
| 1 | 0 | 8,927 | 10.94 s | **816.0** | **211.5** | **1.00** | 772.9 / 822.0 / 816.0 | 91 / 91 / 91 | 0.61 / 1.69 / 1.72 |
| 2 | 0,2 | 8,927 | 5.75 s | **1,552.5** | **402.5** | **0.95** | 1,487.8 / 1,555.2 / 1,552.5 | 79 / 79 / 79 | 0.83 / 1.45 / 1.48 |
| 4 | 0,2,4,6 | 8,927 | 3.96 s | **2,254.3** | **584.4** | **0.69** | 2,254.3 / 2,466.0 / 2,248.6 | 77 / 77 / 77 | 0.93 / 1.42 / 1.44 |
| 8 | 0,2,…,14 | 8,927 | 2.29 s | **3,898.3** | **1,010.5** | **0.60** | 3,673.7 / 3,915.4 / 3,898.3 | 73 / 73 / 73 | 1.08 / 1.35 / 1.51 |

No run dropped a flow, since all runs were unthrottled with lossless backpressure.

**N=1 is 816.0 flows/s, 5.1% under the session-5 mean of 859.5.** Two things differ from session
5, and neither was isolated:
- this run is pinned to one vCPU, so the aiosqlite writer thread shares that vCPU;
- it records every alert (`--alerts-out`). The first run was the slowest of the three, as in session 5.

### Why efficiency falls with N

Efficiency splits into two measured factors (medians over the 3 runs):
- **Balance** = mean shard wall ÷ slowest shard wall.
- **Per-core rate** = the N=1 wall ÷ the sum of shard walls.

Efficiency is roughly their product.

| N (5-tuple) | Balance | Per-core rate | Flows per shard (run 3) |
|---|---|---|---|
| 2 | 0.97 | 0.98 | 4,701 / 4,226 |
| 4 | 0.85 | 0.81 | 2,313 / 2,150 / 2,388 / 2,076 |
| 8 | 0.81 | 0.72 | 1,227 / 1,067 / 1,095 / 1,100 / 1,086 / 1,083 / 1,293 / 976 |

- **Balance:** a hash split of one 8,927-flow capture is uneven: at N=8 the busiest shard carries
  66,604 packets and the lightest 21,775. The slowest shard sets the wall time. A longer capture or
  a live link, with many more flows, evens this out; a single elephant flow does not, because it
  cannot be split.
- **Per-core rate:** each shard runs slower when others run at the same time. At N=4 and N=8 each
  process does its work at 81% and 72% of the lone-core rate. The candidates are:
  - shared L3 and memory bandwidth;
  - a lower all-core turbo;
  - at N=8, Windows placing some vCPUs on E-cores, since there are only 6 P-cores.

  These were not separated: WSL gives no per-core frequency or core-type counters.

**Including start-up.** The launch-to-last-exit wall includes Python imports, model loading and one
read of the capture per process. It is 12.1–14.0 s at N=1 and 3.5–4.4 s at N=8, i.e. 2,050–2,540
flows/s at N=8. A deployed sensor loads models once, so the pipeline wall above is the figure to
size from.

### Host-pair split (N=4 and N=8)

| N | vCPUs | Flows | Slowest shard wall | Flows/s | Mbps | Efficiency | Flows/s per run | Alerts (sum) | Load before each run |
|---|---|---|---|---|---|---|---|---|---|
| 4 | 0,2,4,6 | 8,927 | 3.51 s | 2,543.3 | 659.3 | 0.78 | 2,656.8 / 2,493.6 / 2,543.3 | 81 / 81 / 81 | 1.50 / 1.24 / 1.72 |
| 8 | 0,2,…,14 | 8,927 | 2.37 s | 3,766.7 | 976.4 | 0.58 | 3,570.8 / 3,766.7 / 3,967.6 | 90 / 90 / 90 | 1.65 / 1.34 / 1.60 |

At N=4 the pair split balanced better (balance 0.92 against 0.85) and ran faster. At N=8 the two
splits are within run-to-run spread.

### Alert-union check: do N shards raise the same alerts as one process?

**No.** The single process raises 91 alerts on s12: 69 `RULE_C2_PERIODIC_FLOWS` and 22 LightGBM.
Each alert is compared as the key (rule, Community ID `flow_id`, provisional). In every
configuration, the union over the shards was identical in all 3 runs.

| Split | N | Union | Same key as single | Lost vs single (by rule) | New vs single (by rule) |
|---|---|---|---|---|---|
| 5-tuple | 1 | 91 | 91 | — | — |
| 5-tuple | 2 | 79 | 79 | 12 LightGBM | — |
| 5-tuple | 4 | 77 | 73 | 18 LightGBM | 1 C2, 3 LightGBM |
| 5-tuple | 8 | 73 | 69 | 22 LightGBM | 1 C2, 1 recon fan-out, 1 DDoS volume-baseline, 1 LightGBM |
| host-pair | 4 | 81 | 70 | 21 LightGBM | 5 C2, 1 recon fan-out, 1 DDoS volume-baseline, 4 LightGBM |
| host-pair | 8 | 90 | 70 | 21 LightGBM | 5 C2, 1 recon fan-out, 1 DDoS volume-baseline, 13 LightGBM |

The host-pair split at N=8 has 90 alerts, close to 91 in count, but only 70 of them are the same
alerts. The count is close by coincidence. **The host-pair split did not shrink the difference.**

Why, per rule. Each rule's cross-flow reads are declared in `feature_contract.toml`, under the
tiers flow, pair, host (per source) and dst (per destination). A shard sees only its share of each
entity's flows:
- **C2 beacon** reads pair-tier IAT statistics (`pair_iat_n/mean/cv`) and one host-tier count,
  `src_periodic_dsts_w`.
  - 5-tuple split: all 69 single-process C2 alerts survive. They sit on only 11 distinct 5-tuples,
    the same connection repeated, so each one's repeats stay in one shard.
  - Host-pair split: all pair-tier state is whole, so the only C2 input it changes is
    `src_periodic_dsts_w`. A beaconing host's periodic destinations are spread over shards, each
    shard counts fewer, and 5 alerts appear that the single process does not raise.
- **LightGBM** reads 16 host- and dst-tier window features (distinct destinations, distinct ports
  and SYN-only ratio per source; flows, bytes, sources, entropy and baselines per destination).
  Neither split keeps a host's or a destination's traffic together, because one host talks to many
  peers. The model's inputs change, and 12–22 of the 22 single-process LightGBM alerts are lost.
  Some new ones appear elsewhere.
- **Recon fan-out** reads per-source fan-out (`src_distinct_dsts_w`, `src_distinct_dst_ports_w`,
  `src_syn_only_ratio_w`) and `dst_distinct_srcs_w`. Across shards, one scanner's flows are
  counted separately. Here one alert appears that the single process does not raise. The most likely cause is
  that the shared-destination suppression (`dst_distinct_srcs_w`) sees fewer sources per
  destination in a shard; this was not traced alert by alert.
- **DDoS volume-baseline** reads per-destination volume and its baseline, which a split divides
  between shards. One new alert.
- **Campaign correlator:** each shard has its own, so a host's stages that land in different shards
  form different campaigns. That changes `campaign_id`, not which alerts fire, and is not in the
  key above.

**What this means for a deployment.** Shared-nothing sharding scales throughput: 3,898 flows/s and
1,011 Mbps on 8 vCPUs here, 4.8× one core. It does **not** reproduce the single-process detections
for the rules and model that read per-host or per-destination state. The broker would have to hash
by internal host, keeping every flow of a host in one shard, and even then per-destination state
(DDoS, the destination half of LightGBM) is split. The alternative is a shared store. Neither was
built or measured this session. The single-process figures elsewhere in this file are the ones
whose detections were validated (`docs/RULES.md`, `docs/MODELS.md`).

### Reproduce

```bash
uv run python scripts/shard_scale.py split N [--by pair]      # N = 1 2 4 8 (pair: 4 8); not timed
uv run python scripts/shard_scale.py calibrate                  # per-vCPU single-thread loop, 3 passes
# idle machine; the series ran rep-major: for rep in 1 2 3: N=1,2,4,8 (5-tuple), then N=4,8 (pair), 5 s apart
uv run python scripts/shard_scale.py run N REP [--by pair]      # N x taskset -c CPU .venv/bin/python scripts/benchmark.py SHARD --json .. --alerts-out ..
uv run python scripts/shard_scale.py report                     # medians, efficiency, alert-union diff by rule
```

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
