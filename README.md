# SIH26145 — NTRO: AI-Based Detection of Cyber Threats in Unidirectional IP Traffic

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Python 3.11+](https://img.shields.io/badge/python-3.11+-blue.svg)](https://www.python.org/)
[![FastAPI](https://img.shields.io/badge/FastAPI-1.0.0-green.svg)](https://fastapi.tiangolo.com/)
[![React](https://img.shields.io/badge/React-18.3-blue.svg)](https://react.dev/)

An explainable, read-only passive threat detection engine for traffic observed by an enclave that can never transmit (optical data diodes, passive taps). The capture may contain both halves of each conversation or only one; the system measures which, per flow, and declares for every feature what it needs (see `docs/ARCHITECTURE.md` §2 and §6). Detection uses deterministic rules and classical ML over flow metadata only, with no active mitigation and no payload decryption.

> **Status:** see `docs/ARCHITECTURE.md` §15 and `docs/AUDIT.md`. Model cards and validation: `docs/MODELS.md`. Throughput: `docs/BENCHMARK.md`.


## Watch it work in 2 minutes

```bash
git clone https://github.com/SIH-2026-CSM-A/26145.git && cd 26145 && uv sync && scripts/demo.sh
```

Then open **http://127.0.0.1:8000**. Needs Python 3.11+ with [uv](https://docs.astral.sh/uv/),
and Node 20+ (only to build the dashboard the first time). With Docker instead:
`docker compose up --build`, same address, replaying at 2×. See `DEPLOY.md`.

![The live view: the one-way link (dots only ever move toward the enclave; bytes sent back: 0), the six PS threat classes with their latest alert, the live figures and four campaigns](docs/media/s6-01-hero-tiles-kpi.png)

![The campaign map: 192.168.1.66's scan, C2, rare TLS, DGA, DNS tunnel and exfiltration in one campaign; the SYN flood on 10.50.0.10 is its own](docs/media/s6-02-campaign-map.png)

More stills (the stage timeline, the exfiltration case file, the model card, the KPI strip, and
`verify-log` catching a one-byte edit) are in [`docs/media/`](docs/media/) as `s6-*.png`.
`dashboard/tests/demo-shots.mjs` and `scripts/render_verify_log.py` make them from a live run.

What happens:
- The real pipeline replays `demo/demo.pcap`, a committed 11-minute capture, at 5× real time,
  so one loop takes about 2 minutes plus a 30 s hold.
- For the first two minutes, only real university traffic crosses the link: header-only
  CTU-13-Extended normal hosts (see `demo/ATTRIBUTION.md`).
- Then one host, 192.168.1.66, scans, beacons to a C2 server, opens rare-fingerprint TLS
  sessions, looks up DGA names, tunnels over DNS and uploads 1.2 MB. It shows up as **one
  campaign** with the stages Discovery → Command and Control → Exfiltration.
- A separate SYN flood hits 10.50.0.10 (its own campaign).
- Three C2 alerts on real normal hosts are false positives, and are shown as they are.
- Click a host for its stage timeline. Click an edge for the evidence, the contract state of
  each feature, what the link could see, and the hash-chain record.
- The replay speed is safe for the windowed features: at 5× the alerts are identical to an
  unthrottled offline run (same classes, endpoints and campaigns, 0 flows dropped;
  `scripts/demo_report.py`).

---

## 🔒 Passive Tap & Data-Diode Architecture

The system operates strictly under **PASSIVE READ-ONLY MONITORING** semantics:
- **No Transmit Sockets**: the sensor reads capture files (pcap/pcapng) and opens no network socket during a replay; a static scan and a runtime audit-hook test enforce it. How "nothing goes back" is enforced, and what is only a deployment requirement: [`docs/ISOLATION.md`](docs/ISOLATION.md). What still fires when the capture holds one direction only (IN or OUT), per threat class, with the false alarms it raised: [`docs/ONEWAY.md`](docs/ONEWAY.md).
- **No Active Mitigation**: Zero TCP RST generation, IP blocking, or firewall rule modification.
- **No Payload Decryption**: Operates 100% on observable packet headers, flow metadata, timing, and protocol fields.

---

## 🎯 Threat Classes (mapped to PS 26145)

| PS | Alert class | Detector | Evidence (tier-2 features, windowed) |
|---|---|---|---|
| (a) Volumetric / protocol DDoS | `THREAT_DDOS_VOLUME` | `ddos_volume_detector` | SYN flood: distinct sources, source-IP entropy, SYN-only ratio per destination. UDP reflection/amplification: unsolicited flows from reflector ports (53, 123, 1900, 11211, 389, 19, 161, 111), their mean packet size and bytes. Few-source floods: bytes/flows vs the destination's own EWMA baseline |
| (b) C2 beaconing | `THREAT_C2_BEACON` | `c2_beacon_detector` | Inter-flow interval CV per (src, dst) over >= 8 gaps; pollers suppressed by periodic fan-out and `config/poller_allowlist.txt` |
| (c) DGA and DNS tunnelling | `THREAT_DNS_DGA`, `THREAT_DNS_TUNNEL` | `dga_lexical_detector`, `dns_tunnel_detector` | Distinct high-entropy qnames per host + NXDOMAIN rate when resolver answers were captured; query volume and mean qname length |
| (d) Malware in encrypted sessions (TLS metadata) | `THREAT_ENCRYPTED_ANOMALY` | `encrypted_anomaly_detector` | JA4 on `config/ja4_known_bad.txt` (ships empty); JA4 seen almost only on one pair, used for repeated small, short sessions. No port rule |
| (e) Recon and port scanning | `THREAT_RECON_PORTSCAN` | `recon_portscan_detector` | Distinct destinations/ports per source with SYN-only ratio; shared infrastructure (high fan-in) skipped |
| (f) Data exfiltration | `THREAT_EXFILTRATION` | `exfiltration_detector` | Outbound/inbound ratio when both halves are captured; otherwise egress z-score + destination rarity + off-hours, named as a substitution |

**ML models** (`docs/MODELS.md`): LightGBM (`THREAT_ML_MALICIOUS_FLOW`, malicious vs benign
flow behaviour) and an IsolationForest (`THREAT_UNSUPERVISED_ANOMALY`, novelty against benign
flows), trained on header-only CTU-13-Extended captures. They read flow-level and tier-2
behaviour features only (no DNS/TLS content), so (c) and (d) stay rule-detected. An ML-only
alert is capped at MEDIUM; when a rule and a model agree on a flow, the rule alert's severity
goes up one level. Every ML-raised alert lists its top LightGBM `pred_contrib` features.

**Known weaknesses** (also stated per detector in `src/sih26145/feature_contract.toml`):
- (a) the few-source volumetric rule needs 5 closed windows of per-destination baseline (warm-up).
- (c) **dictionary DGAs** (word-based names) have ordinary label entropy and are **not caught**.
  Without resolver responses in the capture, a host resolving many CDN-style names can reach
  the lexical threshold.
- (b) beacons with more than ~70% jitter (CV > 0.40), fewer than 16 check-ins or a period under
  10 s; (d) a single-user client with an enclave-unique fingerprint reconnecting often to one
  server; (e) full-handshake connect scans.
- Thresholds of (a), (b), (e) and (f) were tuned on real mixed traffic (CTU-13-Extended s1/s5/s6,
  s11/s12 held out). The precision measured before and after, and what it does and does not
  mean, is in `docs/RULES.md`. The DGA, tunnel and TLS thresholds are still hand-set: header-only
  training captures cannot exercise them.
- C2 stays noisy on real traffic: 97.3 alerts per 10k flows on held-out s12, and most of
  them (97%) on unlabelled hosts (`docs/RULES.md` §4).

| Model | Alert class | Detector |
|---|---|---|
| supervised flow model | `THREAT_ML_MALICIOUS_FLOW` | LightGBM (`lightgbm_flow_classifier`) |
| unsupervised novelty | `THREAT_UNSUPERVISED_ANOMALY` | IsolationForest (`isolation_forest_flow_model`) |

---

## ⚡ Quickstart & Installation

### Prerequisites
- Linux / WSL2 Ubuntu with Python 3.11+ and `uv` package manager.
- Node.js 18+ and `npm` for the React monitoring dashboard.

### Installation
```bash
# Clone repository
git clone https://github.com/example/sih26145.git
cd sih26145

# Install Python backend dependencies using uv
uv sync
```

---

## 🚀 Usage Guide

### 1. Command-Line PCAP Analysis
Analyze an offline PCAP file for threat patterns:
```bash
uv run python -m sih26145.cli analyze /path/to/traffic.pcap
```

### 2. Automated Synthetic Threat Demo
Generate a synthetic test PCAP covering the threat classes above and run full pipeline analysis:
```bash
uv run python -m sih26145.cli demo
```

### 3. Live replay: pipeline + API + SSE in one process
Replay a capture at real time (or `--speed N`, or `--unthrottled`) and serve the API from
the same process; alerts reach the dashboard over SSE as they are produced and
`/api/v1/metrics` reports the running pipeline (flows/s, Mbps, queue depth, drops, alert
latency, link visibility):
```bash
uv run python -m sih26145.cli demo --output-pcap demo.pcap   # or any capture
uv run python -m sih26145.cli serve demo.pcap --speed 3 --db alerts.db
```

### 3b. Launch FastAPI REST & SSE Services (API only, no pipeline)
Start the backend REST API server with SSE live streaming:
```bash
uv run uvicorn sih26145.api.app:app --host 0.0.0.0 --port 8000
```

### 4. Launch React Monitoring Dashboard
In a separate terminal, launch the real-time SOC dashboard:
```bash
cd dashboard
npm install
npm run dev
```
Open `http://localhost:3000` in your browser to inspect live traffic metrics, throughput charts, and streaming alerts.

---

## 📊 REST & SSE API Reference

- `GET /api/v1/health`: System health and passive monitoring verification.
- `GET /api/v1/metrics`: Active flow counts, PPS, BPS, and total alert counts.
- `GET /api/v1/alerts`: Query persisted threat alerts with filtering (`threat_class`, `severity`).
- `GET /api/v1/stream/alerts`: Server-Sent Events (SSE) live event stream pushing alerts to client dashboards.

Example alerts, exactly as `GET /api/v1/alerts/{alert_id}` returned them for `demo/demo.pcap` (pretty-printed, content unchanged): a per-flow exfiltration alert, [`docs/examples/alert-exfil.json`](docs/examples/alert-exfil.json), an aggregate SYN-flood alert from the flow lane, [`docs/examples/alert-synflood.json`](docs/examples/alert-synflood.json) (its `flow_id` is a window id, `contributing_flows` names the top flows, and `confirms` points at the fast-lane alert), and that provisional fast-lane alert, [`docs/examples/alert-synflood-provisional.json`](docs/examples/alert-synflood-provisional.json). Exporting the log for one-way transfer (bundle files, `verify-log`, the BSA 2023 s.63 data sheet): [`docs/EXPORT.md`](docs/EXPORT.md).

---

## 🧪 Verification & Benchmarks

Run full test suite:
```bash
uv run pytest
```

Throughput benchmark (flows/s, Mbps, drop %, alert latency) on a capture of your choice:
```bash
uv run python scripts/benchmark.py path/to/capture.pcap              # capacity
uv run python scripts/benchmark.py path/to/capture.pcap --speed 26   # paced replay
```
Measured 2026-09-27 on the current code (correlation and hash-chained log included) on CTU-13
scenario 12 (Intel i5-13450HX, WSL2, Python 3.13.14, one core, trained models batched): about
**860 flows/s and 223 Mbps** sustained, and 1,129 flows/s on the mixed-traffic CTU-13-Extended
capture. Detection latency has two parts. Flow close takes 15 s idle or 60 s active (capture time)
plus at most one 1 s tick. Flush → alert at half load is p50 7 ms and p99 250 ms, with 0 drops.
Details, all runs and the profile: `docs/BENCHMARK.md`.
