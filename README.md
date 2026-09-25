# SIH26145 — NTRO: AI-Based Detection of Cyber Threats in Unidirectional IP Traffic

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Python 3.11+](https://img.shields.io/badge/python-3.11+-blue.svg)](https://www.python.org/)
[![FastAPI](https://img.shields.io/badge/FastAPI-1.0.0-green.svg)](https://fastapi.tiangolo.com/)
[![React](https://img.shields.io/badge/React-18.3-blue.svg)](https://react.dev/)

An explainable, read-only passive threat detection engine for traffic observed by an enclave that can never transmit (optical data diodes, passive taps). The capture may contain both halves of each conversation or only one; the system measures which, per flow, and declares for every feature what it needs (see `docs/ARCHITECTURE.md` §2 and §6). Detection uses deterministic rules and classical ML over flow metadata only, with no active mitigation and no payload decryption.

> **Status:** see `docs/ARCHITECTURE.md` §15 and `docs/AUDIT.md`. The ML models are currently fitted on synthetic vectors, and no throughput figure has been measured yet.

---

## 🔒 Passive Tap & Data-Diode Architecture

The system operates strictly under **PASSIVE READ-ONLY MONITORING** semantics:
- **No Transmit Sockets**: Ingestion interfaces operate strictly in promiscuous receive mode (`AF_PACKET` / `pcap`).
- **No Active Mitigation**: Zero TCP RST generation, IP blocking, or firewall rule modification.
- **No Payload Decryption**: Operates 100% on observable packet headers, flow metadata, timing, and protocol fields.

---

## 🎯 Threat Classes (mapped to PS 26145)

| PS | Alert class | Detector |
|---|---|---|
| (a) Volumetric / protocol DDoS | `THREAT_DDOS_VOLUME` | `ddos_volume_detector` |
| (b) C2 beaconing | `THREAT_C2_BEACON` | `c2_beacon_detector` |
| (c) DGA and DNS tunnelling | `THREAT_DNS_DGA`, `THREAT_DNS_TUNNEL` | `dga_lexical_detector`, `dns_tunnel_detector` |
| (d) Malware in encrypted sessions (TLS/QUIC metadata) | `THREAT_ENCRYPTED_ANOMALY` | `encrypted_anomaly_detector` |
| (e) Recon and port scanning | `THREAT_RECON_PORTSCAN` | `recon_portscan_detector` |
| (f) Data exfiltration | `THREAT_EXFILTRATION` | `exfiltration_detector` |
| — unsupervised novelty | `THREAT_UNSUPERVISED_ANOMALY` | IsolationForest |

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

### 3. Launch FastAPI REST & SSE Services
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

---

## 🧪 Verification & Benchmarks

Run full test suite:
```bash
uv run pytest
```

Run performance benchmark:
```bash
uv run python scripts/benchmark.py
```
