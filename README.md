# SIH26145 — NTRO: AI-Based Detection of Cyber Threats in Unidirectional IP Traffic

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Python 3.11+](https://img.shields.io/badge/python-3.11+-blue.svg)](https://www.python.org/)
[![FastAPI](https://img.shields.io/badge/FastAPI-1.0.0-green.svg)](https://fastapi.tiangolo.com/)
[![React](https://img.shields.io/badge/React-18.3-blue.svg)](https://react.dev/)

An explainable, read-only passive threat detection engine designed for unidirectional IP traffic feeds (e.g., optical data-diodes and passive network TAPs). The system provides multi-layer threat detection across 7 key threat categories using deterministic rule detectors and classical machine learning (Isolation Forest & Random Forest) without deep learning black-boxes or active mitigation calls.

---

## 🔒 Passive Tap & Data-Diode Architecture

The system operates strictly under **PASSIVE READ-ONLY MONITORING** semantics:
- **No Transmit Sockets**: Ingestion interfaces operate strictly in promiscuous receive mode (`AF_PACKET` / `pcap`).
- **No Active Mitigation**: Zero TCP RST generation, IP blocking, or firewall rule modification.
- **No Payload Decryption**: Operates 100% on observable packet headers, flow metadata, timing, and protocol fields.

---

## 🎯 Supported Threat Categories

1. **DNS Tunneling (`THREAT_DNS_TUNNEL`)**: High-entropy subdomains, unusual query length/depth.
2. **DNS Exfiltration (`THREAT_EXFIL_DNS`)**: High-frequency oversized TXT/NULL queries.
3. **ICMP Exfiltration (`THREAT_EXFIL_ICMP`)**: Abnormally large echo request payloads.
4. **C2 Beaconing (`THREAT_BEACON_C2`)**: Periodic inter-arrival times & low jitter.
5. **Slowloris DoS (`THREAT_SLOWLORIS_DOS`)**: Low BPS/PPS with open long-duration TCP sessions.
6. **Port Sweep (`THREAT_PORT_SWEEP`)**: High unique destination port probing from a single source.
7. **Anomalous Traffic Burst (`THREAT_ANOMALOUS_BURST`)**: Statistical PPS/BPS anomaly surges.

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
Generate a test PCAP containing all 7 threat classes and run full pipeline analysis:
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
