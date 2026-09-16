# SIH26145 — Authoritative System Architecture & Design Specification

**Problem Statement:** SIH26145 — NTRO: “AI-Based Detection of Cyber Threats in Unidirectional IP Traffic”  
**Document Status:** Authoritative Design Specification (Phase 02)  
**Target Environment:** WSL2 Ubuntu / Linux (`~/NewProjects/sih26145/`)

---

## 1. System Purpose
The primary purpose of **SIH26145** is to provide real-time, passive, AI-assisted detection of cyber threats within unidirectional network traffic streams (e.g., optical data diodes or passive network taps). The system processes high-throughput traffic feeds, extracts statistical flow metrics and observable unencrypted header telemetry, detects anomalies and known attack vectors, and presents structured evidence-rich alerts to operators via a lightweight monitoring dashboard.

---

## 2. Hard Constraints
1. **Passive / Read-Only Observation**: The system operates exclusively in passive listening mode. There is zero active packet injection, zero mitigation response (no TCP RSTs, no IP blocking), and zero return traffic sent onto the monitored wire.
2. **Unidirectional Traffic Semantics**: Traffic flows strictly in one direction (A -> B). The architecture assumes return-path traffic (ACKs, SYN-ACKs, responses) is physically or logically absent and must never flag missing reverse traffic as network drop or malformed state by default.
3. **No Payload Decryption / TLS Interception**: Encrypted transport payloads (TLS, SSH, QUIC, IPsec) are opaque. Threat detection is performed exclusively via metadata-first analysis (header attributes, packet sizes, inter-arrival times, entropy of unencrypted fields, observable handshake parameters).
4. **No Premature Implementation**: Phase 02 establishes architecture and interfaces only. Application code (`src/`), dependencies, database schemas, frontend assets, and Docker configurations are strictly deferred to subsequent incremental phases.

---

## 3. High-Level Architecture

```mermaid
flowchart TD
    subgraph Ingestion Layer
        A1[Reproducible PCAP Replay Engine] -->|Unidirectional Stream| B[Packet Parser & Metadata Extractor]
        A2[Optional Live Passive NIC Interface] -.->|Passive Sniffing| B
    end

    subgraph Pipeline Stages
        B -->|Parsed Header Telemetry| C[Unidirectional Flow Assembler]
        C -->|Flow Telemetry Windows| D[Windowed Feature Extraction Engine]
        D -->|Feature Vector Stream| E1[Rule Detector Suite]
        D -->|Feature Vector Stream| E2[Classical ML Detector Suite]
    end

    subgraph Aggregation & Alerting Layer
        E1 --> F[Evidence Aggregator & Severity Evaluator]
        E2 --> F
        F --> G[(Embedded SQLite Alert Log)]
        F --> H[FastAPI REST & SSE Service]
        H -->|SSE Stream (Unidirectional Pushes)| I[React Read-Only Monitoring Dashboard]
        H -->|REST API (Historical Queries)| I
    end
```

---

## 4. Ingestion Boundary
- **PCAP Replay (Mandatory Prototype Path)**: Primary pipeline ingestion is driven by reproducible PCAP replay engines capable of pacing traffic at controlled rates for deterministic benchmarking and testing.
- **Passive Live NIC Path (Optional)**: Supports live packet capture via passive promiscuous socket interfaces (e.g., `AF_PACKET` / raw sockets / libpcap).
- **Processing Modes**: Supports both offline PCAP processing and live stream processing using identical downstream feature extraction code.
- **Read-Only Ingestion Boundary**: The ingestion engine opens network interfaces strictly in promiscuous receive mode without binding transmit sockets. *Note: Software-only passive configuration does not constitute physical data-diode enforcement, which requires physical hardware optical diodes.*

---

## 5. Packet Parsing Boundary
The packet parsing engine strictly separates observable header metadata from opaque payload contents:

### Observable Metadata (Inspected)
- **Link & Network Headers**: Ethernet MAC types, IPv4/IPv6 source/destination addresses, IP identification, TTL, IP flags, header length.
- **Transport Headers**: TCP/UDP source/destination ports, TCP flags (SYN, FIN, RST, PSH, URG), sequence numbers, window size, ICMP type/code.
- **Application Unencrypted Metadata**:
  - **DNS**: Query domain name, subdomain depth, query string entropy, record types (A, AAAA, TXT, CNAME, NULL).
  - **TLS/QUIC Handshake**: ClientHello unencrypted SNI (Server Name Indication), cipher suite lists, TLS version, record lengths, JA3/JA4 fingerprints (where unencrypted).

### Opaque Payload (Not Decrypted)
Encrypted application payload contents:
- **NOT INSPECTED**
- **NOT DECRYPTED**
- **NOT interpreted**

Observable encrypted-session features are restricted strictly to non-payload metadata:
- Packet lengths & length distributions
- Packet counts
- Inter-arrival timing & jitter
- Burst patterns
- Flow duration
- Protocol metadata & header fields
- Observable TLS/QUIC unencrypted handshake metadata

---

## 6. Unidirectional Flow Model

### Flow Identity Candidates
To determine the optimal balance between granular micro-flow tracking and behavioral aggregation, the architecture evaluates two candidate representations during early prototyping (Phases 03/04):
1. **Canonical Flow Identity Candidate (5-Tuple)**:  
   `FlowKey5 = (src_ip, src_port, dst_ip, dst_port, protocol)`
2. **Behavioral Aggregation Candidate (4-Tuple)**:  
   `FlowKey4 = (src_ip, dst_ip, dst_port, protocol)`

*Rationale:* In unidirectional traffic, source ports may be ephemeral across short bursts, whereas 4-tuple aggregation allows behavioral aggregation across multiple micro-flows. Source ports are not treated as inherently missing, but their aggregation utility will be empirically validated.

### State & Window Parameters (Initial Prototype Parameters)
- **Active Timeout**: 60 seconds (flushes accumulated flow features for continuous streams).
- **Idle Timeout**: 15 seconds (expires inactive flows).
- **Memory Bounds**: Maximum 100,000 active concurrent flows with LRU eviction.  
*(Note: These parameters represent baseline prototype settings to be empirically validated during Phase 04/05 testing).*

---

## 7. Feature Architecture
Feature extraction operates exclusively on information observable without decrypting payloads across 11 feature families:

1. **Packet Size**: Min, Max, Mean, Standard Deviation, 25%/50%/75% Quantiles.
2. **Inter-Arrival Time (IAT)**: Mean IAT, IAT Variance, Min/Max IAT, Jitter.
3. **Rate Features**: Packets per second (PPS), Bytes per second (BPS), Burstiness index.
4. **Flow Duration**: Total active duration (t_last - t_first).
5. **Packet Count**: Total window packets, ratio of small packets (<64 bytes), payload packet count.
6. **Protocol Distribution**: TCP, UDP, ICMP, DNS percentage ratios.
7. **Port Diversity**: Count of unique destination ports targeted per source IP.
8. **Fan-Out**: Ratio of unique destination IPs targeted per source IP.
9. **Failure / Anomaly Ratios**: SYN-only packet ratios, ICMP unreachable/error code ratios.
10. **DNS Lexical/Statistical Metadata**: Domain Shannon entropy, subdomain depth, TXT/NULL record ratio.
11. **TLS/QUIC Observable Metadata**: SNI length, SNI character entropy, ClientHello cipher list length.

---

## 8. Threat Taxonomy

The system defines 7 distinct threat detector categories:

```text
1. DDoS / Volume Anomalies
   ├── Features: BPS/PPS spikes, destination IP fan-in, SYN packet ratio, ICMP rate
   ├── Detection Method: Threshold heuristics + Isolation Forest anomaly model
   ├── Evidence: Baseline deviation ratio, BPS exceeding N*sigma
   └── Alert Class: THREAT_DDOS_VOLUME

2. Command & Control (C2) / Beaconing
   ├── Features: Periodic IAT low variance, fixed packet size clusters, low BPS persistence
   ├── Detection Method: Autocorrelation / IAT spectral analysis + Random Forest classifier
   ├── Evidence: IAT regularity index > 0.85, delta-time variance < threshold
   └── Alert Class: THREAT_C2_BEACON

3. Domain Generation Algorithm (DGA)
   ├── Features: High DNS query rate, domain Shannon entropy, consonant-to-vowel ratio
   ├── Detection Method: Random Forest / Logistic Regression lexical classifier + Entropy rules
   ├── Evidence: Domain string entropy > 4.2, n-gram anomaly score
   └── Alert Class: THREAT_DNS_DGA

4. DNS Tunnelling / Covert Channels
   ├── Features: High TXT/NULL record ratio, anomalous DNS payload length, high sub-domain diversity
   ├── Detection Method: Rule heuristics (record type + size) + Isolation Forest model
   ├── Evidence: Encoded subdomain length > 50 chars, TXT record ratio > 80%
   └── Alert Class: THREAT_DNS_TUNNEL

5. Encrypted Session / Encrypted Malware Anomaly
   ├── Features: TLS ClientHello SNI entropy, non-standard port usage, packet length sequence profile
   ├── Detection Method: XGBoost classifier trained on unencrypted TLS metadata profiles
   ├── Evidence: Unaligned SNI string, anomalous packet length distribution mismatch
   └── Alert Class: THREAT_ENCRYPTED_ANOMALY

6. Network Reconnaissance / Port Scanning
   ├── Features: High destination port diversity from single source, low packet count per port
   ├── Detection Method: Rule-based sliding window fan-out tracker
   ├── Evidence: > 50 distinct ports targeted within 5-second window
   └── Alert Class: THREAT_RECON_PORTSCAN

7. Data Exfiltration
   ├── Features: Sustained high outbound byte volume, asymmetric outbound size ratio, long flow duration
   ├── Detection Method: Isolation Forest + Threshold rule engine
   ├── Evidence: Outbound byte volume > X MB over non-standard protocol exceeding baseline by K*sigma
   └── Alert Class: THREAT_EXFILTRATION
```

---

## 9. Detection Architecture

```text
Feature Vector Stream
  ├──> Rule Detectors (Deterministic threshold & heuristic signature checks)
  └──> Classical ML Detectors (Isolation Forest, Random Forest, Logistic Regression, XGBoost)
        │
        ▼
Evidence Aggregator
  ├── Correlates rule hits & ML probabilities
  ├── Synthesizes evidence metrics
  └── Calculates Confidence Score (0.0 - 1.0) & Severity (LOW, MED, HIGH, CRITICAL)
        │
        ▼
Structured Versioned Alert Generator (sih26145.alert.v1)
```

*ML Model Scope:* Initial detection relies exclusively on explainable classical ML algorithms. Deep learning architectures (Autoencoders, CNNs, LSTMs) are excluded from the initial architecture to keep the system lightweight and explainable, and will only be reconsidered if empirical evaluation demonstrates a clear necessity.

---

## 10. Alert Contract (`sih26145.alert.v1`)

Alerts conform conceptually to a standardized versioned schema:

```json
{
  "$schema": "https://sih26145.ntro.gov.in/schemas/alert.v1.json",
  "version": "1.0",
  "alert_id": "urn:uuid:f47ac10b-58cc-4372-a567-0e02b2c3d479",
  "timestamp": "2026-09-16T15:00:00Z",
  "threat_class": "THREAT_DNS_TUNNEL",
  "detector": {
    "name": "dns_tunnel_detector",
    "type": "HYBRID_RULE_ML",
    "version": "1.0.0"
  },
  "flow": {
    "src_ip": "192.168.1.105",
    "dst_ip": "10.0.0.53",
    "dst_port": 53,
    "protocol": "UDP",
    "window_start": "2026-09-16T14:59:45Z",
    "window_end": "2026-09-16T15:00:00Z"
  },
  "confidence": 0.92,
  "severity": "HIGH",
  "evidence": {
    "rule_matches": ["DNS_TXT_RECORD_SPIKE", "HIGH_SUBDOMAIN_ENTROPY"],
    "ml_score": 0.89,
    "metrics": {
      "query_domain_entropy": 4.65,
      "txt_record_ratio": 0.85,
      "mean_packet_size": 312.4
    }
  },
  "feature_summary": {
    "total_packets": 142,
    "total_bytes": 44360,
    "pps": 9.46,
    "bps": 2957.3
  }
}
```

---

## 11. Dataset Architecture
- **Benign Baseline**: Captures of standard corporate/enterprise unidirectional network traffic.
- **Threat Scenarios**: Scripted attack traffic generated in controlled test environments.
- **Session-Aware Splitting**: Whole flows/sessions are split between train and test sets to prevent temporal intra-flow data leakage.
- **Feature Pipeline Parity**: Training scripts and live inference pipelines must execute the exact same Python feature extraction code.
- **Ground Truth**: PCAP datasets annotated with precise scenario IDs (`scenario_id`, `threat_class`, `start_time`, `end_time`).
- **Demonstration vs Production**: Synthetic/scripted datasets are used for controlled demonstration and validation; performance metrics on synthetic traffic will never be presented as real-world production accuracy.

---

## 12. Backend / Frontend Boundary

SIH26145 consists of two cleanly separated subsystems:

### Backend Detection System
- Packet ingestion & parsing
- Flow assembly & window state tracking
- Feature extraction engine
- Hybrid rule + classical ML threat detectors
- Evidence aggregation & structured alert generation
- SQLite alert persistence
- FastAPI REST API & SSE event server

### Frontend Monitoring Dashboard
- Read-only visual interface (React + Vite)
- Live traffic rate charts (BPS / PPS)
- Active flow count and memory gauges
- Threat summary charts
- Real-time SSE alert streaming table with expandable JSON evidence
- Visibly prominent **PASSIVE / READ-ONLY MONITORING** header indicator

*Note: The frontend consumes real backend data via REST/SSE APIs. Frontend implementation is deferred to later phases.*

---

## 13. API Architecture
- **REST API (Historical Queries)**:
  - `GET /api/v1/health`: Ingestion status and system health.
  - `GET /api/v1/alerts`: Query persisted alerts with filtering (`threat_class`, `severity`, `time_range`).
  - `GET /api/v1/metrics`: Retrieve current traffic performance metrics (PPS, BPS, active flow count).
- **SSE Stream (Live Event Pushing)**:
  - `GET /api/v1/stream/alerts`: SSE provides a server → dashboard unidirectional event stream. REST remains available for client → server HTTP requests and historical queries. *(WebSockets remain excluded from the initial architecture).*

---

## 14. Performance Measurement Plan
- **Empirical Measurement Strategy**: Phase 03/04 will establish a measured throughput baseline before defining optimization targets. No achieved or required PPS/BPS figure is assumed at this stage.
- **Tracked Operational Metrics**:
  - Ingestion & parsing throughput (Packets/Sec, Bytes/Sec)
  - Active flow tracking capacity and memory allocation (MB/GB)
  - Processing pipeline latency per packet (us or ms)
  - Alert propagation latency via SSE (ms)

---

## 15. Security / Read-Only Model
- **Passive Software Operating Mode**: The application performs receive-only packet capture and contains no transmit, packet-injection, or mitigation functionality. Physical one-way enforcement remains the responsibility of the underlying data-diode or passive-tap hardware.
- **No Active Mitigation**: Threat alerts are published to API/dashboard only; no IP blocking, TCP RSTs, or firewall commands are executed.
- **Disambiguation**: Software-level passive capture guarantees prevent accidental transmission from code, but do not replace physical hardware data-diode enforcement.

---

## 16. Phase Boundaries & Implementation Progression

Implementation will proceed incrementally across structured phases:

- **Phase 01**: Initial Repository Setup & Conceptual Architecture *(Completed)*
- **Phase 02**: Authoritative Architecture Documentation (`docs/ARCHITECTURE.md`) *(Current)*
- **Phase 03**: Project Foundation & Dependency Configuration (`pyproject.toml`, `uv.lock`)
- **Phase 04**: PCAP Ingestion & Parsing Engine
- **Phase 05**: Unidirectional Flow Assembly & State Engine
- **Phase 06**: Feature Extraction Engine
- **Phase 07**: Rule-Based Threat Detectors
- **Phase 08**: Classical ML Threat Detectors
- **Phase 09**: Evidence Aggregator & Alert Schema
- **Phase 10**: SQLite Alert Persistence & FastAPI REST/SSE Services
- **Phase 11**: React Monitoring Dashboard Integration
- **Phase 12**: End-to-End System Integration, Testing & Performance Verification
