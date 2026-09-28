# UniShield AI

**SIH Problem Statement 26145 — Passive Network Threat Intelligence**

[![Python](https://img.shields.io/badge/python-3.12-blue.svg)](https://python.org)
[![License](https://img.shields.io/badge/license-MIT-green.svg)]()
[![Phase](https://img.shields.io/badge/phase-0%20complete-brightgreen)]()

---

## What is UniShield AI?

UniShield AI is a **passive-only** network threat intelligence system designed for critical-infrastructure monitoring environments. Traffic is observed through a hardware data diode or passive mirror — the system **never sends packets back**, **never probes sources**, and **never decrypts payloads**.

### Threats detected

| Category | Method |
|----------|--------|
| Volumetric / Protocol DDoS | Statistical thresholds, SYN anomaly, burst detection, source entropy |
| Botnet C2 Beaconing | IAT periodicity, coefficient of variation, repeated destinations |
| DGA Domains / DNS Tunnelling | Entropy, n-grams, lexical features, query frequency |
| Malware in Encrypted Sessions | TLS/QUIC metadata, packet-size patterns, timing (no decryption) |
| Reconnaissance / Port Scanning | Fan-out, unique port/host counts, connection rate |
| Data Exfiltration | Volume baselines, outbound/inbound ratio, behavioral deviation |

---

## Architecture (Passive-First)

```
PCAP / FLOW INPUT
       ↓
PASSIVE INGESTION  (Scapy / Zeek log adapter)
       ↓
FLOW ENGINE        (5-tuple flow tracking, timeout-based)
       ↓
FEATURE EXTRACTION (timing, entropy, DNS, TLS, behavioral)
       ↓
SPECIALIZED DETECTORS (one per threat class)
       ↓
EVIDENCE FUSION    (score aggregation + explanation)
       ↓
RISK / SEVERITY ENGINE
       ↓
STRUCTURED ALERT   (Pydantic schema, SQLite persistence)
       ↓
FASTAPI BACKEND + STREAMLIT DASHBOARD
```

**There is no return path. No packets are sent back.**

---

## Technology Stack

| Layer | Technology |
|-------|-----------|
| Core | Python 3.12 |
| Passive ingestion | Scapy (PCAP) + Zeek log adapter |
| Data processing | NumPy, Pandas, SciPy |
| Machine learning | scikit-learn, XGBoost |
| API backend | FastAPI + Uvicorn |
| Dashboard | Streamlit + Plotly |
| Database | SQLite (PostgreSQL path available) |
| Validation | Pydantic v2 |
| Configuration | YAML |
| Logging | Loguru |
| Testing | pytest |
| Containers | Docker + docker-compose (Phase 19) |

---

## Quick Start

### 1. Clone and set up

```bash
git clone <repo-url>
cd unishield-ai
python -m pip install -r requirements.txt
```

### 2. Run Phase 0 smoke tests

```bash
python -m pytest tests/test_phase0.py -v
```

### 3. (Future) Run the full pipeline with a PCAP

```bash
# Phase 1 onwards
python -m src.main --pcap data/samples/demo.pcap
```

### 4. (Future) Start the API and dashboard

```bash
# Terminal 1 — API
uvicorn src.api.main:app --reload

# Terminal 2 — Dashboard
streamlit run dashboard/app.py
```

---

## Project Structure

```
unishield-ai/
├── config/
│   ├── config.yaml        ← all tunable parameters
│   └── thresholds.yaml    ← all detection thresholds
├── data/
│   ├── raw/               ← input PCAPs / Zeek logs
│   ├── processed/         ← intermediate artefacts
│   └── samples/           ← demo / synthetic data
├── src/
│   ├── ingestion/         ← PCAP reader, Zeek adapter, stream
│   ├── flows/             ← flow dataclass, manager, sessionizer
│   ├── features/          ← feature extractors (timing, DNS, TLS …)
│   ├── detectors/         ← one module per threat class
│   ├── fusion/            ← evidence fusion and risk scoring
│   ├── alerts/            ← Pydantic schema and generator
│   ├── models/            ← trained model artefacts
│   └── utils/             ← logging, config, metrics, time
├── dashboard/             ← Streamlit SOC console
├── tests/                 ← pytest test suite
├── docs/                  ← architecture, threat models, evaluation
└── notebooks/             ← exploratory analysis
```

---

## Configuration

All thresholds and parameters live in `config/`. **Never scatter magic numbers in source files.**

- `config/config.yaml` — logging, database, API, ingestion, flow engine settings  
- `config/thresholds.yaml` — per-detector detection thresholds with documentation

---

## Passive Security Constraints

UniShield AI enforces these constraints by design:

- ✅ Read-only traffic observation
- ✅ No return path, no acknowledgement
- ✅ No active probing or scanning
- ✅ No TLS/QUIC payload decryption
- ✅ No handshake completion
- ✅ Metadata-only analysis for encrypted sessions
- ✅ All mitigations route to alert output only

---

## Development Phases

| Phase | Description | Status |
|-------|-------------|--------|
| 0 | Project setup, environment, config, logging, tests | ✅ Complete |
| 1 | Passive PCAP ingestion | 🔲 Next |
| 2 | Flow engine | 🔲 |
| 3 | Feature engine | 🔲 |
| 4 | DDoS detector | 🔲 |
| 5 | Alert system | 🔲 |
| 6–10 | Remaining detectors | 🔲 |
| 11 | Evidence fusion | 🔲 |
| 12 | Risk/severity engine | 🔲 |
| 13 | FastAPI backend | 🔲 |
| 14 | Streamlit dashboard | 🔲 |
| 15–20 | Streaming, datasets, Docker, hardening | 🔲 |

---

## Documentation

- [`docs/architecture.md`](docs/architecture.md) — system architecture and passive constraints
- [`docs/threat_models.md`](docs/threat_models.md) — per-threat detection methodology
- [`docs/evaluation.md`](docs/evaluation.md) — benchmarking methodology and dataset documentation

---

## Important — Benchmark Integrity

> Benchmark numbers in this project are **measured at runtime, never invented**.  
> Any metric that has not yet been measured is explicitly labelled:  
> **"Not yet benchmarked."**

---

## License

MIT License — see `LICENSE` for details.

---

*Built for Smart India Hackathon 2026 — Problem Statement 26145*
