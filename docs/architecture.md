# UniShield AI — System Architecture
## SIH Problem Statement 26145

---

## Overview

UniShield AI is a **passive-only** network threat intelligence system. It receives a copy of network traffic via a hardware data diode or passive port mirror, analyses it in real time using a multi-stage pipeline, and produces structured threat alerts — without ever sending a single packet back.

---

## Passive-First Constraint

The fundamental design constraint is:

> The monitoring enclave can **SEE** traffic but MUST NOT interact with it.

This means:
- No return path (no ACKs, no RSTs, no ICMP)
- No active probing or scanning
- No TLS/QUIC decryption
- No handshake completion
- No mitigation commands back through the ingest path

All detectors operate on **metadata only**.

---

## Pipeline Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                     TRAFFIC SOURCE (read-only)                  │
│           PCAP mirror / Zeek-monitored interface                │
└───────────────────────────┬─────────────────────────────────────┘
                            │  (no return path)
                            ▼
┌─────────────────────────────────────────────────────────────────┐
│  PASSIVE INGESTION                                              │
│  · PcapReader (Scapy)     · ZeekLogReader adapter              │
│  · StreamProcessor        · Packet normalisation               │
└───────────────────────────┬─────────────────────────────────────┘
                            ▼
┌─────────────────────────────────────────────────────────────────┐
│  FLOW ENGINE                                                    │
│  · 5-tuple flow identification                                  │
│  · Timeout-based flow expiry                                    │
│  · FlowRecord with packet/byte counters                         │
└───────────────────────────┬─────────────────────────────────────┘
                            ▼
┌─────────────────────────────────────────────────────────────────┐
│  FEATURE EXTRACTION                                             │
│  · flow_features.py       · timing_features.py                 │
│  · dns_features.py        · tls_features.py                    │
│  · behavioral_features.py · feature_pipeline.py                │
└───────────────────────────┬─────────────────────────────────────┘
                            ▼
┌─────────────────────────────────────────────────────────────────┐
│  SPECIALIZED DETECTORS  (run in parallel, independent)          │
│  ┌──────────┐ ┌──────┐ ┌─────────┐ ┌──────┐ ┌──────┐ ┌──────┐ │
│  │  DDoS    │ │  C2  │ │ DGA/DNS │ │ Enc. │ │Recon │ │Exfil │ │
│  └──────────┘ └──────┘ └─────────┘ └──────┘ └──────┘ └──────┘ │
│  Each returns: score, confidence, evidence[]                    │
└───────────────────────────┬─────────────────────────────────────┘
                            ▼
┌─────────────────────────────────────────────────────────────────┐
│  EVIDENCE FUSION ENGINE                                         │
│  · Normalise scores across detectors                            │
│  · Aggregate evidence items                                     │
│  · Calculate combined confidence                                │
│  · Deduplicate overlapping detections                           │
└───────────────────────────┬─────────────────────────────────────┘
                            ▼
┌─────────────────────────────────────────────────────────────────┐
│  RISK / SEVERITY ENGINE                                         │
│  · Map combined score → severity (LOW/MEDIUM/HIGH/CRITICAL)     │
│  · Confidence score is separate from severity                   │
└───────────────────────────┬─────────────────────────────────────┘
                            ▼
┌─────────────────────────────────────────────────────────────────┐
│  STRUCTURED ALERT (Pydantic schema)                             │
│  · Persisted to SQLite                                          │
│  · Emitted to FastAPI REST endpoint                             │
└───────────────────────────┬─────────────────────────────────────┘
                            ▼
┌─────────────────────────────────────────────────────────────────┐
│  STREAMLIT DASHBOARD (SOC console)                              │
│  · Alert feed with evidence drill-down                          │
│  · "WHY THIS ALERT?" explanation per alert                      │
│  · Timeline, threat distribution, suspicious hosts             │
└─────────────────────────────────────────────────────────────────┘
```

---

## Module Responsibilities

### `src/ingestion/`
- `pcap_reader.py` — Scapy-based passive PCAP reader (read-only, no write-back)
- `flow_reader.py` — Zeek conn/dns/ssl log parser adapter
- `stream.py` — Streaming packet/event dispatcher

### `src/flows/`
- `flow.py` — `FlowRecord` dataclass (5-tuple + counters)
- `flow_manager.py` — Active flow table with timeout expiry
- `sessionizer.py` — Assigns packets to flows

### `src/features/`
- `flow_features.py` — Packets/sec, bytes/sec, size statistics
- `timing_features.py` — IAT, periodicity, coefficient of variation
- `dns_features.py` — Entropy, n-grams, query length, record type frequency
- `tls_features.py` — TLS version, SNI, packet-size sequences (no decryption)
- `behavioral_features.py` — Fan-out, unique destinations, baseline deviation
- `feature_pipeline.py` — Orchestrates all feature extractors

### `src/detectors/`
- `base.py` — Abstract `BaseDetector` interface
- `ddos.py` — DDoS detector (statistical + optional ML)
- `c2_beacon.py` — C2 beaconing detector (IAT periodicity)
- `dga_dns.py` — DGA / DNS tunnelling detector (entropy + ML)
- `encrypted.py` — Encrypted traffic anomaly (metadata only)
- `reconnaissance.py` — Port scan / host sweep detector
- `exfiltration.py` — Data exfiltration detector (volume + baseline)

### `src/fusion/`
- `evidence.py` — `EvidenceItem` dataclass
- `risk_score.py` — Score normalisation and severity mapping
- `fusion_engine.py` — Aggregates evidence from all detectors

### `src/alerts/`
- `schema.py` — Pydantic `Alert` model
- `generator.py` — Alert creation and SQLite persistence

---

## Detector Common Interface

Every detector implements:

```python
class BaseDetector(ABC):
    @abstractmethod
    def detect(self, features: FeatureVector) -> DetectionResult:
        ...
```

`DetectionResult` contains:
- `threat_class` — e.g., `"DDoS"`, `"C2"`, `"DGA"`
- `detection_score` — 0.0–1.0
- `confidence` — 0.0–1.0 (separate from severity)
- `severity` — `LOW | MEDIUM | HIGH | CRITICAL`
- `evidence` — list of `EvidenceItem` (feature, observed, baseline, reason)

---

## Alert Schema (Pydantic)

```json
{
  "timestamp": "2025-08-27T18:00:00+00:00",
  "alert_id": "uuid",
  "flow_id": "192.168.1.1:4321->10.0.0.1:80/TCP",
  "source_ip": "192.168.1.1",
  "destination_ip": "10.0.0.1",
  "threat_class": "DDoS",
  "severity": "CRITICAL",
  "confidence": 0.94,
  "detection_score": 0.91,
  "evidence": [
    {
      "feature": "syn_rate",
      "observed": 18420,
      "baseline": 1230,
      "deviation": 14.97,
      "reason": "abnormally_high",
      "detector": "DDoSDetector"
    }
  ]
}
```

---

## Zeek Integration (Current Strategy)

Zeek does not run natively on Windows. Current strategy:

1. **Phase 0–10** — Pure Scapy PCAP reader (no Zeek dependency)
2. **Phase 19** — Zeek containerised in Docker (`docker-compose up`)
3. The `ZeekLogReader` adapter in `src/ingestion/flow_reader.py` accepts real Zeek logs with no pipeline changes

---

## Limitations (Phase 0)

- No live interface capture (PCAP file replay only)
- No Docker containerisation yet
- No Zeek integration yet (stub only)
- Benchmarks labelled "Not yet benchmarked" until measured
