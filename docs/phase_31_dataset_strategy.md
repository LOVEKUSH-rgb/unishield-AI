# Phase 31 Dataset Strategy

## Overview
This document outlines the datasets considered, used, and explicitly rejected for the Phase 31 Real-World Threat Validation & Detector Evaluation. The goal of this evaluation is to establish verifiable, reproducible baseline accuracy metrics for UniShield AI's 6 core detectors without artificially inflating scores.

## Datasets Evaluated

### 1. CIC-IDS2017 (Canadian Institute for Cybersecurity)
- **Source**: https://www.unb.ca/cic/datasets/ids-2017.html
- **License**: Publicly available for academic and research purposes.
- **Format**: CSV (Pre-extracted features)
- **Status**: **REJECTED**
- **Justification**: The `data/raw/CICIDS2017_sample.csv` available in this repository is heavily aggregated and completely lacks crucial flow identifiers (`Source IP`, `Destination IP`, `Source Port`, `Destination Port`). Because UniShield AI's detectors require stateful tracking of entities across time (e.g., `dst_uniq_src_hosts_60s` for DDoS, temporal beacon intervals for C2), an IP-less dataset cannot be ingested into our `FeaturePipeline` or evaluated accurately. Any attempt to map this dataset would require fabricating IPs, which violates Phase 31 mandates.

### 2. DGA Dataset (`data/processed/dga_dataset.csv`)
- **Source**: Internal / Publicly aggregated known DGA domains.
- **Format**: CSV
- **Status**: **USED FOR LEAKAGE AUDIT ONLY**
- **Justification**: This dataset was explicitly used during the training phase (Phase 19). Using it for validation would introduce train-test contamination and yield a falsely optimistic 99%+ accuracy score. It is preserved strictly to ensure our evaluation dataset does not overlap with it.

### 3. Encrypted Malware Dataset (`data/processed/encrypted_dataset.csv`)
- **Source**: Internal / Publicly aggregated TLS features.
- **Format**: CSV
- **Status**: **USED FOR LEAKAGE AUDIT ONLY**
- **Justification**: As with the DGA dataset, this dataset was the training corpus for the XGBoost encrypted session model. It cannot be used for unbiased evaluation.

### 4. UniShield Demo Scenarios (`data/samples/demo_flows_expanded.jsonl`)
- **Source**: Internally generated Golden Demo (`scripts/generate_demo_pcap.py`).
- **Format**: JSON Lines (Pre-parsed `FeatureVector` format).
- **Attack Classes**: Benign, Reconnaissance, DDoS, C2 Beacon, Encrypted Anomaly, DGA DNS, Exfiltration.
- **Ground Truth**: Absolute (Derived from IP addresses).
- **Status**: **ACCEPTED (AS REGRESSION CORPUS)**
- **Justification**: Since the massive public datasets lack the necessary stateful networking fields in their raw CSV formats, and because downloading 50GB+ PCAPs violates the repository constraints, we are utilizing the existing `demo_flows_expanded.jsonl` as our explicit CI regression corpus.
- **Limitations**: This dataset is synthetic. While it exhibits the deterministic behaviors of the six threats, it does not represent the chaotic variance of real-world internet background noise. Accuracy metrics on this dataset prove that the *logic* of the detectors functions correctly, but does not prove *real-world generalization*.

## Ground Truth Mapping

For `demo_flows_expanded.jsonl`, ground truth is deterministically mapped as follows:

| Threat Class | Condition |
|---|---|
| **DDoS** | `source_ip` starts with `203.0.113.` |
| **C2 Beacon** | `source_ip == 192.168.1.50` AND `dst_ip == 103.45.67.89` |
| **Reconnaissance** | `source_ip == 192.168.1.50` AND `dst_ip == 10.0.0.10` |
| **DGA/DNS** | `dst_ip == 8.8.8.8` |
| **Encrypted Anomaly** | `source_ip == 192.168.1.52` |
| **Exfiltration** | `source_ip == 192.168.1.53` AND `dst_ip == 103.45.67.89` |
| **Benign** | Any flow not matching the above conditions. |

Any records missing essential routing information will be classified as `UNMAPPED`.
