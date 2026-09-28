# UniShield AI Detector Validation Report
Generated on: 2026-08-28 17:33:53

## 1. Dataset Sources
The following public datasets are designated for validation. Currently, the raw data files are missing locally, so the framework gracefully degrades to reporting `NOT VALIDATED`.
- **CIC-IDS2017:** Canadian Institute for Cybersecurity (DDoS, Reconnaissance)
- **CTU-13:** Stratosphere IPS (C2 Beaconing)
- **BoT-IoT:** UNSW Canberra Cyber (Data Exfiltration)
- **DNS-DGA (Synthetic/Custom):** Public DGA domain lists
- **CIC-Darknet2020:** UNB CIC (Encrypted Traffic Anomalies)

## 2. Dataset Characteristics
*(Pending dataset download)*

## 3. Label Mappings
To prevent data leakage, all original labels are strictly kept out of feature pipelines and mapped to canonical classes:
- CIC-IDS2017: `BENIGN` -> `NORMAL`, `PortScan` -> `RECONNAISSANCE`, `DoS Hulk` -> `DDOS`
- CTU-13: `Botnet` -> `C2_BEACON`, `Background/Normal` -> `NORMAL`
- BoT-IoT: `Data Exfiltration` -> `EXFILTRATION`

## 4. Features Evaluated
- **DDoS:** Packet rate, byte rate, TCP SYN ratio, UDP ratio
- **C2 Beaconing:** Inter-arrival time (mean/median), coefficient of variation, connection count, destination concentration
- **Reconnaissance:** Unique destination hosts, unique destination ports, fan-out
- **Exfiltration:** Outbound byte ratio, flow duration, outbound bytes
- **DGA / DNS:** Domain length, entropy, digit ratio, character distribution
- **Encrypted Anomaly:** SNI lengths, payload size variance, packet timing

## 5. Train/Test Methodology
- Time-based splitting (where supported by dataset chronologies) to prevent flow leakage.
- Scenario-based splitting (e.g., using CTU-13 Scenario 1 for training and Scenario 2 for testing).

## 6. Models Used
- **DDoS:** Statistical Thresholding
- **C2 Beaconing:** Periodicity Analysis + Isolation Forest (ML Boost)
- **Reconnaissance:** Temporal Aggregation Thresholds
- **Exfiltration:** Baseline Deviation (Byte Ratios)
- **DGA / DNS:** Feature Vector Thresholding + Entropy Analysis
- **Encrypted Anomaly:** Payload Variance Analysis

## 7. Baselines
- **C2:** Pure periodic interval matching (baseline) vs Isolation Forest
- **Recon:** Static limit counting vs Exponential Moving Average (EMA) connection tracking

## 8. Metrics Definition
- **Precision:** TP / (TP + FP)
- **Recall:** TP / (TP + FN)
- **F1 Score:** Harmonic mean of Precision and Recall
- **Throughput:** Processed flows per second
- **Latency:** Time (ms) from feature extraction to detection decision

## 9. Results Summary

| Detector | Dataset | Status | Precision | Recall | F1 Score | FPR | Latency |
|----------|---------|--------|-----------|--------|----------|-----|---------|
| DDoS | CIC-IDS2017 | DATASET NOT AVAILABLE | NOT VALIDATED | NOT VALIDATED | NOT VALIDATED | NOT VALIDATED | NOT VALIDATED |
| Reconnaissance | CIC-IDS2017 | DATASET NOT AVAILABLE | NOT VALIDATED | NOT VALIDATED | NOT VALIDATED | NOT VALIDATED | NOT VALIDATED |
| C2_Beacon | CTU-13 | DATASET NOT AVAILABLE | NOT VALIDATED | NOT VALIDATED | NOT VALIDATED | NOT VALIDATED | NOT VALIDATED |
| Exfiltration | BoT-IoT | DATASET NOT AVAILABLE | NOT VALIDATED | NOT VALIDATED | NOT VALIDATED | NOT VALIDATED | NOT VALIDATED |
| DNS_DGA | DNS-DGA (Synthetic/Custom) | DATASET NOT AVAILABLE | NOT VALIDATED | NOT VALIDATED | NOT VALIDATED | NOT VALIDATED | NOT VALIDATED |
| Encrypted_Anomaly | CIC-Darknet2020 | DATASET NOT AVAILABLE | NOT VALIDATED | NOT VALIDATED | NOT VALIDATED | NOT VALIDATED | NOT VALIDATED |

## 10. False-Positive Analysis
*(Cannot be performed without validation datasets. Expected FPs include legitimate high-frequency beacons like NTP or telemetry, and rapid CDN fetches flagged as DDoS).*

## 11. Performance Benchmarks
| Detector | Throughput (fps) |
|----------|------------------|
| DDoS | NOT VALIDATED |
| Reconnaissance | NOT VALIDATED |
| C2_Beacon | NOT VALIDATED |
| Exfiltration | NOT VALIDATED |
| DNS_DGA | NOT VALIDATED |
| Encrypted_Anomaly | NOT VALIDATED |

## 12. Limitations
- **DATASET NOT AVAILABLE:** The gigabyte-scale validation PCAPs and CSVs are not present in the repository, so ML models and statistical thresholds currently output `NOT VALIDATED` for performance metrics. 
- **Encrypted Traffic Validation:** Exact malware-in-TLS identification cannot be guaranteed; the detector flags *anomalous* encrypted sessions, not definitively malicious payloads.

## 13. Passive Architecture Compliance
**AUDIT PASSED:** No active probing, DNS lookups, or payload decryption are utilized in the validation suite. All evaluation runs strictly over passive flow telemetry (FeatureVectors).
