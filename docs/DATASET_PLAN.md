# UniShield AI Dataset Integration Plan

This document specifies the dataset strategy for validating the six UniShield AI threat detectors. The datasets below must be downloaded manually by the developer and placed into `data/raw/` in their expected formats. The automated evaluation script (`scripts/evaluate_detectors.py`) will automatically process them if present.

## 1. DDoS & Reconnaissance Validation
- **Dataset**: CIC-IDS2017
- **Official Source**: Canadian Institute for Cybersecurity (https://www.unb.ca/cic/datasets/ids-2017.html)
- **Relevant Attack Categories**: DDoS, DoS Hulk, DoS GoldenEye, PortScan
- **Expected Format**: `data/raw/cic_ids2017/` containing generated CSV flow files.
- **Approximate Size**: ~2.5 GB (CSVs only)
- **Detector(s) Validated**: DDoS Detector, Recon Detector
- **License/Usage Notes**: Academic/non-commercial use.
- **Required Preprocessing**: Flow mapping via `src/normalization/cic_ids2017_adapter.py`. Combine DoS sub-labels to `DDOS` and PortScan to `RECONNAISSANCE`.

## 2. C2 Beaconing Validation
- **Dataset**: CTU-13
- **Official Source**: Stratosphere IPS (https://www.stratosphereips.org/datasets-ctu13)
- **Relevant Attack Categories**: Botnet
- **Expected Format**: `data/raw/ctu13/` containing Zeek conn.log or binetflow CSVs.
- **Approximate Size**: ~1 GB per scenario
- **Detector(s) Validated**: C2 Beaconing Detector
- **License/Usage Notes**: Public domain / Open use.
- **Required Preprocessing**: Flow mapping via `src/normalization/ctu13_adapter.py`. Parse periodic botnet connections and label as `C2_BEACON`. Normal traffic mapped to `NORMAL`.

## 3. Data Exfiltration Validation
- **Dataset**: BoT-IoT
- **Official Source**: UNSW Canberra Cyber (https://research.unsw.edu.au/projects/bot-iot-dataset)
- **Relevant Attack Categories**: Data Exfiltration, Information Theft
- **Expected Format**: `data/raw/bot_iot/` containing Argus/Bro flow CSVs.
- **Approximate Size**: ~1 GB (10% extracted set)
- **Detector(s) Validated**: Exfiltration Detector
- **License/Usage Notes**: Academic use.
- **Required Preprocessing**: Flow mapping via `src/normalization/bot_iot_adapter.py`. Extract outbound byte ratios. Map Data Exfiltration labels to `EXFILTRATION`.

## 4. Alternate Validation (General)
- **Dataset**: UNSW-NB15
- **Official Source**: UNSW Canberra Cyber
- **Relevant Attack Categories**: Reconnaissance, DoS, Exploits
- **Expected Format**: `data/raw/unsw_nb15/` containing CSVs.
- **Approximate Size**: ~500 MB (CSVs)
- **Detector(s) Validated**: DDoS, Reconnaissance (Fallback/Supplemental)
- **License/Usage Notes**: Academic use.
- **Required Preprocessing**: Flow mapping via `src/normalization/unsw_nb15_adapter.py`.

## 5. DGA / DNS Tunnelling Validation
- **Dataset**: UMUDGA (University of Murcia DGA Dataset) or similar public DGA dataset.
- **Official Source**: https://osf.io/2q7f9/
- **Relevant Attack Categories**: DGA, DNS Tunnelling
- **Expected Format**: `data/raw/dns_dga/` containing domains and labels.
- **Approximate Size**: ~200 MB
- **Detector(s) Validated**: DGA/DNS Anomaly Detector
- **License/Usage Notes**: Academic use.
- **Required Preprocessing**: Convert domain lists into synthetic DNS `Flow` objects via `src/normalization/dns_dga_adapter.py`. Label as `DNS_DGA`.

## 6. Encrypted Traffic Validation
- **Dataset**: CIC-Darknet2020 or MTA-KDD'19
- **Official Source**: UNB CIC / MTA
- **Relevant Attack Categories**: Malware over TLS, Tor
- **Expected Format**: `data/raw/encrypted/` containing CSVs with TLS features.
- **Approximate Size**: ~1 GB
- **Detector(s) Validated**: Encrypted Traffic Detector
- **License/Usage Notes**: Academic use.
- **Required Preprocessing**: Map TLS metadata (SNI, cipher suites, packet lengths) to `Flow` via `src/normalization/encrypted_adapter.py`. Label as `ENCRYPTED_ANOMALY`.

## Label Normalization Strategy
All adapters map external dataset labels to the following canonical set to prevent data leakage and standardise the evaluation pipeline:
- `NORMAL`
- `DDOS`
- `C2_BEACON`
- `RECONNAISSANCE`
- `EXFILTRATION`
- `DNS_DGA`
- `ENCRYPTED_ANOMALY`

Labels are kept strictly in `original_label` and `normalized_label` attributes and are NEVER used by `FeaturePipeline` or any `Detector`.
