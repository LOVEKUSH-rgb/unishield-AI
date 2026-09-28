# Phase 32: Evaluation Audit

## 1. Dataset Inventory
The current evaluation corpus relies entirely on `data/samples/demo_flows_expanded.jsonl`, generating 10,000 synthetic flows. While this guarantees clean labels, it lacks the true stochastic noise (e.g., retransmissions, out-of-order packets, complex session interleaving) seen in real-world pcaps like CIC-IDS2017.

## 2. Ground-Truth Methodology
Ground truth is currently assigned via rigid, deterministic IP address matching inside `scripts/evaluate_detectors.py` (e.g., `if source_ip == "192.168.1.50"...`). This is 100% deterministic but tightly couples the evaluator to the specific synthetic generation script.

## 3. Detector Coverage
All 6 detectors are executed. However, C2 Beacon and DDoS exhibited 0% recall due to mathematical threshold requirements (e.g., C2 requires >20 connections, DDoS skips 0-duration flows). 

## 4. ML Coverage
ML models (DNS DGA Random Forest, Encrypted Session XGBoost) are loaded if they exist. The evaluation successfully exercises the ML predict paths. 

## 5. Statistical Fallback Coverage
**WEAKNESS IDENTIFIED**: The current evaluation script (`scripts/evaluate_detectors.py`) invokes `detector.detect(fv)`. This method automatically uses ML if available. As a result, the statistical fallback mechanisms for DNS DGA and Encrypted Anomaly are **NOT** being evaluated at all if a model is present. The scores conflate ML and statistical performance.

## 6. Potential Leakage Risks
No leakage. `demo_flows_expanded.jsonl` was generated independently from the ML training sets (`dga_dataset.csv`, `encrypted_dataset.csv`). Domains and IPs do not overlap with training distributions.

## 7. Evaluation Weaknesses
- **Conflation of Modes**: Cannot measure ML and statistical accuracy independently.
- **Latency Measurement**: Latency is measured directly around the `detect(fv)` call. This excludes the `FeatureVector` instantiation, normalization, flow aggregation, and API serialization overhead.
- **Zero-Duration Overrepresentation**: 6,600 out of 10,000 flows (66%) are 0-duration, single-packet flows used to simulate a highly distributed SYN flood. This severely punishes rate-based detectors.
- **Explainability**: The Phase 31 script calculates TP/FP/TN/FN counters but drops the `DetectionResult.evidence` list, making it impossible to audit *why* a specific False Positive or False Negative occurred.

## 8. Reproducibility Assessment
The evaluation is perfectly reproducible offline, provided `demo_flows_expanded.jsonl` exists. It uses no external network dependencies and no non-deterministic randomness.

## 9. Recommendations
1. Build a new `benchmark_detectors.py` that accepts a `--mode [ml|statistical]` flag to force statistical testing even when ML artifacts are present.
2. Log `evidence` strings to disk for offline error analysis.
3. Investigate the 0-duration logic in `ddos.py` to handle highly distributed single-packet SYN floods.
4. Add a benchmark for the full pipeline (`benchmark_pipeline.py`), not just the math functions, to measure true P99 throughput.

## 10. INSUFFICIENT DATA
- **Statistical Fallback Accuracy**: INSUFFICIENT DATA. (Currently unmeasured for DGA and Encrypted Session).
- **End-to-End Pipeline Latency**: INSUFFICIENT DATA. (Currently only measuring pure inference logic).
- **Edge Case Robustness**: INSUFFICIENT DATA. (The synthetic demo dataset is too clean; it lacks malformed fields, missing IP addresses, and extreme statistical outliers).
