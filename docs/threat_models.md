# UniShield AI — Threat Models

> **Phase 3 | Status: DDoS Detector Complete**
> Documents the detection methodology for all planned detectors.

---

## Architecture Overview

```
PCAP / Network Mirror
        ↓ (read-only)
   PcapReader / Zeek Adapter
        ↓
   NetworkEvent (Pydantic)
        ↓
   FlowManager + Sessionizer
        ↓
   FlowRecord
        ↓
   FeaturePipeline
        ↓
   FeatureVector ──────────────────────────┐
        ↓                                  │
   DDoSDetector (Phase 3) ◄───────────────┘
   [C2 Detector]     (Phase 4 — planned)
   [DGA Detector]    (Phase 4 — planned)
   [Recon Detector]  (Phase 4 — planned)
   [Exfil Detector]  (Phase 4 — planned)
        ↓
   DetectionResult
        ↓
   AlertManager (deduplication)
        ↓
   Alert → Dashboard / Report
```

**Invariant:** No component in this pipeline transmits packets or
initiates network activity. Everything is read-only from the mirror.

---

## Threat 1: DDoS — Implemented ✅

### Overview

Detects Distributed Denial-of-Service patterns using multi-signal
statistical analysis of passively observed network metadata.

### Sub-types Detected

| Sub-type | Description |
|----------|-------------|
| `TCP_SYN_Flood` | High SYN ratio, elevated SYN rate vs baseline |
| `UDP_Volumetric` | High UDP packet/byte rate vs baseline |
| `Traffic_Rate_Anomaly` | Overall packet/byte rate anomaly |
| `Distributed_Source_Flood` | Abnormal source IP cardinality/entropy |

### Detection Methodology

#### Phase 1: Baseline Estimation (EWMA)

The system maintains an Exponentially Weighted Moving Average (EWMA)
for each traffic metric:

```
EWMA_new = EWMA_old + α × (observation - EWMA_old)
```

where `α = 0.15` (configurable). This gives more weight to recent
observations while smoothing transient spikes.

Metrics tracked:
- `packets_per_second`
- `bytes_per_second`
- `syn_per_second`
- `udp_per_second`

#### Phase 2: Z-score Anomaly Detection

For each metric, the z-score measures how many standard deviations
the current observation is above the EWMA mean:

```
z = (observed - baseline_mean) / baseline_std
```

A z-score > 3.0 is flagged as anomalous. This is configurable in
`config/thresholds.yaml`.

> **Limitation (documented):** When the EWMA has not yet warmed up
> (< 500 observations), only absolute threshold checks are applied.
> This "cold-start problem" means early detection is less sensitive.

#### Phase 3: Sub-detector Scoring

Four independent sub-detectors each produce a score in [0, 1]:

| Sub-detector | Score Source | Weight |
|-------------|--------------|--------|
| `RateAnomalyDetector` | pps/bps z-score vs EWMA | 0.30 |
| `SYNFloodDetector` | SYN ratio, SYN rate, SYN-only ratio | 0.30 |
| `UDPFloodDetector` | UDP rate z-score, large packet patterns | 0.20 |
| `SourceAnomalyDetector` | Source cardinality, entropy, concentration | 0.20 |

Weights sum to 1.0 and are configurable in `config/thresholds.yaml`.

#### Phase 4: Weighted Score Fusion

```
final_score = 0.30 × rate_score
            + 0.30 × syn_score
            + 0.20 × udp_score
            + 0.20 × source_score
```

#### Phase 5: Confidence Estimation

Confidence reflects **agreement between independent signals**, NOT
calibrated probability:

```
strong_signals = count(sub_score > 0.5)

if strong_signals >= 3: confidence = 0.50 + 0.15 × strong_signals
elif strong_signals == 2: confidence = mean(contributing) × 0.85
elif strong_signals == 1: confidence = max_score × 0.60
else: confidence = max_score × 0.40
```

> This is a heuristic. It has NOT been statistically calibrated
> against a labelled dataset. Confidence values should be interpreted
> as relative indicators, not probability estimates.

#### Phase 6: Severity Mapping

| Score Range | Severity |
|-------------|----------|
| ≥ 0.88 | CRITICAL |
| ≥ 0.70 | HIGH |
| ≥ 0.50 | MEDIUM |
| ≥ 0.30 | LOW |

### Evidence Format

Every alert includes explicit evidence items. Example:

```json
{
  "feature": "packets_per_second",
  "observed": 18500.0,
  "baseline": 1230.0,
  "deviation": 14.97,
  "score": 0.91,
  "detector": "RateAnomaly",
  "reason": "Packet rate is 14.97 standard deviations above baseline
             (1230.0 pkt/s). This is consistent with a volumetric
             traffic flood."
}
```

### Spoofing and Reflection Language Policy

The detector uses careful, hedged language:

| ❌ Prohibited | ✅ Required |
|--------------|------------|
| "Source IP is spoofed" | "High source-IP diversity is consistent with spoofed-source flood behavior" |
| "Handshake failed" | "Handshake completion cannot be confirmed in unidirectional monitoring" |
| "Confirmed amplification" | "UDP reflection/amplification indicator (cannot be confirmed without bidirectional visibility)" |

### Documented Limitations

1. **One-way visibility**: Cannot confirm TCP handshake completion or failure.
2. **No spoofing proof**: Source IP entropy consistent with spoofing ≠ proof of spoofing.
3. **No reflection proof**: Cannot confirm UDP amplification without seeing requests.
4. **Cold-start baseline**: First 500 events use less sensitive absolute thresholds.
5. **Low-and-slow attacks**: Volume-based detector will miss attacks below threshold.
6. **Encrypted traffic**: Cannot distinguish DDoS from encrypted legitimate bulk transfer.
7. **Legitimate spikes**: CDN prefetch, software updates, and backup jobs can produce
   similar patterns. Use in context with other signals.
8. **Single-signal confidence**: A single elevated signal produces low confidence.
   Alerts below 0.50 confidence are suppressed.

### Alert Deduplication

- Same (threat_class, sub_type, source_ip, destination_ip) key
- Within 30-second window → alerts are merged (event_count incremented)
- After 30s of inactivity → alert expires

### Configuration Reference

All thresholds in `config/thresholds.yaml` under `ddos:`:

| Key | Default | Description |
|-----|---------|-------------|
| `baseline.ewma_alpha` | 0.15 | EWMA smoothing factor |
| `baseline.warmup_packets` | 500 | Events before baseline is trusted |
| `rate.pps_z_score_alert` | 3.0 | Z-score threshold for PPS anomaly |
| `rate.pps_absolute_min` | 2000 | Minimum PPS before checking z-score |
| `syn_flood.syn_ratio_threshold` | 0.80 | SYN ratio to flag |
| `syn_flood.syn_pps_absolute_min` | 500 | Min SYN/s to flag |
| `udp_flood.udp_pps_absolute_min` | 1000 | Min UDP PPS to flag |
| `source.uniq_src_high_threshold` | 100 | Unique source IP count |
| `deduplication.window_seconds` | 30 | Alert dedup window |
| `min_score_to_alert` | 0.35 | Score floor for alerting |
| `min_confidence_to_alert` | 0.50 | Confidence floor for alerting |

---

## Threat 2: C2 Beaconing — Implemented ✅

### Overview

Detects Command-and-Control (C2) beaconing patterns using cross-flow
statistical analysis of passively observed network metadata.

Unlike DDoS (which can be detected from a single flow), C2 detection
requires observing a **sequence of flows over time** between the same
source-destination pair.

### Sub-types Detected

| Sub-type | Description |
|----------|-------------|
| `Periodic_Beacon` | Regular inter-connection intervals (low CV) |
| `Repeated_Destination` | Many connections to same (dst_ip, dst_port) |
| `Consistent_Payload` | Uniform per-connection byte counts |

### Detection Methodology

#### Cross-Flow State: BeaconTracker

The `BeaconTracker` maintains a `BeaconState` per `(src_ip, dst_ip, dst_port)` tuple.

Each call to `C2BeaconDetector.detect(fv)`:
1. Records the connection in BeaconTracker
2. Once `min_flows_for_analysis` (default: 5) connections are seen → computes `BeaconFeatures`
3. Scores each sub-detector
4. Fuses scores

#### Periodicity Algorithm

**Inter-Connection Intervals (ICI)**: Time gaps between consecutive connections
to the same (dst_ip, dst_port).

**Coefficient of Variation (CV)**:
```
CV = std(ICI) / mean(ICI)
```

**Periodicity Score**:
```
s_periodicity = max(0, 1 - CV / cv_random_threshold)
```
where `cv_random_threshold = 0.60` (configurable).

| CV | Interpretation | Score |
|----|----------------|-------|
| 0.00 | Perfect periodicity | 1.00 |
| 0.15 | Highly regular | 0.75 |
| 0.30 | Low jitter | 0.50 |
| 0.60 | Random boundary | 0.00 |
| >0.60 | Random traffic | 0.00 |

**Jitter Tolerance**: CV=0.30 still scores 0.50. C2 malware adding ±30%
jitter does not evade detection.

#### Destination Repetition Score

```
s_dst = n / (n + half_point)
```
where `n` = connection count, `half_point` = 30 (produces 0.50 at n=30).

Asymptotic formula: score approaches 1.0 as connections accumulate.
Never claims the destination is malicious — only that repeated targeting
is observed.

#### Size Consistency Score

```
s_size = max(0, 1 - byte_CV / byte_cv_high)
```
where `byte_CV = std(bytes_per_conn) / mean(bytes_per_conn)`.

#### Behavioral Anomaly Score

Scores how focused the source is on one destination:
```
s_focus = 1 / unique_destination_count
```
Only suspicious when unique_dst_count ≤ 3.

#### Weighted Score Fusion

| Component | Weight |
|-----------|--------|
| Periodicity | 0.40 |
| Destination repeat | 0.25 |
| Size consistency | 0.20 |
| Behavioral anomaly | 0.15 |

#### Confidence

Based on count of sub-detectors with score > 0.50:
- 3+ strong: `0.55 + 0.15 × n`
- 2 strong: `mean(contributing) × 0.85`
- 1 strong: `max_score × 0.65`
- 0 strong: `max_score × 0.35`

Heuristic — NOT statistically calibrated.

### Optional ML: Isolation Forest

An optional `C2IsolationForest` component (13-feature vector) is available:
- Disabled by default (`ml.enabled: false`)
- Must be trained on labelled data before use
- When enabled, averages 50/50 with statistical score
- No synthetic accuracy claims

**Expected training dataset**: CTU-13 (botnet capture) or similar.
**Expected format**: PCAP → flows → FeatureVectors → BeaconFeatures (13 floats)

### Evidence Language Policy

| ❌ Prohibited | ✅ Required |
|--------------|------------|
| "Confirmed C2" | "Consistent with C2 beaconing" |
| "Malware detected" | "This pattern is consistent with automated/scripted communication" |
| "C2 server at IP" | "Repeated targeting of endpoint X:Y observed" |

### Documented Limitations

1. **Cold start**: Requires min_flows (5) connections before scoring.
2. **Jitter evasion**: CV > 0.60 will evade CV-based detection.
3. **Legitimate periodic apps**: NTP, monitoring agents, health checks all beacon.
4. **Port hopping**: If malware changes destination port, tracker key won't accumulate.
5. **Domain fronting**: CDN IP ≠ actual C2 server. Destination IP is not reliable.
6. **Low-and-slow beaconing**: Very infrequent beacons may have intervals above max_sec.
7. **Cannot confirm C2**: Detecting the PATTERN, not the malware itself.

### Configuration Reference

All thresholds in `config/thresholds.yaml` under `c2_beacon:`:

| Key | Default | Description |
|-----|---------|-------------|
| `min_flows_for_analysis` | 5 | Minimum connections before scoring |
| `interval.min_sec` | 5 | Minimum ICI to consider |
| `interval.max_sec` | 7200 | Maximum ICI to consider |
| `periodicity.cv_random_threshold` | 0.60 | CV above = random |
| `destination.high_repeat_count` | 30 | Connections for strong signal |
| `deduplication.window_seconds` | 300 | Alert dedup window (5 min) |
| `ml.enabled` | false | ML scoring (requires training) |

---



## Threat 3: DGA & DNS Tunnelling — Implemented ✅

### Overview

Detects Domain Generation Algorithm (DGA) and DNS Tunnelling activity purely from passively observed DNS metadata (query names, lengths, frequencies).

### DGA Detection Methodology

Focuses on the lexical properties of individual domains:

- **Lexical Entropy**: Shannon entropy of the domain characters. High entropy (>4.2) indicates randomness.
- **N-gram Entropy**: Measures randomness of character trigrams.
- **Structural Anomalies**:
  - Unusually long queries (>35 chars).
  - High digit ratio (>0.30).
  - High unique character count.

#### DGA Score Fusion
`final_score = (lexical_score * 0.60) + (structural_score * 0.40)`

### DNS Tunnelling Methodology

Focuses on the behavioral properties of a source IP over time (e.g. 5 minutes). Uses the `DNSTracker` state accumulator.

- **Volume Anomaly**: High sustained query rate.
- **Payload Anomaly**: High average query length and entropy across the window.
- **Subdomain Churn**: High ratio of unique queries to total queries (bypassing caches).
- **Record Type**: Unusual concentration of TXT or NULL records.

#### Tunnelling Score Fusion
`final_score = (vol * 0.25) + (payload * 0.35) + (churn * 0.25) + (record * 0.15)`

### ML Component (DGA Random Forest)
- **Status**: Implemented, disabled by default.
- **Training**: Provided `dga_train.py` can train a model using 7 extracted numeric features.
- **Integration**: Averages 50/50 with statistical score when enabled.

### Documented Limitations
1. **Encrypted DNS**: Cannot analyze DoH or DoT unless decrypted upstream.
2. **Dictionary DGAs**: Lexical entropy may miss dictionary-based algorithms.
3. **Legitimate Tunnels**: Antivirus and some telemetry tools use TXT/DNS tunnelling benignly.
4. **No active resolution**: Cannot confirm if the domain resolves to a malicious IP.
5. **Cold-start**: Tunnelling requires observing multiple queries (default >20) before scoring.

## Threat 5: Network Reconnaissance & Port Scanning — Implemented ✅

### Overview
Detects suspicious network discovery behavior (horizontal scans, vertical scans, network sweeps, host sweeps, and SYN scanning) using exclusively passive traffic metadata.

**Crucial Constraint**: The detector explicitly assumes one-directional visibility. It does NOT assert that a port scan "failed" or a port was "closed", but rather flags "reconnaissance-like indicators" based on traffic sent by the source.

### Detection Methodology
The Reconnaissance detector processes flow metadata grouped by Source IP over multiple sliding windows (e.g., 10s, 30s, 60s) to detect both fast scans and low-and-slow behaviors.

It evaluates the following mutually exclusive scan classifications:
1. **Vertical Port Scan**: Single source communicating with many distinct ports on a very small number of destination hosts.
2. **Horizontal Port Scan**: Single source communicating with a large number of destination hosts over a concentrated set of ports (e.g., searching for Port 22 across the network).
3. **Network Sweep**: Source communicating across many distinct subnets (e.g., IPv4 /24 bounds).
4. **Host Sweep**: Source contacting a large number of unique host-port combinations, indicating broad infrastructure mapping.
5. **SYN Recon**: Traffic heavily dominated by TCP SYN packets without completed handshakes, corroborating scanning intent.

### Scoring & Confidence
- **Score Formulation**: Normalised by the fan-out magnitude (e.g., `min(1.0, observed_ports / (threshold * 3))`).
- **Confidence Layering**: Starts at a baseline confidence when fanout crosses the threshold, and increments by +0.10 if corroborating SYN-heavy behavior is observed.

### Documented Limitations
1. **Passive Ambiguity**: A vulnerability scanner and a threat actor both appear identically in passive telemetry. Detection output is hedged as "reconnaissance-like behavior" unless correlated with other active threat detections (like C2 or DDoS).
2. **Cardinality Bound**: Uses memory-efficient `set()` structures bounded by window expirations. Extremely large, distributed scans spanning hours may fall under the window thresholds but will be captured in behavioral baselines if prolonged.

---

## Threat 6: Encrypted Session Anomaly — Implemented ✅

### Overview
Detects suspicious patterns inside encrypted sessions (TLS/QUIC) strictly via passively observed metadata and SPLT (Sequence of Packet Lengths and Times).

**Crucial Constraint**: The detector explicitly assumes NO access to payload contents. It does not perform TLS decryption, MITM, or QUIC payload analysis.

### Detection Methodology
Because encrypted threats (such as C2 beacons over HTTPS or malware staging) closely resemble benign traffic, this detector relies primarily on an ML component (`EncryptedSessionModel`).

1. **SPLT (Sequence of Packet Lengths and Times)**: Captures the first N (default: 20) packet sizes and inter-arrival times. This structural fingerprint allows the ML model to differentiate between browsing, video streaming, and automated malware.
2. **Volumetric Statistics**: Incorporates standard packet size CV, duration, and bytes.
3. **TLS Cleartext Indicators**: Considers SNI presence, TLS version, and JA3 fingerprints extracted directly from the handshake.

### Metadata Quality Score
To avoid generating high-confidence alerts on traffic lacking sufficient metadata (e.g., very short flows or ECH/QUIC flows hiding SNI), a separate `metadata_quality_score` [0.0 - 1.0] is calculated.

`Confidence = ML_Score * Metadata_Quality`

If the metadata quality is low, even an anomalous flow will result in suppressed confidence.

### Documented Limitations
1. **No Payload Proof**: Cannot confirm the exact malware family or stolen data, only that the structural pattern matches known malicious profiles.
2. **Encrypted Client Hello (ECH)**: ECH prevents SNI visibility, which naturally degrades the `metadata_quality_score` and suppresses confidence.
3. **Model Dependency**: Requires training on a high-quality dataset (e.g., CIC-Darknet2020) to maintain low false-positive rates. The default shipped model in `dga_train.py` is trained on synthetic data for pipeline verification ONLY.
4. **Short Flows**: Flows under 5 packets are unlikely to generate a strong SPLT fingerprint.

---

## Threat 7: Data Exfiltration — Implemented ✅

### Overview
Detects outbound traffic behavior consistent with potential data exfiltration by analyzing host-level baseline deviations, destination novelty, volume spikes (bursts), and low-and-slow sustained anomalies. 

**Crucial Constraint**: The detector explicitly cannot inspect payload contents, files, or decrypt traffic. It cannot confirm exact data stolen, but identifies suspicious structural anomalies.

### Detection Methodology
We utilize a `HostBaselineTracker` to calculate moving averages for daily outbound volume and maintain a rolling list of historically known destinations for each internal source host.

1. **Host Baseline Status**: Hosts enter `BASELINE_WARMING` then `BASELINE_AVAILABLE` after observing a sufficient number of baseline flows (e.g., 50). Poor baselines suppress confidence automatically.
2. **Burst Anomaly**: High outbound byte volume in a small window (60s) that drastically exceeds the historical per-minute average of the host.
3. **Low-and-Slow (Sustained Anomaly)**: Tracks cumulative daily bytes and triggers if it deviates beyond a `sustained_multiplier` (e.g. 3x normal average daily transfer).
4. **Destination Novelty**: Determines if the destination IP is previously unseen for that source, augmenting suspicion.

### Scoring & Evidence
- **Scoring**: Base score is derived from burst volume presence. Additional score is dynamically added based on deviation intensity (e.g., burst rate deviation, sustained rate deviation) and destination novelty.
- **Evidence Fencing**: Legitimate heavy transfers (like scheduled cloud backups) naturally factor into the EMA (Exponential Moving Average) baseline, raising the expected daily volume threshold over time, allowing the detector to suppress future alerts to the known backup destination.

### Documented Limitations
1. **Blind Asymmetry**: While directional `outbound_bytes` vs `inbound_bytes` would be ideal, many PCAP parsers only provide a unidirectional flow record `byte_count`. We model this using strict source->destination traffic accumulation.
2. **No Payload Proof**: We cannot confirm what data was sent, only that a large or unusual transfer occurred.
3. **Initial False Positives**: Until a host reaches `BASELINE_AVAILABLE`, heavy legitimate transfers might trigger low-confidence alerts due to cold-start limits.
