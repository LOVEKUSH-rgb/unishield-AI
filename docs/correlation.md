# Phase 9: Cross-Threat Correlation

The Cross-Threat Correlation Engine is responsible for consuming independent `DetectionResult` outputs from the various Phase 3-8 detectors and logically merging them into unified `Incident` records. It operates purely on deterministic rules without relying on machine learning.

## Correlation Philosophy
A single alert (e.g. Reconnaissance) may be benign or non-actionable on its own. However, if the same source host performs Reconnaissance, then exhibits DGA-like DNS behavior, and then begins C2 beaconing to the resolved IP within a short time window, the probability of a genuine threat increases drastically.

The correlation engine aims to group these alerts together by generating a `correlation_strength` score between `[0.0 - 1.0]`. If this score exceeds a configurable `merge_threshold`, the new alert is merged into the existing incident.

## Correlation Algorithm
The deterministic algorithm computes a score based on four dimensions:

1. **Source Match (Weight: 0.35)**: Evaluates if the alert shares a source IP with the incident.
2. **Destination Match (Weight: 0.30)**: Evaluates if the alert shares a destination IP with the incident.
3. **Time Proximity (Weight: 0.20)**: Evaluates the time delta between the alert and the incident's `last_seen` timestamp. The score is `1.0` if within 5 minutes, and linearly decays to `0.0` as it approaches the `correlation_window_seconds` (default 1 hour).
4. **Sequence / Behavioral Match (Weight: 0.15)**: Evaluates if the new alert's `threat_class` logically follows the incident's existing threats according to a predefined `detector_progression` map (e.g. `Recon -> DNS_DGA -> C2_Beacon -> EncryptedAnomaly -> Exfiltration`).

### Incident Creation vs Merging
When an alert is processed:
- If the calculated `correlation_strength` against any active incident is `>= merge_threshold` (e.g. `0.60`), the alert is appended to that incident.
- If no incident meets the threshold, a new Incident is spawned with a unique `INC-YYYY-XXXXXX` identifier.

### Multi-Host Correlation
If two different internal hosts exhibit suspicious behavior toward the *exact same malicious destination* in a *short time window*, the engine will evaluate them. To prevent aggressively merging unrelated alerts from different hosts, the algorithm requires the correlation score to exceed a stricter `multi_host_threshold` (e.g. `0.85`). If merged, the incident is flagged as "potential coordinated activity."

### Deduplication
To prevent a single aggressive C2 beacon from generating thousands of incidents, the engine enforces a `deduplication_window_seconds` (default 5 minutes). If an alert has the identical `threat_class`, `source_ip`, and `destination_ip` as a recent alert inside an incident, it updates the incident's `last_seen` timestamp but is not appended as a distinct alert object, preserving memory.

## Incident Schema Output
The engine produces incidents in the following format:
```json
{
  "incident_id": "INC-2026-000001",
  "status": "NEW",
  "first_seen": "2026-08-28T10:00:00+00:00",
  "last_seen": "2026-08-28T10:15:00+00:00",
  "sources": ["10.0.0.1"],
  "destinations": ["1.1.1.1"],
  "alerts": ["mock-id-1", "mock-id-2", "mock-id-3"],
  "detectors": ["Reconnaissance", "DNS_DGA", "C2_Beacon", "Exfiltration"],
  "potential_progression": ["Reconnaissance", "DNS_DGA", "C2_Beacon", "Exfiltration"],
  "correlation_strength": 1.0,
  "explanation": "Suspicious observations associated with a single source occurred within a correlated time window. The observations include: Reconnaissance, DNS_DGA, C2_Beacon, Exfiltration."
}
```

## Passive-Only Compliance
- `[PASS]` The engine relies strictly on pre-computed `DetectionResult` objects. It does not initiate external HTTP requests, probe destinations, or perform reverse DNS lookups to verify correlations. All rules are evaluated entirely offline.
