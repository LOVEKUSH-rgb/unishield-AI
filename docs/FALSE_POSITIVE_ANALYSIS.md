# False-Positive Analysis Report

This document categorizes common false positives encountered during the initial validation of the UniShield AI detectors, alongside the structural improvements planned for Phase 13 to mitigate them.

## 1. High Traffic but Legitimate (DDoS False Positives)
**Observation:** Sudden bursts of legitimate traffic (e.g., fetching a large file from a CDN, or many concurrent users connecting simultaneously) trigger the volumetric DDoS thresholds.
**Metadata Context:**
- High `packet_rate` and `byte_rate`.
- Source IP is a known CDN (e.g., Cloudflare/AWS) or traffic is well-distributed.
**Mitigation Strategy:**
- Move away from simple rate thresholds (`pps_z_score_alert`).
- Require **temporal aggregation** + **source concentration** (e.g., one IP or a small subnet sending huge traffic) + **protocol anomalies** (high SYN ratio) to build strong DDoS confidence.

## 2. Periodic Legitimate Services (C2 Beacon False Positives)
**Observation:** Legitimate software telemetry, NTP (Network Time Protocol) syncs, or background cloud syncs trigger C2 Beaconing alerts because they connect on a fixed interval.
**Metadata Context:**
- Extremely consistent inter-arrival times (low Coefficient of Variation - CV).
- Destination is often a known public service (e.g., `time.windows.com` or `telemetry.microsoft.com`).
**Mitigation Strategy:**
- Do not rely solely on periodicity.
- Increase the minimum observation count (`min_flows_for_analysis` and `low_repeat_count`) so 5-10 quick syncs don't fire an alert.
- Reduce confidence for perfectly periodic traffic (CV ≈ 0) on standard ports if the destination is diverse. 
- Calibrate the beacon score to blend periodicity, destination consistency, and *time duration* (beacons must persist over a long window).

## 3. DNS-Heavy Legitimate Applications (DGA/Tunnelling False Positives)
**Observation:** Applications querying long, random-looking CDNs or cryptographic domain validations trigger DGA alerts due to high Shannon entropy.
**Metadata Context:**
- High entropy in the domain string (e.g., `xn--...` or `cdn-1234abcd...`).
- Legitimate record types (A, AAAA).
**Mitigation Strategy:**
- Do not use `"high entropy = malicious"` as the only rule.
- Blend lexical anomalies (entropy, digit ratio, length) with behavioral features (subdomain churn, TXT/NULL record ratios).

## 4. Large Legitimate Data Transfers (Exfiltration False Positives)
**Observation:** Legitimate database backups, large file uploads, or cloud syncs trigger data exfiltration alerts.
**Metadata Context:**
- Very high outbound byte volume.
- High `asymmetry_ratio` (outbound bytes >> inbound bytes).
**Mitigation Strategy:**
- Compare against historical host behavior (sustained deviation).
- Ensure the alert specifies that it detected an "anomalous upload," noting that without payload inspection, administrative syncs can mimic exfiltration.

## 5. Normal Administrative Scanning (Recon False Positives)
**Observation:** Vulnerability scanners (e.g., Nessus), asset discovery tools, or monitoring systems sweep the network and trigger horizontal/vertical scan alerts.
**Metadata Context:**
- High `unique_dst_ips` or `unique_dst_ports`.
- High SYN counts.
**Mitigation Strategy:**
- Improve temporal aggregation (don't alert on 50 unique ports if spread over 2 hours unless strictly tuned).
- Increase the default thresholds for horizontal sweeps (e.g., `horizontal.min_hosts`).

## 6. Encrypted High-Volume Services (Encrypted Anomaly False Positives)
**Observation:** Video streaming or heavy TLS-encrypted web-sockets trigger encrypted anomaly alerts due to sustained, varied packet sizes.
**Metadata Context:**
- Payload variance is high.
- Long flow durations.
**Mitigation Strategy:**
- Tune the standard deviation thresholds (`pkt_size_std_threshold_low` and `high`).
- Clearly distinguish the alert language as "Encrypted Traffic Anomaly" rather than "Confirmed Malware."
