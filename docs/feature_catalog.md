# UniShield AI — Feature Catalog

> **Phase 2 | Status: Complete**
> This catalog documents every feature produced by the Phase 2 feature engine.
> Features are **observations only** — no classification is performed here.

---

## Feature Scopes

| Scope | Meaning |
|-------|---------|
| **Flow** | Computed once per completed FlowRecord |
| **Per-Source** | Aggregated over a time window for one source IP |
| **Per-Destination** | Aggregated over a time window for one destination IP |
| **Query** | Computed per individual DNS query/response |

---

## 1. Flow Features (`flow_features.py`)

Scope: **Flow** | Source: `FlowRecord` | Extractor: `extract_flow_features()`

| Feature | Unit | Description | Applicable Detectors |
|---------|------|-------------|----------------------|
| `packet_count` | count | Total packets observed | DDoS, Recon, C2, Exfil |
| `byte_count` | bytes | Total bytes observed | DDoS, Exfil |
| `flow_duration` | seconds | Time from first to last packet in flow | Recon, C2, Exfil, Encrypted |
| `splt_sizes` | list[float] | Sequence of Packet Lengths up to bounded length | Encrypted |
| `splt_times` | list[float] | Sequence of Inter-Arrival Times up to bounded length | Encrypted |
| `start_time` | epoch | First packet timestamp | All |
| `last_seen` | epoch | Last packet timestamp | All |
| `packets_per_second` | pkt/s | Packet rate (None if single-packet) | DDoS, C2 |
| `bytes_per_second` | B/s | Byte rate | DDoS, Exfil |
| `pkt_size_min` | bytes | Minimum packet length | C2, DPI-evasion |
| `pkt_size_max` | bytes | Maximum packet length | Exfil |
| `pkt_size_mean` | bytes | Mean packet length | All |
| `pkt_size_median` | bytes | Median packet length | C2 |
| `pkt_size_std` | bytes | Standard deviation of packet sizes | C2, Exfil |
| `pkt_size_variance` | bytes² | Variance of packet sizes | C2 |
| `pkt_size_cv` | dimensionless | Coefficient of variation of packet sizes | C2 |
| `tcp_syn_count` | count | Number of SYN packets | Recon, DDoS |
| `tcp_syn_ack_count` | count | Number of SYN-ACK packets | Recon |
| `tcp_ack_count` | count | Number of ACK-only packets | DDoS |
| `tcp_fin_count` | count | Number of FIN packets | C2 |
| `tcp_rst_count` | count | Number of RST packets | Recon, DDoS |
| `bytes_out` | bytes | Number of outbound payload bytes (optional) | Exfil |
| `bytes_in` | bytes | Number of inbound payload bytes (optional) | Exfil |
| `tcp_psh_count` | count | Number of PSH packets | Exfil |
| `tcp_urg_count` | count | Number of URG packets | Anomaly |
| `tcp_syn_ratio` | [0, 1] | Fraction of packets that are SYN | Recon, DDoS |
| `tcp_fin_ratio` | [0, 1] | Fraction of packets that are FIN | C2 |
| `tcp_rst_ratio` | [0, 1] | Fraction of packets that are RST | Recon, DDoS |
| `tcp_ack_ratio` | [0, 1] | Fraction of packets that are ACK-only | DDoS |
| `tcp_syn_only_ratio` | [0, 1] | SYN/(SYN+SYN-ACK) — unanswered SYN ratio | Recon, DDoS |
| `protocol` | int | IP protocol number (6=TCP, 17=UDP, 1=ICMP) | All |
| `flow_completed` | {0,1} | 1 if FIN or RST was observed | All |

---

## 2. Timing Features (`timing_features.py`)

Scope: **Flow** | Source: `FlowRecord.inter_arrival_times` | Extractor: `extract_timing_features()`

| Feature | Unit | Description | Applicable Detectors |
|---------|------|-------------|----------------------|
| `iat_mean` | seconds | Mean inter-arrival time | C2, Exfil |
| `iat_median` | seconds | Median IAT (robust to outliers) | C2 |
| `iat_std` | seconds | Standard deviation of IAT | C2, Exfil |
| `iat_min` | seconds | Minimum IAT | DDoS |
| `iat_max` | seconds | Maximum IAT | C2, Exfil |
| `iat_cv` | dimensionless | CV = std/mean (low → regular timing) | C2 |
| `iat_periodicity` | [0, 1] | Lag-1 autocorrelation normalised to [0,1] | C2 |
| `iat_jitter` | seconds | Mean absolute deviation from mean IAT | C2 |
| `iat_sample_count` | count | Number of IAT samples available | All |

> **Note**: `iat_periodicity ~ 1.0` means regular/periodic timing. This is a **feature**, not a classification. C2 beaconing produces periodic IAT, but so does legitimate heartbeat traffic.

---

## 3. Entropy Features (`entropy_features.py`)

Scope: **Shared library** | Consumed by: dns_features, behavioral_features

| Function | Output | Description |
|----------|--------|-------------|
| `shannon_entropy(values)` | bits | H = -Σ p·log₂(p) |
| `string_entropy(text)` | bits | Character distribution entropy |
| `normalised_entropy(values)` | [0, 1] | H / log₂(n\_unique) |
| `ip_set_entropy(ip_list)` | bits | Entropy of IP address distribution |
| `ngram_frequencies(text, n)` | dict | Count of all n-grams |
| `ngram_entropy(text, n)` | bits | Entropy of n-gram distribution |

---

## 4. DNS Features (`dns_features.py`)

Scope: **Query** | Source: `DNSInfo` | Extractor: `extract_dns_features()`

| Feature | Unit | Description | Applicable Detectors |
|---------|------|-------------|----------------------|
| `dns_is_query` | {0,1} | 1 if DNS query, 0 if response | DGA |
| `dns_query_length` | chars | Total character length of FQDN | DGA |
| `dns_label_count` | count | Number of dot-separated labels | DGA, Tunnel |
| `dns_max_label_length` | chars | Longest label length | DGA, Tunnel |
| `dns_digit_ratio` | [0, 1] | Fraction of digits in FQDN | DGA |
| `dns_alpha_ratio` | [0, 1] | Fraction of alphabetic chars | DGA |
| `dns_hyphen_ratio` | [0, 1] | Fraction of hyphens | Anomaly |
| `dns_unique_char_count` | count | Unique characters used | DGA |
| `dns_entropy` | bits | Shannon entropy of character distribution | DGA |
| `dns_ngram_entropy` | bits | Entropy of trigram (configurable n) distribution | DGA |
| `dns_query_type_A` | {0,1} | Query type is A record | — |
| `dns_query_type_AAAA` | {0,1} | Query type is AAAA record | — |
| `dns_query_type_TXT` | {0,1} | Query type is TXT | Tunnel |
| `dns_query_type_MX` | {0,1} | Query type is MX | — |
| `dns_query_type_NS` | {0,1} | Query type is NS | — |
| `dns_query_type_NULL` | {0,1} | Query type is NULL | Tunnel |
| `dns_query_type_other` | {0,1} | Any other query type | Anomaly |
| `dns_is_suspicious_type` | {0,1} | TXT, NULL, or ANY query | Tunnel, DGA |
| `dns_answer_count` | count | Number of answers in response | DGA |
| `dns_is_nxdomain` | {0,1} | 1 if NXDOMAIN response | DGA |

**Configuration**: `config/config.yaml` → `features.entropy.ngram_size` (default: 3)

---

## 5. TLS Features (`tls_features.py`)

Scope: **Flow** | Source: `TLSInfo` | Extractor: `extract_tls_features()`

> **PASSIVE ONLY**: All features from cleartext handshake metadata. No decryption, no certificate fetching.

| Feature | Unit | Description | Applicable Detectors |
|---------|------|-------------|----------------------|
| `tls_version_is_tls13` | {0,1} | 1 if TLS 1.3 negotiated | Malware C2 |
| `tls_version_is_tls12` | {0,1} | 1 if TLS 1.2 negotiated | — |
| `tls_version_is_old` | {0,1} | 1 if TLS 1.0 / SSL 3.0 (deprecated) | Malware |
| `tls_version_known` | {0,1} | 1 if version string was recognised | — |
| `tls_version_str` | string | Raw version string from handshake | All |
| `tls_has_sni` | {0,1} | 1 if SNI field present in ClientHello | C2, Exfil |
| `tls_sni_length` | chars | Length of SNI value | DGA-over-TLS |
| `tls_sni_entropy` | bits | Shannon entropy of SNI characters | DGA-over-TLS |
| `tls_has_ja3` | {0,1} | 1 if JA3 fingerprint available | Malware, C2 |
| `tls_has_ja3s` | {0,1} | 1 if JA3S fingerprint available | Malware, C2 |
| `tls_ja3` | string | JA3 hash (for lookup against known bad) | Malware, C2 |
| `tls_ja3s` | string | JA3S hash | Malware, C2 |
| `tls_is_self_signed` | {0,1} | 1 if cert appears self-signed | Malware, C2 |
| `tls_resumed` | {0,1} | 1 if session resumption observed | C2 |
| `tls_cert_subject` | string | Cert subject (from Zeek ssl.log only) | C2 |
| `tls_cert_issuer` | string | Cert issuer | C2 |

---

## 6. Behavioral Features (`behavioral_features.py`)

Scope: **Per-Source** and **Per-Destination** | Aggregated over configurable windows.

**Configuration**: `config/config.yaml` → `flows.sliding_window_seconds` (default: [10, 30, 60])

Feature names use a `_Xs` suffix where `X` is the window size in seconds (e.g., `_60s`).

### Per-Source Features

| Feature | Unit | Description | Applicable Detectors |
|---------|------|-------------|----------------------|
| `src_uniq_dst_hosts_Xs` | count | Unique destination IPs in window | Recon |
| `src_uniq_dst_ports_Xs` | count | Unique destination ports in window | Recon |
| `src_conn_count_{X}s` | count | Total flows generated by this source in window | Recon, DDoS |
| `src_uniq_dst_subnets_{X}s` | count | Number of distinct destination IPv4/24 or IPv6/64 subnets | Recon (Network Sweep) |
| `src_uniq_host_port_pairs_{X}s` | count | Number of unique destination host+port combinations | Recon (Host Sweep) |
| `src_bytes_out_{X}s` | bytes | Total bytes sent by this source | Exfil |, DDoS |
| `src_pkts_out_Xs` | count | Total outbound packets in window | DDoS |
| `src_avg_flow_dur_Xs` | seconds | Mean flow duration in window | C2, Exfil |
| `src_dst_entropy_Xs` | bits | Entropy of destination IP distribution | Recon, DDoS |

### Per-Destination Features

| Feature | Unit | Description | Applicable Detectors |
|---------|------|-------------|----------------------|
| `dst_uniq_src_hosts_Xs` | count | Unique source IPs in window | DDoS |
| `dst_conn_count_Xs` | count | Connections received in window | DDoS |
| `dst_src_concentration_Xs` | [0, 1] | 1 − normalised_entropy(sources): high = few sources | DDoS |

---

## 7. Feature Vector Schema (`feature_vector.py`)

```json
{
  "flow_id": "uuid-string",
  "timestamp": "2024-11-14T18:13:20+00:00",
  "source_ip": "192.168.1.100",
  "destination_ip": "10.0.0.1",
  "source_port": 54321,
  "destination_port": 80,
  "protocol": 6,
  "window_start": null,
  "window_end": null,
  "feature_groups": ["flow", "timing", "behavioral", "dns", "tls"],
  "features": {
    "packet_count": 120,
    "byte_count": 8400,
    "packets_per_second": 12.4,
    "bytes_per_second": 870.2,
    "flow_duration": 9.67,
    "pkt_size_mean": 70.0,
    "pkt_size_std": 12.3,
    "pkt_size_cv": 0.175,
    "iat_mean": 0.082,
    "iat_cv": 0.13,
    "iat_periodicity": 0.94,
    "tcp_syn_ratio": 0.008,
    "tcp_rst_ratio": 0.0,
    "dns_entropy": 3.8,
    "dns_is_suspicious_type": 0,
    "tls_version_is_tls13": 1,
    "tls_has_sni": 1,
    "src_uniq_dst_ports_60s": 1,
    "src_conn_count_60s": 3
  }
}
```

---

## Feature Decision Matrix (by Detector)

| Detector | Key Features |
|----------|-------------|
| **DDoS** | `src_conn_count_Xs`, `dst_uniq_src_hosts_Xs`, `dst_src_concentration_Xs`, `bytes_per_second`, `tcp_syn_ratio` |
| **Port Recon** | `src_uniq_dst_ports_Xs`, `src_uniq_dst_hosts_Xs`, `tcp_syn_ratio`, `tcp_rst_ratio`, `flow_duration` |
| **C2 Beaconing** | `iat_periodicity`, `iat_cv`, `iat_jitter`, `pkt_size_cv`, `src_conn_count_Xs`, `tls_is_self_signed` |
| **DNS DGA** | `dns_entropy`, `dns_ngram_entropy`, `dns_digit_ratio`, `dns_unique_char_count`, `dns_label_count`, `dns_is_nxdomain` |
| **DNS Tunnelling** | `dns_query_type_TXT`, `dns_query_type_NULL`, `dns_max_label_length`, `dns_entropy`, `dns_answer_count` |
| **Exfiltration** | `baseline_state`, `is_destination_novel`, `avg_daily_bytes`, `current_day_bytes`, `src_bytes_out_Xs` |

---

> **Version**: Phase 2 — 2026-08-28
> **Total features**: ~80 named features across 6 extractors
> **No classification performed in this module**
