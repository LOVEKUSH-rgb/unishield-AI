# Feature Importance Analysis

This document describes the relative importance of passive metadata features in the UniShield AI detection models, highlighting which features carry the most weight when identifying specific threats without relying on payload inspection.

## 1. C2 Beaconing
| Feature | Importance | Rationale |
|---------|------------|-----------|
| `ici_cv` (Inter-Connection Interval CV) | **High (40%)** | The strongest signal for automated beaconing. CV < 0.15 indicates strict periodicity (machine-driven). |
| `connection_count` | **Medium (25%)** | Repeat targeting of the exact same (IP, Port) tuple is highly suspicious if volume is low. |
| `byte_cv` (Byte Count CV) | **Medium (20%)** | Check-in packets often carry exactly the same number of bytes (e.g., 64 bytes of heartbeats). |
| `src_uniq_dst_hosts_Xs` | **Low (15%)** | Lack of destination diversity points to an infected host dedicated to calling home. |

## 2. DDoS (Volumetric)
| Feature | Importance | Rationale |
|---------|------------|-----------|
| `packets_per_second` (Z-Score) | **High (30%)** | Massive deviation from the EWMA baseline is the primary volumetric indicator. |
| `tcp_syn_ratio` | **High (30%)** | Normal TCP traffic has ~5% SYNs. A flood pushes this >80%. |
| `dst_uniq_src_hosts_Xs` | **Medium (20%)** | A massive influx of unique IPs suggests a distributed (or spoofed) attack. |
| `protocol` | **Medium (20%)** | Segregates TCP SYN floods from UDP amplification attacks. |

## 3. DGA / DNS Tunnelling
| Feature | Importance | Rationale |
|---------|------------|-----------|
| `shannon_entropy` | **High (40%)** | Domain generation algorithms produce high-entropy strings compared to legitimate dictionary words. |
| `unique_subdomain_ratio` | **Medium (30%)** | Tunnelling rapidly iterates through randomized subdomains to evade caching. |
| `domain_length` | **Low (15%)** | DGAs often generate domains longer than typical human-readable URLs. |
| `txt_null_ratio` | **Low (15%)** | Tunnels often exploit TXT or NULL records for maximum payload capacity. |

## 4. Reconnaissance (Port Scanning)
| Feature | Importance | Rationale |
|---------|------------|-----------|
| `unique_dst_ports` | **High (50%)** | Rapidly attempting connections across many ports indicates a vertical scan. |
| `unique_dst_ips` | **High (30%)** | Rapidly sweeping across multiple IPs on a specific port indicates a horizontal scan (e.g., searching for exposed RDP). |
| `tcp_syn_only_ratio` | **Medium (20%)** | Unanswered SYNs are the hallmark of scanning non-existent hosts/ports. |

## 5. Data Exfiltration
| Feature | Importance | Rationale |
|---------|------------|-----------|
| `asymmetry_ratio` (outbound/inbound bytes) | **High (50%)** | Exfiltration involves pushing large amounts of data out with minimal ACKs returned. |
| `bytes_per_second` (Sustained Deviation) | **High (50%)** | Must exceed the historical daily/hourly baseline over a sustained period, differentiating from normal usage spikes. |

## Conclusion
By structuring thresholds around these heavily-weighted features (e.g., CV for C2, Entropy for DGA, Rates for DDoS), we establish clear boundaries for statistical risk engines to evaluate confidence securely and passively.
