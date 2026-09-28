# Phase 33: Dataset Strategy

## Selected Dataset: CTU-13 (Czech Technical University Botnet Dataset)

### Provenance
- **Name**: CTU-13 Botnet Dataset
- **Source**: CVUT FEL – Machine Learning Group, Czech Technical University in Prague
- **URL**: https://mcfp.felk.cvut.cz/publicDatasets/CTU-13-Dataset/
- **Alternative Scenario URL**: https://mcfp.felk.cvut.cz/publicDatasets/CTU-Malware-Capture-Botnet-42/

### License & Usage Terms
CTU-13 is published for academic and research use. Users are expected to cite the original paper:
> Garcia, Sebastian, Martin Grill, Jan Stiborek, and Alejandro Zunino. "An empirical comparison of botnet detection methods." *Computers & Security* 45 (2014): 100–123.

The dataset is freely available for offline academic research. It must not be redistributed or used for commercial purposes without permission. UniShield AI uses it solely for passive, offline security research evaluation.

### Why CTU-13

| Criterion | CTU-13 Status |
|---|---|
| PCAP available | ✅ Yes |
| Traffic labeled | ✅ Yes (Botnet/Normal/Background per flow in `.binetflow` files) |
| Timestamps preserved | ✅ Yes (original packet timestamps in PCAP) |
| Source/Destination IPs | ✅ Yes |
| Source/Destination Ports | ✅ Yes |
| Useful temporal flow context | ✅ Yes (multi-packet flows) |
| DDoS scenarios | ✅ Several scenarios include volumetric flooding |
| Legal/Technical suitability | ✅ Academic use permitted |

### Dataset Scenarios
CTU-13 contains 13 scenarios. Recommended scenario for DDoS evaluation:
- **Scenario 4** (Rbot/SDBOT) — contains UDP flood traffic
- **Scenario 10** (Neris) — contains spam and DDoS traffic

---

## Manual Acquisition Procedure

> [!IMPORTANT]
> The PCAP files are **large** (some exceed 1GB). They must be downloaded manually by the user.

```bash
# Create the dataset directory
mkdir -p data/raw/external/ctu13/

# Download scenario 10 (example — DDoS-relevant)
wget "https://mcfp.felk.cvut.cz/publicDatasets/CTU-13-Dataset/CTU-13-Dataset-Full-Scenarios/Scenario10/" \
    -r -np -l 1 -P data/raw/external/ctu13/ -A "*.pcap,*.binetflow"

# Alternatively, visit the URL and download manually:
# https://mcfp.felk.cvut.cz/publicDatasets/CTU-13-Dataset/
```

The validator script will detect any `.pcap`, `.pcapng`, or `.cap` files placed in `data/raw/external/ctu13/`.

---

## Directory Structure

```
data/
├── raw/
│   └── external/
│       └── ctu13/
│           ├── .gitkeep                          ← committed
│           ├── <scenario>.pcap                   ← NOT committed (too large)
│           └── <scenario>.binetflow              ← label file (small, may commit)
├── processed/
│   └── phase33/                                  ← generated flow records
└── samples/
    └── phase33/                                  ← small synthetic samples
```

---

## Label Structure

CTU-13 provides `.binetflow` (Argus-format) files containing per-flow labels:

| Column | Description |
|---|---|
| `StartTime` | Flow start timestamp |
| `SrcAddr` | Source IP |
| `DstAddr` | Destination IP |
| `Sport` | Source port |
| `Dport` | Destination port |
| `Proto` | Protocol |
| `Label` | `flow=Botnet`, `flow=Normal`, `flow=Background` |

Labels are per-flow, not per-packet. The PCAP and binetflow must be correlated by 5-tuple + timestamp.

---

## Ground Truth Mapping (CTU-13 → UniShield Threat Classes)

| CTU-13 Label | UniShield Class | Notes |
|---|---|---|
| `flow=Botnet` | Per sub-type (see below) | Depends on port/protocol pattern |
| `flow=Normal` | Benign | Background normal traffic |
| `flow=Background` | Excluded | Cannot be reliably labeled — excluded from evaluation |

Sub-type mapping for Botnet flows (scenario-dependent):

| Traffic Pattern | UniShield Threat Class |
|---|---|
| High-rate UDP/TCP SYN from multiple IPs | DDoS |
| Periodic low-payload TCP to external IPs | C2_Beacon |
| High DNS query rate with unusual names | DNS_DGA |
| Large outbound payload | Exfiltration |
| Port scan pattern (many destination ports) | Reconnaissance |
| All others with `flow=Botnet` | UNCLASSIFIED (excluded) |

> [!NOTE]
> Ambiguous botnet traffic that does not clearly match a UniShield threat class is excluded from evaluation rather than force-labeled. This avoids circular detection.

---

## Known Limitations

1. Background traffic in CTU-13 is not reliably labeled and is excluded.
2. The binetflow 5-tuple may not perfectly align with PCAP flows if timestamps differ slightly.
3. Some CTU-13 scenarios contain IPv6 traffic that PcapReader handles but may produce incomplete features.
4. The DGA detector requires DNS metadata — scenarios without DNS traffic cannot be evaluated for DNS_DGA.
5. ML model training data (synthetic DGA/encrypted datasets) may contain domain names that overlap with CTU-13 traffic by coincidence. Leakage is `NOT FULLY VERIFIED`.

---

## Data Leakage Analysis

- CTU-13 botnet domains are real historical malware C2 domains (2011 era).
- UniShield ML training data (`data/processed/dga_dataset.csv`) is synthetically generated with random domain names.
- Overlap is unlikely but **cannot be conclusively ruled out** without domain-level comparison.
- **LEAKAGE STATUS: NOT FULLY VERIFIED**
