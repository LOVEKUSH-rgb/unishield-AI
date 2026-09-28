"""
UniShield AI -- Inference Benchmarking
======================================
Measures the latency introduced by ML inference compared to
purely statistical detection.
"""

import time
import numpy as np
from src.features.feature_vector import FeatureVector
from src.detectors.encrypted import EncryptedSessionDetector
from src.detectors.dga_dns import DGADetector
from src.utils.logging import get_logger

logger = get_logger(__name__)

def generate_fvs(count: int = 1000, type: str = "encrypted"):
    fvs = []
    for _ in range(count):
        if type == "encrypted":
            fvs.append(FeatureVector(
                source_ip="10.0.0.1",
                destination_ip="8.8.8.8",
                destination_port=443,
                protocol="tcp",
                tls_version_known=1,
                tls_has_sni=1,
                splt_sizes=[100, 200, 150, 1000, 500, 1400, 100]
            ))
        else:
            fvs.append(FeatureVector(
                source_ip="10.0.0.1",
                destination_ip="1.1.1.1",
                destination_port=53,
                dns_is_query=True,
                dns_query_length=35,
                dns_entropy=4.2,
                dns_ngram_entropy=3.8,
                dns_digit_ratio=0.15,
                dns_unique_char_count=18,
                dns_alpha_ratio=0.8,
                dns_hyphen_ratio=0.0
            ))
    return fvs

def benchmark_detector(detector_cls, fvs, name, disable_ml=False):
    cfg_override = {"ml": {"enabled": not disable_ml}}
    detector = detector_cls(config_overrides=cfg_override if hasattr(detector_cls, 'ml_enabled') else None)
    
    # Force disable ML if requested (for DGADetector which uses _dga_cfg)
    if disable_ml:
        detector.ml_enabled = False
    
    print(f"\nBenchmarking {name} ({'Statistical Only' if disable_ml else 'Hybrid ML'})")
    print("-" * 50)
    
    # Warmup
    for fv in fvs[:10]:
        detector.detect(fv)
        
    latencies = []
    
    for fv in fvs:
        start = time.perf_counter()
        detector.detect(fv)
        end = time.perf_counter()
        latencies.append((end - start) * 1000) # ms
        
    p50 = np.percentile(latencies, 50)
    p90 = np.percentile(latencies, 90)
    p99 = np.percentile(latencies, 99)
    avg = np.mean(latencies)
    
    print(f"Total Vectors: {len(fvs)}")
    print(f"Average Latency: {avg:.4f} ms/flow")
    print(f"P50 Latency:     {p50:.4f} ms/flow")
    print(f"P90 Latency:     {p90:.4f} ms/flow")
    print(f"P99 Latency:     {p99:.4f} ms/flow")
    print(f"Est. Throughput: {1000/avg:.0f} flows/sec")
    
    return avg

def run_benchmarks():
    print("=" * 60)
    print("UniShield AI -- Inference Benchmark Suite")
    print("=" * 60)
    
    enc_fvs = generate_fvs(5000, "encrypted")
    enc_stat_avg = benchmark_detector(EncryptedSessionDetector, enc_fvs, "EncryptedSessionDetector", disable_ml=True)
    enc_ml_avg = benchmark_detector(EncryptedSessionDetector, enc_fvs, "EncryptedSessionDetector", disable_ml=False)
    
    print(f"\n[Encrypted] ML Overhead: +{(enc_ml_avg - enc_stat_avg):.4f} ms/flow")
    
    dga_fvs = generate_fvs(5000, "dga")
    dga_stat_avg = benchmark_detector(DGADetector, dga_fvs, "DGADetector", disable_ml=True)
    dga_ml_avg = benchmark_detector(DGADetector, dga_fvs, "DGADetector", disable_ml=False)
    
    print(f"\n[DGA] ML Overhead: +{(dga_ml_avg - dga_stat_avg):.4f} ms/flow")

if __name__ == "__main__":
    run_benchmarks()
