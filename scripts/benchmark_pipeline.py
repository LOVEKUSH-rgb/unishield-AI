import time
import json
import statistics
import platform
import sys
from pathlib import Path

from src.features.feature_vector import FeatureVector
from src.detectors.ddos import DDoSDetector
from src.detectors.c2_beacon import C2BeaconDetector
from src.detectors.recon import ReconDetector
from src.detectors.exfiltration import ExfiltrationDetector
from src.detectors.dga_dns import DGADetector
from src.detectors.encrypted import EncryptedSessionDetector

def measure_percentiles(latencies):
    if not latencies:
        return {}
    s = sorted(latencies)
    return {
        "min": s[0],
        "max": s[-1],
        "P50": s[int(len(s) * 0.50)],
        "P90": s[int(len(s) * 0.90)],
        "P95": s[int(len(s) * 0.95)],
        "P99": s[int(len(s) * 0.99)],
        "mean": statistics.mean(s)
    }

def main():
    print("Loading dataset for performance benchmark...")
    flows_data = []
    try:
        with open("data/samples/demo_flows_expanded.jsonl", "r") as f:
            for line in f:
                flows_data.append(json.loads(line))
    except Exception as e:
        print(f"Failed to load dataset: {e}")
        return

    # 1. FeatureVector Creation Latency
    print("Benchmarking FeatureVector creation...")
    fv_latencies = []
    fvs = []
    for d in flows_data:
        t0 = time.perf_counter()
        fv = FeatureVector(**d)
        t1 = time.perf_counter()
        fv_latencies.append((t1 - t0) * 1000)
        fvs.append(fv)

    # 2. Individual Detector Execution
    detectors = [
        ("DDoS", DDoSDetector()),
        ("Recon", ReconDetector()),
        ("C2", C2BeaconDetector()),
        ("Exfil", ExfiltrationDetector()),
        ("DGA", DGADetector()),
        ("Encrypted", EncryptedSessionDetector())
    ]
    
    det_latencies = {n: [] for n, _ in detectors}
    for n, d in detectors:
        print(f"Benchmarking {n} detector...")
        for fv in fvs:
            t0 = time.perf_counter()
            d.detect(fv)
            t1 = time.perf_counter()
            det_latencies[n].append((t1 - t0) * 1000)

    # 3. Complete Pipeline Execution (All 6)
    print("Benchmarking full 6-detector pipeline...")
    pipeline_latencies = []
    for fv in fvs:
        t0 = time.perf_counter()
        for _, d in detectors:
            d.detect(fv)
        t1 = time.perf_counter()
        pipeline_latencies.append((t1 - t0) * 1000)
        
    # Throughput (Batch processing)
    t0 = time.perf_counter()
    for fv in fvs:
        for _, d in detectors:
            d.detect(fv)
    t1 = time.perf_counter()
    throughput = len(fvs) / (t1 - t0)

    report = {
        "environment": {
            "python_version": sys.version,
            "platform": platform.platform(),
            "cpu_info": platform.processor(),
            "dataset_size": len(fvs)
        },
        "feature_vector_creation_ms": measure_percentiles(fv_latencies),
        "full_pipeline_execution_ms": measure_percentiles(pipeline_latencies),
        "throughput_flows_per_second": round(throughput, 2),
        "detectors_ms": {n: measure_percentiles(lats) for n, lats in det_latencies.items()}
    }
    
    out_path = Path("reports/phase32/performance_metrics.json")
    out_path.parent.mkdir(parents=True, exist_ok=True)
    with open(out_path, "w") as f:
        json.dump(report, f, indent=4)
        
    print(f"Performance metrics saved to {out_path}")
    print(f"P99 Pipeline Latency: {report['full_pipeline_execution_ms']['P99']:.3f} ms")
    print(f"Throughput: {throughput:.2f} flows/sec")

if __name__ == "__main__":
    main()
