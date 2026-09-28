import json
import subprocess
from pathlib import Path

def run_benchmark(mode, output_path):
    cmd = [
        "python", "scripts/benchmark_detectors.py",
        "--mode", mode,
        "--output", output_path
    ]
    subprocess.run(cmd, check=True, capture_output=True)
    with open(output_path, "r") as f:
        return json.load(f)

def main():
    out_dir = Path("reports/phase32")
    out_dir.mkdir(parents=True, exist_ok=True)
    
    ml_path = out_dir / "benchmark_ml.json"
    stat_path = out_dir / "benchmark_stat.json"
    
    print("Running ML/Hybrid benchmark...")
    ml_results = run_benchmark("default", str(ml_path))
    
    print("Running Statistical fallback benchmark...")
    stat_results = run_benchmark("statistical", str(stat_path))
    
    comparison = {}
    for det_name in ml_results:
        # We only compare detectors that actually have ML modes
        if det_name not in ["DNS_DGA", "Encrypted_Anomaly"]:
            continue
            
        r_ml = ml_results[det_name]
        r_stat = stat_results[det_name]
        
        # If ML wasn't available anyway, we flag it
        if r_ml.get("Status") == "INSUFFICIENT DATA":
            comparison[det_name] = "INSUFFICIENT DATA - VALID MODEL ARTIFACT UNAVAILABLE"
            continue
            
        comparison[det_name] = {
            "ML_Mode": r_ml,
            "Statistical_Mode": r_stat,
            "Difference": {
                "F1": (r_ml.get("F1", 0) or 0) - (r_stat.get("F1", 0) or 0),
                "FPR": (r_ml.get("FPR", 0) or 0) - (r_stat.get("FPR", 0) or 0),
                "FNR": (r_ml.get("FNR", 0) or 0) - (r_stat.get("FNR", 0) or 0)
            }
        }
        
    comp_path = out_dir / "ml_vs_statistical.json"
    with open(comp_path, "w") as f:
        json.dump(comparison, f, indent=4)
        
    print(f"Comparison saved to {comp_path}")
    
if __name__ == "__main__":
    main()
