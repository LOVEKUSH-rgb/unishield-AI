import argparse
import json
import time
from pathlib import Path
from typing import Dict, Any, List

from src.features.feature_vector import FeatureVector
from src.detectors.ddos import DDoSDetector
from src.detectors.c2_beacon import C2BeaconDetector
from src.detectors.recon import ReconDetector
from src.detectors.exfiltration import ExfiltrationDetector
from src.detectors.dga_dns import DGADetector
from src.detectors.encrypted import EncryptedSessionDetector


def get_ground_truth(fv: FeatureVector) -> str:
    """Map flows to their true attack class based on the deterministic demo IP logic."""
    sip = fv.source_ip or ""
    dip = fv.destination_ip or ""
    
    if sip.startswith("203.0.113."): return "DDoS"
    if sip == "192.168.1.50" and dip == "103.45.67.89": return "C2_Beacon"
    if sip == "192.168.1.50" and dip == "10.0.0.10": return "Reconnaissance"
    if dip == "8.8.8.8": return "DNS_DGA"
    if sip == "192.168.1.52": return "Encrypted_Anomaly"
    if sip == "192.168.1.53" and dip == "103.45.67.89": return "Exfiltration"
    return "Benign"

def main():
    parser = argparse.ArgumentParser(description="UniShield AI - Deterministic Benchmark")
    parser.add_argument("--dataset", type=str, default="data/samples/demo_flows_expanded.jsonl")
    parser.add_argument("--output", type=str, default="reports/phase32/benchmark_results.json")
    parser.add_argument("--mode", type=str, choices=["default", "statistical"], default="default")
    parser.add_argument("--detector", type=str, default="all")
    args = parser.parse_args()

    # Create reports dir
    out_path = Path(args.output)
    out_path.parent.mkdir(parents=True, exist_ok=True)

    detectors = {
        "DDoS": DDoSDetector(),
        "Reconnaissance": ReconDetector(),
        "C2_Beacon": C2BeaconDetector(),
        "Exfiltration": ExfiltrationDetector(),
        "DNS_DGA": DGADetector(),
        "Encrypted_Anomaly": EncryptedSessionDetector()
    }

    if args.mode == "statistical":
        # Force disable ML
        for name, d in detectors.items():
            if hasattr(d, "ml_enabled"):
                d.ml_enabled = False

    if args.detector != "all":
        detectors = {k: v for k, v in detectors.items() if k == args.detector}

    flows = []
    dataset_path = Path(args.dataset)
    if not dataset_path.exists():
        print(f"[!] Dataset {dataset_path} not found.")
        return

    with open(dataset_path, "r") as f:
        for line in f:
            try:
                data = json.loads(line)
                flows.append(FeatureVector(**data))
            except Exception:
                pass

    ground_truths = [get_ground_truth(fv) for fv in flows]
    
    metrics = {d: {"TP": 0, "FP": 0, "TN": 0, "FN": 0} for d in detectors}
    explanations = []

    for det_name, detector in detectors.items():
        print(f"Benchmarking {det_name} in {args.mode} mode...")
        
        for fv, gt in zip(flows, ground_truths):
            try:
                res = detector.detect(fv)
                score = res.detection_score
            except Exception as e:
                score = 0.0
                res = None

            is_malicious = score >= getattr(detector, "min_score", 0.35)
            is_target_attack = (gt == det_name)

            if is_malicious and is_target_attack:
                metrics[det_name]["TP"] += 1
                cat = "TP"
            elif is_malicious and not is_target_attack:
                metrics[det_name]["FP"] += 1
                cat = "FP"
            elif not is_malicious and is_target_attack:
                metrics[det_name]["FN"] += 1
                cat = "FN"
            elif not is_malicious and not is_target_attack:
                metrics[det_name]["TN"] += 1
                cat = "TN"

            # Record explanation for errors
            if cat in ("FP", "FN") and res:
                explanations.append({
                    "detector": det_name,
                    "mode": args.mode,
                    "classification": cat,
                    "ground_truth": gt,
                    "score": round(score, 4),
                    "evidence": [e.to_dict() for e in res.evidence] if res.evidence else [],
                    "flow_duration": fv.get("flow_duration"),
                    "packet_count": fv.get("packet_count")
                })

    results = {}
    for det_name in detectors:
        tp = metrics[det_name]["TP"]
        fp = metrics[det_name]["FP"]
        tn = metrics[det_name]["TN"]
        fn = metrics[det_name]["FN"]

        precision = tp / (tp + fp) if (tp + fp) > 0 else 0.0
        recall = tp / (tp + fn) if (tp + fn) > 0 else 0.0
        f1 = 2 * (precision * recall) / (precision + recall) if (precision + recall) > 0 else 0.0
        acc = (tp + tn) / (tp + tn + fp + fn) if (tp + tn + fp + fn) > 0 else 0.0
        spec = tn / (tn + fp) if (tn + fp) > 0 else 0.0
        fpr = fp / (fp + tn) if (fp + tn) > 0 else 0.0
        fnr = fn / (fn + tp) if (fn + tp) > 0 else 0.0

        if (tp + fn) == 0:
            status = "INSUFFICIENT DATA"
            recall, f1, fnr = None, None, None
        else:
            status = "EVALUATED"

        results[det_name] = {
            "Status": status,
            "Mode": args.mode,
            "TP": tp,
            "TN": tn,
            "FP": fp,
            "FN": fn,
            "Precision": round(precision, 4) if precision is not None else "INSUFFICIENT DATA",
            "Recall": round(recall, 4) if recall is not None else "INSUFFICIENT DATA",
            "F1": round(f1, 4) if f1 is not None else "INSUFFICIENT DATA",
            "Accuracy": round(acc, 4),
            "Specificity": round(spec, 4),
            "FPR": round(fpr, 4),
            "FNR": round(fnr, 4) if fnr is not None else "INSUFFICIENT DATA"
        }

    with open(out_path, "w") as f:
        json.dump(results, f, indent=4)
        
    exp_path = Path("reports/phase32/detection_explanations.json")
    exp_path.parent.mkdir(parents=True, exist_ok=True)
    with open(exp_path, "w") as f:
        json.dump(explanations, f, indent=4)

    print(f"\n--- Benchmark Results ({args.mode}) ---")
    for k, v in results.items():
        print(f"{k}: P={v.get('Precision')} R={v.get('Recall')} F1={v.get('F1')} Status={v['Status']}")
    print(f"Results saved to {out_path}")

if __name__ == "__main__":
    main()
