import json
import time
import uuid
import datetime
from pathlib import Path
from typing import Dict, Any, List, Optional

from src.detectors.ddos import DDoSDetector
from src.detectors.c2_beacon import C2BeaconDetector
from src.detectors.recon import ReconDetector
from src.detectors.exfiltration import ExfiltrationDetector
from src.detectors.dga_dns import DGADetector
from src.detectors.encrypted import EncryptedSessionDetector
from src.features.feature_vector import FeatureVector

def determine_ground_truth(fv: FeatureVector) -> str:
    """Map flows to their true attack class based on the golden demo PCAP IPs."""
    sip = fv.source_ip or ""
    dip = fv.destination_ip or ""
    
    if sip.startswith("203.0.113."):
        return "DDoS"
    if sip == "192.168.1.50" and dip == "103.45.67.89":
        return "C2_Beacon"
    if sip == "192.168.1.50" and dip == "10.0.0.10":
        return "Reconnaissance"
    if dip == "8.8.8.8":
        return "DNS_DGA"
    if sip == "192.168.1.52":
        return "Encrypted_Anomaly"
    if sip == "192.168.1.53" and dip == "103.45.67.89":
        return "Exfiltration"
    
    return "Benign"

def get_detector_class_name(detector_name: str) -> str:
    return detector_name

def evaluate():
    print("--- UniShield AI Detector Evaluation Harness ---")
    
    # 2. Setup Detectors
    detectors = {
        "DDoS": DDoSDetector(),
        "Reconnaissance": ReconDetector(),
        "C2_Beacon": C2BeaconDetector(),
        "Exfiltration": ExfiltrationDetector(),
        "DNS_DGA": DGADetector(),
        "Encrypted_Anomaly": EncryptedSessionDetector()
    }
    
    results = {}
    dataset_path = Path("data/samples/demo_flows_expanded.jsonl")
    if not dataset_path.exists():
        print(f"[!] Dataset {dataset_path} not found.")
        return
        
    print(f"[*] Loading dataset: {dataset_path}")
    
    # Load all flows into memory since it's small enough for the regression set (15MB)
    flows = []
    with open(dataset_path, "r") as f:
        for line in f:
            try:
                data = json.loads(line)
                flows.append(FeatureVector(**data))
            except Exception:
                pass
                
    print(f"[*] Loaded {len(flows)} flows. Beginning evaluation...")
    
    # Prepare metrics counters
    metrics = {d: {"TP": 0, "FP": 0, "TN": 0, "FN": 0, "latency": []} for d in detectors}
    
    # Pre-calculate ground truths
    ground_truths = [determine_ground_truth(fv) for fv in flows]
    
    # Count occurrences
    gt_counts = {}
    for gt in ground_truths:
        gt_counts[gt] = gt_counts.get(gt, 0) + 1
    print("\nDataset Composition:")
    for gt, count in gt_counts.items():
        print(f"  {gt}: {count}")
    
    for det_name, detector in detectors.items():
        print(f"\nEvaluating {det_name}...")
        
        start_time = time.time()
        for fv, gt in zip(flows, ground_truths):
            
            # Ensure protocol matches detector expectations (e.g., DNS needs UDP, Recon needs TCP etc, but detectors usually handle this via feature extraction logic)
            t0 = time.time()
            try:
                result = detector.detect(fv)
                score = result.detection_score
            except Exception as e:
                score = 0.0
            latency = time.time() - t0
            
            metrics[det_name]["latency"].append(latency)
            
            is_malicious = score > 0.5  # Detection threshold
            is_target_attack = (gt == det_name)
            
            # If the flow is malicious but belongs to a DIFFERENT attack, we skip it as TN to avoid penalizing 
            # e.g., DDoS detector for not flagging C2.
            # But wait, if DDoS flags C2, is it a False Positive? 
            # Yes. If DDoS flags C2, it's a FP for DDoS.
            
            if is_malicious and is_target_attack:
                metrics[det_name]["TP"] += 1
            elif is_malicious and not is_target_attack:
                metrics[det_name]["FP"] += 1
            elif not is_malicious and is_target_attack:
                metrics[det_name]["FN"] += 1
            elif not is_malicious and not is_target_attack:
                metrics[det_name]["TN"] += 1
                
        duration = time.time() - start_time
        
        tp = metrics[det_name]["TP"]
        fp = metrics[det_name]["FP"]
        fn = metrics[det_name]["FN"]
        tn = metrics[det_name]["TN"]
        
        precision = tp / (tp + fp) if (tp + fp) > 0 else 0.0
        recall = tp / (tp + fn) if (tp + fn) > 0 else 0.0
        f1 = 2 * (precision * recall) / (precision + recall) if (precision + recall) > 0 else 0.0
        
        # Calculate latency
        lats = sorted(metrics[det_name]["latency"])
        p50 = lats[int(len(lats) * 0.50)] * 1000 if lats else 0.0
        p95 = lats[int(len(lats) * 0.95)] * 1000 if lats else 0.0
        p99 = lats[int(len(lats) * 0.99)] * 1000 if lats else 0.0
        
        results[det_name] = {
            "Dataset": "demo_flows_expanded.jsonl",
            "Status": "EVALUATED" if (tp + fn) > 0 else "INSUFFICIENT VALIDATION DATA",
            "TP": tp,
            "TN": tn,
            "FP": fp,
            "FN": fn,
            "Precision": round(precision, 4),
            "Recall": round(recall, 4),
            "F1": round(f1, 4),
            "Throughput_fps": round(len(flows) / max(duration, 0.001), 2),
            "Latency_P50_ms": round(p50, 4),
            "Latency_P99_ms": round(p99, 4)
        }
        
    # 3. Save Results
    reports_dir = Path("reports/phase31")
    reports_dir.mkdir(parents=True, exist_ok=True)
    
    with open(reports_dir / "detector_metrics.json", "w") as f:
        json.dump(results, f, indent=4)
        
    print("\n--- Summary ---")
    for k, v in results.items():
        print(f"{k}: Precision={v['Precision']} Recall={v['Recall']} F1={v['F1']} Status={v['Status']}")
        
    print("\nEvaluation complete. Results saved to reports/phase31/")

if __name__ == "__main__":
    evaluate()
