import json
import argparse
from pathlib import Path
from collections import defaultdict

def determine_cause(error: dict) -> str:
    flow_duration = error.get("flow_duration")
    packet_count = error.get("packet_count")
    detector = error.get("detector")
    
    if flow_duration == 0.0:
        return "zero duration"
    
    if packet_count is not None and packet_count <= 3:
        return "sparse packet count"
        
    if detector == "C2_Beacon":
        return "periodicity boundary (insufficient connections)"
        
    if detector == "Encrypted_Anomaly" and error["classification"] == "FP":
        return "schema incompatibility (synthetic short warmup traffic)"
        
    return "unknown"

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--input", default="reports/phase32/detection_explanations.json")
    parser.add_argument("--output", default="reports/phase32/error_analysis.json")
    args = parser.parse_args()
    
    in_path = Path(args.input)
    if not in_path.exists():
        print(f"[!] File not found: {in_path}")
        return
        
    with open(in_path, "r") as f:
        data = json.load(f)
        
    analysis = {}
    for error in data:
        det = error["detector"]
        cls = error["classification"]
        cause = determine_cause(error)
        
        if det not in analysis:
            analysis[det] = {"FP": defaultdict(int), "FN": defaultdict(int)}
            
        analysis[det][cls][cause] += 1
        
    # Convert defaultdict to dict for JSON serialization
    final_output = {}
    for det, counts in analysis.items():
        final_output[det] = {
            "FP": dict(counts["FP"]),
            "FN": dict(counts["FN"])
        }
        
    out_path = Path(args.output)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    with open(out_path, "w") as f:
        json.dump(final_output, f, indent=4)
        
    print(f"Error analysis written to {out_path}")
    
if __name__ == "__main__":
    main()
