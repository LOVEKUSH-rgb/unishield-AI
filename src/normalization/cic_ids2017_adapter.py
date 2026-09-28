import csv
from pathlib import Path
from typing import Generator, Dict, Any
from src.normalization.base_adapter import DatasetAdapter

class CICIDS2017Adapter(DatasetAdapter):
    def __init__(self, base_path: str = "data/raw/cic_ids2017"):
        super().__init__("CIC-IDS2017", base_path)
        
    def normalize_label(self, original_label: str) -> str:
        label = original_label.strip().upper()
        if label == "BENIGN": return "NORMAL"
        if "DOS" in label or "DDOS" in label: return "DDOS"
        if "PORTSCAN" in label: return "RECONNAISSANCE"
        if "BOT" in label: return "C2_BEACON"
        return "UNKNOWN"

    def stream_normalized(self) -> Generator[Dict[str, Any], None, None]:
        if not self.is_available():
            return
            
        # Example parsing logic for CIC-IDS2017 CSVs
        for csv_file in self.base_path.glob("*.csv"):
            with open(csv_file, 'r', encoding='utf-8') as f:
                reader = csv.DictReader(f)
                for row in reader:
                    # Map CIC-IDS2017 columns to canonical format
                    # e.g., ' Flow Duration', ' Total Fwd Packets', ' Label'
                    try:
                        orig_label = row.get(" Label", "BENIGN")
                        norm_label = self.normalize_label(orig_label)
                        
                        yield {
                            "flow_id": row.get("Flow ID", ""),
                            "src_ip": row.get(" Source IP", ""),
                            "src_port": int(row.get(" Source Port", 0)),
                            "dst_ip": row.get(" Destination IP", ""),
                            "dst_port": int(row.get(" Destination Port", 0)),
                            "protocol": row.get(" Protocol", ""),
                            "duration": float(row.get(" Flow Duration", 0)) / 1e6, # microsec to sec
                            "packets_fwd": int(row.get(" Total Fwd Packets", 0)),
                            "packets_bwd": int(row.get(" Total Backward Packets", 0)),
                            "bytes_fwd": int(row.get("Total Length of Fwd Packets", 0)),
                            "bytes_bwd": int(row.get(" Total Length of Bwd Packets", 0)),
                            
                            "original_label": orig_label,
                            "normalized_label": norm_label,
                            "dataset": self.dataset_name
                        }
                    except Exception:
                        continue
