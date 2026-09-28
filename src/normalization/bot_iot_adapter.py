import csv
from pathlib import Path
from typing import Generator, Dict, Any
from src.normalization.base_adapter import DatasetAdapter

class BotIoTAdapter(DatasetAdapter):
    def __init__(self, base_path: str = "data/raw/bot_iot"):
        super().__init__("BoT-IoT", base_path)
        
    def normalize_label(self, original_label: str) -> str:
        label = original_label.strip().upper()
        if label == "NORMAL": return "NORMAL"
        if "DATA EXFILTRATION" in label or "THEFT" in label: return "EXFILTRATION"
        if "DDOS" in label or "DOS" in label: return "DDOS"
        if "RECONNAISSANCE" in label or "SCAN" in label: return "RECONNAISSANCE"
        return "UNKNOWN"

    def stream_normalized(self) -> Generator[Dict[str, Any], None, None]:
        if not self.is_available():
            return
            
        for csv_file in self.base_path.glob("*.csv"):
            with open(csv_file, 'r', encoding='utf-8') as f:
                reader = csv.DictReader(f)
                for row in reader:
                    try:
                        orig_label = row.get("category", "Normal")
                        norm_label = self.normalize_label(orig_label)
                        
                        yield {
                            "flow_id": f"{row.get('saddr')}-{row.get('daddr')}-{row.get('dport')}",
                            "src_ip": row.get("saddr", ""),
                            "src_port": int(row.get("sport", 0) or 0),
                            "dst_ip": row.get("daddr", ""),
                            "dst_port": int(row.get("dport", 0) or 0),
                            "protocol": row.get("proto", ""),
                            "duration": float(row.get("dur", 0)),
                            "bytes_fwd": int(row.get("sbytes", 0)),
                            "bytes_bwd": int(row.get("dbytes", 0)),
                            "packets_fwd": int(row.get("spkts", 0)),
                            "packets_bwd": int(row.get("dpkts", 0)),
                            
                            "original_label": orig_label,
                            "normalized_label": norm_label,
                            "dataset": self.dataset_name
                        }
                    except Exception:
                        continue
