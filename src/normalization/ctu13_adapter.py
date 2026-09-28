import csv
from pathlib import Path
from typing import Generator, Dict, Any
from src.normalization.base_adapter import DatasetAdapter

class CTU13Adapter(DatasetAdapter):
    def __init__(self, base_path: str = "data/raw/ctu13"):
        super().__init__("CTU-13", base_path)
        
    def normalize_label(self, original_label: str) -> str:
        label = original_label.strip().lower()
        if "botnet" in label: return "C2_BEACON"
        if "normal" in label or "background" in label: return "NORMAL"
        return "UNKNOWN"

    def stream_normalized(self) -> Generator[Dict[str, Any], None, None]:
        if not self.is_available():
            return
            
        for csv_file in self.base_path.glob("*.csv"): # Binetflow files
            with open(csv_file, 'r', encoding='utf-8') as f:
                reader = csv.DictReader(f)
                for row in reader:
                    try:
                        orig_label = row.get("Label", "Background")
                        norm_label = self.normalize_label(orig_label)
                        
                        yield {
                            "flow_id": f"{row.get('SrcAddr')}-{row.get('DstAddr')}-{row.get('Dport')}",
                            "src_ip": row.get("SrcAddr", ""),
                            "src_port": int(row.get("Sport", 0) or 0),
                            "dst_ip": row.get("DstAddr", ""),
                            "dst_port": int(row.get("Dport", 0) or 0),
                            "protocol": row.get("Proto", ""),
                            "duration": float(row.get("Dur", 0)),
                            "packets": int(row.get("TotPkts", 0)),
                            "bytes": int(row.get("TotBytes", 0)),
                            
                            "original_label": orig_label,
                            "normalized_label": norm_label,
                            "dataset": self.dataset_name
                        }
                    except Exception:
                        continue
