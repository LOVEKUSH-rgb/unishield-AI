import abc
from typing import List, Dict, Any, Generator
from pathlib import Path
import json

class DatasetAdapter(abc.ABC):
    """
    Base class for all dataset adapters.
    Adapters parse raw public datasets (e.g., CIC-IDS2017, CTU-13) and
    convert them into UniShield's canonical schema.
    """
    
    def __init__(self, dataset_name: str, base_path: str):
        self.dataset_name = dataset_name
        self.base_path = Path(base_path)
        
    def is_available(self) -> bool:
        """Check if the dataset exists locally in the expected path."""
        return self.base_path.exists() and any(self.base_path.iterdir())
        
    @abc.abstractmethod
    def stream_normalized(self) -> Generator[Dict[str, Any], None, None]:
        """
        Streams normalized records.
        Each record must contain strictly observable features plus ground truth:
        {
            "timestamp": float,
            "flow_id": str,
            "src_ip": str,
            "src_port": int,
            "dst_ip": str,
            "dst_port": int,
            "protocol": str,
            ... <other observable metadata> ...
            "original_label": str,
            "normalized_label": str,
            "dataset": str
        }
        """
        pass
        
    def normalize_label(self, original_label: str) -> str:
        """Override to implement dataset-specific label mappings."""
        return "NORMAL"
