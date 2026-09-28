"""
UniShield AI -- Model Metadata Management
=========================================
Handles the parsing and saving of model metadata files.
"""
import json
import os
from typing import Dict, Any, Optional

def load_metadata(model_path: str) -> Optional[Dict[str, Any]]:
    """
    Load metadata for a given model path.
    Tries replacing .pkl or .json with .json or _meta.json.
    """
    # 1. Direct match if it's already a json
    if model_path.endswith("_meta.json"):
        meta_path = model_path
    elif model_path.endswith(".json"):
        meta_path = model_path.replace(".json", "_meta.json")
    elif model_path.endswith(".pkl"):
        meta_path = model_path.replace(".pkl", ".json")
    else:
        return None
        
    if os.path.exists(meta_path):
        try:
            with open(meta_path, "r") as f:
                return json.load(f)
        except Exception:
            return None
    return None

def save_metadata(model_path: str, metadata: Dict[str, Any]) -> str:
    """
    Save metadata for a given model path.
    """
    if model_path.endswith(".json"):
        meta_path = model_path.replace(".json", "_meta.json")
    elif model_path.endswith(".pkl"):
        meta_path = model_path.replace(".pkl", ".json")
    else:
        meta_path = model_path + ".json"
        
    with open(meta_path, "w") as f:
        json.dump(metadata, f, indent=4)
        
    return meta_path
