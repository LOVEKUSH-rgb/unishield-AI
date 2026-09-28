"""
UniShield AI -- Model Registry
==============================
Tracks, validates, and loads trained ML models for production use.
Enforces feature schema compatibility before loading to prevent runtime crashes.
"""

import os
import json
import logging
import hashlib
from typing import Dict, Any, Optional, Tuple
from src.utils.config import settings

logger = logging.getLogger(__name__)

# Expected canonical feature schema version
CURRENT_SCHEMA_VERSION = "v1"

def verify_sha256(filepath: str, expected_sha256: str) -> bool:
    """Computes SHA-256 of the file and compares it to the expected hash."""
    if not os.path.exists(filepath):
        return False
    
    sha256_hash = hashlib.sha256()
    try:
        with open(filepath, "rb") as f:
            for byte_block in iter(lambda: f.read(4096), b""):
                sha256_hash.update(byte_block)
        return sha256_hash.hexdigest() == expected_sha256
    except Exception as e:
        logger.error(f"Failed to read file for hashing {filepath}: {e}")
        return False

class ModelRegistry:
    """
    Singleton registry to load and validate models safely.
    Uses versioned manifest schema.
    """
    
    def __init__(self, models_dir: str = None):
        self.models_dir = models_dir or settings.model_registry_path
        self.active_models = {}
        self.registry_state_path = os.path.join(self.models_dir, "registry_state.json")
        
    def _read_registry_state(self) -> Dict:
        if not os.path.exists(self.registry_state_path):
            return {}
        try:
            with open(self.registry_state_path, "r") as f:
                return json.load(f)
        except Exception as e:
            logger.error(f"Failed to read registry state: {e}")
            return {}
            
    def _write_registry_state(self, state: Dict):
        try:
            os.makedirs(self.models_dir, exist_ok=True)
            with open(self.registry_state_path, "w") as f:
                json.dump(state, f, indent=4)
        except Exception as e:
            logger.error(f"Failed to write registry state: {e}")

    def update_model_state(self, model_name: str, active_version: str, status: str, integrity: str):
        state = self._read_registry_state()
        if model_name not in state:
            state[model_name] = {}
        state[model_name].update({
            "active_version": active_version,
            "status": status,
            "integrity": integrity
        })
        self._write_registry_state(state)

    def _validate_metadata(self, meta_path: str) -> Tuple[bool, Optional[Dict]]:
        """Validate that the model manifest exists and matches the current schema."""
        if not os.path.exists(meta_path):
            logger.warning(f"Manifest missing: {meta_path}")
            return False, None
            
        try:
            with open(meta_path, "r") as f:
                meta = json.load(f)
                
            schema_version = meta.get("feature_schema_version", "v1")
            if schema_version != CURRENT_SCHEMA_VERSION:
                logger.error(f"Schema mismatch in {meta_path}: expected {CURRENT_SCHEMA_VERSION}, got {schema_version}")
                return False, meta
                
            if "model_name" not in meta or "sha256" not in meta:
                logger.error(f"Invalid manifest format in {meta_path}")
                return False, meta
                
            return True, meta
            
        except Exception as e:
            logger.error(f"Failed to read manifest {meta_path}: {e}")
            return False, None

    def get_model(self, model_name: str) -> Optional[Dict[str, Any]]:
        return self.active_models.get(model_name)
        
    def get_all_models_status(self) -> Dict[str, Dict]:
        """Returns the full runtime state of all known models."""
        state = self._read_registry_state()
        result = {}
        # Provide base structure for all potential models
        for m in ["dga_random_forest", "encrypted_xgboost"]:
            st = state.get(m, {})
            result[m] = {
                "active_version": st.get("active_version"),
                "status": st.get("status", "NOT_AVAILABLE"),
                "integrity": st.get("integrity", "UNKNOWN"),
                "schema_version": "unknown"
            }
            # Enrich with loaded runtime data if available
            if m in self.active_models:
                result[m]["status"] = "LOADED"
                result[m]["schema_version"] = self.active_models[m]["metadata"].get("feature_schema_version", "v1")
        return result

    def discover_and_validate(self, expected_name: str, preferred_type: str = "xgboost") -> Tuple[Optional[str], Optional[Dict]]:
        """
        Locates the active version from registry_state, validates integrity and schema,
        and returns the (artifact_path, manifest).
        """
        state = self._read_registry_state()
        model_state = state.get(expected_name)
        
        # Avoid circular imports
        try:
            from src.api.replay_manager import manager
            state_mgr = manager.state_mgr
        except Exception:
            state_mgr = None
        
        if not model_state or not model_state.get("active_version"):
            logger.warning(f"No active version marked in registry for {expected_name}")
            if state_mgr: state_mgr.increment_metric("model_fallback_active")
            return None, None
            
        version = model_state["active_version"]
        target_dir = os.path.join(self.models_dir, expected_name, version)
        manifest_path = os.path.join(target_dir, "manifest.json")
        
        is_valid, meta = self._validate_metadata(manifest_path)
        if not is_valid:
            logger.error(f"Model {expected_name} version {version} rejected due to manifest validation failure.")
            self.update_model_state(expected_name, version, "INVALID_MANIFEST", "UNKNOWN")
            if state_mgr: 
                state_mgr.increment_metric("model_load_failure")
                state_mgr.increment_metric("model_fallback_active")
            return None, None
            
        artifact_path = os.path.join(target_dir, meta["artifact"])
        
        if settings.model_require_integrity:
            if not verify_sha256(artifact_path, meta["sha256"]):
                logger.error(f"Model {expected_name} version {version} failed integrity check. REJECTED.")
                self.update_model_state(expected_name, version, "INVALID", "FAILED")
                if state_mgr:
                    state_mgr.increment_metric("model_integrity_failure")
                    state_mgr.increment_metric("model_load_failure")
                    state_mgr.increment_metric("model_fallback_active")
                return None, None
        
        # Validation successful
        self.active_models[expected_name] = {
            "path": artifact_path,
            "metadata": meta,
            "type": meta.get("model_type", preferred_type),
            "drift_scores": []
        }
        
        self.update_model_state(expected_name, version, "LOADED", "VALID")
        logger.info(f"Successfully loaded valid model {expected_name} ({version}) into registry.")
        if state_mgr: state_mgr.increment_metric("model_load_success")
        return artifact_path, meta
        
    def record_score(self, model_name: str, score: float):
        if model_name in self.active_models:
            scores = self.active_models[model_name]["drift_scores"]
            scores.append(score)
            if len(scores) > 10000:
                scores.pop(0)

registry = ModelRegistry()
