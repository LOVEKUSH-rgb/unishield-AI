"""
UniShield AI -- Model Synchronization Logic
===========================================
Handles syncing models from a remote store (or local source) to the active runtime cache,
enforcing SHA-256 integrity checks and schema validations.
"""

import os
import json
import hashlib
import logging
import shutil
from typing import Optional, Tuple
from src.models.storage import ModelArtifactStore, ModelManifest
from src.utils.config import settings

logger = logging.getLogger(__name__)

def verify_sha256(filepath: str, expected_sha256: str) -> bool:
    """Computes SHA-256 of the file and compares it to the expected hash."""
    if not os.path.exists(filepath):
        return False
    
    sha256_hash = hashlib.sha256()
    try:
        with open(filepath, "rb") as f:
            for byte_block in iter(lambda: f.read(4096), b""):
                sha256_hash.update(byte_block)
        actual_hash = sha256_hash.hexdigest()
        return actual_hash == expected_sha256
    except Exception as e:
        logger.error(f"Failed to read file for hashing {filepath}: {e}")
        return False

class ModelSynchronizer:
    def __init__(self, store: ModelArtifactStore, local_cache_dir: str):
        self.store = store
        self.local_cache_dir = local_cache_dir
        os.makedirs(self.local_cache_dir, exist_ok=True)
        
    def sync_model(self, model_name: str, version: str) -> bool:
        """
        Synchronizes a specific model version from the store to the local cache.
        Returns True if successful (or already present and valid), False otherwise.
        """
        manifest = self.store.get_manifest(model_name, version)
        if not manifest:
            logger.error(f"Manifest not found in store for {model_name} version {version}")
            return False
            
        target_dir = os.path.join(self.local_cache_dir, model_name, version)
        target_artifact = os.path.join(target_dir, manifest.artifact)
        target_manifest = os.path.join(target_dir, "manifest.json")
        
        # Check if already present and valid
        if os.path.exists(target_artifact) and os.path.exists(target_manifest):
            if settings.model_require_integrity:
                if verify_sha256(target_artifact, manifest.sha256):
                    logger.info(f"Model {model_name} {version} is already cached and valid.")
                    return True
                else:
                    logger.warning(f"Cached model {model_name} {version} failed integrity check. Re-downloading.")
            else:
                logger.info(f"Model {model_name} {version} is already cached (integrity check disabled).")
                return True
                
        # Needs download
        logger.info(f"Downloading model {model_name} {version}...")
        os.makedirs(target_dir, exist_ok=True)
        
        # Download to a temporary file for atomic installation
        temp_artifact = target_artifact + ".tmp"
        success = self.store.download_artifact(model_name, version, temp_artifact)
        if not success:
            logger.error(f"Failed to download artifact for {model_name} {version}")
            if os.path.exists(temp_artifact):
                os.remove(temp_artifact)
            return False
            
        # Verify integrity
        if settings.model_require_integrity:
            if not verify_sha256(temp_artifact, manifest.sha256):
                logger.error(f"Downloaded artifact for {model_name} {version} failed integrity check. Rejecting.")
                os.remove(temp_artifact)
                return False
                
        # Atomic install: rename temp file to final artifact
        shutil.move(temp_artifact, target_artifact)
        
        # Write manifest locally
        with open(target_manifest, "w") as f:
            f.write(manifest.model_dump_json(indent=4))
            
        logger.info(f"Successfully synced model {model_name} {version}")
        return True
