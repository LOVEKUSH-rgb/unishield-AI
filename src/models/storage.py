"""
UniShield AI -- Model Storage Abstraction
=========================================
Abstracts the source of ML models so they can be fetched from
local storage or remote cloud storage cleanly.
"""

from abc import ABC, abstractmethod
import os
import json
import shutil
from typing import List, Dict, Optional, Any
from pydantic import BaseModel

class ModelManifest(BaseModel):
    model_name: str
    model_type: str
    version: str
    artifact: str
    sha256: str
    feature_schema_version: str
    framework: str
    dataset: Optional[str] = None
    trained_at: Optional[str] = None
    metrics: Dict[str, Any] = {}
    status: str = "active"


class ModelArtifactStore(ABC):
    """Base abstraction for retrieving model manifests and artifacts."""
    
    @abstractmethod
    def list_models(self) -> List[str]:
        """Returns a list of available model names."""
        pass
        
    @abstractmethod
    def list_versions(self, model_name: str) -> List[str]:
        """Returns a list of versions for a specific model."""
        pass
        
    @abstractmethod
    def get_manifest(self, model_name: str, version: str) -> Optional[ModelManifest]:
        """Fetches the manifest for a given model version."""
        pass
        
    @abstractmethod
    def download_artifact(self, model_name: str, version: str, destination_path: str) -> bool:
        """Downloads the actual model artifact to the destination path."""
        pass


class LocalArtifactStore(ModelArtifactStore):
    """
    Implements the artifact store using the local filesystem.
    Useful for local development or Docker volumes.
    """
    
    def __init__(self, base_path: str):
        self.base_path = base_path
        
    def _get_model_dir(self, model_name: str, version: str) -> str:
        return os.path.join(self.base_path, model_name, version)
        
    def list_models(self) -> List[str]:
        if not os.path.exists(self.base_path):
            return []
        return [d for d in os.listdir(self.base_path) if os.path.isdir(os.path.join(self.base_path, d))]
        
    def list_versions(self, model_name: str) -> List[str]:
        model_dir = os.path.join(self.base_path, model_name)
        if not os.path.exists(model_dir):
            return []
        # exclude active/candidate symlinks or metadata files
        versions = [d for d in os.listdir(model_dir) if os.path.isdir(os.path.join(model_dir, d))]
        # filter out functional directories like 'active'
        return [v for v in versions if v.startswith("v")]
        
    def get_manifest(self, model_name: str, version: str) -> Optional[ModelManifest]:
        manifest_path = os.path.join(self._get_model_dir(model_name, version), "manifest.json")
        if not os.path.exists(manifest_path):
            return None
        try:
            with open(manifest_path, "r") as f:
                data = json.load(f)
            return ModelManifest(**data)
        except Exception:
            return None
            
    def download_artifact(self, model_name: str, version: str, destination_path: str) -> bool:
        # In a purely local context where destination_path is the cache,
        # we might just copy it from the canonical "remote" local folder to a cache.
        # But if the LocalArtifactStore IS the primary store, we can just return True.
        
        manifest = self.get_manifest(model_name, version)
        if not manifest:
            return False
            
        source_artifact = os.path.join(self._get_model_dir(model_name, version), manifest.artifact)
        if not os.path.exists(source_artifact):
            return False
            
        # Avoid copying to itself
        if os.path.abspath(source_artifact) == os.path.abspath(destination_path):
            return True
            
        try:
            os.makedirs(os.path.dirname(destination_path), exist_ok=True)
            shutil.copy2(source_artifact, destination_path)
            return True
        except Exception:
            return False
