import pytest
import os
import json
import shutil
import hashlib
from src.models.registry import ModelRegistry
from src.utils.config import settings

@pytest.fixture
def temp_models_dir(tmp_path):
    # Set up a fake model registry directory
    d = tmp_path / "models" / "trained"
    d.mkdir(parents=True)
    return str(d)

def create_fake_model(base_dir, model_name, version, content="fake_model_content"):
    target_dir = os.path.join(base_dir, model_name, version)
    os.makedirs(target_dir, exist_ok=True)
    
    artifact_path = os.path.join(target_dir, f"{model_name}.pkl")
    with open(artifact_path, "w") as f:
        f.write(content)
        
    # Get hash
    sha256 = hashlib.sha256()
    sha256.update(content.encode("utf-8"))
    hash_val = sha256.hexdigest()
    
    manifest = {
        "model_name": model_name,
        "model_type": "random_forest",
        "version": version,
        "artifact": f"{model_name}.pkl",
        "sha256": hash_val,
        "feature_schema_version": "v1"
    }
    
    with open(os.path.join(target_dir, "manifest.json"), "w") as f:
        json.dump(manifest, f)
        
    return artifact_path, hash_val

def test_registry_load_valid_model(temp_models_dir, monkeypatch):
    monkeypatch.setattr(settings, "model_registry_path", temp_models_dir)
    monkeypatch.setattr(settings, "model_require_integrity", True)
    
    create_fake_model(temp_models_dir, "dga_random_forest", "v1.0.0")
    
    registry = ModelRegistry(models_dir=temp_models_dir)
    registry.update_model_state("dga_random_forest", "v1.0.0", "LOADED", "VALID")
    
    path, meta = registry.discover_and_validate("dga_random_forest")
    assert path is not None
    assert meta is not None
    assert meta["version"] == "v1.0.0"

def test_registry_integrity_failure(temp_models_dir, monkeypatch):
    monkeypatch.setattr(settings, "model_registry_path", temp_models_dir)
    monkeypatch.setattr(settings, "model_require_integrity", True)
    
    artifact_path, _ = create_fake_model(temp_models_dir, "dga_random_forest", "v1.0.0", "original_content")
    
    registry = ModelRegistry(models_dir=temp_models_dir)
    registry.update_model_state("dga_random_forest", "v1.0.0", "LOADED", "VALID")
    
    # Tamper with the artifact
    with open(artifact_path, "a") as f:
        f.write("tampered")
        
    path, meta = registry.discover_and_validate("dga_random_forest")
    assert path is None  # Should reject
    assert meta is None
    
    status = registry.get_all_models_status()["dga_random_forest"]
    assert status["status"] == "INVALID"
    assert status["integrity"] == "FAILED"

def test_registry_fallback_behavior(temp_models_dir, monkeypatch):
    # Test that missing active_version correctly returns None, leading to fallback
    monkeypatch.setattr(settings, "model_registry_path", temp_models_dir)
    
    registry = ModelRegistry(models_dir=temp_models_dir)
    
    path, meta = registry.discover_and_validate("encrypted_xgboost")
    assert path is None
    assert meta is None
    
    # Simulate API status check
    status = registry.get_all_models_status()["encrypted_xgboost"]
    assert status["status"] == "NOT_AVAILABLE"
