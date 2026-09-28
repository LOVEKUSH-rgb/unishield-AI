"""
Tests for Phase 22 ML Runtime, Registry, and Pipeline integration.
"""

import pytest
import os
import json
from src.features.feature_vector import FeatureVector
from src.models.registry import ModelRegistry
from src.detectors.dga_dns import DGADetector
from src.detectors.encrypted import EncryptedSessionDetector

@pytest.fixture
def mock_registry_dir(tmp_path):
    d = tmp_path / "models"
    d.mkdir()
    
    # Create mock DGA artifact
    meta = {
        "model_name": "DGARandomForest",
        "model_type": "random_forest",
        "model_version": "v1.0.0",
        "feature_schema_version": "v1",
        "features": ["dns_query_length", "dns_entropy"],
        "artifact": "dga_rf.pkl",
        "sha256": "ddbc24f1ac507d3773cfb582985c9f7e762ddaba36fb7b7a244ead74132bba4e"
    }
    
    # State file
    state = {
        "dga": {
            "active_version": "v1.0.0",
            "status": "LOADED",
            "integrity": "VALID"
        }
    }
    with open(d / "registry_state.json", "w") as f:
        json.dump(state, f)
        
    model_dir = d / "dga" / "v1.0.0"
    model_dir.mkdir(parents=True)
    
    with open(model_dir / "manifest.json", "w") as f:
        json.dump(meta, f)
    with open(model_dir / "dga_rf.pkl", "wb") as f:
        f.write(b"mock_pkl_data")
        
    return str(d)

def test_registry_load_success(mock_registry_dir, monkeypatch):
    from src.utils.config import settings
    monkeypatch.setattr(settings, "model_require_integrity", False)
    
    registry = ModelRegistry(models_dir=mock_registry_dir)
    path, meta = registry.discover_and_validate("dga", preferred_type="xgboost")
    
    assert path is not None
    assert path.endswith("dga_rf.pkl")
    assert meta["model_name"] == "DGARandomForest"
    assert registry.active_models["dga"]["type"] == "random_forest"

def test_registry_schema_mismatch(mock_registry_dir):
    # Alter schema version
    meta_path = os.path.join(mock_registry_dir, "dga", "v1.0.0", "manifest.json")
    with open(meta_path, "r") as f:
        meta = json.load(f)
    meta["feature_schema_version"] = "v2"
    with open(meta_path, "w") as f:
        json.dump(meta, f)
        
    registry = ModelRegistry(models_dir=mock_registry_dir)
    path, meta_out = registry.discover_and_validate("dga", preferred_type="random_forest")
    
    assert path is None
    assert "dga" not in registry.active_models

def test_dga_statistical_fallback():
    # If ML model fails to load, it should fallback to statistical detection
    # We pass an empty config which means ML won't find the models in standard path if they are not there,
    # or we can explicitly disable it. Let's just instantiate and check ml_enabled.
    detector = DGADetector({"ml": {"enabled": False}})
    assert detector.ml_enabled == False
    
    fv = FeatureVector(
        source_ip="10.0.0.1",
        destination_ip="8.8.8.8",
        destination_port=53
    )
    fv.set("dns_is_query", True)
    fv.set("dns_query_length", 40)
    fv.set("dns_entropy", 4.5)
    fv.set("dns_ngram_entropy", 4.0)
    fv.set("dns_digit_ratio", 0.5)
    fv.set("dns_unique_char_count", 25)
    
    result = detector.detect(fv)
    
    # Should flag as DGA even without ML
    assert result.detection_score > 0.5
    assert not result.is_suppressed
    assert result.ml_available == False
    assert result.detector == "statistical_dga"

def test_encrypted_statistical_fallback():
    # Similar test for Encrypted session
    detector = EncryptedSessionDetector({"ml": {"enabled": False}})
    
    fv = FeatureVector(
        source_ip="10.0.0.1",
        destination_ip="10.0.0.2",
        destination_port=443
    )
    fv.set("tls_version_known", True)
    fv.set("packet_count", 50)
    fv.set("byte_count", 25000)
    fv.set("tls_has_sni", False)
    
    result = detector.detect(fv)
    assert not result.is_suppressed
    assert result.detector == "encrypted_statistical"
