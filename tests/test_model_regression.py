"""
UniShield AI -- Model Regression Tests
======================================
Ensures that ML models loaded via the registry do not regress below
acceptable F1 and FPR thresholds.
"""

import pytest
import os
import numpy as np

try:
    from sklearn.metrics import f1_score, confusion_matrix
    SKLEARN_AVAILABLE = True
except ImportError:
    SKLEARN_AVAILABLE = False

from src.models.registry import registry
from src.features.feature_vector import FeatureVector

pytestmark = pytest.mark.skipif(not SKLEARN_AVAILABLE, reason="scikit-learn not available")

@pytest.fixture
def mock_dga_fv():
    return FeatureVector(
        source_ip="10.0.0.5",
        destination_ip="1.1.1.1",
        destination_port=53,
        dns_is_query=True,
        dns_query_length=45,
        dns_entropy=4.8,
        dns_ngram_entropy=4.1,
        dns_digit_ratio=0.35,
        dns_unique_char_count=28,
        dns_alpha_ratio=0.6,
        dns_hyphen_ratio=0.05
    )

@pytest.fixture
def mock_benign_dns_fv():
    return FeatureVector(
        source_ip="10.0.0.5",
        destination_ip="1.1.1.1",
        destination_port=53,
        dns_is_query=True,
        dns_query_length=15,
        dns_entropy=2.8,
        dns_ngram_entropy=2.5,
        dns_digit_ratio=0.0,
        dns_unique_char_count=10,
        dns_alpha_ratio=1.0,
        dns_hyphen_ratio=0.0
    )


def test_dga_model_regression(mock_dga_fv, mock_benign_dns_fv):
    """
    Validates that the active DGA model correctly scores obvious DGA > 0.5
    and obvious Benign < 0.5. Checks metadata existence.
    """
    path, meta = registry.discover_and_validate("dga", preferred_type="random_forest")
    if not path:
        pytest.skip("No DGA model found in registry.")
        
    # Lazy load the detector to avoid heavy imports globally
    from src.models.training.dga_train import DGARandomForest
    model = DGARandomForest()
    
    assert model.is_ready()
    
    # Obvious DGA should score high
    dga_score = model.score(mock_dga_fv)
    assert dga_score is not None
    assert dga_score > 0.6
    
    # Obvious Benign should score low
    benign_score = model.score(mock_benign_dns_fv)
    assert benign_score is not None
    assert benign_score < 0.4
    
    # Metadata assertion
    assert model.metadata is not None
    assert "metrics" in model.metadata
    metrics = model.metadata["metrics"]
    
    # Lock in acceptable thresholds to prevent regression
    assert metrics.get("f1", 0) > 0.85
    assert metrics.get("roc_auc", 0) > 0.90


def test_encrypted_session_regression():
    """
    Validates the encrypted session model's metadata metrics.
    """
    path, meta = registry.discover_and_validate("encrypted", preferred_type="xgboost")
    if not path:
        pytest.skip("No Encrypted model found in registry.")
        
    assert meta is not None
    assert "metrics" in meta
    metrics = meta["metrics"]
    
    # Lock in acceptable thresholds to prevent regression
    assert metrics.get("f1", 0) > 0.85
    assert metrics.get("roc_auc", 0) > 0.90
