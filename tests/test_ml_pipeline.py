"""
UniShield AI -- ML Pipeline Tests
=================================
Tests that the feature extraction schemas match the ML models,
preventing model breakage during inference.
"""

import pytest
import os
import numpy as np
from src.features.feature_vector import FeatureVector
from src.models.training.encrypted_train import EncryptedSessionModel
from src.models.training.dga_train import DGARandomForest

def test_encrypted_session_feature_contract():
    fv = FeatureVector(flow_id="test", source_ip="1.2.3.4", destination_ip="4.3.2.1", source_port=123, destination_port=443, protocol=6)
    
    # We must mark it as having TLS for extraction to run
    fv.update("tls", {"tls_version_known": 1.0})
    
    model = EncryptedSessionModel()
    
    # If XGBoost model doesn't exist, we skip validation of the loaded object but test the extraction
    x = model._extract_features(fv)
    
    assert x is not None
    # 12 statistical + 20 sizes + 20 times = 52 features
    expected_length = len(model.STAT_FEATURES) + (2 * model.splt_max_seq)
    assert x.shape[1] == expected_length

def test_dga_feature_contract():
    fv = FeatureVector(flow_id="test", source_ip="1.2.3.4", destination_ip="4.3.2.1", source_port=123, destination_port=53, protocol=17)
    
    # Mark as query
    fv.update("dns", {"dns_is_query": 1.0})
    
    model = DGARandomForest()
    
    x = model._extract_features(fv)
    
    assert x is not None
    assert x.shape[1] == len(model.FEATURE_NAMES)
