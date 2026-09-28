"""
Tests for Encrypted Session Detector and SPLT boundaries.
"""

import math
import pytest
from src.features.feature_vector import FeatureVector
from src.detectors.encrypted import EncryptedSessionDetector
from src.models.training.encrypted_train import EncryptedSessionModel

# We mock the EncryptedSessionModel to return fixed scores based on fv characteristics
# to avoid needing a real trained model file during unit tests.
class MockEncryptedModel(EncryptedSessionModel):
    def __init__(self, cfg=None):
        super().__init__(cfg)
        self.model = True  # Mock ready state
        self.model_type = "mock"
        
    def is_ready(self):
        return True
        
    def score(self, fv):
        # A simple deterministic scoring for testing
        pkts = fv.get("packet_count", 0)
        
        # We pretend flows > 100 packets with no SNI are highly suspicious
        if pkts > 100 and fv.get("tls_has_sni", 0) == 0:
            return 0.95
            
        # Benign-looking flow
        if pkts < 50 and fv.get("tls_has_sni", 0) == 1:
            return 0.10
            
        # Middle ground
        return 0.50


@pytest.fixture
def detector(monkeypatch):
    # Monkeypatch the model with our mock
    monkeypatch.setattr("src.detectors.encrypted.EncryptedSessionModel", MockEncryptedModel)
    return EncryptedSessionDetector({
        "ml": {"enabled": True},
        "min_score_to_alert": 0.60,
        "min_confidence_to_alert": 0.50,
        "splt_max_sequence_length": 20
    })


def create_tls_fv(pkts=10, has_sni=1, has_ja3=1, splt_len=20, is_tls=True):
    fv = FeatureVector(flow_id="f1", source_ip="10.0.0.1", destination_ip="1.1.1.1")
    if is_tls:
        fv.update("tls", {
            "tls_version_known": 1,
            "tls_has_sni": has_sni,
            "tls_has_ja3": has_ja3
        })
        
    fv.features["packet_count"] = pkts
    fv.features["splt_sizes"] = [500] * splt_len
    fv.features["splt_times"] = [0.1] * splt_len
    return fv


def test_non_tls_flow_ignored(detector):
    fv = create_tls_fv(is_tls=False)
    res = detector.detect(fv)
    assert res.is_suppressed
    assert res.detection_score == 0.0


def test_benign_tls_flow(detector):
    # pkts < 50, has SNI -> score 0.10
    fv = create_tls_fv(pkts=10, has_sni=1, has_ja3=1)
    res = detector.detect(fv)
    assert res.is_suppressed
    assert res.detection_score == 0.10


def test_suspicious_flow_high_quality(detector):
    # pkts > 100, no SNI -> score 0.95
    # Quality: 0.4 (version) + 0.0 (no sni) + 0.15 (ja3) + 0.15 (splt) = 0.70
    # Confidence: 0.95 * 0.70 = 0.665
    # Both > thresholds (0.60, 0.50), should alert!
    fv = create_tls_fv(pkts=150, has_sni=0, has_ja3=1, splt_len=10)
    res = detector.detect(fv)
    
    assert not res.is_suppressed
    assert res.detection_score == 0.95
    assert math.isclose(res.confidence, 0.665)
    
    # Evidence should exist
    assert any(e.feature == "ml_classification_score" for e in res.evidence)
    
    # Metadata quality should be 0.70
    assert math.isclose(res.meta["metadata_quality_score"], 0.70)


def test_suspicious_flow_low_quality(detector):
    # pkts > 100, no SNI -> score 0.95
    # Quality: 0.4 (version) + 0.0 (no sni) + 0.0 (no ja3) + 0.0 (short splt) = 0.40
    # Confidence: 0.95 * 0.40 = 0.38
    # Confidence < 0.50, should be suppressed!
    fv = create_tls_fv(pkts=150, has_sni=0, has_ja3=0, splt_len=2)
    res = detector.detect(fv)
    
    assert res.is_suppressed
    assert math.isclose(res.meta["metadata_quality_score"], 0.40)
    assert math.isclose(res.confidence, 0.38)


def test_ml_disabled(detector):
    detector.ml_enabled = False
    fv = create_tls_fv(pkts=150, has_sni=0, has_ja3=1)
    res = detector.detect(fv)
    assert res.is_suppressed
