import pytest
import json
from pathlib import Path
from src.features.feature_vector import FeatureVector
from src.detectors.ddos import DDoSDetector
from src.detectors.c2_beacon import C2BeaconDetector
from src.detectors.recon import ReconDetector
from src.detectors.exfiltration import ExfiltrationDetector
from src.detectors.dga_dns import DGADetector
from src.detectors.encrypted import EncryptedSessionDetector

@pytest.fixture
def edge_cases():
    cases = []
    path = Path("data/samples/phase32_edge_cases.jsonl")
    if not path.exists():
        pytest.skip(f"Edge case dataset missing: {path}")
    with open(path, "r") as f:
        for line in f:
            cases.append(FeatureVector(**json.loads(line)))
    return cases

@pytest.fixture
def detectors():
    return {
        "DDoS": DDoSDetector(),
        "Reconnaissance": ReconDetector(),
        "C2_Beacon": C2BeaconDetector(),
        "Exfiltration": ExfiltrationDetector(),
        "DNS_DGA": DGADetector(),
        "Encrypted_Anomaly": EncryptedSessionDetector()
    }

def test_detectors_robustness(detectors, edge_cases):
    """Ensure detectors never crash on malformed or extreme input."""
    for det_name, detector in detectors.items():
        for i, fv in enumerate(edge_cases):
            try:
                res = detector.detect(fv)
                assert res is not None
                assert isinstance(res.detection_score, float)
                # ML models and stats both shouldn't crash
            except Exception as e:
                pytest.fail(f"Detector {det_name} crashed on edge case {i}: {e}")

def test_statistical_fallback_robustness(detectors, edge_cases):
    """Ensure detectors don't crash when ML is explicitly disabled."""
    for det_name, detector in detectors.items():
        if hasattr(detector, "ml_enabled"):
            detector.ml_enabled = False
            
        for i, fv in enumerate(edge_cases):
            try:
                res = detector.detect(fv)
                assert res is not None
            except Exception as e:
                pytest.fail(f"Detector {det_name} crashed on edge case {i} in statistical mode: {e}")
