"""
Tests for Unified Risk Engine (Phase 10).
"""

import pytest
from datetime import datetime, timezone, timedelta

from src.detectors.base import DetectionResult, ThreatClass
from src.correlation.correlation_models import Incident
from src.risk.risk_engine import RiskEngine

@pytest.fixture
def risk_engine():
    return RiskEngine()

def _mock_alert(threat_class, severity="MEDIUM", confidence=0.70, meta=None):
    return DetectionResult(
        result_id="mock-id",
        timestamp=datetime.now(timezone.utc).isoformat(),
        threat_class=threat_class,
        source_ip="10.0.0.1",
        destination_ip="1.1.1.1",
        detection_score=0.9,
        confidence=confidence,
        severity=severity,
        meta=meta or {}
    )

def test_scenario_a_single_medium_alert(risk_engine):
    # DGA alert, confidence 0.70, severity MEDIUM -> Medium-ish risk.
    inc = Incident(incident_id="INC-1")
    alert = _mock_alert(ThreatClass.DNS_DGA, "MEDIUM", 0.70)
    inc.add_alert(alert, strength=0.0, progression_map=[])
    
    risk_engine.update_risk(inc)
    
    # Base MEDIUM is 30.
    # Confidence adjustment: (0.70 - 0.75) * 20 = -1.0.
    # Total = 29 -> LOW risk (20-39).
    assert 20 <= inc.risk_score <= 39
    assert inc.risk_level == "LOW"
    assert inc.priority == "P4"

def test_scenario_b_correlated_alerts(risk_engine):
    # Recon + DGA + C2 same source short window -> High risk
    inc = Incident(incident_id="INC-2")
    inc.correlation_strength = 0.90 # simulates tight correlation
    
    inc.add_alert(_mock_alert(ThreatClass.RECON, "LOW", 0.8), strength=0.9, progression_map=["Reconnaissance", "DNS_DGA", "C2_Beacon"])
    inc.add_alert(_mock_alert(ThreatClass.DNS_DGA, "MEDIUM", 0.8), strength=0.9, progression_map=["Reconnaissance", "DNS_DGA", "C2_Beacon"])
    inc.add_alert(_mock_alert(ThreatClass.C2_BEACON, "HIGH", 0.8), strength=0.9, progression_map=["Reconnaissance", "DNS_DGA", "C2_Beacon"])
    
    risk_engine.update_risk(inc)
    
    # Base HIGH = 45. Corroboration = 2 * 12 = 24. 
    # Temp Bonus = 0.9 * 10 = 9. Prog Bonus = 2 * 5 = 10. 
    # Total = 45 + 24 + 9 + 10 + 1 (conf) = 89 (CRITICAL)
    assert inc.risk_score > 60
    assert inc.risk_level in ["HIGH", "CRITICAL"]

def test_scenario_c_full_progression(risk_engine):
    # Recon -> DGA -> C2 -> Encrypted -> Exfil -> CRITICAL
    inc = Incident(incident_id="INC-3")
    inc.correlation_strength = 1.0
    
    progression = ["Reconnaissance", "DNS_DGA", "C2_Beacon", "EncryptedAnomaly", "Exfiltration"]
    inc.add_alert(_mock_alert(ThreatClass.RECON, "LOW", 0.9), strength=1.0, progression_map=progression)
    inc.add_alert(_mock_alert(ThreatClass.DNS_DGA, "MEDIUM", 0.9), strength=1.0, progression_map=progression)
    inc.add_alert(_mock_alert(ThreatClass.C2_BEACON, "HIGH", 0.9), strength=1.0, progression_map=progression)
    inc.add_alert(_mock_alert(ThreatClass.ENCRYPTED_ANOMALY, "HIGH", 0.9), strength=1.0, progression_map=progression)
    inc.add_alert(_mock_alert(ThreatClass.EXFILTRATION, "CRITICAL", 0.9), strength=1.0, progression_map=progression)
    
    risk_engine.update_risk(inc)
    
    assert inc.risk_level == "CRITICAL"
    assert inc.priority == "P1"
    assert inc.risk_score >= 80

def test_scenario_d_unrelated_mediums(risk_engine):
    # Two unrelated medium alerts from different sources don't exist in same incident due to Phase 9.
    # But if they somehow did with low correlation strength (e.g. 0.0), it shouldn't hit critical.
    inc = Incident(incident_id="INC-4")
    inc.correlation_strength = 0.0
    
    inc.add_alert(_mock_alert(ThreatClass.DNS_DGA, "MEDIUM", 0.70), strength=0.0, progression_map=[])
    inc.add_alert(_mock_alert(ThreatClass.DNS_DGA, "MEDIUM", 0.70), strength=0.0, progression_map=[])
    
    risk_engine.update_risk(inc)
    
    # Base = 30. Corroboration = 0 (same detector). Temp = 0. Prog = 0.
    assert inc.risk_level in ["LOW", "MEDIUM"]

def test_scenario_e_exfiltration_insufficient_baseline(risk_engine):
    # Single exfil event with insufficient baseline -> Risk penalty
    inc = Incident(incident_id="INC-5")
    alert = _mock_alert(ThreatClass.EXFILTRATION, "HIGH", 0.75, meta={"baseline_quality": "BASELINE_INSUFFICIENT"})
    inc.add_alert(alert, strength=0.0, progression_map=[])
    
    risk_engine.update_risk(inc)
    
    # Base HIGH = 45. Conf = 0. Meta penalty = -10. Total = 35 (LOW).
    assert inc.risk_score == 35.0
    
def test_risk_history_tracking(risk_engine):
    inc = Incident(incident_id="INC-6")
    alert1 = _mock_alert(ThreatClass.DNS_DGA, "LOW", 0.75)
    inc.add_alert(alert1, strength=0.0, progression_map=[])
    
    risk_engine.update_risk(inc)
    assert len(inc.risk_history) == 1
    
    alert2 = _mock_alert(ThreatClass.C2_BEACON, "CRITICAL", 0.90)
    inc.add_alert(alert2, strength=0.8, progression_map=[])
    risk_engine.update_risk(inc)
    
    assert len(inc.risk_history) == 2
    assert inc.risk_history[0]["score"] < inc.risk_history[1]["score"]
