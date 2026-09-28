"""
UniShield AI -- Persistence Tests
=================================
Tests that the Repositories and ORM properly save/load domain objects.
"""

import pytest
import datetime
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from src.persistence.models import Base
from src.persistence.repositories import AlertRepository, IncidentRepository
from src.detectors.base import DetectionResult, Evidence, Severity, ThreatClass
from src.correlation.correlation_models import Incident
from src.persistence.state_manager import StateManager

@pytest.fixture(scope="module")
def engine():
    engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(engine)
    yield engine

@pytest.fixture
def db_session(engine):
    Session = sessionmaker(bind=engine)
    session = Session()
    yield session
    session.rollback()
    session.close()

def test_alert_repository_save_and_retrieve(db_session):
    repo = AlertRepository(db_session)
    
    alert = DetectionResult(
        result_id="ALT-001",
        timestamp=datetime.datetime.now(datetime.timezone.utc).isoformat(),
        threat_class=ThreatClass.C2_BEACON,
        sub_type="Test",
        detection_score=0.9,
        confidence=0.8,
        severity=Severity.HIGH,
        detector="test_detector",
        evidence=[
            Evidence(feature="conn_count", observed=100, score=0.9)
        ]
    )
    
    repo.save(alert)
    
    recent = repo.get_recent(limit=10)
    assert len(recent) == 1
    assert recent[0].result_id == "ALT-001"
    assert recent[0].threat_class == ThreatClass.C2_BEACON
    assert len(recent[0].evidence) == 1
    assert recent[0].evidence[0].feature == "conn_count"
    assert float(recent[0].evidence[0].observed) == 100.0

def test_incident_repository_save_and_retrieve(db_session):
    alert_repo = AlertRepository(db_session)
    inc_repo = IncidentRepository(db_session, alert_repo)
    
    inc = Incident(incident_id="INC-001")
    inc.risk_score = 75.0
    inc.risk_level = "HIGH"
    inc.sources.add("10.0.0.1")
    
    # Add an alert to the incident
    alert = DetectionResult(
        result_id="ALT-002",
        timestamp=datetime.datetime.now(datetime.timezone.utc).isoformat(),
        threat_class=ThreatClass.C2_BEACON,
        sub_type=None,
        detection_score=0.9,
        confidence=0.8,
        severity=Severity.HIGH,
        detector="test",
        evidence=[]
    )
    
    inc.alerts.append(alert)
    
    inc_repo.save(inc)
    
    active = inc_repo.get_active()
    assert len(active) == 1
    
    loaded = inc_repo.get_by_id("INC-001")
    assert loaded is not None
    assert loaded.risk_score == 75.0
    assert "10.0.0.1" in loaded.sources
    assert len(loaded.alerts) == 1
    assert loaded.alerts[0].result_id == "ALT-002"

def test_state_manager(monkeypatch):
    monkeypatch.setenv("REDIS_URL", "redis://invalid:6379/0") # Will fallback to fakeredis
    
    mgr = StateManager()
    mgr.reset()
    
    state = mgr.get_state()
    assert state["status"] == "STOPPED"
    
    state["status"] = "PLAYING"
    state["packets_processed"] = 500
    mgr.set_state(state)
    
    new_state = mgr.get_state()
    assert new_state["status"] == "PLAYING"
    assert new_state["packets_processed"] == 500
    
    threats = mgr.get_threats()
    assert threats["DDoS"] == 0
    threats["DDoS"] = 5
    mgr.set_threats(threats)
    
    new_threats = mgr.get_threats()
    assert new_threats["DDoS"] == 5
