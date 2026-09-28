"""
Tests for Phase 20 API extensions.
"""

import pytest
from fastapi.testclient import TestClient
from src.api.app import app, get_db
from src.persistence.database import Base
from src.persistence.models import AlertModel, IncidentModel
import datetime
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool
import uuid

# Setup file-based SQLite for testing to avoid FastAPI thread-sharing issues
import os
SQLALCHEMY_DATABASE_URL = "sqlite:///./test_api.db"
if os.path.exists("./test_api.db"):
    os.remove("./test_api.db")

engine = create_engine(
    SQLALCHEMY_DATABASE_URL, 
    connect_args={"check_same_thread": False}
)
TestingSessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

def override_get_db():
    try:
        db = TestingSessionLocal()
        yield db
    finally:
        db.close()

app.dependency_overrides[get_db] = override_get_db

client = TestClient(app)

@pytest.fixture(scope="module", autouse=True)
def setup_db():
    Base.metadata.create_all(bind=engine)
    db = TestingSessionLocal()
    
    # Add mock alerts
    a1 = AlertModel(
        id=str(uuid.uuid4()),
        timestamp=datetime.datetime.now(),
        threat_class="DDoS",
        severity="HIGH",
        detector="DDoSDetector",
        confidence=0.9,
        detection_score=0.9,
        source_ip="1.2.3.4",
        ml_available=False,
        processing_latency=1.5
    )
    a2 = AlertModel(
        id=str(uuid.uuid4()),
        timestamp=datetime.datetime.now(),
        threat_class="C2_Beacon",
        severity="CRITICAL",
        detector="C2BeaconDetector",
        confidence=0.85,
        detection_score=0.85,
        source_ip="5.6.7.8",
        ml_available=True,
        processing_latency=2.0
    )
    
    # Add mock incident
    inc = IncidentModel(
        id=str(uuid.uuid4()),
        status="NEW",
        risk_score=95,
        risk_level="CRITICAL",
        sources=["5.6.7.8"],
        destinations=["8.8.8.8"],
        detectors=["C2BeaconDetector"]
    )
    
    db.add(a1)
    db.add(a2)
    db.add(inc)
    db.commit()
    
    yield
    
    db.query(AlertModel).delete()
    db.query(IncidentModel).delete()
    db.commit()
    db.close()
    if os.path.exists("./test_api.db"):
        try:
            os.remove("./test_api.db")
        except:
            pass


def test_get_alerts_filtered():
    res = client.get("/alerts?source_ip=1.2.3.4")
    assert res.status_code == 200
    data = res.json()
    assert len(data) == 1
    assert data[0]["source_ip"] == "1.2.3.4"
    
    res = client.get("/alerts?severity=CRITICAL")
    assert res.status_code == 200
    data = res.json()
    assert len(data) == 1
    assert data[0]["threat_class"] == "C2_Beacon"

def test_get_incidents_filtered():
    res = client.get("/incidents?source_ip=5.6.7.8")
    assert res.status_code == 200
    data = res.json()
    assert len(data) == 1
    assert data[0]["risk_level"] == "CRITICAL"
    assert "5.6.7.8" in data[0]["sources"]

def test_get_analytics_detectors():
    res = client.get("/analytics/detectors")
    assert res.status_code == 200
    data = res.json()
    assert len(data) == 2
    for item in data:
        if item["detector"] == "DDoSDetector":
            assert item["count"] == 1
            assert item["uses_ml"] is False
        elif item["detector"] == "C2BeaconDetector":
            assert item["count"] == 1
            assert item["uses_ml"] is True
