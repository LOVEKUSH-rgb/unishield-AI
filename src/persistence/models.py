"""
UniShield AI -- ORM Models
==========================
Defines the database schema using SQLAlchemy.
"""

from sqlalchemy import Column, String, Float, Integer, Boolean, ForeignKey, DateTime, JSON, Text
from sqlalchemy.orm import relationship
import datetime

from src.persistence.database import Base

class IncidentModel(Base):
    __tablename__ = "incidents"
    
    id = Column(String, primary_key=True, index=True)
    correlation_id = Column(String, index=True, nullable=True)
    status = Column(String, default="NEW", index=True)
    risk_score = Column(Float, default=0.0)
    risk_level = Column(String, default="LOW", index=True)
    first_seen = Column(DateTime(timezone=True), default=datetime.datetime.utcnow)
    last_seen = Column(DateTime(timezone=True), default=datetime.datetime.utcnow)
    
    # Store lists as JSON for simplicity in SQLite/Postgres
    sources = Column(JSON, default=list)
    destinations = Column(JSON, default=list)
    detectors = Column(JSON, default=list)
    potential_progression = Column(JSON, default=list)
    
    alerts = relationship("AlertModel", secondary="incident_alerts", back_populates="incidents")


class AlertModel(Base):
    __tablename__ = "alerts"
    
    id = Column(String, primary_key=True, index=True)
    correlation_id = Column(String, index=True, nullable=True)
    timestamp = Column(DateTime(timezone=True), default=datetime.datetime.utcnow, index=True)
    threat_class = Column(String, index=True)
    sub_type = Column(String, nullable=True)
    detection_score = Column(Float)
    confidence = Column(Float)
    severity = Column(String, index=True)
    detector = Column(String)
    model = Column(String, nullable=True)
    model_version = Column(String, nullable=True)
    ml_available = Column(Boolean, default=False)
    processing_latency = Column(Float, default=0.0)
    
    source_ip = Column(String, index=True, nullable=True)
    destination_ip = Column(String, index=True, nullable=True)
    source_port = Column(Integer, nullable=True)
    destination_port = Column(Integer, nullable=True)
    protocol = Column(String, nullable=True)
    flow_id = Column(String, index=True, nullable=True)
    
    is_suppressed = Column(Boolean, default=False)
    suppression_reason = Column(String, nullable=True)
    meta_data = Column(JSON, default=dict)
    
    incidents = relationship("IncidentModel", secondary="incident_alerts", back_populates="alerts")
    evidence = relationship("EvidenceModel", back_populates="alert", cascade="all, delete-orphan")


class IncidentAlertModel(Base):
    __tablename__ = "incident_alerts"
    
    incident_id = Column(String, ForeignKey("incidents.id"), primary_key=True)
    alert_id = Column(String, ForeignKey("alerts.id"), primary_key=True)
    correlation_strength = Column(Float, default=1.0)


class EvidenceModel(Base):
    __tablename__ = "evidence"
    
    id = Column(Integer, primary_key=True, autoincrement=True)
    alert_id = Column(String, ForeignKey("alerts.id", ondelete="CASCADE"), index=True)
    
    feature = Column(String)
    observed = Column(String)
    baseline = Column(String, nullable=True)
    deviation = Column(Float, nullable=True)
    score = Column(Float, nullable=True)
    detector = Column(String, nullable=True)
    reason = Column(Text, nullable=True)
    
    alert = relationship("AlertModel", back_populates="evidence")

class User(Base):
    __tablename__ = "users"

    username = Column(String(50), primary_key=True, index=True)
    password_hash = Column(String(255), nullable=False)
    role = Column(String(20), nullable=False, default="viewer") # roles: viewer, analyst, admin
    active = Column(Boolean, default=True, nullable=False)
