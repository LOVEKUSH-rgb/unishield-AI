"""
UniShield AI -- Detector Base Models
======================================
Common models shared by ALL threat detectors.

DetectionResult, Evidence, Alert, Severity, ThreatClass,
and the BaseDetector abstract interface live here.

Design goals:
  - All detectors return the same DetectionResult shape
  - Evidence is always explicit (no black-box scores)
  - Alerts are Pydantic models -- JSON-serialisable by default
  - Severity and confidence are SEPARATE concepts

IMPORTANT: This module contains NO detection logic.
           It is a shared contract.
"""

from __future__ import annotations

import uuid
from abc import ABC, abstractmethod
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, List, Optional, Union

from pydantic import BaseModel, Field


# ================================================================
# Enumerations
# ================================================================

class Severity(str, Enum):
    """Alert severity level."""
    UNCLASSIFIED = "UNCLASSIFIED"
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


class ThreatClass(str, Enum):
    """Recognised threat categories."""
    DDOS = "DDoS"
    C2_BEACON = "C2_Beacon"
    DNS_DGA = "DNS_DGA"
    DNS_TUNNEL = "DNS_Tunnel"
    RECON = "Reconnaissance"
    EXFILTRATION = "Exfiltration"
    ENCRYPTED_ANOMALY = "EncryptedAnomaly"
    UNKNOWN = "Unknown"


# ================================================================
# Evidence
# ================================================================

class Evidence(BaseModel):
    """
    A single piece of supporting evidence for a detection.

    Every alert MUST include at least one Evidence item explaining
    WHY the alert was generated. No unexplained scores.
    """

    model_config = {"frozen": True}

    feature: str
    """Name of the feature or metric that triggered this evidence."""

    observed: Optional[Union[float, int, str]] = None
    """The actual observed value."""

    baseline: Optional[Union[float, int, str]] = None
    """The baseline/expected value (None if no baseline available)."""

    deviation: Optional[float] = None
    """
    Deviation from baseline.
    For z-score: number of standard deviations.
    For ratio: observed / baseline.
    For binary: None.
    """

    score: float = 0.0
    """Partial score contribution from this evidence item (0.0 to 1.0)."""

    detector: str = ""
    """Sub-detector that generated this evidence."""

    reason: str = ""
    """
    Human-readable explanation of why this is evidence of a threat.
    Use careful, hedged language.
    Example: "SYN rate significantly exceeds baseline, consistent with
    TCP SYN flood behavior."
    NOT: "This is a SYN flood."
    """

    def to_dict(self) -> dict:
        return {
            "feature": self.feature,
            "observed": self.observed,
            "baseline": self.baseline,
            "deviation": self.deviation,
            "score": round(self.score, 4),
            "detector": self.detector,
            "reason": self.reason,
        }


# ================================================================
# Detection Result
# ================================================================

class DetectionResult(BaseModel):
    """
    The standardised output of any detector.

    Produced by: BaseDetector.detect()
    Consumed by: AlertManager, Dashboard, Report

    Confidence vs Severity:
      - confidence: how certain is the detector (0-1, based on signal agreement)
      - severity: how bad is it IF the detection is correct
    """

    model_config = {"frozen": False}

    # Identity
    result_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    timestamp: str = Field(
        default_factory=lambda: datetime.now(tz=timezone.utc).isoformat()
    )

    # Threat classification
    threat_class: ThreatClass = ThreatClass.UNKNOWN
    sub_type: Optional[str] = None
    """More specific threat subtype (e.g. 'TCP_SYN_Flood', 'UDP_Volumetric')."""

    # Scores
    detection_score: float = 0.0
    """
    Composite detection score in [0, 1].
    0 = definitely benign, 1 = maximum threat signal.
    This is the fusion of all sub-detector scores.
    """

    confidence: float = 0.0
    """
    Confidence in the detection in [0, 1].
    Reflects agreement between independent signals.
    NOT statistically calibrated unless explicitly documented.
    """

    # Severity
    severity: Severity = Severity.UNCLASSIFIED

    # Evidence
    evidence: List[Evidence] = Field(default_factory=list)

    # Source context
    source_ip: Optional[str] = None
    destination_ip: Optional[str] = None
    source_port: Optional[int] = None
    destination_port: Optional[int] = None
    protocol: Optional[str] = None
    flow_id: Optional[str] = None

    # Lineage
    detector: Optional[str] = None
    model: Optional[str] = None
    model_version: Optional[str] = None
    ml_available: bool = False
    processing_latency: float = 0.0

    # Alert suppression
    is_suppressed: bool = False
    suppression_reason: Optional[str] = None

    # Additional metadata
    meta: Dict[str, Any] = Field(default_factory=dict)

    def add_evidence(self, ev: Evidence) -> None:
        self.evidence.append(ev)

    def is_alert(self, min_score: float = 0.35, min_confidence: float = 0.50) -> bool:
        """True if this result meets the threshold to become an alert."""
        return (
            not self.is_suppressed
            and self.detection_score >= min_score
            and self.confidence >= min_confidence
        )

    def to_dict(self) -> dict:
        return {
            "result_id": self.result_id,
            "timestamp": self.timestamp,
            "threat_class": self.threat_class.value,
            "sub_type": self.sub_type,
            "detection_score": round(self.detection_score, 4),
            "confidence": round(self.confidence, 4),
            "severity": self.severity.value if self.severity else None,
            "source_ip": self.source_ip,
            "destination_ip": self.destination_ip,
            "source_port": self.source_port,
            "destination_port": self.destination_port,
            "protocol": self.protocol,
            "flow_id": self.flow_id,
            "detector": self.detector,
            "model": self.model,
            "model_version": self.model_version,
            "ml_available": self.ml_available,
            "processing_latency": self.processing_latency,
            "evidence": [e.to_dict() for e in self.evidence],
            "is_suppressed": self.is_suppressed,
        }

    def to_summary(self) -> str:
        return (
            f"[{self.threat_class.value}] "
            f"score={self.detection_score:.3f} "
            f"confidence={self.confidence:.3f} "
            f"severity={self.severity.value if self.severity else 'N/A'} "
            f"evidence_count={len(self.evidence)}"
        )


# ================================================================
# Alert (deduplicated output)
# ================================================================

class Alert(BaseModel):
    """
    An alert is a deduplicated, actionable DetectionResult.

    Multiple DetectionResults for the same ongoing threat
    are collapsed into a single Alert with an updated last_seen
    and event_count.
    """

    model_config = {"frozen": False}

    alert_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    dedup_key: str = ""
    """Key used for deduplication: e.g. 'DDoS:SYN:192.168.1.1'"""

    threat_class: ThreatClass = ThreatClass.UNKNOWN
    sub_type: Optional[str] = None
    severity: Optional[Severity] = None
    detection_score: float = 0.0
    confidence: float = 0.0
    source_ip: Optional[str] = None
    destination_ip: Optional[str] = None
    source_port: Optional[int] = None
    destination_port: Optional[int] = None
    protocol: Optional[str] = None
    detector: Optional[str] = None
    model: Optional[str] = None
    model_version: Optional[str] = None
    ml_available: bool = False
    processing_latency: float = 0.0

    first_seen: str = Field(
        default_factory=lambda: datetime.now(tz=timezone.utc).isoformat()
    )
    last_seen: str = Field(
        default_factory=lambda: datetime.now(tz=timezone.utc).isoformat()
    )
    event_count: int = 1
    evidence: List[Evidence] = Field(default_factory=list)
    active: bool = True

    def update(self, result: DetectionResult) -> None:
        """Merge a new DetectionResult into this ongoing alert."""
        self.last_seen = result.timestamp
        self.event_count += 1
        # Keep highest score / confidence
        if result.detection_score > self.detection_score:
            self.detection_score = result.detection_score
            self.confidence = result.confidence
            self.evidence = result.evidence
            self.model = result.model
            self.model_version = result.model_version
            self.ml_available = result.ml_available
            self.processing_latency = result.processing_latency
        if result.severity and (self.severity is None or
                result.severity.value > self.severity.value):
            self.severity = result.severity

    def to_dict(self) -> dict:
        return {
            "alert_id": self.alert_id,
            "dedup_key": self.dedup_key,
            "threat_class": self.threat_class.value,
            "sub_type": self.sub_type,
            "severity": self.severity.value if self.severity else None,
            "detection_score": round(self.detection_score, 4),
            "confidence": round(self.confidence, 4),
            "source_ip": self.source_ip,
            "destination_ip": self.destination_ip,
            "source_port": self.source_port,
            "destination_port": self.destination_port,
            "protocol": self.protocol,
            "detector": self.detector,
            "model": self.model,
            "model_version": self.model_version,
            "ml_available": self.ml_available,
            "processing_latency": self.processing_latency,
            "first_seen": self.first_seen,
            "last_seen": self.last_seen,
            "event_count": self.event_count,
            "active": self.active,
            "evidence": [e.to_dict() for e in self.evidence],
        }


# ================================================================
# Severity mapping utility
# ================================================================

def score_to_severity(score: float) -> Severity:
    """
    Map a detection score to a Severity label.
    Thresholds are read from config/thresholds.yaml.
    Falls back to hardcoded defaults if config unavailable.
    """
    try:
        from src.utils.config import get_thresholds
        t = get_thresholds().get("severity", {})
        critical = float(t.get("critical_min", 0.88))
        high = float(t.get("high_min", 0.70))
        medium = float(t.get("medium_min", 0.50))
        low = float(t.get("low_min", 0.30))
    except Exception:
        critical, high, medium, low = 0.88, 0.70, 0.50, 0.30

    if score >= critical:
        return Severity.CRITICAL
    if score >= high:
        return Severity.HIGH
    if score >= medium:
        return Severity.MEDIUM
    return Severity.LOW


# ================================================================
# Base Detector interface
# ================================================================

class BaseDetector(ABC):
    """
    Abstract base class that all threat detectors must implement.

    Contract:
      - detect(fv) receives a FeatureVector
      - Returns DetectionResult
      - Must NEVER transmit packets
      - Must NEVER modify the FeatureVector
    """

    @property
    @abstractmethod
    def threat_class(self) -> ThreatClass:
        """The threat class this detector targets."""
        ...

    @abstractmethod
    def detect(self, fv: "FeatureVector") -> DetectionResult:
        """
        Analyse a FeatureVector and return a DetectionResult.

        Parameters
        ----------
        fv:
            FeatureVector from the feature pipeline.

        Returns
        -------
        DetectionResult
            score=0 means no threat detected.
        """
        ...

    def __repr__(self) -> str:
        return f"{self.__class__.__name__}(threat={self.threat_class.value})"
