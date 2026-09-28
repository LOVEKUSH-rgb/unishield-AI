"""
UniShield AI -- Correlation Models
==================================
Defines the structure for Correlated Security Incidents.
"""

from typing import List, Dict, Set, Optional, Any
from dataclasses import dataclass, field
from datetime import datetime, timezone

from src.detectors.base import DetectionResult

@dataclass
class RiskFactor:
    factor: str
    contribution: float

@dataclass
class Incident:
    incident_id: str
    status: str = "NEW"
    
    first_seen: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    last_seen: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    
    # Core correlated entities
    sources: Set[str] = field(default_factory=set)
    destinations: Set[str] = field(default_factory=set)
    
    # Associated alerts
    alerts: List[DetectionResult] = field(default_factory=list)
    
    # Metadata
    detectors: Set[str] = field(default_factory=set)
    potential_progression: List[str] = field(default_factory=list)
    correlation_strength: float = 0.0
    
    # Risk Engine Fields
    risk_score: float = 0.0
    risk_level: str = "INFORMATIONAL"
    priority: str = "P4"
    risk_factors: List[RiskFactor] = field(default_factory=list)
    risk_history: List[Dict[str, Any]] = field(default_factory=list)
    
    # Human readable summary
    explanation: str = ""

    def add_alert(self, alert: DetectionResult, strength: float, progression_map: List[str]):
        """
        Merge a new alert into this incident.
        """
        self.alerts.append(alert)
        self.last_seen = max(self.last_seen, alert.timestamp)
        self.first_seen = min(self.first_seen, alert.timestamp)
        
        if alert.source_ip:
            self.sources.add(alert.source_ip)
        if alert.destination_ip:
            self.destinations.add(alert.destination_ip)
            
        self.detectors.add(alert.threat_class)
        
        # Max out correlation strength
        self.correlation_strength = max(self.correlation_strength, strength)
        
        # Update progression based on defined chronological map
        prog = []
        for stage in progression_map:
            if stage in self.detectors:
                prog.append(stage)
        self.potential_progression = prog
        
        # Update explanation
        self._generate_explanation()
        
    def _generate_explanation(self):
        source_str = "a single source" if len(self.sources) == 1 else f"{len(self.sources)} sources"
        
        self.explanation = (
            f"Suspicious observations associated with {source_str} occurred within a correlated time window. "
            f"The observations include: {', '.join(self.detectors)}."
        )
        if len(self.sources) > 1:
            self.explanation += " This represents potential coordinated activity across multiple internal hosts."

    def to_dict(self) -> Dict[str, Any]:
        return {
            "incident_id": self.incident_id,
            "status": self.status,
            "first_seen": self.first_seen,
            "last_seen": self.last_seen,
            "sources": list(self.sources),
            "destinations": list(self.destinations),
            "alerts": [a.to_dict() for a in self.alerts],
            "detectors": list(self.detectors),
            "potential_progression": self.potential_progression,
            "correlation_strength": round(self.correlation_strength, 2),
            "risk_score": round(self.risk_score, 1),
            "risk_level": self.risk_level,
            "priority": self.priority,
            "risk_factors": [{"factor": f.factor, "contribution": round(f.contribution, 1)} for f in self.risk_factors],
            "risk_history": self.risk_history,
            "explanation": self.explanation
        }
