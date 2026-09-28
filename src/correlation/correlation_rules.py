"""
UniShield AI -- Correlation Rules
=================================
Deterministic scoring rules to evaluate if a new alert correlates with an existing incident.
"""

from datetime import datetime, timezone
from src.detectors.base import DetectionResult
from src.correlation.correlation_models import Incident

class CorrelationRules:
    def __init__(self, config: dict):
        self.cfg = config
        
        weights = self.cfg.get("weights", {})
        self.w_source = float(weights.get("source_match", 0.35))
        self.w_dest = float(weights.get("destination_match", 0.30))
        self.w_time = float(weights.get("time_proximity", 0.20))
        self.w_seq = float(weights.get("sequence_match", 0.15))
        
        self.corr_window = float(self.cfg.get("correlation_window_seconds", 3600))
        self.progression_map = self.cfg.get("detector_progression", [])

    def _calculate_time_proximity(self, alert_time: str, incident_last_seen: str) -> float:
        """
        Calculates time proximity with a linear decay over the correlation_window_seconds.
        If diff <= 300s (5 mins), score is 1.0.
        If diff >= window, score is 0.0.
        """
        try:
            t1 = datetime.fromisoformat(alert_time.replace("Z", "+00:00"))
            t2 = datetime.fromisoformat(incident_last_seen.replace("Z", "+00:00"))
            diff_sec = abs((t1 - t2).total_seconds())
        except ValueError:
            return 0.0
            
        if diff_sec <= 300:
            return 1.0
        if diff_sec >= self.corr_window:
            return 0.0
            
        # Linear decay between 300s and window
        return 1.0 - ((diff_sec - 300) / (self.corr_window - 300))
        
    def _calculate_sequence_match(self, new_threat: str, existing_threats: set) -> float:
        """
        Returns 1.0 if the new threat logically follows the existing threats 
        based on the progression map.
        """
        if new_threat not in self.progression_map:
            return 0.0
            
        new_idx = self.progression_map.index(new_threat)
        
        for ext in existing_threats:
            if ext in self.progression_map:
                ext_idx = self.progression_map.index(ext)
                if new_idx > ext_idx:
                    return 1.0
                    
        # If it doesn't strictly follow, but it's part of the sequence and we have multiple things,
        # grant partial credit for just being another stage.
        if len(existing_threats) > 0 and new_threat not in existing_threats:
            return 0.5
            
        return 0.0

    def evaluate(self, alert: DetectionResult, incident: Incident) -> float:
        """
        Returns a correlation strength [0.0 - 1.0] between an alert and an incident.
        """
        score = 0.0
        
        # Source match
        if alert.source_ip and alert.source_ip in incident.sources:
            score += self.w_source
            
        # Destination match
        if alert.destination_ip and alert.destination_ip in incident.destinations:
            score += self.w_dest
            
        # Time proximity
        time_score = self._calculate_time_proximity(alert.timestamp, incident.last_seen)
        score += (time_score * self.w_time)
        
        # Sequence / Behavioral match
        seq_score = self._calculate_sequence_match(alert.threat_class, incident.detectors)
        score += (seq_score * self.w_seq)
        
        return min(1.0, score)
