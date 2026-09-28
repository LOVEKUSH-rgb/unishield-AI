"""
UniShield AI -- Correlation Engine
==================================
Orchestrates rule evaluation, incident creation, deduplication, and merging.
"""

import uuid
from typing import Dict, List, Optional
from datetime import datetime, timezone

from src.detectors.base import DetectionResult
from src.correlation.correlation_models import Incident
from src.correlation.correlation_rules import CorrelationRules
from src.utils.config import get_thresholds
from src.utils.logging import get_logger

logger = get_logger(__name__)

class CorrelationEngine:
    def __init__(self, config_overrides: dict = None):
        cfg = get_thresholds().get("correlation", {})
        if config_overrides:
            cfg.update(config_overrides)
            
        self.rules = CorrelationRules(cfg)
        self.merge_threshold = float(cfg.get("merge_threshold", 0.60))
        self.multi_host_threshold = float(cfg.get("multi_host_threshold", 0.85))
        self.dedup_window = float(cfg.get("deduplication_window_seconds", 300))
        
        # In-memory prototype store
        self.active_incidents: Dict[str, Incident] = {}
        self.incident_counter = 1
        
        self.max_incident_age = float(cfg.get("max_incident_age_seconds", 86400)) # 24h default
        self._last_processed_time = 0.0

    def _generate_incident_id(self) -> str:
        year = datetime.now(timezone.utc).year
        iid = f"INC-{year}-{self.incident_counter:06d}"
        self.incident_counter += 1
        return iid
        
    def _is_duplicate(self, alert: DetectionResult, incident: Incident) -> bool:
        """
        Check if an alert is just a rapid repeat of the same threat 
        class on the same source/dest within the deduplication window.
        """
        for ext in reversed(incident.alerts):
            if ext.threat_class == alert.threat_class and ext.source_ip == alert.source_ip and ext.destination_ip == alert.destination_ip:
                try:
                    t1 = datetime.fromisoformat(alert.timestamp.replace("Z", "+00:00"))
                    t2 = datetime.fromisoformat(ext.timestamp.replace("Z", "+00:00"))
                    diff_sec = abs((t1 - t2).total_seconds())
                    if diff_sec <= self.dedup_window:
                        return True
                except ValueError:
                    pass
        return False

    def expire_incidents(self) -> int:
        """
        Removes incidents that have not seen new alerts within max_incident_age.
        This provides bounded memory for sustained streaming.
        Returns the number of incidents evicted.
        """
        expired = []
        for inc_id, inc in self.active_incidents.items():
            try:
                # inc.last_seen is an ISO format string like "2026-08-28T18:36:16.701Z"
                t = datetime.fromisoformat(inc.last_seen.replace("Z", "+00:00")).timestamp()
                if self._last_processed_time - t > self.max_incident_age:
                    expired.append(inc_id)
            except Exception:
                pass
                
        for inc_id in expired:
            del self.active_incidents[inc_id]
            
        if expired:
            logger.info(f"Evicted {len(expired)} stale incidents to bound memory.")
        return len(expired)

    def correlate_alert(self, alert: DetectionResult) -> Optional[Incident]:
        """
        Processes a new alert, trying to merge it into an existing incident,
        or creating a new one if no strong correlation exists.
        Returns the affected Incident.
        """
        try:
            alert_t = datetime.fromisoformat(alert.timestamp.replace("Z", "+00:00")).timestamp()
            self._last_processed_time = max(self._last_processed_time, alert_t)
            # Run eviction every time the high-water mark moves forward significantly, or just inline.
            # To avoid huge overhead, we could do this periodically, but for now we do it inline.
            self.expire_incidents()
        except ValueError:
            pass

        if alert.is_suppressed:
            return None
            
        best_incident = None
        best_score = 0.0
        
        # Find best match
        for inc_id, inc in self.active_incidents.items():
            if self._is_duplicate(alert, inc):
                # Update last_seen but do not append the full duplicate
                inc.last_seen = max(inc.last_seen, alert.timestamp)
                return inc
                
            score = self.rules.evaluate(alert, inc)
            if score > best_score:
                best_score = score
                best_incident = inc
                
        # Decide action based on score
        if best_incident and best_score >= self.merge_threshold:
            # Multi-host safety check: if sources differ, require a strictly higher threshold
            if alert.source_ip and alert.source_ip not in best_incident.sources:
                if best_score >= self.multi_host_threshold:
                    best_incident.add_alert(alert, best_score, self.rules.progression_map)
                    logger.info(f"Merged alert {alert.threat_class} into {best_incident.incident_id} (Multi-Host Correlation)")
                    return best_incident
            else:
                best_incident.add_alert(alert, best_score, self.rules.progression_map)
                logger.info(f"Merged alert {alert.threat_class} into {best_incident.incident_id} (Score: {best_score:.2f})")
                return best_incident
                
        # If no strong match, create new incident
        new_id = self._generate_incident_id()
        new_inc = Incident(incident_id=new_id)
        new_inc.add_alert(alert, strength=1.0, progression_map=self.rules.progression_map)
        
        self.active_incidents[new_id] = new_inc
        logger.info(f"Created new incident {new_id} from alert {alert.threat_class}")
        return new_inc

    def get_incident(self, incident_id: str) -> Optional[Incident]:
        return self.active_incidents.get(incident_id)
        
    def list_incidents(self) -> List[Incident]:
        return list(self.active_incidents.values())
