"""
UniShield AI -- Unified Risk Engine
===================================
Transforms correlated incidents into prioritized, transparent risk scores.
"""

from typing import List, Tuple, Optional
from datetime import datetime, timezone
import math

from src.correlation.correlation_models import Incident, RiskFactor
from src.utils.config import get_risk_config
from src.risk.risk_explanation import generate_risk_explanation
from src.utils.logging import get_logger

logger = get_logger(__name__)

class RiskEngine:
    def __init__(self, config_overrides: dict = None):
        cfg_root = get_risk_config()
        cfg = cfg_root.get("risk", cfg_root)
        if config_overrides:
            cfg.update(config_overrides)
            
        self.levels = cfg.get("levels", {})
        self.priorities = cfg.get("priority_mapping", {})
        self.severity_bases = cfg.get("severity_base_scores", {})
        self.weights = cfg.get("weights", {})
        
        self.decay_enabled = cfg.get("decay", {}).get("enabled", True)
        self.decay_rate = float(cfg.get("decay", {}).get("decay_rate_per_day", 0.10))
        self.decay_floor = float(cfg.get("decay", {}).get("minimum_floor", 20.0))

    def _determine_base_risk(self, incident: Incident) -> Tuple[float, List[RiskFactor]]:
        """
        Determines base risk from the highest severity alert, plus a corroboration bonus.
        """
        max_base = 0.0
        factors = []
        unique_detectors = set()
        
        for alert in incident.alerts:
            # Map severity to base score
            sev_str = (alert.severity.upper() if hasattr(alert, 'severity') and alert.severity else "MEDIUM")
            # Fallback for detectors that don't emit severity explicitly
            if sev_str not in self.severity_bases:
                sev_str = "MEDIUM"
                
            base_val = float(self.severity_bases.get(sev_str, 30.0))
            if base_val > max_base:
                max_base = base_val
                
            unique_detectors.add(alert.threat_class)
            
        # The base risk factor is driven by the highest severity
        factors.append(RiskFactor(factor="Base Risk (Highest Severity)", contribution=max_base))
        
        # Corroboration Bonus
        corrob_bonus = (len(unique_detectors) - 1) * float(self.weights.get("corroboration_bonus_per_detector", 12.0))
        max_corrob = float(self.weights.get("max_corroboration_bonus", 30.0))
        corrob_bonus = min(corrob_bonus, max_corrob)
        
        if corrob_bonus > 0:
            factors.append(RiskFactor(factor="Corroboration Bonus", contribution=corrob_bonus))
            
        # Add a factor indicating what detectors fired
        for d in unique_detectors:
            factors.append(RiskFactor(factor=str(d), contribution=0.0))
            
        return max_base + corrob_bonus, factors

    def _calculate_confidence_adj(self, incident: Incident) -> Tuple[float, Optional[RiskFactor]]:
        """
        Scales score based on average confidence of alerts.
        """
        if not incident.alerts:
            return 0.0, None
            
        avg_conf = sum(a.confidence for a in incident.alerts) / len(incident.alerts)
        
        # If avg confidence is high, slight boost. If low, slight penalty.
        # e.g. conf 1.0 -> +5, conf 0.5 -> -10
        adj = (avg_conf - 0.75) * 20.0
        return adj, RiskFactor(factor="Confidence Adjustment", contribution=adj)

    def _calculate_temporal_bonus(self, incident: Incident) -> Tuple[float, Optional[RiskFactor]]:
        """
        Rewards tight time clustering based on correlation_strength.
        """
        if len(incident.alerts) <= 1:
            return 0.0, None
            
        max_bonus = float(self.weights.get("temporal_bonus", 10.0))
        # Correlation strength is 0-1.0. A high strength indicates tight timing/progression.
        bonus = incident.correlation_strength * max_bonus
        return bonus, RiskFactor(factor="Temporal Correlation", contribution=bonus)

    def _calculate_progression_bonus(self, incident: Incident) -> Tuple[float, Optional[RiskFactor]]:
        """
        Rewards observing a multi-stage attack sequence.
        """
        prog_len = len(incident.potential_progression)
        if prog_len <= 1:
            return 0.0, None
            
        bonus_per = float(self.weights.get("progression_bonus_per_stage", 5.0))
        max_prog = float(self.weights.get("max_progression_bonus", 15.0))
        bonus = min((prog_len - 1) * bonus_per, max_prog)
        return bonus, RiskFactor(factor="Attack Progression", contribution=bonus)
        
    def _calculate_metadata_quality(self, incident: Incident) -> Tuple[float, Optional[RiskFactor]]:
        """
        Penalizes risk if baseline metadata is insufficient.
        """
        penalty = 0.0
        for alert in incident.alerts:
            meta = getattr(alert, "meta", {})
            if meta and meta.get("baseline_quality") == "BASELINE_INSUFFICIENT":
                penalty = float(self.weights.get("metadata_quality_penalty", -10.0))
                break
                
        if penalty < 0:
            return penalty, RiskFactor(factor="Metadata Quality Penalty", contribution=penalty)
        return 0.0, None
        
    def _apply_decay(self, incident: Incident, score: float) -> float:
        """
        Decays the score if a long time has passed since `last_seen`.
        """
        if not self.decay_enabled or len(incident.alerts) == 0:
            return score
            
        try:
            last_seen = datetime.fromisoformat(incident.last_seen.replace("Z", "+00:00"))
            now = datetime.now(timezone.utc)
            days_inactive = (now - last_seen).total_seconds() / 86400.0
        except ValueError:
            return score
            
        if days_inactive > 1.0:
            decay_factor = 1.0 - min(days_inactive * self.decay_rate, 1.0)
            decayed = score * max(0.0, decay_factor)
            return max(self.decay_floor, decayed)
            
        return score

    def _get_level_and_priority(self, score: float) -> Tuple[str, str]:
        level_name = "INFORMATIONAL"
        for name, bounds in self.levels.items():
            if float(bounds.get("min", 0)) <= score <= float(bounds.get("max", 100)):
                level_name = name.upper()
                break
                
        priority = self.priorities.get(level_name.lower(), "P4")
        return level_name, priority

    def update_risk(self, incident: Incident) -> None:
        """
        Recalculates the unified risk score for the incident,
        updates its internal fields, and logs to history if changed.
        """
        factors = []
        score = 0.0
        
        # 1. Base Score + Corroboration
        base, b_factors = self._determine_base_risk(incident)
        score += base
        factors.extend(b_factors)
        
        # 2. Confidence Adjustment
        c_adj, c_factor = self._calculate_confidence_adj(incident)
        score += c_adj
        if c_factor: factors.append(c_factor)
        
        # 3. Temporal Bonus
        t_adj, t_factor = self._calculate_temporal_bonus(incident)
        score += t_adj
        if t_factor: factors.append(t_factor)
        
        # 4. Progression Bonus
        p_adj, p_factor = self._calculate_progression_bonus(incident)
        score += p_adj
        if p_factor: factors.append(p_factor)
        
        # 5. Metadata Quality
        m_adj, m_factor = self._calculate_metadata_quality(incident)
        score += m_adj
        if m_factor: factors.append(m_factor)
        
        # 6. Clamp
        score = max(0.0, min(100.0, score))
        
        # 7. Apply Decay
        score = self._apply_decay(incident, score)
        
        # 8. Level & Priority
        level, priority = self._get_level_and_priority(score)
        
        # 9. Explanation
        explanation = generate_risk_explanation(incident, factors, level)
        
        # Record updates
        timestamp = datetime.now(timezone.utc).isoformat()
        
        # Only log history if score meaningfully changed or it's new
        if abs(incident.risk_score - score) > 1.0 or not incident.risk_history:
            incident.risk_history.append({
                "timestamp": timestamp,
                "score": round(score, 1),
                "level": level
            })
            
        incident.risk_score = score
        incident.risk_level = level
        incident.priority = priority
        incident.risk_factors = factors
        incident.explanation = explanation
        
        # Optional lifecycle state bump
        if incident.status == "NEW" and score >= 40.0:
            incident.status = "INVESTIGATING"
