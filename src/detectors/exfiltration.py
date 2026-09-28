"""
UniShield AI -- Data Exfiltration Detector
==========================================
Identifies outbound traffic behavior consistent with potential
data exfiltration using flow statistics and historical host baselines.
"""

import datetime
import uuid
from typing import List, Tuple

from src.detectors.base import BaseDetector, DetectionResult, Evidence, Severity, ThreatClass
from src.features.feature_vector import FeatureVector
from src.utils.config import get_thresholds


class ExfiltrationDetector(BaseDetector):
    def __init__(self, config_overrides: dict = None) -> None:
        cfg = get_thresholds().get("exfiltration", {})
        if config_overrides:
            cfg.update(config_overrides)
            
        self.min_byte_count = int(cfg.get("min_byte_count", 50000000))
        self.burst_multiplier = float(cfg.get("burst_deviation_multiplier", 5.0))
        self.sustained_multiplier = float(cfg.get("sustained_deviation_multiplier", 3.0))
        
        self.min_score_to_alert = float(cfg.get("min_score_to_alert", 0.60))
        self.min_confidence_to_alert = float(cfg.get("min_confidence_to_alert", 0.50))
        
    @property
    def threat_class(self) -> ThreatClass:
        return getattr(ThreatClass, "EXFILTRATION", "Exfiltration")

    def detect(self, fv: FeatureVector) -> DetectionResult:
        # Relaxed for demo: If no baseline, use a static absolute threshold (e.g., 50KB)
        norm_tx = fv.get("avg_daily_bytes")
        if norm_tx is None or norm_tx <= 0:
            norm_tx = 50000.0   
        baseline_state = fv.get("baseline_state")
        is_novel = fv.get("is_destination_novel", False)
        
        avg_daily = fv.get("avg_daily_bytes", 0.0)
        current_day = fv.get("current_day_bytes", 0.0)
        
        # Volume burst (from 60s behavioral window)
        burst_volume = fv.get("src_bytes_out_60s", 0)
        
        # Asymmetry calculation - We simulate this as we track total bytes.
        # In a passive tap, outbound bytes from source to destination are recorded in `byte_count`.
        flow_bytes = fv.get("byte_count", 0)
        burst_volume = max(burst_volume, flow_bytes)
        
        score = 0.0
        confidence_modifier = 1.0
        evidence: List[Evidence] = []
        
        # 1. Adjust confidence based on baseline maturity
        if baseline_state == "BASELINE_INSUFFICIENT":
            confidence_modifier = 0.5
        elif baseline_state == "BASELINE_WARMING":
            confidence_modifier = 0.8
            
        # 2. Evaluate Burst Anomaly
        # We consider a burst suspicious if it drastically exceeds the *average daily rate* proportionally,
        # or if it's just raw huge (e.g. 50MB in 60s) for a cold-start host.
        if burst_volume >= self.min_byte_count:
            # Score contribution
            score += 0.4
            evidence.append(Evidence(
                feature="src_bytes_out_60s",
                observed=burst_volume,
                baseline=self.min_byte_count,
                score=0.4,
                reason=f"Sudden outbound spike of {burst_volume / 1000000:.1f} MB in a 60s window."
            ))
            
            # If we have a baseline, deviation matters
            if baseline_state == "BASELINE_AVAILABLE" and avg_daily > 0:
                deviation = burst_volume / (avg_daily / 1440.0) # vs per-minute average
                if deviation >= self.burst_multiplier:
                    score += 0.3
                    evidence.append(Evidence(
                        feature="burst_deviation",
                        observed=round(deviation, 1),
                        baseline=self.burst_multiplier,
                        deviation=deviation,
                        score=0.3,
                        reason=f"Outbound burst rate is {deviation:.1f}x the historical average rate for this host."
                    ))

        # 3. Evaluate Low-and-Slow (Sustained Anomaly)
        # If today's volume is > sustained_multiplier * avg_daily
        if baseline_state == "BASELINE_AVAILABLE" and avg_daily > 0:
            sustained_ratio = current_day / avg_daily
            if sustained_ratio >= self.sustained_multiplier and current_day > self.min_byte_count:
                score += 0.5
                evidence.append(Evidence(
                    feature="cumulative_outbound_deviation",
                    observed=round(sustained_ratio, 1),
                    baseline=self.sustained_multiplier,
                    deviation=sustained_ratio,
                    score=0.5,
                    reason=f"Sustained outbound volume today ({current_day / 1000000:.1f} MB) is {sustained_ratio:.1f}x the historical daily average."
                ))
                
        # 4. Destination Novelty
        if is_novel and score > 0:
            score += 0.3
            evidence.append(Evidence(
                feature="destination_novelty",
                observed="New Destination",
                score=0.3,
                reason="The destination IP has not been frequently observed in the host's historical baseline."
            ))
            
        # 5. Calculate Final Score & Confidence
        score = min(1.0, score)
        confidence = score * confidence_modifier
        
        is_suppressed = True
        if score >= self.min_score_to_alert and confidence >= self.min_confidence_to_alert:
            is_suppressed = False
            
        sub_type = None
        if not is_suppressed:
            sub_type = "Data_Exfiltration" if score >= 1.0 else "Potential_Data_Exfiltration"
            
        return DetectionResult(
            result_id=str(uuid.uuid4()),
            timestamp=datetime.datetime.now(datetime.timezone.utc).isoformat(),
            threat_class=self.threat_class,
            sub_type=sub_type,
            detection_score=score,
            confidence=confidence,
            severity=Severity.UNCLASSIFIED,
            detector="statistical_exfiltration",
            model=None,
            evidence=evidence,
            source_ip=fv.source_ip,
            destination_ip=fv.destination_ip,
            source_port=fv.source_port,
            destination_port=fv.destination_port,
            protocol=str(fv.protocol) if fv.protocol else None,
            flow_id=fv.flow_id,
            is_suppressed=is_suppressed,
            suppression_reason="Volume within acceptable baseline" if is_suppressed else None,
            meta={
                "baseline_quality": baseline_state
            }
        )
