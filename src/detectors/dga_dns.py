"""
UniShield AI -- DGA & DNS Tunnelling Detectors
=================================================
Implements Phase 5 detectors:
1. DGADetector (Domain Generation Algorithm)
2. DNSTunnelDetector (DNS Tunnelling)

Strictly relies on passively observable DNS metadata.
Does not perform active resolution, payload decryption,
or external reputation lookups.
"""

from __future__ import annotations

import logging
from typing import Dict, List, Optional, Tuple

from src.detectors.base import (
    BaseDetector,
    DetectionResult,
    Evidence,
    ThreatClass,
    score_to_severity,
)
from src.detectors.dns_tracker import DNSFeatures, DNSTracker
from src.features.feature_vector import FeatureVector
from src.utils.config import get_thresholds

logger = logging.getLogger(__name__)


def _dga_cfg() -> dict:
    try:
        return get_thresholds().get("dga_dns", {}).get("dga", {})
    except Exception:
        return {}


def _tunnel_cfg() -> dict:
    try:
        return get_thresholds().get("dga_dns", {}).get("tunnel", {})
    except Exception:
        return {}


def _get(cfg: dict, *keys, default=0.0):
    val = cfg
    for k in keys:
        if not isinstance(val, dict):
            return default
        val = val.get(k, default)
    try:
        return type(default)(val)
    except (TypeError, ValueError):
        return default


# ================================================================
# DGA Detection
# ================================================================

class LexicalEntropySub:
    """Detects DGA domains via character and n-gram entropy."""
    def __init__(self, cfg: dict) -> None:
        self.ent_high = float(_get(cfg, "entropy_high", default=4.2))
        self.ent_mod = float(_get(cfg, "entropy_moderate", default=3.5))
        self.ngram_high = float(_get(cfg, "ngram_entropy_high", default=3.8))
        self.ngram_mod = float(_get(cfg, "ngram_entropy_moderate", default=3.2))

    def evaluate(self, fv: FeatureVector) -> Tuple[float, List[Evidence]]:
        ent = fv.get("dns_entropy")
        ngram_ent = fv.get("dns_ngram_entropy")
        
        if ent is None or ngram_ent is None:
            return 0.0, []
            
        ent, ngram_ent = float(ent), float(ngram_ent)
        score = 0.0
        evidence = []
        
        # Base Entropy
        if ent >= self.ent_high:
            score += 0.6
            evidence.append(Evidence(
                feature="dns_entropy",
                observed=ent,
                baseline=self.ent_mod,
                score=0.6,
                detector="LexicalEntropySub",
                reason=f"Domain entropy ({ent:.2f}) is unusually high, indicating random character distribution consistent with DGA."
            ))
        elif ent >= self.ent_mod:
            s = 0.3 * ((ent - self.ent_mod) / (self.ent_high - self.ent_mod))
            score += s
            evidence.append(Evidence(
                feature="dns_entropy",
                observed=ent,
                baseline=self.ent_mod,
                score=s,
                detector="LexicalEntropySub",
                reason=f"Domain entropy ({ent:.2f}) is moderately high."
            ))
            
        # N-Gram Entropy
        if ngram_ent >= self.ngram_high:
            score += 0.4
            evidence.append(Evidence(
                feature="dns_ngram_entropy",
                observed=ngram_ent,
                baseline=self.ngram_mod,
                score=0.4,
                detector="LexicalEntropySub",
                reason=f"N-gram entropy ({ngram_ent:.2f}) is unusually high, lacking normal linguistic structure."
            ))
        elif ngram_ent >= self.ngram_mod:
            s = 0.2 * ((ngram_ent - self.ngram_mod) / (self.ngram_high - self.ngram_mod))
            score += s
            evidence.append(Evidence(
                feature="dns_ngram_entropy",
                observed=ngram_ent,
                baseline=self.ngram_mod,
                score=s,
                detector="LexicalEntropySub",
                reason=f"N-gram entropy ({ngram_ent:.2f}) is elevated."
            ))
            
        return min(1.0, score), evidence


class StructuralAnomalySub:
    """Detects DGA domains via lengths, digit ratios, and unique chars."""
    def __init__(self, cfg: dict) -> None:
        self.len_suspicious = int(_get(cfg, "length_suspicious", default=35))
        self.digit_ratio_high = float(_get(cfg, "digit_ratio_high", default=0.30))
        self.unique_char_high = int(_get(cfg, "unique_char_high", default=25))

    def evaluate(self, fv: FeatureVector) -> Tuple[float, List[Evidence]]:
        length = fv.get("dns_query_length")
        digit_ratio = fv.get("dns_digit_ratio")
        unique_chars = fv.get("dns_unique_char_count")
        
        if length is None or digit_ratio is None or unique_chars is None:
            return 0.0, []
            
        length, digit_ratio, unique_chars = int(length), float(digit_ratio), int(unique_chars)
        score = 0.0
        evidence = []
        
        if length >= self.len_suspicious:
            s = min(0.4, 0.4 * (length / (self.len_suspicious * 1.5)))
            score += s
            evidence.append(Evidence(
                feature="dns_query_length",
                observed=length,
                baseline=self.len_suspicious,
                score=s,
                detector="StructuralAnomalySub",
                reason=f"Domain length ({length}) is unusually long, characteristic of some DGA families."
            ))
            
        if digit_ratio >= self.digit_ratio_high:
            s = min(0.3, 0.3 * (digit_ratio / 0.8))
            score += s
            evidence.append(Evidence(
                feature="dns_digit_ratio",
                observed=digit_ratio,
                baseline=self.digit_ratio_high,
                score=s,
                detector="StructuralAnomalySub",
                reason=f"High proportion of digits ({digit_ratio:.2f}) is consistent with algorithmic generation."
            ))
            
        if unique_chars >= self.unique_char_high:
            score += 0.3
            evidence.append(Evidence(
                feature="dns_unique_char_count",
                observed=unique_chars,
                baseline=self.unique_char_high,
                score=0.3,
                detector="StructuralAnomalySub",
                reason=f"Unusually high unique character count ({unique_chars}) indicates non-natural language structure."
            ))
            
        return min(1.0, score), evidence


class DGADetector(BaseDetector):
    def __init__(self, cfg: Optional[dict] = None) -> None:
        self.cfg = cfg or _dga_cfg()
        self.lexical = LexicalEntropySub(self.cfg)
        self.structural = StructuralAnomalySub(self.cfg)
        
        w = self.cfg.get("weights", {})
        self.w_lex = float(w.get("lexical_entropy", 0.60))
        self.w_struct = float(w.get("structural_anomaly", 0.40))
        
        self.min_score = float(self.cfg.get("min_score_to_alert", 0.35))
        self.min_confidence = float(self.cfg.get("min_confidence_to_alert", 0.45))
        
        # ML model (Isolation Forest/Random Forest)
        self.ml_enabled = bool(_get(self.cfg, "ml", "enabled", default=True))
        self.ml_model = None
        if self.ml_enabled:
            # We initialize dynamically to avoid circular imports if model is missing
            try:
                from src.models.training.dga_train import DGARandomForest
                self.ml_model = DGARandomForest(self.cfg.get("ml", {}))
                if not self.ml_model.is_ready():
                    self.ml_enabled = False
            except ImportError:
                self.ml_enabled = False

    @property
    def threat_class(self) -> ThreatClass:
        return ThreatClass.DNS_DGA

    def detect(self, fv: FeatureVector) -> DetectionResult:
        if not fv.get("dns_is_query"):
            return DetectionResult(threat_class=self.threat_class)

        lex_score, lex_ev = self.lexical.evaluate(fv)
        struct_score, struct_ev = self.structural.evaluate(fv)
        
        stat_score = (lex_score * self.w_lex) + (struct_score * self.w_struct)
        final_score = stat_score
        
        all_ev = lex_ev + struct_ev
        
        model_name = None
        model_version = None
        ml_available = False
        detector_name = "statistical_dga"

        if self.ml_enabled and self.ml_model:
            ml_score = self.ml_model.score(fv)
            if ml_score is not None:
                from src.models.registry import registry
                registry.record_score("dga", ml_score)
                final_score = (stat_score + ml_score) / 2
                model_name = self.ml_model.metadata.get("model_name", "DGARandomForest") if self.ml_model.metadata else "DGARandomForest"
                model_version = self.ml_model.metadata.get("model_version", "unknown") if self.ml_model.metadata else "unknown"
                ml_available = True
                detector_name = "hybrid_dga"
                
                all_ev.append(Evidence(
                    feature="ml_dga_score",
                    observed=round(ml_score, 3),
                    baseline=0.5,
                    score=ml_score,
                    detector=detector_name,
                    reason=f"ML Model ({model_name} v{model_version}) scored this domain as {(ml_score*100):.1f}% likely DGA."
                ))
        
        # Confidence calculation
        strong_signals = sum(1 for e in all_ev if e.score >= 0.25)
        confidence = 0.0
        if strong_signals >= 3:
            confidence = min(0.95, 0.60 + (strong_signals * 0.1))
        elif strong_signals == 2:
            confidence = 0.55
        elif strong_signals == 1:
            confidence = 0.35
            
        res = DetectionResult(
            threat_class=self.threat_class,
            sub_type="Algorithmic_Domain",
            detection_score=final_score,
            confidence=confidence,
            severity=score_to_severity(final_score),
            source_ip=fv.source_ip,
            destination_ip=fv.destination_ip,
            source_port=fv.source_port,
            destination_port=fv.destination_port,
            protocol=str(fv.protocol) if fv.protocol else None,
            flow_id=fv.flow_id,
            detector=detector_name,
            model=model_name,
            model_version=model_version,
            ml_available=ml_available,
            evidence=all_ev
        )
        
        if not res.is_alert(min_score=self.min_score, min_confidence=self.min_confidence):
            res.is_suppressed = True
            res.suppression_reason = "Score or confidence below DGA thresholds."
            
        # Passive Audit Disclaimer
        if not res.is_suppressed:
            res.add_evidence(Evidence(
                feature="passive_audit",
                observed="True",
                detector="DGADetector",
                reason="Note: Detection relies entirely on passively observed lexical characteristics. DGA assessment is probabilistic, not confirmed."
            ))
            
        return res


# ================================================================
# DNS Tunnelling Detection
# ================================================================

class DNSTunnelDetector(BaseDetector):
    def __init__(self, tracker: DNSTracker, cfg: Optional[dict] = None) -> None:
        self.tracker = tracker
        self.cfg = cfg or _tunnel_cfg()
        
        self.min_queries = int(_get(self.cfg, "min_queries_for_analysis", default=20))
        self.qrate_high = float(_get(self.cfg, "query_rate_high", default=5.0))
        self.qrate_mod = float(_get(self.cfg, "query_rate_moderate", default=2.0))
        self.len_high = float(_get(self.cfg, "avg_query_length_high", default=50.0))
        self.ent_high = float(_get(self.cfg, "avg_entropy_high", default=4.0))
        self.churn_high = float(_get(self.cfg, "unique_subdomain_ratio_high", default=0.80))
        self.txt_null_high = float(_get(self.cfg, "txt_null_ratio_high", default=0.50))
        
        w = self.cfg.get("weights", {})
        self.w_vol = float(w.get("volume", 0.25))
        self.w_pay = float(w.get("payload", 0.35))
        self.w_churn = float(w.get("churn", 0.25))
        self.w_rectype = float(w.get("record_type", 0.15))
        
        self.min_score = float(self.cfg.get("min_score_to_alert", 0.40))
        self.min_confidence = float(self.cfg.get("min_confidence_to_alert", 0.45))

    @property
    def threat_class(self) -> ThreatClass:
        return ThreatClass.DNS_TUNNEL

    def detect(self, fv: FeatureVector) -> DetectionResult:
        if not fv.get("dns_is_query"):
            return DetectionResult(threat_class=self.threat_class)
            
        # Update tracker
        self.tracker.record_from_fv(fv)
        
        # Get features
        if not fv.source_ip:
            return DetectionResult(threat_class=self.threat_class)
            
        tfeat = self.tracker.get_features(fv.source_ip)
        if not tfeat or tfeat.query_count < self.min_queries:
            # Cold start suppression
            return DetectionResult(threat_class=self.threat_class, is_suppressed=True)
            
        score = 0.0
        evidence = []
        strong_signals = 0
        
        # 1. Volume (Query Rate)
        if tfeat.query_rate >= self.qrate_mod:
            s_vol = min(1.0, (tfeat.query_rate - self.qrate_mod) / (self.qrate_high - self.qrate_mod))
            score += s_vol * self.w_vol
            if s_vol > 0.5: strong_signals += 1
            evidence.append(Evidence(
                feature="query_rate",
                observed=round(tfeat.query_rate, 2),
                baseline=self.qrate_mod,
                score=s_vol,
                detector="VolumeAnomalySub",
                reason=f"High DNS query frequency ({tfeat.query_rate:.1f} qps) observed from source, often associated with covert data transfer."
            ))
            
        # 2. Payload Anomaly
        s_pay = 0.0
        if tfeat.avg_query_length >= self.len_high:
            s_pay += 0.5
            evidence.append(Evidence(
                feature="avg_query_length",
                observed=round(tfeat.avg_query_length, 1),
                baseline=self.len_high,
                score=0.5,
                detector="PayloadAnomalySub",
                reason=f"Average query length ({tfeat.avg_query_length:.1f}) is unusually long, consistent with encoded payload transmission."
            ))
        if tfeat.avg_entropy >= self.ent_high:
            s_pay += 0.5
            evidence.append(Evidence(
                feature="avg_entropy",
                observed=round(tfeat.avg_entropy, 2),
                baseline=self.ent_high,
                score=0.5,
                detector="PayloadAnomalySub",
                reason=f"Average domain entropy ({tfeat.avg_entropy:.2f}) is high, indicating random encoded data."
            ))
        score += s_pay * self.w_pay
        if s_pay > 0.5: strong_signals += 1
        
        # 3. Subdomain Churn
        if tfeat.unique_query_ratio >= self.churn_high:
            s_churn = min(1.0, tfeat.unique_query_ratio / 0.95)
            score += s_churn * self.w_churn
            if s_churn > 0.5: strong_signals += 1
            evidence.append(Evidence(
                feature="unique_subdomain_ratio",
                observed=round(tfeat.unique_query_ratio, 2),
                baseline=self.churn_high,
                score=s_churn,
                detector="SubdomainChurnSub",
                reason=f"Extremely high churn ({tfeat.unique_query_ratio*100:.0f}% unique queries). Tunneling relies on unique domains to bypass caching."
            ))
            
        # 4. Record Type
        if tfeat.txt_null_ratio >= self.txt_null_high:
            s_rec = min(1.0, tfeat.txt_null_ratio / 0.9)
            score += s_rec * self.w_rectype
            if s_rec > 0.5: strong_signals += 1
            evidence.append(Evidence(
                feature="txt_null_ratio",
                observed=round(tfeat.txt_null_ratio, 2),
                baseline=self.txt_null_high,
                score=s_rec,
                detector="RecordTypeSub",
                reason=f"High concentration of TXT/NULL queries ({tfeat.txt_null_ratio*100:.0f}%), which are commonly used for high-bandwidth C2/exfiltration."
            ))
            
        # Confidence
        confidence = 0.0
        if strong_signals >= 3:
            confidence = min(0.95, 0.70 + (strong_signals * 0.05))
        elif strong_signals == 2:
            confidence = 0.55
        elif strong_signals == 1:
            confidence = 0.35
            
        res = DetectionResult(
            threat_class=self.threat_class,
            sub_type="Covert_DNS_Channel",
            detection_score=score,
            confidence=confidence,
            severity=score_to_severity(score),
            source_ip=fv.source_ip,
            destination_ip=fv.destination_ip,
            source_port=fv.source_port,
            destination_port=fv.destination_port,
            protocol=str(fv.protocol) if fv.protocol else None,
            flow_id=fv.flow_id,
            detector="statistical_dns_tunnel",
            model=None,
            evidence=evidence
        )
        
        if not res.is_alert(min_score=self.min_score, min_confidence=self.min_confidence):
            res.is_suppressed = True
            res.suppression_reason = "Score or confidence below DNS Tunnelling thresholds."
            
        if not res.is_suppressed:
            res.add_evidence(Evidence(
                feature="passive_audit",
                observed="True",
                detector="DNSTunnelDetector",
                reason="Note: Detection is based entirely on one-directional query metadata. Responses were not analyzed."
            ))
            
        return res
