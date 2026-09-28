"""
UniShield AI -- Reconnaissance & Port Scanning Detector
=======================================================
Detects horizontal port scans, vertical port scans, host sweeps,
network sweeps, and SYN scanning using passively observed metadata.
"""

import datetime
import uuid
from typing import Dict, List, Tuple

from src.detectors.base import BaseDetector, DetectionResult, Evidence, ThreatClass, Severity
from src.features.feature_vector import FeatureVector
from src.utils.config import get_thresholds


class ReconDetector(BaseDetector):
    def __init__(self, config_overrides: dict = None) -> None:
        cfg = get_thresholds().get("reconnaissance", {})
        if config_overrides:
            cfg.update(config_overrides)
            
        self.min_conns = int(cfg.get("min_connections", 20))
        
        horiz = cfg.get("horizontal", {})
        self.h_min_hosts = int(horiz.get("min_hosts", 20))
        self.h_max_ports = int(horiz.get("max_ports", 5))
        
        vert = cfg.get("vertical", {})
        self.v_min_ports = int(vert.get("min_ports", 20))
        self.v_max_hosts = int(vert.get("max_hosts", 2))
        
        hsweep = cfg.get("host_sweep", {})
        self.hs_min_pairs = int(hsweep.get("min_host_port_pairs", 30))
        
        nsweep = cfg.get("network_sweep", {})
        self.ns_min_subnets = int(nsweep.get("min_subnets", 5))
        
        self.syn_ratio_high = float(cfg.get("syn_ratio_high", 0.80))
        
        self.min_score_to_alert = float(cfg.get("min_score_to_alert", 0.40))
        self.min_confidence_to_alert = float(cfg.get("min_confidence_to_alert", 0.50))
        
        # Windows to evaluate
        try:
            w = get_thresholds().get("flows", {}).get("sliding_window_seconds", [10, 30, 60])
            self.windows = [int(x) for x in w] if isinstance(w, list) else [int(w)]
        except Exception:
            self.windows = [10, 30, 60]
            
    @property
    def threat_class(self) -> ThreatClass:
        return getattr(ThreatClass, "RECON", "Reconnaissance")

    def _evaluate_window(self, fv: FeatureVector, window: int) -> Tuple[str, float, float, List[Evidence]]:
        """
        Evaluates reconnaissance behavior for a specific time window.
        Returns: (sub_type, score, confidence, evidence_list)
        """
        suffix = f"{window}s"
        
        conn_count = fv.get(f"src_conn_count_{suffix}", 0)
        if conn_count is None or conn_count < self.min_conns:
            return "NORMAL", 0.0, 0.0, []
            
        uniq_hosts = fv.get(f"src_uniq_dst_hosts_{suffix}", 0) or 0
        uniq_ports = fv.get(f"src_uniq_dst_ports_{suffix}", 0) or 0
        uniq_subnets = fv.get(f"src_uniq_dst_subnets_{suffix}", 0) or 0
        uniq_pairs = fv.get(f"src_uniq_host_port_pairs_{suffix}", 0) or 0
        
        syn_ratio = fv.get("tcp_syn_ratio", 0.0) or 0.0
        
        sub_type = "NORMAL"
        score = 0.0
        confidence = 0.0
        evidence = []
        
        # Determine scan sub-type (mutually exclusive priority)
        if uniq_ports >= self.v_min_ports and uniq_hosts <= self.v_max_hosts:
            sub_type = "VERTICAL_SCAN"
            # Score based on how many ports scanned (normalized to min_ports * 3)
            score = min(1.0, uniq_ports / (self.v_min_ports * 3.0))
            confidence = 0.70 + (0.10 if syn_ratio >= self.syn_ratio_high else 0.0)
            
            evidence.append(Evidence(
                feature="uniq_dst_ports",
                observed=uniq_ports,
                baseline=self.v_min_ports,
                score=score,
                reason=f"One source contacted {uniq_ports} distinct ports on a small number of hosts within {window}s. This behavior is consistent with port reconnaissance."
            ))
            
        elif uniq_hosts >= self.h_min_hosts and uniq_ports <= self.h_max_ports:
            sub_type = "HORIZONTAL_SCAN"
            score = min(1.0, uniq_hosts / (self.h_min_hosts * 3.0))
            confidence = 0.70 + (0.10 if syn_ratio >= self.syn_ratio_high else 0.0)
            
            evidence.append(Evidence(
                feature="uniq_dst_hosts",
                observed=uniq_hosts,
                baseline=self.h_min_hosts,
                score=score,
                reason=f"One source contacted {uniq_hosts} distinct hosts on very few service ports within {window}s. This behavior is consistent with horizontal service discovery."
            ))
            
        elif uniq_subnets >= self.ns_min_subnets:
            sub_type = "NETWORK_SWEEP"
            score = min(1.0, uniq_subnets / (self.ns_min_subnets * 3.0))
            confidence = 0.65 + (0.15 if syn_ratio >= self.syn_ratio_high else 0.0)
            
            evidence.append(Evidence(
                feature="uniq_dst_subnets",
                observed=uniq_subnets,
                baseline=self.ns_min_subnets,
                score=score,
                reason=f"Source contacted {uniq_subnets} different network subnets within {window}s, consistent with broad network sweeping."
            ))
            
        elif uniq_pairs >= self.hs_min_pairs:
            sub_type = "HOST_SWEEP"
            score = min(1.0, uniq_pairs / (self.hs_min_pairs * 2.0))
            confidence = 0.60 + (0.10 if syn_ratio >= self.syn_ratio_high else 0.0)
            
            evidence.append(Evidence(
                feature="uniq_host_port_pairs",
                observed=uniq_pairs,
                baseline=self.hs_min_pairs,
                score=score,
                reason=f"Source contacted {uniq_pairs} unique host-port combinations within {window}s, indicating broad sweeping behavior."
            ))
            
        elif syn_ratio >= self.syn_ratio_high and conn_count >= self.min_conns * 2:
            sub_type = "SYN_RECON"
            score = min(1.0, conn_count / (self.min_conns * 4.0))
            confidence = 0.55
            
            evidence.append(Evidence(
                feature="tcp_syn_ratio",
                observed=round(syn_ratio, 3),
                baseline=self.syn_ratio_high,
                score=score,
                reason=f"High volume of SYN-dominant traffic ({conn_count} flows) without established connections is consistent with SYN-based reconnaissance indicators."
            ))
            
        # Corroborating Evidence
        if sub_type != "NORMAL" and syn_ratio >= self.syn_ratio_high:
            evidence.append(Evidence(
                feature="tcp_syn_ratio",
                observed=round(syn_ratio, 3),
                reason="Traffic is heavily SYN-dominant, corroborating active scanning intent."
            ))
            
        return sub_type, score, min(1.0, confidence), evidence

    def detect(self, fv: FeatureVector) -> DetectionResult:
        if not fv.has_group("behavioral"):
            return DetectionResult(threat_class=self.threat_class)
            
        best_sub_type = "NORMAL"
        best_score = 0.0
        best_conf = 0.0
        best_ev = []
        
        # Evaluate all windows and pick the strongest signal
        # E.g. A slow scan might evade the 10s window but trigger the 60s window.
        for w in self.windows:
            sub_type, score, conf, ev = self._evaluate_window(fv, w)
            if score > best_score:
                best_sub_type = sub_type
                best_score = score
                best_conf = conf
                best_ev = ev
                
        is_suppressed = True
        if best_score >= self.min_score_to_alert and best_conf >= self.min_confidence_to_alert:
            is_suppressed = False
            
        return DetectionResult(
            result_id=str(uuid.uuid4()),
            timestamp=datetime.datetime.now(datetime.timezone.utc).isoformat(),
            threat_class=self.threat_class,
            sub_type=best_sub_type if not is_suppressed else None,
            detection_score=best_score,
            confidence=best_conf,
            severity=Severity.UNCLASSIFIED,
            detector="statistical_recon",
            model=None,
            evidence=best_ev,
            source_ip=fv.source_ip,
            destination_ip=fv.destination_ip,
            source_port=fv.source_port,
            destination_port=fv.destination_port,
            protocol=str(fv.protocol) if fv.protocol else None,
            flow_id=fv.flow_id,
            is_suppressed=is_suppressed,
            suppression_reason="Below alert thresholds or normal behavior" if is_suppressed else None
        )
