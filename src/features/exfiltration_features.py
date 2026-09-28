"""
UniShield AI -- Exfiltration Features & Host Baselines
======================================================
Tracks long-term behavioral baselines for internal hosts
to identify anomalous outbound data transfers.
"""

from typing import Dict, Set, Optional
import time

class BaselineState:
    INSUFFICIENT = "BASELINE_INSUFFICIENT"
    WARMING = "BASELINE_WARMING"
    AVAILABLE = "BASELINE_AVAILABLE"


class HostBaseline:
    """
    Maintains historical outbound behavior for a single internal source host.
    Uses simple Exponential Moving Averages (EMA) to model normal daily traffic.
    """
    
    def __init__(self, src_ip: str, min_flows: int = 50, ema_alpha: float = 0.05):
        self.src_ip = src_ip
        
        # EMA for expected flow byte size
        self.avg_flow_size_bytes = 0.0
        
        # Accumulators for the current day
        self.current_day_bytes = 0
        self.last_reset_time = time.time()
        
        # EMA for expected daily outbound volume
        self.avg_daily_bytes = 0.0
        
        # Flow counter to gauge baseline maturity
        self.total_flows_observed = 0
        self.min_flows_required = min_flows
        
        self.alpha = ema_alpha
        
        # Track frequent/known destinations to model novelty
        # For prototype bounds, limit to max 1000 items
        self.known_destinations: Set[str] = set()
        self.max_known_destinations = 1000

    @property
    def state(self) -> str:
        if self.total_flows_observed < self.min_flows_required:
            return BaselineState.INSUFFICIENT
        elif self.total_flows_observed < self.min_flows_required * 3:
            return BaselineState.WARMING
        return BaselineState.AVAILABLE

    def update_flow(self, dst_ip: str, byte_count: int, timestamp: float) -> bool:
        """
        Updates the baseline with a new flow.
        Returns True if the destination was previously unseen (destination novelty).
        """
        self.total_flows_observed += 1
        
        # 1. Update average flow size via EMA
        if self.avg_flow_size_bytes == 0.0:
            self.avg_flow_size_bytes = float(byte_count)
        else:
            self.avg_flow_size_bytes = (self.alpha * byte_count) + ((1.0 - self.alpha) * self.avg_flow_size_bytes)
            
        # 2. Update daily volume (simulate daily reset if timestamp crossed 86400s gap)
        # We assume `timestamp` is epoch seconds
        if timestamp - self.last_reset_time > 86400:
            if self.avg_daily_bytes == 0.0:
                self.avg_daily_bytes = float(self.current_day_bytes)
            else:
                self.avg_daily_bytes = (self.alpha * self.current_day_bytes) + ((1.0 - self.alpha) * self.avg_daily_bytes)
            
            self.current_day_bytes = 0
            self.last_reset_time = timestamp
            
        self.current_day_bytes += byte_count
        
        # 3. Check novelty
        is_novel = False
        if dst_ip not in self.known_destinations:
            is_novel = True
            if len(self.known_destinations) < self.max_known_destinations:
                self.known_destinations.add(dst_ip)
                
        return is_novel


class HostBaselineTracker:
    """
    Global tracker for all internal hosts.
    """
    
    def __init__(self, config: dict = None):
        self.cfg = config or {}
        self.min_flows = int(self.cfg.get("baseline_min_flows", 50))
        self.baselines: Dict[str, HostBaseline] = {}
        
    def record_flow(self, flow, fv: "FeatureVector") -> None:
        """
        Update the tracker with a new flow and inject baseline deviation features
        into the FeatureVector for Exfiltration scoring.
        """
        src = flow.source_ip
        if not src:
            return
            
        if src not in self.baselines:
            # Memory boundary protection for prototype
            if len(self.baselines) > 50_000:
                return
            self.baselines[src] = HostBaseline(src, min_flows=self.min_flows)
            
        baseline = self.baselines[src]
        is_novel = baseline.update_flow(flow.destination_ip, flow.byte_count, flow.last_seen)
        
        # Extract features for detector
        features = {
            "baseline_state": baseline.state,
            "is_destination_novel": is_novel,
            "avg_flow_size_bytes": baseline.avg_flow_size_bytes,
            "avg_daily_bytes": baseline.avg_daily_bytes,
            "current_day_bytes": baseline.current_day_bytes
        }
        
        fv.update("baseline", features)
