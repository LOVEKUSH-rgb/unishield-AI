"""
UniShield AI -- DNS Tracker
=============================
Stateful accumulator for tracking DNS behavior per source IP.

Required for DNS Tunnelling detection, which depends on observing
a sequence of queries from a single source over a sliding window.

Tracks:
  - Query rate (volume)
  - Unique domains/subdomains (churn)
  - Average query length (payload anomaly)
  - Average entropy (payload anomaly)
  - TXT/NULL record prevalence

PASSIVE AUDIT:
  [PASS] No DNS queries generated
  [PASS] No active probing
  [PASS] Derives entirely from FeatureVector metadata
"""

from __future__ import annotations

import collections
import statistics
from dataclasses import dataclass, field
from typing import Deque, Dict, Optional

from src.features.feature_vector import FeatureVector
from src.utils.config import get_thresholds
from src.utils.logging import get_logger

logger = get_logger(__name__)


def _cfg() -> dict:
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
# DNS Query Record
# ================================================================

@dataclass(frozen=True)
class DNSQueryRecord:
    timestamp: float
    query_name: str
    query_length: int
    entropy: float
    is_txt_or_null: bool


# ================================================================
# Per-Source DNS State
# ================================================================

@dataclass
class DNSState:
    """
    Accumulates DNS queries for a single source IP over a sliding window.
    """
    src_ip: str
    window_seconds: float = 300.0
    queries: Deque[DNSQueryRecord] = field(default_factory=collections.deque)
    
    def add(self, record: DNSQueryRecord) -> None:
        """Add a query and evict old ones."""
        self.queries.append(record)
        cutoff = record.timestamp - self.window_seconds
        while self.queries and self.queries[0].timestamp < cutoff:
            self.queries.popleft()

    @property
    def count(self) -> int:
        return len(self.queries)

    def get_features(self) -> DNSFeatures:
        if not self.queries:
            return DNSFeatures(self.src_ip, 0)
            
        count = len(self.queries)
        start_ts = self.queries[0].timestamp
        end_ts = self.queries[-1].timestamp
        duration = max(1.0, end_ts - start_ts)
        
        query_rate = count / duration
        
        unique_queries = len({q.query_name for q in self.queries})
        unique_ratio = unique_queries / count if count > 0 else 0.0
        
        lengths = [q.query_length for q in self.queries]
        avg_length = statistics.mean(lengths) if lengths else 0.0
        
        entropies = [q.entropy for q in self.queries if q.entropy is not None]
        avg_entropy = statistics.mean(entropies) if entropies else 0.0
        
        txt_null_count = sum(1 for q in self.queries if q.is_txt_or_null)
        txt_null_ratio = txt_null_count / count if count > 0 else 0.0
        
        return DNSFeatures(
            src_ip=self.src_ip,
            query_count=count,
            duration=duration,
            query_rate=query_rate,
            unique_query_count=unique_queries,
            unique_query_ratio=unique_ratio,
            avg_query_length=avg_length,
            avg_entropy=avg_entropy,
            txt_null_ratio=txt_null_ratio,
        )


# ================================================================
# Computed DNS Features (Input to Tunnelling Scorer)
# ================================================================

@dataclass
class DNSFeatures:
    src_ip: str
    query_count: int
    duration: float = 0.0
    query_rate: float = 0.0
    unique_query_count: int = 0
    unique_query_ratio: float = 0.0
    avg_query_length: float = 0.0
    avg_entropy: float = 0.0
    txt_null_ratio: float = 0.0


# ================================================================
# DNS Tracker
# ================================================================

class DNSTracker:
    """
    Manages DNSState for all observed source IPs.
    """
    def __init__(self, cfg: Optional[dict] = None) -> None:
        self._cfg = cfg or _cfg()
        self._window_seconds = float(_get(self._cfg, "tracking_window_seconds", default=300.0))
        self._states: Dict[str, DNSState] = {}
        
    def record_from_fv(self, fv: FeatureVector) -> None:
        """Extract DNS metadata and record it if this is a DNS query."""
        src_ip = fv.source_ip
        if not src_ip:
            return
            
        if not fv.get("dns_is_query"):
            return
            
        qname = fv.get("dns_query_name")
        if not qname:
            return
            
        start_time = float(fv.get("start_time") or 0.0)
        qlen = int(fv.get("dns_query_length") or 0)
        ent = float(fv.get("dns_entropy") or 0.0)
        is_txt = bool(fv.get("dns_query_type_TXT") or fv.get("dns_query_type_NULL"))
        
        record = DNSQueryRecord(
            timestamp=start_time,
            query_name=str(qname),
            query_length=qlen,
            entropy=ent,
            is_txt_or_null=is_txt,
        )
        
        if src_ip not in self._states:
            if len(self._states) >= 10000:
                # Evict oldest state if bounded
                oldest = next(iter(self._states))
                del self._states[oldest]
            self._states[src_ip] = DNSState(src_ip=src_ip, window_seconds=self._window_seconds)
            
        self._states[src_ip].add(record)
        
    def get_features(self, src_ip: str) -> Optional[DNSFeatures]:
        if src_ip not in self._states:
            return None
        return self._states[src_ip].get_features()
