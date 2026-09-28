"""
UniShield AI -- Beacon Tracker
================================
Stateful accumulator that tracks connection history for each
(source_ip, destination_ip, destination_port) tuple.

This is the core of C2 beaconing detection: unlike DDoS which
can be detected from a single flow, C2 requires observing a
SEQUENCE of flows over time and measuring periodicity.

Architecture:
  C2Detector.detect(fv)
       |
       v
  BeaconTracker.record(fv)   ← updates state for this src/dst pair
       |
       v
  BeaconState                ← per-tuple accumulated connection history
       |
       v
  BeaconFeatures             ← computed from the accumulated history
       |
       v
  C2Detector._score(features) ← produces DetectionResult

Periodicity Methodology (documented):
  The key metric is the Coefficient of Variation (CV) of inter-
  connection intervals:

    CV = std(intervals) / mean(intervals)

  CV interpretation:
    0.00 → perfectly periodic (every connection exactly identical)
    0.15 → highly regular (likely automated/scripted)
    0.30 → low jitter (still suspicious — malware adds jitter)
    0.60 → irregular (threshold for "random" classification)
    >0.60→ random traffic (not suspicious by periodicity alone)

  Periodicity score:
    s_period = max(0, 1 - CV / cv_random_threshold)

  This formula:
    - Is monotonically decreasing in CV (more regular = higher score)
    - Is 0 when CV ≥ cv_random_threshold (random intervals = no signal)
    - Is 1 when CV = 0 (perfect periodicity)
    - Is linear between 0 and cv_random_threshold

  Jitter tolerance is built-in: CV=0.30 still produces s_period=0.5
  with cv_random_threshold=0.60.

PASSIVE AUDIT:
  [PASS] No packets transmitted
  [PASS] No active probing
  [PASS] All state derived from FeatureVector metadata
"""

from __future__ import annotations

import math
import statistics
from collections import defaultdict, deque
from dataclasses import dataclass, field
from typing import Deque, Dict, List, Optional, Tuple

from src.utils.config import get_thresholds
from src.utils.logging import get_logger

logger = get_logger(__name__)


def _cfg() -> dict:
    try:
        return get_thresholds().get("c2_beacon", {})
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
# Connection record stored per observed flow
# ================================================================

@dataclass(frozen=True)
class ConnectionRecord:
    """
    One observed connection in a beacon sequence.

    Fields are purely observational — no inferred or active data.
    """
    timestamp: float       # UNIX epoch of connection start
    byte_count: int        # total bytes in this flow
    packet_count: int      # total packets
    duration: float        # flow duration in seconds
    dst_ip: str            # destination IP (for diversity tracking)
    dst_port: int          # destination port


# ================================================================
# Beacon state per (src_ip, dst_ip, dst_port) tuple
# ================================================================

@dataclass
class BeaconState:
    """
    Accumulated connection history for one (src, dst, dport) endpoint pair.

    Maintains a bounded sliding window of ConnectionRecords.
    """
    src_ip: str
    dst_ip: str
    dst_port: int

    connections: Deque[ConnectionRecord] = field(default_factory=deque)
    max_records: int = 200

    def add(self, record: ConnectionRecord) -> None:
        """Add a new connection record, evicting the oldest if at capacity."""
        self.connections.append(record)
        if len(self.connections) > self.max_records:
            self.connections.popleft()

    @property
    def count(self) -> int:
        return len(self.connections)

    @property
    def timestamps(self) -> List[float]:
        return [r.timestamp for r in self.connections]

    @property
    def byte_counts(self) -> List[int]:
        return [r.byte_count for r in self.connections]

    @property
    def packet_counts(self) -> List[int]:
        return [r.packet_count for r in self.connections]

    @property
    def durations(self) -> List[float]:
        return [r.duration for r in self.connections]

    def inter_connection_intervals(
        self,
        min_sec: float = 5.0,
        max_sec: float = 7200.0,
    ) -> List[float]:
        """
        Compute inter-connection intervals (ICI) from timestamp sequence.

        Parameters
        ----------
        min_sec:
            Intervals below this are excluded (noise / fast retransmit).
        max_sec:
            Intervals above this are excluded (too slow for C2 beacon).

        Returns
        -------
        List[float]
            Filtered list of intervals in seconds (sorted by time).

        Note
        ----
        ICIs are computed between consecutive sorted timestamps.
        They represent the waiting time between successive connections
        to the same (dst_ip, dst_port) pair.
        """
        ts = sorted(self.timestamps)
        if len(ts) < 2:
            return []
        intervals = []
        for i in range(1, len(ts)):
            ici = ts[i] - ts[i - 1]
            if min_sec <= ici <= max_sec:
                intervals.append(ici)
        return intervals


# ================================================================
# Computed beacon features (the input to the scorer)
# ================================================================

@dataclass
class BeaconFeatures:
    """
    Computed statistical features for one beacon candidate.

    All features are derived from accumulated BeaconState.
    None values mean insufficient data for that feature.
    """
    src_ip: str
    dst_ip: str
    dst_port: int

    # Connection count
    connection_count: int = 0

    # Inter-connection interval statistics
    ici_mean: Optional[float] = None
    ici_median: Optional[float] = None
    ici_std: Optional[float] = None
    ici_min: Optional[float] = None
    ici_max: Optional[float] = None
    ici_cv: Optional[float] = None       # Coefficient of Variation
    ici_periodicity: Optional[float] = None  # Periodicity score [0,1]
    ici_jitter: Optional[float] = None   # Mean absolute deviation
    ici_sample_count: int = 0

    # Per-connection byte/packet statistics (consistency)
    byte_mean: Optional[float] = None
    byte_std: Optional[float] = None
    byte_cv: Optional[float] = None
    pkt_mean: Optional[float] = None
    pkt_std: Optional[float] = None
    pkt_cv: Optional[float] = None
    duration_mean: Optional[float] = None

    # Observation window
    first_seen: Optional[float] = None
    last_seen: Optional[float] = None
    observation_duration: Optional[float] = None

    def to_dict(self) -> dict:
        return {
            "src_ip": self.src_ip,
            "dst_ip": self.dst_ip,
            "dst_port": self.dst_port,
            "connection_count": self.connection_count,
            "ici_mean": self.ici_mean,
            "ici_cv": self.ici_cv,
            "ici_periodicity": self.ici_periodicity,
            "ici_jitter": self.ici_jitter,
            "byte_cv": self.byte_cv,
            "pkt_cv": self.pkt_cv,
            "observation_duration": self.observation_duration,
        }

    def to_feature_array(self) -> List[float]:
        """
        Return a flat numeric array suitable for ML model input.

        Uses 0.0 for any None/unavailable feature.
        """
        def _f(v, default=0.0):
            if v is None:
                return default
            try:
                return float(v)
            except (TypeError, ValueError):
                return default

        return [
            _f(self.connection_count),
            _f(self.ici_mean),
            _f(self.ici_cv, default=1.0),
            _f(self.ici_periodicity),
            _f(self.ici_jitter),
            _f(self.ici_std),
            _f(self.ici_sample_count),
            _f(self.byte_cv, default=1.0),
            _f(self.pkt_cv, default=1.0),
            _f(self.byte_mean),
            _f(self.pkt_mean),
            _f(self.duration_mean),
            _f(self.observation_duration),
        ]


# ================================================================
# Feature computation from BeaconState
# ================================================================

def _safe_cv(values: List[float]) -> Optional[float]:
    """CV = std/mean. Returns None if mean=0 or < 2 samples."""
    if len(values) < 2:
        return None
    mean = statistics.mean(values)
    if mean <= 0.0:
        return None
    try:
        std = statistics.stdev(values)
    except statistics.StatisticsError:
        return None
    cv = std / mean
    return cv if math.isfinite(cv) else None


def _safe_mean(values: List[float]) -> Optional[float]:
    if not values:
        return None
    return statistics.mean(values)


def _safe_stdev(values: List[float]) -> Optional[float]:
    if len(values) < 2:
        return None
    try:
        return statistics.stdev(values)
    except statistics.StatisticsError:
        return None


def _safe_jitter(values: List[float]) -> Optional[float]:
    """Mean absolute deviation from mean."""
    if len(values) < 2:
        return None
    mean = statistics.mean(values)
    return statistics.mean(abs(v - mean) for v in values)


def _periodicity_score(cv: Optional[float], cv_random: float = 0.60) -> Optional[float]:
    """
    Convert a CV value to a periodicity score in [0, 1].

    Formula:
        s = max(0, 1 - CV / cv_random_threshold)

    Mathematical properties:
        - Monotonically decreasing in CV
        - s = 1.0 when CV = 0 (perfect periodicity)
        - s = 0.0 when CV >= cv_random_threshold
        - Linear interpolation between the extremes

    Parameters
    ----------
    cv:
        Coefficient of variation of inter-connection intervals.
    cv_random:
        CV value at which the signal becomes indistinguishable from random.

    Returns
    -------
    Optional[float]
        Score in [0, 1], or None if cv is None.
    """
    if cv is None:
        return None
    if cv_random <= 0.0:
        return 0.0
    score = max(0.0, 1.0 - cv / cv_random)
    return min(1.0, score)


def compute_beacon_features(
    state: BeaconState,
    cfg: Optional[dict] = None,
) -> BeaconFeatures:
    """
    Compute BeaconFeatures from a BeaconState.

    Parameters
    ----------
    state:
        Accumulated connection history.
    cfg:
        Configuration dict (c2_beacon section). Uses defaults if None.

    Returns
    -------
    BeaconFeatures
        Populated with all computable statistics.
        None for any feature that cannot be computed from available data.
    """
    if cfg is None:
        cfg = _cfg()

    min_ici = float(_get(cfg, "interval", "min_sec", default=5.0))
    max_ici = float(_get(cfg, "interval", "max_sec", default=7200.0))
    cv_random = float(_get(cfg, "periodicity", "cv_random_threshold", default=0.60))

    intervals = state.inter_connection_intervals(min_sec=min_ici, max_sec=max_ici)
    bytes_ = [float(b) for b in state.byte_counts]
    pkts = [float(p) for p in state.packet_counts]
    durs = [float(d) for d in state.durations]
    ts = sorted(state.timestamps)

    cv = _safe_cv(intervals)

    feat = BeaconFeatures(
        src_ip=state.src_ip,
        dst_ip=state.dst_ip,
        dst_port=state.dst_port,
        connection_count=state.count,
        ici_mean=_safe_mean(intervals),
        ici_median=statistics.median(intervals) if intervals else None,
        ici_std=_safe_stdev(intervals),
        ici_min=min(intervals) if intervals else None,
        ici_max=max(intervals) if intervals else None,
        ici_cv=cv,
        ici_periodicity=_periodicity_score(cv, cv_random),
        ici_jitter=_safe_jitter(intervals),
        ici_sample_count=len(intervals),
        byte_mean=_safe_mean(bytes_),
        byte_std=_safe_stdev(bytes_),
        byte_cv=_safe_cv(bytes_),
        pkt_mean=_safe_mean(pkts),
        pkt_std=_safe_stdev(pkts),
        pkt_cv=_safe_cv(pkts),
        duration_mean=_safe_mean(durs),
        first_seen=ts[0] if ts else None,
        last_seen=ts[-1] if ts else None,
        observation_duration=(ts[-1] - ts[0]) if len(ts) >= 2 else None,
    )
    return feat


# ================================================================
# Beacon Tracker (manages all BeaconState instances)
# ================================================================

class BeaconTracker:
    """
    Manages per-(src_ip, dst_ip, dst_port) beacon state for all
    observed communication pairs.

    Call record() for each completed FlowRecord or FeatureVector.
    Call get_features() to retrieve computed BeaconFeatures for
    a specific endpoint pair.

    Memory is bounded: max_pairs limits total tracked tuples.

    Parameters
    ----------
    cfg:
        C2 beacon config dict. Reads from thresholds.yaml if None.
    max_pairs:
        Maximum number of (src, dst, dport) pairs tracked simultaneously.
    """

    def __init__(
        self,
        cfg: Optional[dict] = None,
        max_pairs: int = 50_000,
    ) -> None:
        self._cfg = cfg or _cfg()
        self._max_pairs = max_pairs
        self._min_flows = int(_get(self._cfg, "min_flows_for_analysis", default=5))
        self._max_records = int(_get(self._cfg, "max_tracked_connections", default=200))
        self._max_age_seconds = float(_get(self._cfg, "max_age_seconds", default=86400))
        self._states: Dict[Tuple[str, str, int], BeaconState] = {}
        self._last_processed_time = 0.0

        logger.debug(
            "BeaconTracker initialised",
            min_flows=self._min_flows,
            max_pairs=max_pairs,
        )

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def expire_old_states(self) -> int:
        """Evict tracked states that haven't been active recently."""
        expired = []
        for key, state in self._states.items():
            if state.timestamps and (self._last_processed_time - state.timestamps[-1] > self._max_age_seconds):
                expired.append(key)
        for key in expired:
            del self._states[key]
        return len(expired)

    def record(
        self,
        src_ip: str,
        dst_ip: str,
        dst_port: int,
        timestamp: float,
        byte_count: int = 0,
        packet_count: int = 0,
        duration: float = 0.0,
    ) -> None:
        """
        Record one connection observation.

        Parameters
        ----------
        src_ip, dst_ip, dst_port:
            5-tuple components identifying the endpoint pair.
        timestamp:
            UNIX epoch timestamp of connection start.
        byte_count, packet_count, duration:
            Per-connection statistics.
        """
        if not src_ip or not dst_ip:
            return

        self._last_processed_time = max(self._last_processed_time, timestamp)

        # Periodically expire old states based on the current timestamp window
        # (Could optimize to only run occasionally, but doing it inline ensures memory bounds)
        self.expire_old_states()

        key = (src_ip, dst_ip, dst_port)

        if key not in self._states:
            if len(self._states) >= self._max_pairs:
                # Evict oldest state (LRU-like: pop first inserted)
                oldest = next(iter(self._states))
                del self._states[oldest]
                logger.warning(
                    "BeaconTracker capacity reached — evicting oldest pair",
                    evicted=oldest,
                )
            self._states[key] = BeaconState(
                src_ip=src_ip,
                dst_ip=dst_ip,
                dst_port=dst_port,
                max_records=self._max_records,
            )

        record = ConnectionRecord(
            timestamp=timestamp,
            byte_count=byte_count,
            packet_count=packet_count,
            duration=duration,
            dst_ip=dst_ip,
            dst_port=dst_port,
        )
        self._states[key].add(record)

    def record_from_fv(self, fv: "FeatureVector") -> None:
        """
        Convenience wrapper: extract fields from a FeatureVector and record.

        Parameters
        ----------
        fv:
            FeatureVector from the feature pipeline.
        """
        src_ip = fv.source_ip or ""
        dst_ip = fv.destination_ip or ""
        dst_port = fv.destination_port or 0
        start_time = fv.get("start_time") or 0.0
        byte_count = int(fv.get("byte_count") or 0)
        packet_count = int(fv.get("packet_count") or 0)
        duration = float(fv.get("flow_duration") or 0.0)

        self.record(
            src_ip=src_ip,
            dst_ip=dst_ip,
            dst_port=dst_port,
            timestamp=float(start_time),
            byte_count=byte_count,
            packet_count=packet_count,
            duration=duration,
        )

    def get_features(
        self, src_ip: str, dst_ip: str, dst_port: int
    ) -> Optional[BeaconFeatures]:
        """
        Return computed BeaconFeatures for an endpoint pair,
        or None if insufficient data.
        """
        key = (src_ip, dst_ip, dst_port)
        state = self._states.get(key)
        if state is None or state.count < self._min_flows:
            return None
        return compute_beacon_features(state, self._cfg)

    def get_features_from_fv(self, fv: "FeatureVector") -> Optional[BeaconFeatures]:
        """Convenience wrapper for get_features using FeatureVector fields."""
        return self.get_features(
            src_ip=fv.source_ip or "",
            dst_ip=fv.destination_ip or "",
            dst_port=fv.destination_port or 0,
        )

    def connection_count(self, src_ip: str, dst_ip: str, dst_port: int) -> int:
        """Return observed connection count for a pair, or 0 if not tracked."""
        key = (src_ip, dst_ip, dst_port)
        state = self._states.get(key)
        return state.count if state else 0

    @property
    def tracked_pairs(self) -> int:
        return len(self._states)

    def all_candidates(self, min_connections: Optional[int] = None) -> List[BeaconFeatures]:
        """
        Return BeaconFeatures for all pairs that have enough connections.

        Parameters
        ----------
        min_connections:
            Minimum connection count. Defaults to min_flows_for_analysis.
        """
        threshold = min_connections or self._min_flows
        results = []
        for state in self._states.values():
            if state.count >= threshold:
                results.append(compute_beacon_features(state, self._cfg))
        return results
