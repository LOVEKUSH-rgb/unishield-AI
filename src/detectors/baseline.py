"""
UniShield AI -- Baseline Engine
==================================
Maintains exponentially-weighted moving average (EWMA) baselines
for traffic metrics, enabling anomaly detection by comparing
current observations to recent normal behavior.

Why EWMA?
  - Adapts continuously without storing all history
  - More weight on recent observations
  - Memory-efficient for streaming detection
  - Well-suited to non-stationary network traffic

Limitations (explicitly documented):
  - Cold-start: first N events have no reliable baseline
  - Cannot handle sudden legitimate traffic spikes without
    temporarily elevated false-positive risk
  - EWMA alpha tuned empirically -- not statistically calibrated

PASSIVE AUDIT: Read-only. No network activity.
"""

from __future__ import annotations

import math
import time
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple

from src.utils.config import get_thresholds
from src.utils.logging import get_logger

logger = get_logger(__name__)


def _get_ddos_baseline_cfg() -> dict:
    try:
        return get_thresholds().get("ddos", {}).get("baseline", {})
    except Exception:
        return {}


# ================================================================
# EWMA State
# ================================================================

@dataclass
class EWMAState:
    """
    Single EWMA metric tracker.

    Tracks mean and variance using Welford's online algorithm
    for variance, combined with EWMA for the mean.

    Attributes
    ----------
    alpha:
        Smoothing factor in (0, 1).
        High alpha = fast adaptation (more responsive, less stable).
        Low alpha = slow adaptation (more stable, slower to adapt).
    mean:
        Current EWMA of the metric.
    variance:
        Current EWMA variance estimate.
    count:
        Number of observations recorded.
    """

    alpha: float = 0.15
    mean: float = 0.0
    variance: float = 0.0
    count: int = 0

    def update(self, value: float) -> None:
        """Update the EWMA with a new observation."""
        if not math.isfinite(value):
            return

        self.count += 1

        if self.count == 1:
            self.mean = value
            self.variance = 0.0
            return

        # EWMA mean
        diff = value - self.mean
        self.mean = self.mean + self.alpha * diff

        # EWMA variance (incr. approximation)
        self.variance = (1 - self.alpha) * (self.variance + self.alpha * diff * diff)

    @property
    def std(self) -> float:
        """Standard deviation of the EWMA estimate."""
        return math.sqrt(max(0.0, self.variance))

    def z_score(self, value: float) -> Optional[float]:
        """
        Compute the z-score of a value relative to this baseline.

        Returns None if insufficient data.
        When std is effectively zero (constant input), uses a small
        minimum std floor (1% of mean) to avoid division by zero while
        still being able to detect large deviations.

        A z-score of 3.0 means the value is 3 standard deviations
        above the mean -- typically associated with anomalies.
        """
        if self.count < 5:
            return None
        # Use minimum std floor: 1% of mean, at least 0.001
        effective_std = max(self.std, max(abs(self.mean) * 0.01, 0.001))
        z = (value - self.mean) / effective_std
        return z

    def ratio_to_baseline(self, value: float) -> Optional[float]:
        """Return value / mean, or None if mean is zero."""
        if self.mean <= 0.0:
            return None
        return value / self.mean

    @property
    def is_warmed_up(self) -> bool:
        """True if enough observations have been recorded."""
        return self.count >= 5

    def reset(self) -> None:
        self.mean = 0.0
        self.variance = 0.0
        self.count = 0


# ================================================================
# Multi-metric Baseline
# ================================================================

class TrafficBaseline:
    """
    Maintains EWMA baselines for multiple traffic metrics simultaneously.

    Metrics tracked:
      - packets_per_second  (aggregate)
      - bytes_per_second    (aggregate)
      - syn_per_second      (TCP SYN rate)
      - udp_per_second      (UDP packet rate)
      - flows_per_second    (new flow creation rate)
      - unique_sources      (per time window)

    Parameters
    ----------
    alpha:
        EWMA smoothing factor. Reads from config if None.
    warmup_count:
        Number of observations before the baseline is "trusted".
    """

    _METRIC_KEYS = [
        "packets_per_second",
        "bytes_per_second",
        "syn_per_second",
        "udp_per_second",
        "flows_per_second",
        "unique_sources",
    ]

    def __init__(
        self,
        alpha: Optional[float] = None,
        warmup_count: Optional[int] = None,
    ) -> None:
        cfg = _get_ddos_baseline_cfg()
        self._alpha = alpha if alpha is not None else float(cfg.get("ewma_alpha", 0.15))
        self._warmup = warmup_count if warmup_count is not None else int(cfg.get("warmup_packets", 500))

        self._metrics: Dict[str, EWMAState] = {
            key: EWMAState(alpha=self._alpha)
            for key in self._METRIC_KEYS
        }
        self._total_observations = 0

        logger.debug(
            "TrafficBaseline initialised",
            alpha=self._alpha,
            warmup=self._warmup,
        )

    def update(self, metrics: Dict[str, float]) -> None:
        """
        Update baselines with a new observation dict.

        Parameters
        ----------
        metrics:
            Dict of metric_name -> float value.
            Unknown keys are ignored.
        """
        self._total_observations += 1
        for key, value in metrics.items():
            if key in self._metrics:
                self._metrics[key].update(value)

    def z_score(self, metric: str, value: float) -> Optional[float]:
        """
        Return the z-score for a metric.

        Parameters
        ----------
        metric:
            Metric name (must match a tracked key).
        value:
            Current observed value.

        Returns
        -------
        Optional[float]
            Z-score, or None if baseline not yet warmed up.
        """
        state = self._metrics.get(metric)
        if state is None or not state.is_warmed_up:
            return None
        return state.z_score(value)

    def ratio(self, metric: str, value: float) -> Optional[float]:
        """Return observed / baseline mean for a metric."""
        state = self._metrics.get(metric)
        if state is None or not state.is_warmed_up:
            return None
        return state.ratio_to_baseline(value)

    def baseline_value(self, metric: str) -> Optional[float]:
        """Return current baseline mean for a metric."""
        state = self._metrics.get(metric)
        if state is None or not state.is_warmed_up:
            return None
        return state.mean

    @property
    def is_warmed_up(self) -> bool:
        """True if we have observed enough data for reliable baselines."""
        return self._total_observations >= self._warmup

    @property
    def observations(self) -> int:
        return self._total_observations

    def get_all_baselines(self) -> Dict[str, Optional[float]]:
        """Return dict of all current baseline means."""
        return {
            key: (state.mean if state.is_warmed_up else None)
            for key, state in self._metrics.items()
        }

    def reset(self) -> None:
        """Reset all baselines (e.g. after a configuration change)."""
        for state in self._metrics.values():
            state.reset()
        self._total_observations = 0


# ================================================================
# Rate window (for burst detection)
# ================================================================

class RateWindow:
    """
    Tracks a rolling count over a short time window.

    Used for burst detection: if count spikes suddenly in the
    burst_window, that is a burst indicator.

    Parameters
    ----------
    window_seconds:
        Duration of the rolling window.
    """

    def __init__(self, window_seconds: float = 5.0) -> None:
        self._window = window_seconds
        self._events: List[float] = []  # list of timestamps

    def add(self, timestamp: float, count: int = 1) -> None:
        """Record `count` events at the given timestamp."""
        for _ in range(count):
            self._events.append(timestamp)
        self._evict(timestamp)

    def _evict(self, current_time: float) -> None:
        cutoff = current_time - self._window
        self._events = [t for t in self._events if t >= cutoff]

    def rate(self, current_time: float) -> float:
        """Return events/second in the current window."""
        self._evict(current_time)
        return len(self._events) / max(self._window, 1e-9)

    def count(self, current_time: float) -> int:
        self._evict(current_time)
        return len(self._events)
