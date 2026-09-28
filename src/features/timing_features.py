"""
UniShield AI -- Timing Features
=================================
Extracts timing-based features from the inter-arrival time (IAT)
sequence stored in a FlowRecord.

Features produced:
  iat_mean, iat_median, iat_std, iat_min, iat_max
  iat_cv          -- coefficient of variation (std/mean)
  iat_periodicity -- simple periodicity score (0..1)
  iat_jitter      -- mean absolute deviation from expected period

Design notes:
  - IAT is always >= 0 (enforced by FlowRecord.update)
  - Periodicity score uses autocorrelation at lag-1 after normalisation
  - A high periodicity score does NOT mean C2 beaconing is confirmed --
    it is a FEATURE for the C2 detector to interpret

IMPORTANT: This module produces features only. No classification.
"""

from __future__ import annotations

import math
import statistics
from typing import TYPE_CHECKING, List, Optional

if TYPE_CHECKING:
    from src.flows.flow import FlowRecord
    from src.features.feature_vector import FeatureVector


def _mean(values: List[float]) -> Optional[float]:
    if not values:
        return None
    return statistics.mean(values)


def _median(values: List[float]) -> Optional[float]:
    if not values:
        return None
    return statistics.median(values)


def _stdev(values: List[float]) -> Optional[float]:
    if len(values) < 2:
        return None
    try:
        result = statistics.stdev(values)
        return result if math.isfinite(result) else None
    except statistics.StatisticsError:
        return None


def coefficient_of_variation(values: List[float]) -> Optional[float]:
    """
    Compute the coefficient of variation (CV = std / mean).

    CV is dimensionless and measures relative variability.
    Low CV (<= 0.3) suggests regular/periodic timing.
    High CV (> 1.0) suggests bursty or irregular timing.

    Returns None if fewer than 2 samples or mean is zero.
    """
    if len(values) < 2:
        return None
    mean_val = statistics.mean(values)
    if mean_val <= 0.0:
        return None
    std_val = _stdev(values)
    if std_val is None:
        return None
    cv = std_val / mean_val
    return cv if math.isfinite(cv) else None


def periodicity_score(values: List[float]) -> Optional[float]:
    """
    Estimate how periodic the IAT sequence is.

    Method: Normalised lag-1 autocorrelation of the IAT sequence.
    Score in [0, 1] where:
      ~1.0 = highly periodic (each interval is similar to the previous)
      ~0.0 = random / irregular

    This is a FEATURE. High score does not imply malice.

    Parameters
    ----------
    values:
        List of inter-arrival times in seconds.

    Returns
    -------
    float or None
        Periodicity score in [0, 1], or None if insufficient data.
    """
    n = len(values)
    if n < 4:
        return None

    mean_val = statistics.mean(values)
    if mean_val <= 0.0:
        return None

    # Centre the series
    centred = [v - mean_val for v in values]

    # Lag-0 (variance term)
    lag0 = sum(c * c for c in centred)
    if lag0 == 0.0:
        # All values identical -> perfectly periodic
        return 1.0

    # Lag-1 autocorrelation
    lag1 = sum(centred[i] * centred[i + 1] for i in range(n - 1))

    # Normalised by lag-0 (Pearson-like)
    autocorr = lag1 / lag0

    # Clamp to [0, 1] — negative autocorrelation is set to 0
    score = max(0.0, min(1.0, autocorr))
    return score if math.isfinite(score) else None


def iat_jitter(values: List[float]) -> Optional[float]:
    """
    Compute IAT jitter: mean absolute deviation from the mean IAT.

    Low jitter indicates very regular inter-arrival times.
    High jitter indicates irregular timing.

    Returns None if fewer than 2 samples.
    """
    if len(values) < 2:
        return None
    mean_val = statistics.mean(values)
    mad = statistics.mean(abs(v - mean_val) for v in values)
    return mad if math.isfinite(mad) else None


def extract_timing_features(flow: "FlowRecord", fv: "FeatureVector") -> None:
    """
    Compute all timing features from a FlowRecord's IAT list.

    Parameters
    ----------
    flow:
        A FlowRecord with at least one inter-arrival time sample.
    fv:
        The FeatureVector to update in-place.
    """
    iats = flow.inter_arrival_times

    try:
        from src.utils.config import get_thresholds
        splt_max = int(get_thresholds().get("encrypted_session", {}).get("splt_max_sequence_length", 20))
    except Exception:
        splt_max = 20

    features: dict = {}

    if not iats:
        # Not enough packets for timing features
        for key in (
            "iat_mean", "iat_median", "iat_std", "iat_min", "iat_max",
            "iat_cv", "iat_periodicity", "iat_jitter", "splt_times"
        ):
            features[key] = None
        fv.update("timing", features)
        return

    features["iat_mean"] = _mean(iats)
    features["iat_median"] = _median(iats)
    features["iat_std"] = _stdev(iats)
    features["iat_min"] = min(iats)
    features["iat_max"] = max(iats)
    features["iat_cv"] = coefficient_of_variation(iats)
    features["iat_periodicity"] = periodicity_score(iats)
    features["iat_jitter"] = iat_jitter(iats)
    features["iat_sample_count"] = len(iats)
    features["splt_times"] = iats[:splt_max]

    fv.update("timing", features)
