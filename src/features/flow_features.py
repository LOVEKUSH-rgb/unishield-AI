"""
UniShield AI -- Flow Features
==============================
Extracts statistical features from a completed FlowRecord.

Features produced:
  Packet statistics:   count, bytes, min/max/mean/median/std/variance
  Rate statistics:     packets/sec, bytes/sec
  TCP flag features:   per-flag counts and ratios
  Flow metadata:       duration, direction hints

These are OBSERVATIONS only. No classification is performed here.

Usage:
    from src.features.flow_features import extract_flow_features
    fv = FeatureVector(flow_id=flow.flow_id, ...)
    extract_flow_features(flow, fv)
"""

from __future__ import annotations

import math
import statistics
from typing import TYPE_CHECKING, Optional

if TYPE_CHECKING:
    from src.flows.flow import FlowRecord
    from src.features.feature_vector import FeatureVector


def _safe_stat(values: list, fn, default: float = 0.0) -> float:
    """Apply a statistics function safely, returning default on failure."""
    if not values:
        return default
    try:
        result = fn(values)
        if not math.isfinite(result):
            return default
        return result
    except (statistics.StatisticsError, ZeroDivisionError, ValueError):
        return default


def extract_flow_features(flow: "FlowRecord", fv: "FeatureVector") -> None:
    """
    Compute all flow-level statistical features and write them into *fv*.

    Parameters
    ----------
    flow:
        A completed or in-progress FlowRecord.
    fv:
        The FeatureVector to update in-place.

    Notes
    -----
    Zero-division is handled explicitly.
    Missing packet size lists produce 0/None defaults, not errors.
    """
    sizes = flow.packet_sizes
    duration = flow.duration  # seconds (0.0 if single packet)

    try:
        from src.utils.config import get_thresholds
        splt_max = int(get_thresholds().get("encrypted_session", {}).get("splt_max_sequence_length", 20))
    except Exception:
        splt_max = 20

    # ----------------------------------------------------------------
    # Basic flow identity (already on fv, but ensure they're set)
    # ----------------------------------------------------------------
    features: dict = {
        "flow_duration": duration,
        "start_time": flow.start_time,
        "last_seen": flow.last_seen,
    }

    # ----------------------------------------------------------------
    # Packet and byte counts
    # ----------------------------------------------------------------
    features["packet_count"] = flow.packet_count
    features["byte_count"] = flow.byte_count

    # ----------------------------------------------------------------
    # Rate statistics
    # ----------------------------------------------------------------
    if duration > 0.0:
        features["packets_per_second"] = flow.packet_count / duration
        features["bytes_per_second"] = flow.byte_count / duration
    else:
        # Single-packet or zero-duration flow — rates undefined
        features["packets_per_second"] = None
        features["bytes_per_second"] = None

    # ----------------------------------------------------------------
    # Packet size statistics
    # ----------------------------------------------------------------
    if sizes:
        features["pkt_size_min"] = float(min(sizes))
        features["pkt_size_max"] = float(max(sizes))
        features["pkt_size_mean"] = _safe_stat(sizes, statistics.mean)
        features["pkt_size_median"] = float(_safe_stat(
            sizes, statistics.median
        ))
        features["pkt_size_std"] = float(_safe_stat(
            sizes,
            lambda v: statistics.stdev(v) if len(v) >= 2 else 0.0,
        ))
        features["pkt_size_variance"] = float(_safe_stat(
            sizes,
            lambda v: statistics.variance(v) if len(v) >= 2 else 0.0,
        ))

        # Coefficient of variation (std / mean) for packet sizes
        mean_sz = features["pkt_size_mean"]
        if mean_sz and mean_sz > 0.0:
            features["pkt_size_cv"] = features["pkt_size_std"] / mean_sz
        else:
            features["pkt_size_cv"] = None
        # SPLT bounds
        features["splt_sizes"] = sizes[:splt_max]
    else:
        for key in (
            "pkt_size_min", "pkt_size_max",
            "pkt_size_median", "pkt_size_std", "pkt_size_variance", "pkt_size_cv",
            "splt_sizes"
        ):
            features[key] = None
        
        # Derivable even if aggregated
        if flow.packet_count > 0:
            features["pkt_size_mean"] = flow.byte_count / flow.packet_count
        else:
            features["pkt_size_mean"] = None

    # ----------------------------------------------------------------
    # TCP flag features
    # ----------------------------------------------------------------
    pkt_count = max(flow.packet_count, 1)  # avoid /0
    flags = flow.tcp_flags

    features["tcp_syn_count"] = flags.syn
    features["tcp_syn_ack_count"] = flags.syn_ack
    features["tcp_ack_count"] = flags.ack
    features["tcp_fin_count"] = flags.fin
    features["tcp_rst_count"] = flags.rst
    features["tcp_psh_count"] = flags.psh
    features["tcp_urg_count"] = flags.urg

    # Flag ratios (per packet)
    features["tcp_syn_ratio"] = flags.syn / pkt_count
    features["tcp_fin_ratio"] = flags.fin / pkt_count
    features["tcp_rst_ratio"] = flags.rst / pkt_count
    features["tcp_ack_ratio"] = flags.ack / pkt_count

    # SYN without SYN-ACK response ratio
    total_syn = flags.syn + flags.syn_ack
    if total_syn > 0:
        features["tcp_syn_only_ratio"] = flags.syn / total_syn
    else:
        features["tcp_syn_only_ratio"] = None

    # Protocol as a numeric code
    features["protocol"] = flow.protocol

    # Whether the flow was completed (FIN/RST seen)
    features["flow_completed"] = int(flow.completed)

    fv.update("flow", features)
