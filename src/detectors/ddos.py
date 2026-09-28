"""
UniShield AI -- DDoS Detector
================================
Passively detects Distributed Denial-of-Service patterns
using multi-signal statistical analysis of flow metadata.

============================================================
THREATS COVERED
============================================================

A. TCP SYN Flood
   Characteristics: High SYN rate, SYN ratio >> normal,
   many unanswered connection attempts.
   Limitation: In unidirectional monitoring we cannot confirm
   handshake incompletion. We report indicators, not certainty.

B. UDP Volumetric Flood
   Characteristics: High UDP packet/byte rate, often to
   a single destination, sometimes with large packets.

C. General Traffic Rate Anomaly
   Characteristics: Overall packet/byte rate significantly
   above the EWMA baseline.

D. Spoofed-Source Indicators
   Characteristics: Abnormally high source IP cardinality or
   entropy, many different sources sending to one target.
   Limitation: We CANNOT prove IP spoofing from one-way metadata.
   We report "consistent with spoofed-source flood" language.

E. UDP Reflection/Amplification Indicators
   Characteristics: Large inbound UDP responses from many
   external sources to concentrated destinations.
   Limitation: Without bidirectional visibility we cannot
   confirm that a request was sent. We report indicators only.

============================================================
SCORING METHODOLOGY
============================================================

Four independent sub-detectors each produce a score in [0,1]:

  rate_score     -- volumetric rate vs EWMA baseline (z-score)
  syn_score      -- SYN flood indicators
  udp_score      -- UDP flood indicators
  source_score   -- source IP distribution anomalies

Weighted fusion:
  final_score = w1*rate + w2*syn + w3*udp + w4*source

Weights are configurable in config/thresholds.yaml.
Default: rate=0.30, syn=0.30, udp=0.20, source=0.20

Confidence:
  Confidence reflects AGREEMENT between signals.
  If 3+ independent sub-detectors all exceed 0.6, confidence is high.
  A single signal with no corroboration produces low confidence.

  confidence = mean(sub_scores where score > 0.5) +
               agreement_bonus * (n_strong_signals / 4)

  This is a heuristic, not a calibrated probability.

============================================================
ARCHITECTURE CONSTRAINTS (PASSIVE-ONLY)
============================================================

[PASS] No packets transmitted
[PASS] No active probing
[PASS] No handshake initiation or completion
[PASS] No payload decryption
[PASS] All inputs from FeatureVector (metadata only)

============================================================
KNOWN LIMITATIONS
============================================================

1. One-way visibility: Cannot confirm SYN handshake failed.
2. No spoofing proof: High source entropy is CONSISTENT WITH
   spoofing, not proof of spoofing.
3. No reflection proof: Without seeing the original requests,
   we cannot confirm UDP amplification. We report indicators.
4. Baseline cold-start: First N events have unreliable baselines.
   During warmup, only absolute threshold checks are used.
5. Low-and-slow attacks: Volume-based detector may miss slow
   attacks designed to stay under thresholds.
6. Encrypted traffic: Cannot inspect payload to distinguish
   DDoS from encrypted legitimate bulk transfer.
7. Legitimate spikes: CDN traffic, backup jobs, software updates
   can look like volumetric floods. Use in context.

============================================================
USAGE
============================================================

Library:
    from src.detectors.ddos import DDoSDetector
    detector = DDoSDetector()
    result = detector.detect(feature_vector)

CLI:
    python -m src.detectors.ddos path/to/capture.pcap
"""

from __future__ import annotations

import math
import time
from typing import Dict, List, Optional, Tuple

from src.detectors.base import (
    BaseDetector,
    DetectionResult,
    Evidence,
    Severity,
    ThreatClass,
    score_to_severity,
)
from src.detectors.baseline import TrafficBaseline, RateWindow
from src.features.feature_vector import FeatureVector
from src.utils.config import get_thresholds
from src.utils.logging import get_logger

logger = get_logger(__name__)


# ================================================================
# Config helpers
# ================================================================

def _cfg() -> dict:
    try:
        return get_thresholds().get("ddos", {})
    except Exception:
        return {}


def _get(cfg: dict, *keys, default=0.0):
    """Safely traverse nested config dict."""
    val = cfg
    for k in keys:
        if not isinstance(val, dict):
            return default
        val = val.get(k, default)
    try:
        return type(default)(val)
    except (TypeError, ValueError):
        return default


def _sigmoid(x: float, steepness: float = 2.0) -> float:
    """Map a z-score to [0,1] using a sigmoid curve."""
    try:
        return 1.0 / (1.0 + math.exp(-steepness * x))
    except OverflowError:
        return 1.0 if x > 0 else 0.0


def _clamp(v: float, lo: float = 0.0, hi: float = 1.0) -> float:
    return max(lo, min(hi, v))


# ================================================================
# Sub-detector: Rate Anomaly
# ================================================================

class RateAnomalyDetector:
    """
    Detects anomalous traffic rates by comparing current observations
    against an EWMA baseline.

    Evidence produced:
      - packets_per_second vs baseline (z-score)
      - bytes_per_second vs baseline (z-score)
    """

    def __init__(self, cfg: dict, baseline: TrafficBaseline) -> None:
        self._cfg = cfg
        self._bl = baseline
        self._pps_z_threshold = _get(cfg, "rate", "pps_z_score_alert", default=3.0)
        self._bps_z_threshold = _get(cfg, "rate", "bps_z_score_alert", default=3.0)
        self._pps_abs_min = _get(cfg, "rate", "pps_absolute_min", default=2000.0)
        self._bps_abs_min = _get(cfg, "rate", "bps_absolute_min", default=5_000_000.0)

    def score(self, fv: FeatureVector) -> Tuple[float, List[Evidence]]:
        evidence = []
        scores = []

        pps = fv.get("packets_per_second")
        bps = fv.get("bytes_per_second")

        # --- Packets/second ---
        if isinstance(pps, (int, float)) and pps is not None:
            pps_z = self._bl.z_score("packets_per_second", float(pps))
            pps_baseline = self._bl.baseline_value("packets_per_second")

            if pps_z is not None and pps >= self._pps_abs_min:
                s = _clamp(_sigmoid(pps_z - self._pps_z_threshold + 1))
                scores.append(s)
                if pps_z > self._pps_z_threshold * 0.7:
                    evidence.append(Evidence(
                        feature="packets_per_second",
                        observed=round(pps, 2),
                        baseline=round(pps_baseline, 2) if pps_baseline else None,
                        deviation=round(pps_z, 3),
                        score=s,
                        detector="RateAnomaly",
                        reason=(
                            f"Packet rate is {pps_z:.1f} standard deviations above "
                            f"baseline ({pps_baseline:.1f} pkt/s). This is consistent "
                            f"with a volumetric traffic flood."
                        ),
                    ))
            elif pps >= self._pps_abs_min and not self._bl.is_warmed_up:
                # Cold start: use absolute threshold
                s = min(1.0, pps / (self._pps_abs_min * 5))
                scores.append(s)
                if s > 0.3:
                    evidence.append(Evidence(
                        feature="packets_per_second",
                        observed=round(pps, 2),
                        baseline=None,
                        deviation=None,
                        score=s,
                        detector="RateAnomaly",
                        reason=(
                            f"Packet rate {pps:.0f} pkt/s exceeds absolute threshold "
                            f"(baseline not yet established — cold start)."
                        ),
                    ))

        # --- Bytes/second ---
        if isinstance(bps, (int, float)) and bps is not None:
            bps_z = self._bl.z_score("bytes_per_second", float(bps))
            bps_baseline = self._bl.baseline_value("bytes_per_second")

            if bps_z is not None and bps >= self._bps_abs_min:
                s = _clamp(_sigmoid(bps_z - self._bps_z_threshold + 1))
                scores.append(s)
                if bps_z > self._bps_z_threshold * 0.7:
                    evidence.append(Evidence(
                        feature="bytes_per_second",
                        observed=round(bps, 2),
                        baseline=round(bps_baseline, 2) if bps_baseline else None,
                        deviation=round(bps_z, 3),
                        score=s,
                        detector="RateAnomaly",
                        reason=(
                            f"Byte rate is {bps_z:.1f} standard deviations above "
                            f"baseline ({bps_baseline:.1f} B/s). Consistent with "
                            f"volumetric flood."
                        ),
                    ))

        final = max(scores) if scores else 0.0
        return _clamp(final), evidence


# ================================================================
# Sub-detector: SYN Flood
# ================================================================

class SYNFloodDetector:
    """
    Detects TCP SYN flood indicators.

    Limitation: In unidirectional monitoring we cannot confirm
    that SYN packets were not answered. We report indicators only.

    Evidence produced:
      - tcp_syn_ratio (SYN / total packets)
      - tcp_syn_count vs baseline
      - tcp_syn_only_ratio (unanswered SYN indicator)
    """

    def __init__(self, cfg: dict, baseline: TrafficBaseline) -> None:
        self._cfg = cfg
        self._bl = baseline
        syn_cfg = cfg.get("syn_flood", {})
        self._ratio_threshold = float(syn_cfg.get("syn_ratio_threshold", 0.80))
        self._ratio_high = float(syn_cfg.get("syn_ratio_high", 0.95))
        self._syn_pps_min = float(syn_cfg.get("syn_pps_absolute_min", 500.0))
        self._syn_pps_z = float(syn_cfg.get("syn_pps_z_score", 3.0))
        self._syn_only_ratio = float(syn_cfg.get("max_syn_only_ratio", 0.90))

    def score(self, fv: FeatureVector) -> Tuple[float, List[Evidence]]:
        evidence = []
        scores = []

        # --- SYN ratio ---
        syn_ratio = fv.get("tcp_syn_ratio")
        pkt_count = fv.get("packet_count") or 0

        if isinstance(syn_ratio, (int, float)) and pkt_count >= 10:
            if syn_ratio >= self._ratio_threshold:
                # Linear scale from threshold to 1.0
                s = _clamp((syn_ratio - self._ratio_threshold) /
                            (1.0 - self._ratio_threshold))
                scores.append(s)
                evidence.append(Evidence(
                    feature="tcp_syn_ratio",
                    observed=round(syn_ratio, 4),
                    baseline=0.05,   # typical SYN ratio in normal TCP traffic
                    deviation=round(syn_ratio / 0.05, 2),
                    score=s,
                    detector="SYNFlood",
                    reason=(
                        f"SYN packets constitute {syn_ratio*100:.1f}% of total "
                        f"TCP traffic. Normal traffic typically has SYN ratio < 5%. "
                        f"This is consistent with TCP SYN flood behavior. "
                        f"Note: In unidirectional monitoring, handshake completion "
                        f"cannot be confirmed."
                    ),
                ))

        # --- SYN count vs baseline ---
        syn_count = fv.get("tcp_syn_count")
        duration = fv.get("flow_duration")
        
        # Safe handling of 0-duration distributed flows (e.g. 1-packet SYN floods)
        if duration == 0.0 and syn_count == 1:
            # Approximate the effective rate at the destination using the 60s aggregation window
            dst_conn_60s = fv.get("dst_conn_count_60s")
            if isinstance(dst_conn_60s, (int, float)) and dst_conn_60s > 0:
                syn_pps = float(dst_conn_60s) / 60.0
            else:
                syn_pps = 0.0
        else:
            duration_safe = duration or 1.0
            syn_pps = float(syn_count) / float(duration_safe) if isinstance(syn_count, (int, float)) else 0.0

        if isinstance(syn_count, (int, float)) and syn_pps > 0:
            syn_z = self._bl.z_score("syn_per_second", syn_pps)
            syn_baseline = self._bl.baseline_value("syn_per_second")

            if syn_pps >= self._syn_pps_min:
                if syn_z is not None:
                    s = _clamp(_sigmoid(syn_z - self._syn_pps_z + 1))
                    scores.append(s)
                    if syn_z > self._syn_pps_z * 0.7:
                        evidence.append(Evidence(
                            feature="syn_rate_per_second",
                            observed=round(syn_pps, 2),
                            baseline=round(syn_baseline, 2) if syn_baseline else None,
                            deviation=round(syn_z, 3),
                            score=s,
                            detector="SYNFlood",
                            reason=(
                                f"SYN rate {syn_pps:.0f}/s is {syn_z:.1f}σ above "
                                f"baseline ({syn_baseline:.0f}/s if available). "
                                f"Elevated SYN rate is consistent with SYN flood activity."
                            ),
                        ))
                else:
                    # Cold start: absolute check
                    s = min(1.0, syn_pps / (self._syn_pps_min * 10))
                    scores.append(s)

        # --- SYN-only ratio (unanswered SYN indicator) ---
        syn_only = fv.get("tcp_syn_only_ratio")
        if isinstance(syn_only, (int, float)) and pkt_count >= 10:
            if syn_only >= self._syn_only_ratio:
                s = _clamp((syn_only - self._syn_only_ratio) /
                            (1.0 - self._syn_only_ratio))
                scores.append(s * 0.7)  # partial weight
                evidence.append(Evidence(
                    feature="tcp_syn_only_ratio",
                    observed=round(syn_only, 4),
                    baseline=0.5,
                    deviation=round(syn_only / 0.5, 2),
                    score=s * 0.7,
                    detector="SYNFlood",
                    reason=(
                        f"A high proportion ({syn_only*100:.1f}%) of SYN packets "
                        f"do not have a corresponding SYN-ACK in this observation. "
                        f"This may indicate unanswered connection attempts, consistent "
                        f"with SYN flood or port scanning behavior."
                    ),
                ))

        final = max(scores) if scores else 0.0
        return _clamp(final), evidence


# ================================================================
# Sub-detector: UDP Flood
# ================================================================

class UDPFloodDetector:
    """
    Detects UDP volumetric flood and amplification indicators.

    Limitation: Cannot confirm amplification without seeing
    original requests. Reports indicators only.

    Evidence produced:
      - UDP packet/byte rate vs baseline
      - Large packet patterns (possible amplification)
    """

    def __init__(self, cfg: dict, baseline: TrafficBaseline) -> None:
        self._cfg = cfg
        self._bl = baseline
        udp_cfg = cfg.get("udp_flood", {})
        self._udp_pps_z = float(udp_cfg.get("udp_pps_z_score", 3.0))
        self._udp_pps_min = float(udp_cfg.get("udp_pps_absolute_min", 1000.0))
        self._large_pkt_ratio = float(udp_cfg.get("large_packet_ratio", 0.70))
        self._large_pkt_threshold = float(udp_cfg.get("max_packet_size_threshold", 1400.0))

    def score(self, fv: FeatureVector) -> Tuple[float, List[Evidence]]:
        evidence = []
        scores = []

        # Check protocol from both the model field and features dict
        protocol = fv.protocol if fv.protocol is not None else fv.get("protocol")
        if protocol != 17:
            return 0.0, []

        pps = fv.get("packets_per_second")
        bps = fv.get("bytes_per_second")
        pkt_max = fv.get("pkt_size_max")

        # --- UDP packet rate ---
        if isinstance(pps, (int, float)) and pps is not None:
            udp_z = self._bl.z_score("udp_per_second", float(pps))
            udp_baseline = self._bl.baseline_value("udp_per_second")

            if pps >= self._udp_pps_min:
                if udp_z is not None:
                    s = _clamp(_sigmoid(udp_z - self._udp_pps_z + 1))
                    scores.append(s)
                    if udp_z > self._udp_pps_z * 0.7:
                        evidence.append(Evidence(
                            feature="udp_packets_per_second",
                            observed=round(pps, 2),
                            baseline=round(udp_baseline, 2) if udp_baseline else None,
                            deviation=round(udp_z, 3),
                            score=s,
                            detector="UDPFlood",
                            reason=(
                                f"UDP packet rate {pps:.0f}/s is {udp_z:.1f}σ above "
                                f"baseline. Consistent with UDP volumetric flood."
                            ),
                        ))
                else:
                    s = min(1.0, pps / (self._udp_pps_min * 5))
                    scores.append(s)

        # --- Large packet size indicator (possible amplification) ---
        if isinstance(pkt_max, (int, float)) and pkt_max >= self._large_pkt_threshold:
            pkt_mean = fv.get("pkt_size_mean") or 0
            if pkt_mean >= self._large_pkt_threshold * 0.8:
                s = _clamp(pkt_mean / 1500.0)
                scores.append(s * 0.6)  # partial indicator
                evidence.append(Evidence(
                    feature="udp_large_packet_size",
                    observed=round(float(pkt_max), 2),
                    baseline=512.0,
                    deviation=round(float(pkt_max) / 512.0, 2),
                    score=s * 0.6,
                    detector="UDPFlood",
                    reason=(
                        f"UDP packets are unusually large "
                        f"(max={pkt_max:.0f}B, mean={pkt_mean:.0f}B). "
                        f"Large UDP responses from multiple external sources "
                        f"may indicate UDP reflection/amplification. "
                        f"Note: Without bidirectional visibility, amplification "
                        f"cannot be confirmed. This is an indicator only."
                    ),
                ))

        final = max(scores) if scores else 0.0
        return _clamp(final), evidence


# ================================================================
# Sub-detector: Source Anomaly (spoofed-source indicators)
# ================================================================

class SourceAnomalyDetector:
    """
    Detects anomalous source IP distribution patterns.

    High source cardinality or entropy is CONSISTENT WITH
    spoofed-source flood attacks. We cannot prove spoofing
    from one-way metadata alone.

    Evidence produced:
      - dst_uniq_src_hosts_Xs (unique source count)
      - src IP entropy vs expected
      - source concentration
    """

    def __init__(self, cfg: dict) -> None:
        self._cfg = cfg
        src_cfg = cfg.get("source", {})
        self._uniq_src_high = float(src_cfg.get("uniq_src_high_threshold", 100.0))
        self._entropy_low = float(src_cfg.get("entropy_low_threshold", 1.5))
        self._entropy_high = float(src_cfg.get("entropy_high_threshold", 7.0))
        self._conc_high = float(src_cfg.get("concentration_high", 0.90))
        self._conc_low = float(src_cfg.get("concentration_low", 0.05))

    def score(self, fv: FeatureVector) -> Tuple[float, List[Evidence]]:
        evidence = []
        scores = []

        # Try all configured window sizes
        for window in [10, 30, 60]:
            suffix = f"{window}s"

            # --- Unique source count (per destination) ---
            uniq_src = fv.get(f"dst_uniq_src_hosts_{suffix}")
            if isinstance(uniq_src, (int, float)) and uniq_src >= self._uniq_src_high:
                s = _clamp(math.log2(max(1, uniq_src / self._uniq_src_high)) / 4.0)
                scores.append(s)
                evidence.append(Evidence(
                    feature=f"dst_uniq_src_hosts_{suffix}",
                    observed=int(uniq_src),
                    baseline=int(self._uniq_src_high),
                    deviation=round(uniq_src / self._uniq_src_high, 2),
                    score=s,
                    detector="SourceAnomaly",
                    reason=(
                        f"{int(uniq_src)} unique source IPs contacted this "
                        f"destination in the {window}s window. "
                        f"High source IP diversity is consistent with "
                        f"spoofed-source or distributed flood behavior. "
                        f"Note: IP spoofing cannot be confirmed from passive "
                        f"one-directional observation."
                    ),
                ))

            # --- Source concentration ---
            concentration = fv.get(f"dst_src_concentration_{suffix}")
            if isinstance(concentration, (int, float)):
                if float(concentration) >= self._conc_high:
                    # Very concentrated → single-source flood
                    s = float(concentration)
                    scores.append(s * 0.6)
                    evidence.append(Evidence(
                        feature=f"dst_src_concentration_{suffix}",
                        observed=round(float(concentration), 4),
                        baseline=0.5,
                        deviation=round(float(concentration) / 0.5, 2),
                        score=s * 0.6,
                        detector="SourceAnomaly",
                        reason=(
                            f"Source IP concentration is very high ({concentration:.2f}), "
                            f"indicating that most traffic to this destination comes from "
                            f"a small number of sources. Consistent with single-source flood."
                        ),
                    ))
                elif float(concentration) <= self._conc_low:
                    # Very dispersed → many sources → possible spoofing
                    s = _clamp(1.0 - float(concentration) * 5)
                    scores.append(s * 0.5)
                    evidence.append(Evidence(
                        feature=f"dst_src_concentration_{suffix}",
                        observed=round(float(concentration), 4),
                        baseline=0.5,
                        deviation=round(float(concentration), 4),
                        score=s * 0.5,
                        detector="SourceAnomaly",
                        reason=(
                            f"Source IP concentration is unusually low ({concentration:.4f}), "
                            f"indicating highly dispersed source IPs. This is consistent with "
                            f"a spoofed-source or botnet-based distributed flood. "
                            f"Note: Spoofing cannot be proven from passive metadata."
                        ),
                    ))

            # --- Source entropy (from source perspective) ---
            src_entropy = fv.get(f"src_dst_entropy_{suffix}")
            if isinstance(src_entropy, (int, float)):
                if float(src_entropy) >= self._entropy_high:
                    s = _clamp((float(src_entropy) - self._entropy_high) / 2.0)
                    scores.append(s * 0.4)
                    evidence.append(Evidence(
                        feature=f"src_dst_entropy_{suffix}",
                        observed=round(float(src_entropy), 4),
                        baseline=self._entropy_high,
                        deviation=round(float(src_entropy) / self._entropy_high, 2),
                        score=s * 0.4,
                        detector="SourceAnomaly",
                        reason=(
                            f"Destination IP entropy from this source is very high "
                            f"({src_entropy:.2f} bits). This may indicate scanning or "
                            f"distributed attack traffic hitting many destinations."
                        ),
                    ))

        final = max(scores) if scores else 0.0
        return _clamp(final), evidence


# ================================================================
# Main DDoS Detector
# ================================================================

class DDoSDetector(BaseDetector):
    """
    Multi-signal DDoS detector using statistical analysis.

    Combines four independent sub-detectors:
      1. RateAnomalyDetector  — volumetric rate vs EWMA baseline
      2. SYNFloodDetector     — TCP SYN-specific indicators
      3. UDPFloodDetector     — UDP volumetric and amplification
      4. SourceAnomalyDetector — source IP distribution anomalies

    Parameters
    ----------
    baseline:
        Optional pre-initialised TrafficBaseline.
        If None, a new one is created from config.
    """

    def __init__(self, baseline: Optional[TrafficBaseline] = None) -> None:
        self._cfg = _cfg()
        self._bl = baseline or TrafficBaseline()

        # Weights (configurable)
        w = self._cfg.get("weights", {})
        self._w_rate = float(w.get("rate_anomaly", 0.30))
        self._w_syn = float(w.get("syn_flood", 0.30))
        self._w_udp = float(w.get("udp_flood", 0.20))
        self._w_src = float(w.get("source_anomaly", 0.20))

        self._rate_det = RateAnomalyDetector(self._cfg, self._bl)
        self._syn_det = SYNFloodDetector(self._cfg, self._bl)
        self._udp_det = UDPFloodDetector(self._cfg, self._bl)
        self._src_det = SourceAnomalyDetector(self._cfg)

        self._min_score = float(self._cfg.get("min_score_to_alert", 0.35))
        self._min_conf = float(self._cfg.get("min_confidence_to_alert", 0.50))

        logger.info(
            "DDoSDetector initialised",
            weights=dict(rate=self._w_rate, syn=self._w_syn,
                         udp=self._w_udp, src=self._w_src),
        )

    @property
    def threat_class(self) -> ThreatClass:
        return ThreatClass.DDOS

    def detect(self, fv: FeatureVector) -> DetectionResult:
        """
        Analyse a FeatureVector for DDoS indicators.

        Parameters
        ----------
        fv:
            FeatureVector from the feature pipeline.

        Returns
        -------
        DetectionResult
            detection_score=0 if no DDoS indicators found.
            All evidence items explain the scoring.
        """
        # Update baseline with this flow's traffic metrics
        self._update_baseline(fv)

        # Run sub-detectors
        rate_score, rate_ev = self._rate_det.score(fv)
        syn_score, syn_ev = self._syn_det.score(fv)
        udp_score, udp_ev = self._udp_det.score(fv)
        src_score, src_ev = self._src_det.score(fv)

        all_evidence = rate_ev + syn_ev + udp_ev + src_ev

        # Weighted fusion
        final_score = (
            self._w_rate * rate_score
            + self._w_syn * syn_score
            + self._w_udp * udp_score
            + self._w_src * src_score
        )
        final_score = _clamp(final_score)

        # Confidence: based on number of independent signals that agree
        sub_scores = [rate_score, syn_score, udp_score, src_score]
        strong_signals = sum(1 for s in sub_scores if s > 0.5)
        contributing = [s for s in sub_scores if s > 0.1]

        if strong_signals >= 3:
            confidence = _clamp(0.50 + 0.15 * strong_signals)
        elif strong_signals == 2:
            confidence = _clamp(sum(contributing) / len(contributing) * 0.85)
        elif strong_signals == 1:
            confidence = _clamp(max(sub_scores) * 0.60)
        else:
            confidence = _clamp(max(sub_scores) * 0.40 if sub_scores else 0.0)

        # Sub-type determination
        sub_type = self._determine_subtype(
            rate_score, syn_score, udp_score, src_score
        )

        # Build result
        result = DetectionResult(
            threat_class=ThreatClass.DDOS,
            sub_type=sub_type,
            detection_score=round(final_score, 4),
            confidence=round(confidence, 4),
            severity=score_to_severity(final_score) if final_score >= self._min_score else Severity.UNCLASSIFIED,
            detector="statistical_ddos",
            model=None,
            evidence=all_evidence,
            source_ip=fv.source_ip,
            destination_ip=fv.destination_ip,
            source_port=fv.source_port,
            destination_port=fv.destination_port,
            protocol=str(fv.protocol) if fv.protocol else None,
            flow_id=fv.flow_id,
        )

        # Suppress if below alerting thresholds
        if final_score < self._min_score or confidence < self._min_conf:
            result.is_suppressed = True
            result.suppression_reason = (
                f"Score {final_score:.3f} < {self._min_score} or "
                f"confidence {confidence:.3f} < {self._min_conf}"
            )

        if not result.is_suppressed:
            logger.debug(
                "DDoS detection result",
                score=final_score,
                confidence=confidence,
                sub_type=sub_type,
                evidence_count=len(all_evidence),
            )

        return result

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _update_baseline(self, fv: FeatureVector) -> None:
        """Update EWMA baselines with observable metrics from fv."""
        metrics: Dict[str, float] = {}

        pps = fv.get("packets_per_second")
        if isinstance(pps, (int, float)):
            metrics["packets_per_second"] = float(pps)

        bps = fv.get("bytes_per_second")
        if isinstance(bps, (int, float)):
            metrics["bytes_per_second"] = float(bps)

        syn_count = fv.get("tcp_syn_count")
        duration = fv.get("flow_duration") or 1.0
        if isinstance(syn_count, (int, float)) and float(duration) > 0:
            metrics["syn_per_second"] = float(syn_count) / float(duration)

        if fv.protocol == 17:
            if isinstance(pps, (int, float)):
                metrics["udp_per_second"] = float(pps)

        self._bl.update(metrics)

    @staticmethod
    def _determine_subtype(
        rate: float, syn: float, udp: float, src: float
    ) -> Optional[str]:
        """Choose the most specific DDoS sub-type label."""
        scores = {
            "TCP_SYN_Flood": syn,
            "UDP_Volumetric": udp,
            "Traffic_Rate_Anomaly": rate,
            "Distributed_Source_Flood": src,
        }
        if max(scores.values()) < 0.2:
            return None
        return max(scores, key=scores.get)

    @property
    def baseline(self) -> TrafficBaseline:
        return self._bl


# ================================================================
# CLI entry point
# ================================================================

def _run_cli(pcap_path: str) -> None:
    """
    End-to-end DDoS detection pipeline from a PCAP file.

    Reports actual measured values only.
    """
    import warnings
    warnings.filterwarnings("ignore")
    import json

    from src.utils.logging import configure_logging
    configure_logging(level="WARNING")

    from src.ingestion.pcap_reader import PcapReader
    from src.flows.flow_manager import FlowManager
    from src.flows.sessionizer import Sessionizer
    from src.features.feature_pipeline import FeaturePipeline
    from src.detectors.alerts import AlertManager

    print(f"\nUniShield AI -- DDoS Detector")
    print(f"PCAP : {pcap_path}")
    print(f"Mode : Passive (read-only)")
    print("-" * 55)

    t_start = time.time()

    reader = PcapReader(pcap_path)
    manager = FlowManager(timeout_seconds=120.0)
    sess = Sessionizer(manager)
    pipeline = FeaturePipeline(window_sizes=[10.0, 30.0, 60.0])
    detector = DDoSDetector()
    alert_mgr = AlertManager(dedup_window_seconds=30.0)

    flow_count = 0
    alert_count = 0
    results_emitted = []

    for flow in sess.process(reader.stream()):
        flow_count += 1
        fv = pipeline.extract(flow)
        result = detector.detect(fv)

        if result.is_alert(
            min_score=detector._min_score,
            min_confidence=detector._min_conf,
        ):
            alert = alert_mgr.process(result)
            if alert:
                alert_count += 1
                results_emitted.append(result)

    elapsed = time.time() - t_start

    print(f"Packets processed  : {reader.stats.packets_processed}")
    print(f"Flows analysed     : {flow_count}")
    print(f"Detection results  : {pipeline.vectors_produced}")
    print(f"Alerts generated   : {alert_mgr.summary()['total_new']}")
    print(f"Active alerts      : {alert_mgr.active_count}")
    print(f"Processing time    : {elapsed:.3f} s")
    print("-" * 55)

    if results_emitted:
        print("\nDetection Results:")
        for i, r in enumerate(results_emitted[:3]):
            print(f"\n  [{i+1}] {r.to_summary()}")
            if r.evidence:
                print("  Evidence:")
                for ev in r.evidence[:3]:
                    print(f"    - {ev.feature}: obs={ev.observed}, "
                          f"baseline={ev.baseline}, deviation={ev.deviation}")
                    print(f"      {ev.reason[:90]}")
    else:
        print("\nNo DDoS alerts generated for this PCAP.")
        print("(This is expected for normal or small captures.)")


if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(
        description="UniShield AI -- DDoS Detector"
    )
    parser.add_argument("pcap", help="Path to PCAP file")
    args = parser.parse_args()
    _run_cli(args.pcap)
