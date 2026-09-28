"""
UniShield AI -- C2 Beaconing Detector
========================================
Detects Command-and-Control (C2) beaconing patterns using
passively observed network metadata.

============================================================
THREAT MODEL
============================================================

C2 beaconing occurs when malware on an infected host periodically
contacts a remote server to receive commands or exfiltrate data.

Observable indicators (metadata-only):
  - Regular inter-connection intervals (periodic beaconing)
  - Repeated targeting of the same destination (IP + port)
  - Consistent per-connection packet/byte counts
  - Single source contacting an unusual destination exclusively

NOT observable (unidirectional mirror):
  - Payload content
  - Command structure
  - Whether the connection succeeds
  - Response content from the destination

============================================================
DETECTION METHODOLOGY
============================================================

Because C2 requires CROSS-FLOW analysis, the detector maintains
a stateful BeaconTracker that accumulates connection history per
(source_ip, destination_ip, destination_port) tuple.

For each FeatureVector received:
  1. Record the connection in BeaconTracker
  2. If enough connections are accumulated:
     a. Compute BeaconFeatures (periodicity, consistency, etc.)
     b. Score each sub-detector
     c. Fuse scores with configurable weights
     d. Generate DetectionResult with Evidence

Sub-detectors:
  1. PeriodicitySub      -- CV-based interval regularity [weight=0.40]
  2. DestinationRepeatSub-- connection count to same dst [weight=0.25]
  3. SizeConsistencySub  -- CV of per-connection bytes   [weight=0.20]
  4. BehavioralAnomalySub-- source diversity anomaly     [weight=0.15]

Periodicity formula:
  s_periodicity = max(0, 1 - CV / cv_random_threshold)

where:
  CV = std(intervals) / mean(intervals)
  cv_random_threshold = 0.60 (configurable)

Confidence formula:
  Based on count of sub-detectors with score > 0.50.
  Documented as heuristic — NOT calibrated probability.

============================================================
LIMITATIONS (EXPLICITLY DOCUMENTED)
============================================================

1. Cold start: first min_flows_for_analysis connections produce
   no output. Detection is delayed by design.
2. Jitter evasion: sufficiently high jitter (CV > 0.60) will
   evade CV-based detection. Low-and-slow beacons may also evade.
3. Legitimate periodic apps: NTP, monitoring agents, health checks,
   telemetry can all produce periodic traffic. Use in context.
4. Cannot confirm C2: We detect patterns CONSISTENT WITH beaconing,
   not confirmed C2. Never claim "confirmed malware."
5. Port hopping: If the malware changes destination port every
   connection, the (dst_ip, dst_port) key will not accumulate.
6. Domain fronting: If CDN IPs are used as destinations, the
   destination IP is not the actual C2 server.

PASSIVE AUDIT:
  [PASS] No packets transmitted
  [PASS] No DNS lookups performed on observed destinations
  [PASS] No active probing
  [PASS] All signals from flow metadata only

============================================================
USAGE
============================================================

Library:
    from src.detectors.c2_beacon import C2BeaconDetector
    detector = C2BeaconDetector()
    result = detector.detect(feature_vector)

CLI:
    python -m src.detectors.c2_beacon path/to/capture.pcap
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
from src.detectors.beacon_tracker import BeaconTracker, BeaconFeatures, compute_beacon_features
from src.features.feature_vector import FeatureVector
from src.utils.config import get_thresholds
from src.utils.logging import get_logger

logger = get_logger(__name__)


# ================================================================
# Config helpers
# ================================================================

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


def _clamp(v: float, lo: float = 0.0, hi: float = 1.0) -> float:
    return max(lo, min(hi, v))


# ================================================================
# Sub-detector 1: Periodicity (CV-based)
# ================================================================

class PeriodicitySub:
    """
    Scores regularity of inter-connection intervals.

    Formula:
        s = max(0, 1 - CV / cv_random_threshold)

    CV = std(intervals) / mean(intervals)

    Evidence:
        Reports observed CV, mean interval, expected random CV,
        and computed score with full mathematical explanation.
    """

    def __init__(self, cfg: dict) -> None:
        p = cfg.get("periodicity", {})
        self._cv_high = float(p.get("cv_highly_periodic", 0.15))
        self._cv_mod = float(p.get("cv_moderately_periodic", 0.35))
        self._cv_random = float(p.get("cv_random_threshold", 0.60))

    def score(self, feat: BeaconFeatures) -> Tuple[float, List[Evidence]]:
        evidence = []

        if feat.ici_cv is None or feat.ici_sample_count < 3:
            return 0.0, []

        cv = feat.ici_cv
        s = _clamp(max(0.0, 1.0 - cv / self._cv_random))

        if s < 0.10:
            return 0.0, []

        # Jitter descriptor
        if cv <= self._cv_high:
            regularity = "highly periodic"
        elif cv <= self._cv_mod:
            regularity = "moderately periodic"
        else:
            regularity = "irregularly periodic"

        mean_str = f"{feat.ici_mean:.1f}s" if feat.ici_mean else "N/A"
        jitter_str = f"{feat.ici_jitter:.1f}s" if feat.ici_jitter else "N/A"

        evidence.append(Evidence(
            feature="ici_coefficient_of_variation",
            observed=round(cv, 4),
            baseline=round(self._cv_random, 4),
            deviation=round(cv / self._cv_random, 3),
            score=round(s, 4),
            detector="PeriodicitySub",
            reason=(
                f"Inter-connection intervals are {regularity} "
                f"(CV={cv:.3f}; threshold for 'random' is {self._cv_random:.2f}). "
                f"Mean interval: {mean_str}, mean absolute jitter: {jitter_str}. "
                f"Score formula: max(0, 1 - {cv:.3f} / {self._cv_random:.2f}) = {s:.3f}. "
                f"This pattern is consistent with automated/scripted communication, "
                f"such as C2 beaconing. "
                f"Note: Legitimate monitoring agents and NTP traffic can produce "
                f"similar periodicity."
            ),
        ))

        if feat.ici_mean is not None and feat.ici_sample_count >= 3:
            evidence.append(Evidence(
                feature="ici_mean_interval_seconds",
                observed=round(feat.ici_mean, 2),
                baseline=None,
                deviation=None,
                score=s,
                detector="PeriodicitySub",
                reason=(
                    f"Mean inter-connection interval is {feat.ici_mean:.1f}s over "
                    f"{feat.ici_sample_count} measured intervals. "
                    f"This suggests a connection attempt approximately every "
                    f"{feat.ici_mean:.0f} seconds."
                ),
            ))

        return _clamp(s), evidence


# ================================================================
# Sub-detector 2: Destination Repetition
# ================================================================

class DestinationRepeatSub:
    """
    Scores based on the number of repeated connections to the same
    (dst_ip, dst_port) endpoint.

    Formula:
        raw = connection_count / (connection_count + half_score_at)
        s = raw × scaling_factor

    This produces an asymptotic score approaching 1.0 as connections
    accumulate. The 'half_score_at' parameter controls how many
    connections produce a score of 0.5.

    Evidence:
        Reports connection count and endpoint.
    """

    def __init__(self, cfg: dict) -> None:
        d = cfg.get("destination", {})
        self._low = int(d.get("low_repeat_count", 5))
        self._med = int(d.get("medium_repeat_count", 15))
        self._high = int(d.get("high_repeat_count", 30))
        # Asymptotic formula: score at which count=high → 0.80
        # half_point chosen so count=high gives ~0.75
        self._half_point = self._high

    def score(self, feat: BeaconFeatures) -> Tuple[float, List[Evidence]]:
        evidence = []
        n = feat.connection_count

        if n < self._low:
            return 0.0, []

        # Asymptotic formula: score = n / (n + half_point)
        # At n=half_point → score = 0.50
        # At n=2*half_point → score = 0.67
        # As n→∞ → score → 1.0
        s = _clamp(n / (n + self._half_point))

        if n >= self._high:
            strength = "strong"
        elif n >= self._med:
            strength = "moderate"
        else:
            strength = "weak"

        evidence.append(Evidence(
            feature="repeated_connection_count",
            observed=n,
            baseline=self._low,
            deviation=round(n / self._low, 2),
            score=round(s, 4),
            detector="DestinationRepeatSub",
            reason=(
                f"{n} connections observed to {feat.dst_ip}:{feat.dst_port} "
                f"from {feat.src_ip} — a {strength} repeated-destination signal. "
                f"Score: {n} / ({n} + {self._half_point}) = {s:.3f}. "
                f"Repeated targeting of the same endpoint is consistent with "
                f"C2 beaconing. "
                f"Note: Persistent applications (VPN, streaming, monitoring) "
                f"also produce repeated connections to fixed endpoints."
            ),
        ))

        return _clamp(s), evidence


# ================================================================
# Sub-detector 3: Size Consistency
# ================================================================

class SizeConsistencySub:
    """
    Scores based on consistency of per-connection byte counts.

    Highly repetitive traffic with very similar byte counts per
    connection may indicate automated/scripted keepalive communication.

    Formula:
        s_byte = max(0, 1 - byte_cv / byte_cv_high)

    Evidence:
        Reports byte_cv with comparison to expected random CV.
    """

    def __init__(self, cfg: dict) -> None:
        sc = cfg.get("size_consistency", {})
        self._byte_cv_low = float(sc.get("byte_cv_low", 0.15))
        self._byte_cv_high = float(sc.get("byte_cv_high", 0.80))
        self._pkt_cv_low = float(sc.get("pkt_cv_low", 0.20))

    def score(self, feat: BeaconFeatures) -> Tuple[float, List[Evidence]]:
        evidence = []
        scores = []

        # Byte count consistency
        if feat.byte_cv is not None and feat.connection_count >= 3:
            cv = feat.byte_cv
            # Normalize: 0 at cv_high, 1 at cv=0
            s = _clamp(max(0.0, 1.0 - cv / self._byte_cv_high))
            scores.append(s)

            if s > 0.20 and cv <= self._byte_cv_high:
                evidence.append(Evidence(
                    feature="per_connection_byte_cv",
                    observed=round(cv, 4),
                    baseline=round(self._byte_cv_high, 4),
                    deviation=round(cv / max(0.001, self._byte_cv_high), 3),
                    score=round(s, 4),
                    detector="SizeConsistencySub",
                    reason=(
                        f"Per-connection byte count has coefficient of variation "
                        f"CV={cv:.3f} (mean={feat.byte_mean:.0f}B, "
                        f"std={feat.byte_std:.0f}B if available). "
                        f"Low byte-count variability is consistent with fixed-size "
                        f"beacon or keepalive packets. "
                        f"Score: max(0, 1 - {cv:.3f}/{self._byte_cv_high:.2f}) = {s:.3f}."
                    ),
                ))

        # Packet count consistency
        if feat.pkt_cv is not None and feat.connection_count >= 3:
            cv_p = feat.pkt_cv
            s_p = _clamp(max(0.0, 1.0 - cv_p / self._byte_cv_high))
            scores.append(s_p * 0.5)  # partial weight for pkt count

        final = max(scores) if scores else 0.0
        return _clamp(final), evidence


# ================================================================
# Sub-detector 4: Behavioral Anomaly
# ================================================================

class BehavioralAnomalySub:
    """
    Scores based on how unusual it is for this source to focus
    exclusively on one destination.

    A source that normally contacts many destinations but is now
    consistently contacting one specific (dst_ip, dst_port) is
    more suspicious than a source that always contacts few dests.

    Feature used:
        dst_uniq_dst_hosts_Xs from behavioral features: how many
        unique destinations does this source normally contact?

    If behavioral features are not available, returns 0 (no signal).

    Evidence:
        Reports focus ratio and normal diversity.
    """

    def score(self, feat: BeaconFeatures, fv: Optional[FeatureVector] = None) -> Tuple[float, List[Evidence]]:
        evidence = []

        if fv is None:
            return 0.0, []

        # Look for behavioral features across all window sizes
        best_score = 0.0
        best_uniq = None
        best_window = None

        for window in [60, 30, 10]:
            uniq = fv.get(f"src_uniq_dst_hosts_{window}s")
            if isinstance(uniq, (int, float)) and uniq > 0:
                # If source contacts only 1-2 destinations, focus is high
                # Normalised focus = 1 / uniq_dsts (1.0 when only 1 dst)
                focus = _clamp(1.0 / max(1.0, float(uniq)))
                # Only suspicious if source is very focused
                if float(uniq) <= 3:
                    s = focus
                    if s > best_score:
                        best_score = s
                        best_uniq = float(uniq)
                        best_window = window

        if best_uniq is not None and best_score > 0.2:
            evidence.append(Evidence(
                feature=f"src_uniq_dst_hosts_{best_window}s",
                observed=best_uniq,
                baseline=None,
                deviation=None,
                score=round(best_score, 4),
                detector="BehavioralAnomalySub",
                reason=(
                    f"Source {feat.src_ip} contacts only {best_uniq:.0f} unique "
                    f"destination(s) in the {best_window}s window. "
                    f"A source focused exclusively on one destination is consistent "
                    f"with C2 beaconing behavior. "
                    f"Note: VPN clients, proxies, and single-service applications "
                    f"also show low destination diversity."
                ),
            ))

        return _clamp(best_score), evidence


# ================================================================
# Optional ML component (Isolation Forest)
# ================================================================

class C2IsolationForest:
    """
    Optional Isolation Forest for C2 anomaly detection.

    This is a secondary detector that scores beacon feature arrays
    using an Isolation Forest model.

    IMPORTANT:
      - This model must be trained on real labeled data.
      - Synthetic training data scores must NOT be reported as real accuracy.
      - The model is off by default (enabled: false in config).
      - If no model file exists, get_score() returns None.

    Feature array:
      See BeaconFeatures.to_feature_array() for the 13-element vector.

    Dataset:
      CTU-13 or similar botnet capture dataset.
      Expected format: see docs/threat_models.md § Dataset Format.
    """

    FEATURE_NAMES = [
        "connection_count",
        "ici_mean",
        "ici_cv",
        "ici_periodicity",
        "ici_jitter",
        "ici_std",
        "ici_sample_count",
        "byte_cv",
        "pkt_cv",
        "byte_mean",
        "pkt_mean",
        "duration_mean",
        "observation_duration",
    ]

    def __init__(self, model_path: Optional[str] = None) -> None:
        self._model = None
        self._scaler = None
        self._model_path = model_path
        if model_path:
            self._load(model_path)

    def _load(self, path: str) -> None:
        try:
            import pickle, os
            if not os.path.exists(path):
                logger.info("C2 IF model not found — ML scoring disabled", path=path)
                return
            with open(path, "rb") as f:
                saved = pickle.load(f)
            self._model = saved.get("model")
            self._scaler = saved.get("scaler")
            logger.info("C2 Isolation Forest loaded", path=path)
        except Exception as exc:
            logger.warning("Failed to load C2 IF model", error=str(exc))

    def train(self, feature_arrays: List[List[float]]) -> None:
        """
        Train the Isolation Forest on a list of feature arrays.

        Parameters
        ----------
        feature_arrays:
            List of 13-element feature arrays (from BeaconFeatures.to_feature_array()).
            This should include MIXED data (both normal and anomalous if possible).
            Isolation Forest is unsupervised — it does not use labels.

        WARNING:
            Never claim this produces calibrated detection rates unless
            evaluated against a labelled dataset with a proper train/test split.
        """
        try:
            from sklearn.ensemble import IsolationForest
            from sklearn.preprocessing import StandardScaler
            import numpy as np

            X = np.array(feature_arrays, dtype=float)
            self._scaler = StandardScaler()
            X_scaled = self._scaler.fit_transform(X)
            self._model = IsolationForest(
                n_estimators=100,
                contamination=0.05,
                random_state=42,
            )
            self._model.fit(X_scaled)
            logger.info("C2 Isolation Forest trained", n_samples=len(feature_arrays))
        except ImportError:
            logger.warning("scikit-learn not available — ML scoring disabled")
        except Exception as exc:
            logger.warning("C2 IF training failed", error=str(exc))

    def save(self, path: str) -> None:
        if self._model is None:
            return
        import pickle
        with open(path, "wb") as f:
            pickle.dump({"model": self._model, "scaler": self._scaler}, f)
        logger.info("C2 IF model saved", path=path)

    def get_score(self, features: BeaconFeatures) -> Optional[float]:
        """
        Return an anomaly score in [0, 1] for a feature set.

        Higher = more anomalous.
        Returns None if model not available.

        IMPORTANT: This is the Isolation Forest decision function,
        rescaled to [0, 1]. It is NOT a probability.
        """
        if self._model is None:
            return None
        try:
            import numpy as np
            arr = np.array(features.to_feature_array(), dtype=float).reshape(1, -1)
            if self._scaler:
                arr = self._scaler.transform(arr)
            # decision_function: more negative = more anomalous
            raw = float(self._model.decision_function(arr)[0])
            # Rescale: typical range [-0.5, 0.5] → flip and normalize to [0,1]
            score = _clamp(0.5 - raw)
            return score
        except Exception as exc:
            logger.debug("C2 IF scoring failed", error=str(exc))
            return None

    @property
    def is_ready(self) -> bool:
        return self._model is not None


# ================================================================
# Main C2 Beacon Detector
# ================================================================

class C2BeaconDetector(BaseDetector):
    """
    Multi-signal C2 beaconing detector.

    Stateful: accumulates connection history per (src, dst, dport)
    using a BeaconTracker. Results improve as more flows are observed.

    Parameters
    ----------
    tracker:
        Optional pre-initialised BeaconTracker.
    ml_model:
        Optional C2IsolationForest. Disabled if None.
    """

    def __init__(
        self,
        tracker: Optional[BeaconTracker] = None,
        ml_model: Optional[C2IsolationForest] = None,
    ) -> None:
        self._cfg = _cfg()
        self._tracker = tracker or BeaconTracker(self._cfg)
        self._ml = ml_model

        # Weights
        w = self._cfg.get("weights", {})
        self._w_period = float(w.get("periodicity", 0.40))
        self._w_dst = float(w.get("destination_repeat", 0.25))
        self._w_size = float(w.get("size_consistency", 0.20))
        self._w_behav = float(w.get("behavioral_anomaly", 0.15))

        self._period_sub = PeriodicitySub(self._cfg)
        self._dst_sub = DestinationRepeatSub(self._cfg)
        self._size_sub = SizeConsistencySub(self._cfg)
        self._behav_sub = BehavioralAnomalySub()

        self._min_score = float(_get(self._cfg, "min_score_to_alert", default=0.35))
        self._min_conf = float(_get(self._cfg, "min_confidence_to_alert", default=0.45))

        # Check if ML should be loaded
        if self._ml is None and _get(self._cfg, "ml", "enabled", default=False):
            model_path = _get(self._cfg, "ml", "model_path", default="")
            if model_path:
                self._ml = C2IsolationForest(model_path)

        logger.info(
            "C2BeaconDetector initialised",
            weights=dict(
                period=self._w_period,
                dst=self._w_dst,
                size=self._w_size,
                behav=self._w_behav,
            ),
            ml_enabled=self._ml is not None and self._ml.is_ready,
        )

    @property
    def threat_class(self) -> ThreatClass:
        return ThreatClass.C2_BEACON

    @property
    def tracker(self) -> BeaconTracker:
        return self._tracker

    def detect(self, fv: FeatureVector) -> DetectionResult:
        """
        Analyse a FeatureVector for C2 beaconing indicators.

        Phase 1: Record this connection in the BeaconTracker.
        Phase 2: If enough data, score the (src, dst, dport) tuple.
        Phase 3: Return DetectionResult (score=0 if insufficient data).

        Parameters
        ----------
        fv:
            FeatureVector from the feature pipeline.

        Returns
        -------
        DetectionResult
            detection_score=0 if fewer than min_flows connections observed.
        """
        # Phase 1: always record the connection
        self._tracker.record_from_fv(fv)

        # Phase 2: check if enough data
        feat = self._tracker.get_features_from_fv(fv)

        if feat is None:
            # Not enough data yet — return empty (not suppressed) result
            result = DetectionResult(
                threat_class=ThreatClass.C2_BEACON,
                detection_score=0.0,
                confidence=0.0,
                source_ip=fv.source_ip,
                destination_ip=fv.destination_ip,
                detector="c2_statistical_periodicity",
                is_suppressed=True,
                suppression_reason="Insufficient connection history (warmup)",
            )
            return result

        # Phase 3: score
        return self._score(feat, fv)

    def detect_from_features(self, feat: BeaconFeatures, fv: Optional[FeatureVector] = None) -> DetectionResult:
        """
        Score pre-computed BeaconFeatures directly.
        Useful for batch analysis or testing.
        """
        return self._score(feat, fv)

    def _score(self, feat: BeaconFeatures, fv: Optional[FeatureVector]) -> DetectionResult:
        """Run all sub-detectors and fuse scores."""
        # Sub-detector scores
        p_score, p_ev = self._period_sub.score(feat)
        d_score, d_ev = self._dst_sub.score(feat)
        s_score, s_ev = self._size_sub.score(feat)
        b_score, b_ev = self._behav_sub.score(feat, fv)

        all_evidence = p_ev + d_ev + s_ev + b_ev

        # Weighted fusion
        final_score = (
            self._w_period * p_score
            + self._w_dst * d_score
            + self._w_size * s_score
            + self._w_behav * b_score
        )
        final_score = _clamp(final_score)

        # Optional ML boost
        ml_score = None
        if self._ml and self._ml.is_ready:
            ml_score = self._ml.get_score(feat)
            if ml_score is not None:
                # Average ML with statistical score (50/50)
                final_score = _clamp((final_score + ml_score) / 2.0)
                all_evidence.append(Evidence(
                    feature="isolation_forest_score",
                    observed=round(ml_score, 4),
                    baseline=0.5,
                    deviation=round(ml_score - 0.5, 4),
                    score=round(ml_score, 4),
                    detector="IsolationForest",
                    reason=(
                        f"Isolation Forest anomaly score: {ml_score:.3f}. "
                        f"Values > 0.5 indicate unusual traffic patterns. "
                        f"Note: This model has not been calibrated against a "
                        f"labelled dataset — scores are relative indicators only."
                    ),
                ))

        # Confidence: count of strong signals
        sub_scores = [p_score, d_score, s_score, b_score]
        strong_signals = sum(1 for s in sub_scores if s > 0.50)
        contributing = [s for s in sub_scores if s > 0.10]

        if strong_signals >= 3:
            confidence = _clamp(0.55 + 0.15 * strong_signals)
        elif strong_signals == 2:
            confidence = _clamp(sum(contributing) / len(contributing) * 0.85) if contributing else 0.0
        elif strong_signals == 1:
            confidence = _clamp(max(sub_scores) * 0.65)
        else:
            confidence = _clamp(max(sub_scores) * 0.35 if sub_scores else 0.0)

        # Sub-type
        sub_type = self._determine_subtype(p_score, d_score, s_score)

        result = DetectionResult(
            threat_class=ThreatClass.C2_BEACON,
            sub_type=sub_type,
            detection_score=round(final_score, 4),
            confidence=round(confidence, 4),
            severity=(
                score_to_severity(final_score) if final_score >= self._min_score else Severity.UNCLASSIFIED
            ),
            evidence=all_evidence,
            source_ip=feat.src_ip,
            destination_ip=feat.dst_ip,
            source_port=fv.source_port if fv else None,
            destination_port=feat.dst_port,
            protocol=str(fv.protocol) if fv and fv.protocol else None,
            detector="hybrid_isolation_forest" if ml_score is not None else "c2_statistical_periodicity",
            model="C2IsolationForest" if ml_score is not None else None,
            meta={
                "dst_port": feat.dst_port,
                "connection_count": feat.connection_count,
                "ici_cv": feat.ici_cv,
                "ici_mean": feat.ici_mean,
                "ml_score": ml_score,
            },
        )

        if final_score < self._min_score or confidence < self._min_conf:
            result.is_suppressed = True
            result.suppression_reason = (
                f"Score {final_score:.3f} < {self._min_score} or "
                f"confidence {confidence:.3f} < {self._min_conf}"
            )

        if not result.is_suppressed:
            logger.info(
                "C2 detection result",
                src=feat.src_ip,
                dst=f"{feat.dst_ip}:{feat.dst_port}",
                score=final_score,
                confidence=confidence,
                sub_type=sub_type,
                n_connections=feat.connection_count,
                ici_cv=feat.ici_cv,
            )

        return result

    @staticmethod
    def _determine_subtype(p: float, d: float, s: float) -> Optional[str]:
        scores = {
            "Periodic_Beacon": p,
            "Repeated_Destination": d,
            "Consistent_Payload": s,
        }
        best = max(scores, key=scores.get)
        return best if scores[best] > 0.15 else None


# ================================================================
# CLI entry point
# ================================================================

def _run_cli(pcap_path: str) -> None:
    """End-to-end C2 detection pipeline from a PCAP file."""
    import warnings
    warnings.filterwarnings("ignore")

    from src.utils.logging import configure_logging
    configure_logging(level="WARNING")

    from src.ingestion.pcap_reader import PcapReader
    from src.flows.flow_manager import FlowManager
    from src.flows.sessionizer import Sessionizer
    from src.features.feature_pipeline import FeaturePipeline
    from src.detectors.alerts import AlertManager

    print(f"\nUniShield AI -- C2 Beaconing Detector")
    print(f"PCAP : {pcap_path}")
    print(f"Mode : Passive (read-only, stateful cross-flow analysis)")
    print("-" * 60)

    t_start = time.time()

    reader = PcapReader(pcap_path)
    manager = FlowManager(timeout_seconds=120.0)
    sess = Sessionizer(manager)
    pipeline = FeaturePipeline(window_sizes=[10.0, 30.0, 60.0])
    detector = C2BeaconDetector()
    alert_mgr = AlertManager(dedup_window_seconds=300.0)

    flow_count = 0
    alert_count = 0
    results_emitted = []

    for flow in sess.process(reader.stream()):
        flow_count += 1
        fv = pipeline.extract(flow)
        result = detector.detect(fv)

        if result.is_alert(min_score=detector._min_score, min_confidence=detector._min_conf):
            alert = alert_mgr.process(result)
            if alert:
                alert_count += 1
                results_emitted.append(result)

    elapsed = time.time() - t_start

    print(f"Packets processed  : {reader.stats.packets_processed}")
    print(f"Flows analysed     : {flow_count}")
    print(f"Tracked pairs      : {detector.tracker.tracked_pairs}")
    print(f"Alerts generated   : {alert_mgr.summary()['total_new']}")
    print(f"Processing time    : {elapsed:.3f} s")
    print("-" * 60)

    if results_emitted:
        print("\nC2 Detection Results:")
        for i, r in enumerate(results_emitted[:3]):
            print(f"\n  [{i+1}] {r.to_summary()}")
            print(f"  dst_port={r.meta.get('dst_port')}, "
                  f"n_conn={r.meta.get('connection_count')}, "
                  f"ici_cv={r.meta.get('ici_cv')}")
            for ev in r.evidence[:3]:
                print(f"  • {ev.feature}: {ev.observed}")
                print(f"    {ev.reason[:100]}...")
    else:
        print("\nNo C2 beaconing alerts generated for this PCAP.")
        print(f"(Beacon detection requires {_cfg().get('min_flows_for_analysis', 5)}+ "
              f"connections to same endpoint — small PCAPs may not trigger.)")


if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description="UniShield AI -- C2 Beaconing Detector")
    parser.add_argument("pcap", help="Path to PCAP file")
    args = parser.parse_args()
    _run_cli(args.pcap)
