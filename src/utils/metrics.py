"""
UniShield AI — Performance Metrics Utility
==========================================
Stubs and helpers for tracking operational metrics:
  - Flows processed per second
  - Alert generation latency
  - Detection latency per detector
  - Memory and CPU (future: psutil integration)

These metrics are gathered during processing and exposed via
the FastAPI /statistics endpoint (Phase 13).

IMPORTANT: Never invent benchmark values.
           All reported values must be measured at runtime.
           If a metric has not yet been collected, its value
           is explicitly None with label "not_yet_benchmarked".
"""

import time
from dataclasses import dataclass, field
from typing import Dict, List, Optional


@dataclass
class DetectorMetrics:
    """Per-detector performance counters."""

    detector_name: str
    calls: int = 0
    true_positives: int = 0
    false_positives: int = 0
    total_latency_ms: float = 0.0

    @property
    def avg_latency_ms(self) -> Optional[float]:
        """Average detection latency in milliseconds."""
        if self.calls == 0:
            return None
        return self.total_latency_ms / self.calls

    def to_dict(self) -> dict:
        return {
            "detector": self.detector_name,
            "calls": self.calls,
            "avg_latency_ms": self.avg_latency_ms,
            "true_positives": self.true_positives,
            "false_positives": self.false_positives,
            "note": "runtime_measured",
        }


@dataclass
class PipelineMetrics:
    """
    Global pipeline performance counters.

    All values are measured at runtime; nothing is pre-filled.
    """

    start_time: float = field(default_factory=time.time)
    flows_processed: int = 0
    packets_ingested: int = 0
    alerts_generated: int = 0
    detector_metrics: Dict[str, DetectorMetrics] = field(default_factory=dict)
    _latency_samples: List[float] = field(default_factory=list)

    # ----------------------------------------------------------------
    # Ingestion tracking
    # ----------------------------------------------------------------

    def record_packet(self) -> None:
        """Increment packet ingestion counter."""
        self.packets_ingested += 1

    def record_flow(self) -> None:
        """Increment completed flow counter."""
        self.flows_processed += 1

    def record_alert(self) -> None:
        """Increment alert generation counter."""
        self.alerts_generated += 1

    # ----------------------------------------------------------------
    # Detector tracking
    # ----------------------------------------------------------------

    def record_detection(
        self,
        detector_name: str,
        latency_ms: float,
        is_tp: Optional[bool] = None,
    ) -> None:
        """
        Record one detector invocation.

        Parameters
        ----------
        detector_name:
            Name of the detector (e.g. "DDoSDetector").
        latency_ms:
            Wall-clock time taken for this detection call.
        is_tp:
            True if confirmed true-positive, False if confirmed FP.
            None if not yet labelled.
        """
        if detector_name not in self.detector_metrics:
            self.detector_metrics[detector_name] = DetectorMetrics(detector_name)
        dm = self.detector_metrics[detector_name]
        dm.calls += 1
        dm.total_latency_ms += latency_ms
        if is_tp is True:
            dm.true_positives += 1
        elif is_tp is False:
            dm.false_positives += 1

    # ----------------------------------------------------------------
    # Throughput
    # ----------------------------------------------------------------

    @property
    def elapsed_seconds(self) -> float:
        return max(time.time() - self.start_time, 1e-6)

    @property
    def flows_per_second(self) -> float:
        return self.flows_processed / self.elapsed_seconds

    @property
    def packets_per_second(self) -> float:
        return self.packets_ingested / self.elapsed_seconds

    # ----------------------------------------------------------------
    # Summary
    # ----------------------------------------------------------------

    def summary(self) -> dict:
        """Return a JSON-serialisable summary of all metrics."""
        return {
            "elapsed_seconds": round(self.elapsed_seconds, 2),
            "packets_ingested": self.packets_ingested,
            "flows_processed": self.flows_processed,
            "alerts_generated": self.alerts_generated,
            "packets_per_second": round(self.packets_per_second, 2),
            "flows_per_second": round(self.flows_per_second, 2),
            "detectors": [
                dm.to_dict()
                for dm in self.detector_metrics.values()
            ],
        }


# Module-level singleton — import and use directly in the pipeline
pipeline_metrics = PipelineMetrics()
