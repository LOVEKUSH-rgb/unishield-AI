"""
Phase 33 — PCAP Replay Pipeline
=================================
Replays a PCAP through the full UniShield production pipeline:

  PcapReader
      -> NetworkEvent (with original packet timestamps)
      -> FlowManager / Sessionizer (temporal flow reconstruction)
      -> FlowRecord (with real duration from packet timestamps)
      -> FeaturePipeline (behavioral/timing/DNS/TLS features)
      -> 6 Detectors (DDoS, C2, Recon, Exfil, DGA, Encrypted)
      -> Alerts

This is NOT a parallel/fake evaluation path.
This is the identical runtime pipeline used in production.

PASSIVE GUARANTEES:
  [PASS] PCAP files opened read-only
  [PASS] No packets transmitted
  [PASS] No active probing or scanning
  [PASS] No external network connections made

Usage:
  python scripts/replay_pcap_phase33.py \\
      --pcap data/samples/test_synthetic.pcap \\
      --output reports/phase33/replay_metrics.json

  python scripts/replay_pcap_phase33.py \\
      --pcap data/raw/external/ctu13/scenario10.pcap \\
      --max-packets 50000 \\
      --output reports/phase33/replay_metrics.json
"""

from __future__ import annotations

import argparse
import json
import time
import os
import statistics
from pathlib import Path
from typing import Dict, List, Optional

# --- Pipeline imports ---
from src.ingestion.pcap_reader import PcapReader
from src.flows.flow_manager import FlowManager
from src.flows.sessionizer import Sessionizer
from src.features.feature_pipeline import FeaturePipeline
from src.detectors.ddos import DDoSDetector
from src.detectors.c2_beacon import C2BeaconDetector
from src.detectors.recon import ReconDetector
from src.detectors.exfiltration import ExfiltrationDetector
from src.detectors.dga_dns import DGADetector
from src.detectors.encrypted import EncryptedSessionDetector
from src.utils.logging import get_logger

logger = get_logger(__name__)


def _percentile(data: List[float], p: float) -> Optional[float]:
    if not data:
        return None
    s = sorted(data)
    idx = int(len(s) * p / 100)
    return s[min(idx, len(s) - 1)]


def run_replay(
    pcap_path: str,
    output_path: str,
    max_packets: Optional[int] = None,
    flow_timeout: float = 120.0,
    mode: str = "default",
) -> Tuple[Dict, List[Dict]]:
    """
    Execute full pipeline replay from a PCAP file.
    Returns (report_dict, list_of_all_alerts).

    Parameters
    ----------
    pcap_path:
        Path to PCAP file (read-only access).
    output_path:
        Where to save the replay metrics JSON.
    max_packets:
        Stop after this many packets (None = read all).
    flow_timeout:
        FlowManager idle timeout in seconds.
    mode:
        'default' = ML+statistical hybrid, 'statistical' = statistical only.

    Returns
    -------
    dict
        Replay metrics.
    """
    pcap_path = Path(pcap_path)
    output_path = Path(output_path)
    output_path.parent.mkdir(parents=True, exist_ok=True)

    # Validate read-only access (passive compliance)
    if not os.access(str(pcap_path), os.R_OK):
        raise PermissionError(f"Cannot read PCAP file: {pcap_path}")

    # Initialize pipeline components
    completed_flows: List = []
    pipeline = FeaturePipeline()

    detectors = [
        ("DDoS", DDoSDetector()),
        ("Reconnaissance", ReconDetector()),
        ("C2_Beacon", C2BeaconDetector()),
        ("Exfiltration", ExfiltrationDetector()),
        ("DNS_DGA", DGADetector()),
        ("Encrypted_Anomaly", EncryptedSessionDetector()),
    ]

    # Force statistical mode if requested
    if mode == "statistical":
        for _, det in detectors:
            if hasattr(det, "ml_enabled"):
                det.ml_enabled = False

    flow_manager = FlowManager(
        on_flow_complete=completed_flows.append,
        timeout_seconds=flow_timeout,
    )
    sessionizer = Sessionizer(flow_manager)
    reader = PcapReader(pcap_path, max_packets=max_packets)

    # Metrics accumulators
    alerts: List[Dict] = []
    feature_vectors_produced = 0
    feature_vector_latencies: List[float] = []
    detection_latencies: Dict[str, List[float]] = {n: [] for n, _ in detectors}
    pipeline_latencies: List[float] = []
    zero_duration_flows = 0
    nonzero_duration_flows = 0
    flow_durations: List[float] = []

    t_replay_start = time.perf_counter()

    print(f"Starting PCAP replay: {pcap_path}")
    print(f"Mode: {mode} | Max packets: {max_packets or 'all'} | Timeout: {flow_timeout}s")

    for flow in sessionizer.process(reader.stream()):
        # --- Feature extraction ---
        t0 = time.perf_counter()
        try:
            fv = pipeline.extract(flow)
        except Exception as e:
            logger.warning("Feature extraction failed", error=str(e))
            continue

        t_fv = time.perf_counter()
        feature_vector_latencies.append((t_fv - t0) * 1000)
        feature_vectors_produced += 1

        # Track flow duration distribution
        dur = flow.duration
        flow_durations.append(dur)
        if dur == 0.0:
            zero_duration_flows += 1
        else:
            nonzero_duration_flows += 1

        # --- Detection ---
        t_pipeline_start = time.perf_counter()

        for det_name, detector in detectors:
            t_det_start = time.perf_counter()
            try:
                result = detector.detect(fv)
                if result and result.is_alert:
                    alerts.append({
                        "detector": det_name,
                        "flow_id": flow.flow_id,
                        "src_ip": flow.source_ip,
                        "dst_ip": flow.destination_ip,
                        "src_port": flow.source_port,
                        "dst_port": flow.destination_port,
                        "protocol": flow.protocol,
                        "score": result.detection_score,
                        "threat_class": result.threat_class,
                        "flow_duration": dur,
                        "packet_count": flow.packet_count,
                    })
            except Exception as e:
                logger.warning("Detector failed", detector=det_name, error=str(e))

            t_det_end = time.perf_counter()
            detection_latencies[det_name].append((t_det_end - t_det_start) * 1000)

        pipeline_latencies.append((time.perf_counter() - t_pipeline_start) * 1000)

    t_replay_end = time.perf_counter()
    replay_elapsed = t_replay_end - t_replay_start

    # Collect ingestion stats
    stats = reader.stats

    # Alert breakdown by detector
    alerts_by_detector = {}
    for det_name, _ in detectors:
        count = sum(1 for a in alerts if a["detector"] == det_name)
        alerts_by_detector[det_name] = count

    # Build report
    report = {
        "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "pcap_file": str(pcap_path),
        "mode": mode,
        "max_packets_limit": max_packets,
        "flow_timeout_seconds": flow_timeout,

        # Ingestion counters
        "ingestion": {
            "packets_read": stats.packets_processed,
            "packets_skipped": stats.packets_skipped,
            "events_produced": stats.events_produced,
            "parse_errors": stats.parse_errors,
            "dns_events": stats.dns_events,
            "tls_events": stats.tls_events,
            "elapsed_seconds": round(stats.elapsed_seconds, 4),
            "packet_throughput_pps": round(stats.packets_per_second, 2),
        },

        # Flow reconstruction
        "flows": {
            "total_flows": flow_manager.total_flows_created,
            "feature_vectors_produced": feature_vectors_produced,
            "zero_duration_flows": zero_duration_flows,
            "nonzero_duration_flows": nonzero_duration_flows,
            "zero_duration_fraction": (
                round(zero_duration_flows / max(flow_manager.total_flows_created, 1), 4)
            ),
            "flow_duration_stats_seconds": {
                "min": round(min(flow_durations), 4) if flow_durations else None,
                "max": round(max(flow_durations), 4) if flow_durations else None,
                "mean": round(statistics.mean(flow_durations), 4) if flow_durations else None,
                "median": round(statistics.median(flow_durations), 4) if flow_durations else None,
            }
        },

        # Detection
        "detection": {
            "total_alerts": len(alerts),
            "alerts_by_detector": alerts_by_detector,
        },

        # Performance
        "performance": {
            "total_replay_seconds": round(replay_elapsed, 3),
            "flows_per_second": round(feature_vectors_produced / max(replay_elapsed, 1e-9), 2),
            "feature_vector_latency_ms": {
                "P50": _percentile(feature_vector_latencies, 50),
                "P90": _percentile(feature_vector_latencies, 90),
                "P95": _percentile(feature_vector_latencies, 95),
                "P99": _percentile(feature_vector_latencies, 99),
            },
            "full_pipeline_latency_ms": {
                "P50": _percentile(pipeline_latencies, 50),
                "P90": _percentile(pipeline_latencies, 90),
                "P95": _percentile(pipeline_latencies, 95),
                "P99": _percentile(pipeline_latencies, 99),
            },
            "detector_latency_ms": {
                det_name: {
                    "P50": _percentile(lats, 50),
                    "P90": _percentile(lats, 90),
                    "P99": _percentile(lats, 99),
                }
                for det_name, lats in detection_latencies.items()
            }
        }
    }

    with open(output_path, "w") as f:
        json.dump(report, f, indent=4)

    print(f"\n--- Phase 33 Replay Summary ---")
    print(f"Packets read      : {stats.packets_processed}")
    print(f"Events produced   : {stats.events_produced}")
    print(f"Flows created     : {flow_manager.total_flows_created}")
    print(f"FVs produced      : {feature_vectors_produced}")
    print(f"Zero-duration     : {zero_duration_flows} ({report['flows']['zero_duration_fraction']*100:.1f}%)")
    print(f"Total alerts      : {len(alerts)}")
    print(f"Replay time       : {replay_elapsed:.2f}s")
    print(f"Throughput        : {report['performance']['flows_per_second']:.1f} flows/sec")
    print(f"Output            : {output_path}")

    return report, alerts


def main():
    parser = argparse.ArgumentParser(
        description="UniShield Phase 33 — Passive PCAP Replay Pipeline"
    )
    parser.add_argument("--pcap", required=True, help="Path to PCAP file")
    parser.add_argument(
        "--output",
        default="reports/phase33/replay_metrics.json",
        help="Output report path"
    )
    parser.add_argument(
        "--max-packets", type=int, default=None,
        help="Maximum packets to read (default: all)"
    )
    parser.add_argument(
        "--flow-timeout", type=float, default=120.0,
        help="Flow idle timeout in seconds (default: 120)"
    )
    parser.add_argument(
        "--mode",
        choices=["default", "statistical"],
        default="default",
        help="Detection mode: default (ML+stat) or statistical (fallback only)"
    )
    args = parser.parse_args()
    report, _ = run_replay(
        pcap_path=args.pcap,
        output_path=args.output,
        max_packets=args.max_packets,
        flow_timeout=args.flow_timeout,
        mode=args.mode,
    )


if __name__ == "__main__":
    main()
