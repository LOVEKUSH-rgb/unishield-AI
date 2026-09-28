"""
UniShield AI -- Feature Pipeline
====================================
Orchestrates all feature extractors and produces FeatureVectors.

Pipeline:

  FlowRecord
      |
      +---> extract_flow_features()        [always]
      |
      +---> extract_timing_features()      [always, >= 2 packets]
      |
      +---> BehavioralAggregator           [always, window-based]
      |
      +---> extract_dns_features()         [only if dns info present]
      |
      +---> extract_tls_features()         [only if tls info present]
      |
      v
  FeatureVector

The pipeline is passive: it only reads FlowRecord data.
It does NOT initiate any network activity.

Usage (library):
    pipeline = FeaturePipeline()
    for flow in sessionizer.process(events):
        fv = pipeline.extract(flow)
        # fv is ready for detectors

Usage (CLI):
    python -m src.features.feature_pipeline path/to/capture.pcap
"""

from __future__ import annotations

import json
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Generator, List, Optional

from src.features.behavioral_features import BehavioralAggregator
from src.features.dns_features import extract_dns_features
from src.features.flow_features import extract_flow_features
from src.features.tls_features import extract_tls_features
from src.features.timing_features import extract_timing_features
from src.features.exfiltration_features import HostBaselineTracker
from src.features.feature_vector import FeatureVector
from src.flows.flow import FlowRecord
from src.utils.logging import get_logger

logger = get_logger(__name__)


class FeaturePipeline:
    """
    Converts FlowRecords into FeatureVectors.

    Maintains a BehavioralAggregator for window-based statistics.
    The aggregator must be shared across all flows from the same
    traffic source to accumulate per-IP behavioural history.

    Parameters
    ----------
    window_sizes:
        Window sizes in seconds for behavioral features.
        Reads from config if not provided.
    """

    def __init__(
        self,
        window_sizes: Optional[List[float]] = None,
    ) -> None:
        self._aggregator = BehavioralAggregator(window_sizes=window_sizes)
        self._exfil_tracker = HostBaselineTracker()
        self._vectors_produced = 0
        self._errors = 0

        logger.info(
            "FeaturePipeline initialised",
            window_sizes=window_sizes or "from_config",
        )

    # ------------------------------------------------------------------
    # Primary interface
    # ------------------------------------------------------------------

    def extract(self, flow: FlowRecord, dns_event=None, tls_event=None) -> FeatureVector:
        """
        Produce a FeatureVector for one FlowRecord.

        Parameters
        ----------
        flow:
            The FlowRecord to extract features from.
        dns_event:
            Optional: the last DNS NetworkEvent associated with this flow
            (provides DNSInfo for dns_features extraction).
        tls_event:
            Optional: the last TLS NetworkEvent associated with this flow
            (provides TLSInfo for tls_features extraction).

        Returns
        -------
        FeatureVector
            Populated with all applicable features.
        """
        # First, register this flow with the behavioral aggregator
        # so that source/dest profiles are updated BEFORE querying
        self._aggregator.record_flow(flow)

        fv = FeatureVector(
            flow_id=flow.flow_id,
            timestamp=datetime.fromtimestamp(
                flow.last_seen, tz=timezone.utc
            ).isoformat(),
            source_ip=flow.source_ip,
            destination_ip=flow.destination_ip,
            source_port=flow.source_port,
            destination_port=flow.destination_port,
            protocol=flow.protocol,
        )

        try:
            # --- Always extract ---
            extract_flow_features(flow, fv)
            extract_timing_features(flow, fv)
            self._aggregator.extract_behavioral_features(flow, fv)
            self._exfil_tracker.record_flow(flow, fv)

            # --- DNS: only when available ---
            if dns_event and dns_event.dns:
                extract_dns_features(dns_event.dns, fv)

            # --- TLS: only when available ---
            if tls_event and tls_event.tls:
                extract_tls_features(tls_event.tls, fv)

            # --- Validation ---
            bad = fv.validate_no_infinities()
            if bad:
                logger.warning(
                    "FeatureVector contains non-finite values",
                    features=bad,
                    flow_id=flow.flow_id,
                )

            self._vectors_produced += 1

        except Exception as exc:
            self._errors += 1
            logger.error(
                "Feature extraction failed",
                flow_id=flow.flow_id,
                error=str(exc),
            )

        return fv

    def extract_stream(
        self,
        flows: Generator[FlowRecord, None, None],
    ) -> Generator[FeatureVector, None, None]:
        """
        Yield FeatureVectors for a stream of FlowRecords.

        Parameters
        ----------
        flows:
            Generator of FlowRecord objects (e.g. from Sessionizer).

        Yields
        ------
        FeatureVector
            One per flow.
        """
        for flow in flows:
            yield self.extract(flow)

    @property
    def vectors_produced(self) -> int:
        return self._vectors_produced

    @property
    def errors(self) -> int:
        return self._errors

    def summary(self) -> dict:
        return {
            "vectors_produced": self._vectors_produced,
            "errors": self._errors,
            "tracked_sources": self._aggregator.tracked_sources,
            "tracked_destinations": self._aggregator.tracked_destinations,
        }


# ----------------------------------------------------------------
# CLI entry point
# ----------------------------------------------------------------

def _run_cli(pcap_path: str) -> None:
    """
    Process a PCAP file end-to-end and display feature extraction results.

    Metrics reported are actual runtime measurements.
    """
    from src.utils.logging import configure_logging
    configure_logging(level="WARNING")  # suppress noise in CLI

    from src.ingestion.pcap_reader import PcapReader
    from src.flows.flow_manager import FlowManager
    from src.flows.sessionizer import Sessionizer

    print(f"\nUniShield AI -- Feature Pipeline")
    print(f"Input  : {pcap_path}")
    print(f"Mode   : Passive PCAP ingestion (read-only)")
    print("-" * 50)

    t_start = time.time()

    reader = PcapReader(pcap_path)
    manager = FlowManager(timeout_seconds=120.0)
    sess = Sessionizer(manager)
    pipeline = FeaturePipeline()

    flow_count = 0
    fv_list: List[FeatureVector] = []

    for flow in sess.process(reader.stream()):
        flow_count += 1
        fv = pipeline.extract(flow)
        fv_list.append(fv)

    elapsed = time.time() - t_start

    print(f"Packets processed  : {reader.stats.packets_processed}")
    print(f"Flows produced     : {flow_count}")
    print(f"Feature vectors    : {pipeline.vectors_produced}")
    print(f"Extraction errors  : {pipeline.errors}")
    print(f"Processing time    : {elapsed:.3f} s")
    if elapsed > 0:
        print(f"Flows/second       : {flow_count / elapsed:.1f}")
    print("-" * 50)

    if fv_list:
        print("\nSample FeatureVector (first flow):")
        first = fv_list[0]
        sample = {
            "flow_id": first.flow_id,
            "source_ip": first.source_ip,
            "destination_ip": first.destination_ip,
            "protocol": first.protocol,
            "feature_groups": first.feature_groups,
            "features": {
                k: v for k, v in list(first.features.items())[:20]
            },
        }
        print(json.dumps(sample, indent=2, default=str))
    else:
        print("No flows extracted.")


if __name__ == "__main__":
    import argparse
    import warnings
    warnings.filterwarnings("ignore")

    parser = argparse.ArgumentParser(
        description="UniShield AI -- Feature Pipeline CLI"
    )
    parser.add_argument("pcap", help="Path to PCAP file")
    args = parser.parse_args()
    _run_cli(args.pcap)
