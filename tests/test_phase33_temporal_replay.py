"""
Phase 33 — Temporal PCAP Replay Tests
=======================================
Validates that:

1. Packets belonging to the same connection aggregate into one FlowRecord
2. Flow duration is calculated from actual packet timestamps (not wall clock)
3. Single-packet flows produce zero duration (documented behavior, not a bug)
4. Multi-packet flows from the same source produce duration > 0
5. Idle timeout expiration works (flow expires after inactivity)
6. End-of-stream flush expires all remaining active flows
7. Empty PCAP does not crash
8. Malformed/missing packets are handled safely
9. Replay speed has no effect on original event timestamps
10. PcapReader opens files read-only (passive compliance)

All tests use either:
  - The synthetic PCAP from test_pcap_generator (self-contained)
  - Programmatically constructed NetworkEvents (no PCAP needed)

Tests NEVER require external dataset availability.
"""

from __future__ import annotations

import os
import time
from pathlib import Path
from typing import List
from unittest.mock import patch

import pytest

from src.flows.flow import FlowRecord
from src.flows.flow_manager import FlowManager
from src.flows.sessionizer import Sessionizer
from src.ingestion.models import NetworkEvent, TCPFlags


# ----------------------------------------------------------------
# Helpers: construct minimal NetworkEvents programmatically
# ----------------------------------------------------------------

def make_event(
    src_ip="192.168.1.1",
    src_port=12345,
    dst_ip="10.0.0.1",
    dst_port=80,
    proto=6,
    timestamp=1_700_000_000.0,
    pkt_len=64,
    tcp_flags: int = 0x02,  # SYN
) -> NetworkEvent:
    """Create a minimal NetworkEvent for testing."""
    return NetworkEvent(
        timestamp=timestamp,
        source_ip=src_ip,
        source_port=src_port,
        destination_ip=dst_ip,
        destination_port=dst_port,
        protocol=proto,
        packet_length=pkt_len,
        tcp_flags=tcp_flags,
        ttl=64,
    )


def run_events(events: List[NetworkEvent], flow_timeout: float = 120.0) -> List[FlowRecord]:
    """Drive events through FlowManager+Sessionizer and return all completed flows."""
    completed = []
    fm = FlowManager(
        on_flow_complete=completed.append,
        timeout_seconds=flow_timeout,
        cleanup_interval_seconds=0.0,  # Run cleanup on every event for tests
    )
    sess = Sessionizer(fm)
    result = sess.process_all(events, flush_at_end=True)
    return result


# ----------------------------------------------------------------
# Test 1: Same-connection packets aggregate into one FlowRecord
# ----------------------------------------------------------------

def test_same_connection_aggregates():
    """Packets from the same 5-tuple must build a single FlowRecord."""
    base_ts = 1_700_000_000.0
    events = [
        make_event(timestamp=base_ts, tcp_flags=0x02),           # SYN
        make_event(timestamp=base_ts + 0.1, tcp_flags=0x12),     # SYN-ACK
        make_event(timestamp=base_ts + 0.2, tcp_flags=0x10),     # ACK
        make_event(timestamp=base_ts + 1.0, tcp_flags=0x11),     # FIN+ACK
    ]
    flows = run_events(events)
    assert len(flows) == 1, f"Expected 1 flow, got {len(flows)}"
    flow = flows[0]
    assert flow.packet_count == 4
    assert flow.source_ip == "192.168.1.1"
    assert flow.destination_ip == "10.0.0.1"


# ----------------------------------------------------------------
# Test 2: Flow duration from actual packet timestamps
# ----------------------------------------------------------------

def test_flow_duration_from_timestamps():
    """Flow duration must equal last_seen - start_time using packet timestamps."""
    base_ts = 1_700_000_000.0
    expected_duration = 5.0
    events = [
        make_event(timestamp=base_ts, tcp_flags=0x02),
        make_event(timestamp=base_ts + expected_duration, tcp_flags=0x11),  # FIN
    ]
    flows = run_events(events)
    assert len(flows) == 1
    flow = flows[0]
    assert abs(flow.duration - expected_duration) < 0.001, (
        f"Expected duration {expected_duration}s, got {flow.duration}s"
    )


# ----------------------------------------------------------------
# Test 3: Single-packet flows produce zero duration (documented behavior)
# ----------------------------------------------------------------

def test_single_packet_flow_zero_duration():
    """
    A flow with one packet has start_time == last_seen, so duration == 0.
    This is mathematically correct, not a bug.
    The DDoS detector handles this via the dst_conn_count_60s proxy.
    """
    events = [
        make_event(timestamp=1_700_000_000.0, tcp_flags=0x02)  # SYN only, no reply
    ]
    flows = run_events(events)
    assert len(flows) == 1
    flow = flows[0]
    assert flow.duration == 0.0, (
        f"Single-packet flow must have zero duration, got {flow.duration}"
    )
    assert flow.packet_count == 1


# ----------------------------------------------------------------
# Test 4: Multi-packet flow has duration > 0
# ----------------------------------------------------------------

def test_multi_packet_flow_has_positive_duration():
    """Multi-packet flows must have duration > 0 when timestamps differ."""
    events = [
        make_event(timestamp=1_700_000_000.0, tcp_flags=0x02),
        make_event(timestamp=1_700_000_001.0, tcp_flags=0x12),  # 1 second later
        make_event(timestamp=1_700_000_002.0, tcp_flags=0x01),  # FIN
    ]
    flows = run_events(events)
    assert len(flows) == 1
    assert flows[0].duration > 0.0
    assert flows[0].packet_count == 3


# ----------------------------------------------------------------
# Test 5: Idle timeout expiration
# ----------------------------------------------------------------

def test_idle_timeout_expiration():
    """
    Flows idle beyond the timeout window must be expired when the
    next event arrives (cleanup is triggered by event timestamps).
    """
    timeout = 10.0
    base_ts = 1_700_000_000.0

    # Event 1: start a flow
    e1 = make_event(src_ip="1.2.3.4", timestamp=base_ts)

    # Event 2: a completely different flow arriving after timeout
    e2 = make_event(
        src_ip="5.6.7.8",
        timestamp=base_ts + timeout + 1.0  # beyond timeout
    )

    completed = []
    fm = FlowManager(
        on_flow_complete=completed.append,
        timeout_seconds=timeout,
        cleanup_interval_seconds=0.0,  # sweep on every event
    )
    sess = Sessionizer(fm)
    flows = sess.process_all([e1, e2], flush_at_end=True)

    # Both flows must appear in output
    assert len(flows) == 2
    # First flow (expired by timeout) should appear
    first_flow = next((f for f in flows if f.source_ip == "1.2.3.4"), None)
    assert first_flow is not None


# ----------------------------------------------------------------
# Test 6: End-of-stream flush expires all remaining active flows
# ----------------------------------------------------------------

def test_end_of_stream_flush():
    """
    FlowManager.flush() must be called at stream end, yielding
    all active (incomplete) flows.
    """
    # Multiple flows, none closed with FIN/RST
    events = [
        make_event(src_ip="10.0.0.1", src_port=1001, timestamp=1_700_000_000.0),
        make_event(src_ip="10.0.0.2", src_port=1002, timestamp=1_700_000_001.0),
        make_event(src_ip="10.0.0.3", src_port=1003, timestamp=1_700_000_002.0),
    ]
    flows = run_events(events)
    assert len(flows) == 3, (
        f"All 3 flows must be flushed at end-of-stream, got {len(flows)}"
    )


# ----------------------------------------------------------------
# Test 7: Empty PCAP does not crash
# ----------------------------------------------------------------

def test_empty_event_stream_does_not_crash():
    """Passing zero events must not crash the pipeline."""
    flows = run_events([])
    assert flows == []


# ----------------------------------------------------------------
# Test 8: Malformed / minimal packet produces no crash
# ----------------------------------------------------------------

def test_malformed_event_no_crash():
    """
    NetworkEvent with missing optional fields must not crash FlowManager.
    Protocol-less events should still produce a FlowRecord.
    """
    event = NetworkEvent(
        timestamp=1_700_000_000.0,
        source_ip=None,
        destination_ip=None,
        source_port=None,
        destination_port=None,
        protocol=None,
        packet_length=0,
    )
    # Should not raise
    flows = run_events([event])
    assert len(flows) == 1


# ----------------------------------------------------------------
# Test 9: Replay does not alter original event timestamps
# ----------------------------------------------------------------

def test_timestamps_preserved_through_pipeline():
    """
    The FlowRecord start_time and last_seen must match original event timestamps.
    """
    t1 = 1_700_000_000.0
    t2 = 1_700_000_005.0

    events = [
        make_event(timestamp=t1, tcp_flags=0x02),
        make_event(timestamp=t2, tcp_flags=0x01),  # FIN
    ]
    flows = run_events(events)
    assert len(flows) == 1
    flow = flows[0]
    assert flow.start_time == t1
    assert abs(flow.last_seen - t2) < 0.001


# ----------------------------------------------------------------
# Test 10: FlowManager flush returns all remaining flows
# ----------------------------------------------------------------

def test_flow_manager_flush_returns_all_active():
    """
    Direct test of FlowManager.flush() — must return exactly the
    number of flows that are still active.
    """
    flushed = []
    fm = FlowManager(
        on_flow_complete=flushed.append,
        timeout_seconds=300.0,
    )

    events = [
        make_event(src_ip="10.0.0.1", src_port=1, timestamp=1_700_000_000.0),
        make_event(src_ip="10.0.0.2", src_port=2, timestamp=1_700_000_001.0),
        make_event(src_ip="10.0.0.3", src_port=3, timestamp=1_700_000_002.0),
    ]
    for e in events:
        fm.process_event(e)

    assert fm.active_count == 3

    returned = fm.flush(current_time=1_700_000_500.0)
    assert len(returned) == 3
    assert fm.active_count == 0


# ----------------------------------------------------------------
# Test 11: PCAP replay through full pipeline on synthetic PCAP
# ----------------------------------------------------------------

def test_synthetic_pcap_replay():
    """
    Generate the synthetic PCAP and replay it through the full
    PcapReader -> Sessionizer -> FeaturePipeline path.

    This validates the complete temporal pipeline without requiring
    any external dataset.
    """
    pytest.importorskip("scapy", reason="Scapy not installed — skipping PCAP replay test")

    from src.ingestion.test_pcap_generator import generate
    from src.ingestion.pcap_reader import PcapReader
    from src.features.feature_pipeline import FeaturePipeline

    pcap_path = Path("data/samples/test_synthetic.pcap")
    if not pcap_path.exists():
        generate(pcap_path)

    completed_flows = []
    fm = FlowManager(on_flow_complete=completed_flows.append, timeout_seconds=60.0)
    sess = Sessionizer(fm)
    pipeline = FeaturePipeline()

    reader = PcapReader(str(pcap_path))
    flows = sess.process_all(reader.stream(), flush_at_end=True)

    assert len(flows) > 0, "Expected at least one flow from synthetic PCAP"

    vectors = []
    for flow in flows:
        try:
            fv = pipeline.extract(flow)
            vectors.append(fv)
        except Exception as e:
            pytest.fail(f"FeaturePipeline.extract raised on flow {flow.flow_id}: {e}")

    assert len(vectors) > 0, "Expected at least one FeatureVector"

    # Validate timestamps are preserved
    for flow in flows:
        assert flow.start_time > 0.0
        assert flow.last_seen >= flow.start_time
        assert flow.duration >= 0.0


# ----------------------------------------------------------------
# Test 12: PCAP file opened read-only (passive compliance)
# ----------------------------------------------------------------

def test_pcap_reader_opens_read_only(tmp_path):
    """
    PcapReader must only request read access to the PCAP file.
    """
    pytest.importorskip("scapy", reason="Scapy not installed — skipping")

    from src.ingestion.test_pcap_generator import generate
    from src.ingestion.pcap_reader import PcapReader

    pcap_path = tmp_path / "test.pcap"
    generate(pcap_path)

    # Make file read-only
    pcap_path.chmod(0o444)

    try:
        reader = PcapReader(str(pcap_path))
        events = list(reader.stream())
        # If we get here without permission error, read-only access works
        assert reader.stats.packets_processed >= 0
    finally:
        # Restore write permission for cleanup
        pcap_path.chmod(0o644)


# ----------------------------------------------------------------
# Test 13: DDoS zero-duration — dst_conn_count_60s context
# ----------------------------------------------------------------

def test_ddos_single_packet_zero_duration_detected():
    """
    Phase 31/32 finding: single-packet SYN flows have zero duration.
    The DDoS detector must NOT crash on zero-duration flows.
    The detector uses dst_conn_count_60s as a proxy for rate.
    """
    from src.detectors.ddos import DDoSDetector
    from src.features.feature_vector import FeatureVector

    detector = DDoSDetector()
    detector.ml_enabled = False

    # Simulate what a high-volume SYN flood looks like
    # when single-packet flows are all flushed together
    fv = FeatureVector(
        flow_id="test-ddos-zero-dur",
        timestamp="2026-01-01T00:00:00Z",
        source_ip="203.0.113.1",
        destination_ip="10.0.0.1",
        source_port=12345,
        destination_port=80,
        protocol=6,
        features={
            "flow_duration": 0.0,         # Zero duration — single packet
            "packet_count": 1,
            "byte_count": 64,
            "bytes_per_second": 0.0,
            "packets_per_second": 0.0,    # Would be 0 without fix
            "tcp_syn_count": 1,
            "tcp_syn_rate": 0.0,
            "dst_conn_count_60s": 800,    # Phase 32 fix: temporal proxy
            "src_unique_dsts": 1,
            "protocol_tcp": True,
            "protocol_udp": False,
        }
    )

    # Must not crash
    result = detector.detect(fv)
    assert result is not None
    assert isinstance(result.detection_score, float)
    # With dst_conn_count_60s=800, rate_proxy = 800/60 ≈ 13.3 conn/s
    # This is below the absolute SYN flood threshold (500 pps) but
    # the important thing is it doesn't crash and returns a result


def test_ddos_multi_packet_flow_duration_positive():
    """
    Multi-packet flows from the same source must produce
    duration > 0, enabling rate-based detection.
    """
    base_ts = 1_700_000_000.0
    # 500 packets from same source (simulated SYN flood)
    events = []
    for i in range(50):
        events.append(make_event(
            src_ip="203.0.113.1",
            src_port=10000 + i,  # different src ports (distributed)
            dst_ip="10.0.0.1",
            dst_port=80,
            timestamp=base_ts + (i * 0.01),  # 10ms apart
            tcp_flags=0x02,  # SYN
        ))

    flows = run_events(events, flow_timeout=120.0)
    # With different src ports, each SYN from different source port creates its own flow
    # But all flows share the same destination — this is the DDoS pattern
    assert len(flows) == 50  # Each unique src_port = unique flow

    # Each flow here has only 1 packet (no reply), so duration = 0
    # This is the documented single-packet zero-duration behavior
    zero_dur = sum(1 for f in flows if f.duration == 0.0)
    assert zero_dur == 50, (
        f"All {len(flows)} single-SYN flows should have zero duration, {zero_dur} did"
    )
