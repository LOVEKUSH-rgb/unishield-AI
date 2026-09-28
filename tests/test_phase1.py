"""
UniShield AI -- Phase 1 Tests
================================
Tests for the complete ingestion and flow pipeline:

  NetworkEvent model
  PcapReader (PCAP parsing)
  ZeekLogReader (Zeek log adapter)
  StreamProcessor
  FlowRecord (creation, update, statistics)
  FlowManager (flow table, timeout, FIN/RST)
  Sessionizer (end-to-end)

All tests use SYNTHETIC data clearly labelled as such.
No real network traffic is required.
No packets are transmitted during these tests.

Run with:
    python -m pytest tests/test_phase1.py -v
"""

from __future__ import annotations

import io
import tempfile
import time
from pathlib import Path
from typing import List

import pytest

# Ensure project root on sys.path (conftest.py does this)
PROJECT_ROOT = Path(__file__).parents[1]

# ================================================================
# Fixtures
# ================================================================

@pytest.fixture(scope="session")
def synthetic_pcap(tmp_path_factory) -> Path:
    """
    Generate a synthetic PCAP once per test session.

    SYNTHETIC DATA ONLY -- not real attack traffic.
    """
    import warnings
    warnings.filterwarnings("ignore")

    out_dir = tmp_path_factory.mktemp("pcap")
    pcap_path = out_dir / "test_synthetic.pcap"

    from src.ingestion.test_pcap_generator import generate
    generate(output_path=pcap_path)
    return pcap_path


@pytest.fixture
def sample_event():
    """Return a minimal valid NetworkEvent for unit testing."""
    from src.ingestion.models import NetworkEvent
    return NetworkEvent(
        timestamp=1_700_000_000.0,
        source_ip="192.168.1.1",
        destination_ip="10.0.0.1",
        source_port=54321,
        destination_port=80,
        protocol=6,
        packet_length=64,
        tcp_flags=0x02,  # SYN
    )


@pytest.fixture
def flow_manager():
    """Return a fresh FlowManager with a short timeout for testing."""
    from src.flows.flow_manager import FlowManager
    return FlowManager(timeout_seconds=5.0, cleanup_interval_seconds=1.0)


# ================================================================
# 1. NetworkEvent model
# ================================================================

class TestNetworkEventModel:
    """Validate the NetworkEvent Pydantic model."""

    def test_minimal_event_requires_only_timestamp(self):
        from src.ingestion.models import NetworkEvent
        event = NetworkEvent(timestamp=1_700_000_000.0)
        assert event.timestamp == 1_700_000_000.0
        assert event.source_ip is None

    def test_full_event_creation(self, sample_event):
        assert sample_event.source_ip == "192.168.1.1"
        assert sample_event.destination_ip == "10.0.0.1"
        assert sample_event.source_port == 54321
        assert sample_event.destination_port == 80
        assert sample_event.protocol == 6

    def test_protocol_name_tcp(self, sample_event):
        assert sample_event.protocol_name == "TCP"

    def test_protocol_name_udp(self):
        from src.ingestion.models import NetworkEvent
        e = NetworkEvent(timestamp=1.0, protocol=17)
        assert e.protocol_name == "UDP"

    def test_protocol_name_unknown(self):
        from src.ingestion.models import NetworkEvent
        e = NetworkEvent(timestamp=1.0, protocol=253)
        assert e.protocol_name == "253"

    def test_is_tcp_syn_true(self, sample_event):
        assert sample_event.is_tcp_syn() is True

    def test_is_tcp_syn_false_for_ack(self):
        from src.ingestion.models import NetworkEvent
        e = NetworkEvent(timestamp=1.0, tcp_flags=0x10)  # ACK only
        assert e.is_tcp_syn() is False

    def test_is_tcp_syn_ack(self):
        from src.ingestion.models import NetworkEvent
        e = NetworkEvent(timestamp=1.0, tcp_flags=0x12)  # SYN+ACK
        assert e.is_tcp_syn_ack() is True
        assert e.is_tcp_syn() is False

    def test_datetime_utc_is_aware(self, sample_event):
        from datetime import timezone
        dt = sample_event.datetime_utc
        assert dt.tzinfo == timezone.utc

    def test_flow_key_is_tuple(self, sample_event):
        key = sample_event.flow_key
        assert isinstance(key, tuple)
        assert len(key) == 5

    def test_flow_key_is_bidirectional(self):
        """A->B and B->A should produce the same flow key."""
        from src.ingestion.models import NetworkEvent
        fwd = NetworkEvent(
            timestamp=1.0,
            source_ip="192.168.1.1", source_port=1234,
            destination_ip="10.0.0.1", destination_port=80,
            protocol=6,
        )
        rev = NetworkEvent(
            timestamp=1.1,
            source_ip="10.0.0.1", source_port=80,
            destination_ip="192.168.1.1", destination_port=1234,
            protocol=6,
        )
        assert fwd.flow_key == rev.flow_key

    def test_invalid_port_raises(self):
        from src.ingestion.models import NetworkEvent
        from pydantic import ValidationError
        with pytest.raises(ValidationError):
            NetworkEvent(timestamp=1.0, source_port=99999)

    def test_invalid_ip_version_raises(self):
        from src.ingestion.models import NetworkEvent
        from pydantic import ValidationError
        with pytest.raises(ValidationError):
            NetworkEvent(timestamp=1.0, ip_version=5)

    def test_invalid_tcp_flags_raises(self):
        from src.ingestion.models import NetworkEvent
        from pydantic import ValidationError
        with pytest.raises(ValidationError):
            NetworkEvent(timestamp=1.0, tcp_flags=256)

    def test_event_is_frozen(self, sample_event):
        """NetworkEvent must be immutable."""
        with pytest.raises(Exception):
            sample_event.source_ip = "1.2.3.4"

    def test_to_summary_returns_string(self, sample_event):
        s = sample_event.to_summary()
        assert isinstance(s, str)
        assert "192.168.1.1" in s

    def test_dns_info_attached(self):
        from src.ingestion.models import NetworkEvent, DNSInfo
        dns = DNSInfo(query_name="example.com", query_type="A", is_query=True)
        e = NetworkEvent(timestamp=1.0, dns=dns)
        assert e.dns.query_name == "example.com"

    def test_tls_info_attached(self):
        from src.ingestion.models import NetworkEvent, TLSInfo
        tls = TLSInfo(version="TLS 1.3", sni="example.com")
        e = NetworkEvent(timestamp=1.0, tls=tls)
        assert e.tls.sni == "example.com"

    def test_missing_dns_fields_are_none(self):
        from src.ingestion.models import DNSInfo
        dns = DNSInfo()  # all optional
        assert dns.query_name is None
        assert dns.query_type is None

    def test_missing_tls_fields_are_none(self):
        from src.ingestion.models import TLSInfo
        tls = TLSInfo()
        assert tls.version is None
        assert tls.sni is None


# ================================================================
# 2. TCPFlags
# ================================================================

class TestTCPFlags:
    """Validate TCP flag parsing."""

    def test_syn_flag(self):
        from src.ingestion.models import TCPFlags
        f = TCPFlags.from_int(0x02)
        assert bool(f & TCPFlags.SYN)
        assert not bool(f & TCPFlags.ACK)

    def test_syn_ack_flags(self):
        from src.ingestion.models import TCPFlags
        f = TCPFlags.from_int(0x12)
        assert bool(f & TCPFlags.SYN)
        assert bool(f & TCPFlags.ACK)

    def test_fin_flag(self):
        from src.ingestion.models import TCPFlags
        f = TCPFlags.from_int(0x01)
        assert bool(f & TCPFlags.FIN)

    def test_rst_flag(self):
        from src.ingestion.models import TCPFlags
        f = TCPFlags.from_int(0x04)
        assert bool(f & TCPFlags.RST)

    def test_to_dict_contains_all_flags(self):
        from src.ingestion.models import TCPFlags
        d = TCPFlags.from_int(0x12).to_dict()
        assert "SYN" in d
        assert "ACK" in d
        assert "FIN" in d
        assert d["SYN"] is True
        assert d["ACK"] is True
        assert d["FIN"] is False

    def test_invalid_flags_clamped(self):
        from src.ingestion.models import TCPFlags
        f = TCPFlags.from_int(999)  # Should not raise
        assert isinstance(f, TCPFlags)

    def test_zero_flags(self):
        from src.ingestion.models import TCPFlags
        f = TCPFlags.from_int(0)
        d = f.to_dict()
        assert not any(d.values())


# ================================================================
# 3. PCAP Reader
# ================================================================

class TestPcapReader:
    """Test PCAP parsing with synthetic test data."""

    def test_pcap_reader_initialises(self, synthetic_pcap):
        from src.ingestion.pcap_reader import PcapReader
        reader = PcapReader(synthetic_pcap)
        assert reader.pcap_path == synthetic_pcap

    def test_nonexistent_file_raises(self):
        from src.ingestion.pcap_reader import PcapReader
        with pytest.raises(FileNotFoundError):
            PcapReader("/nonexistent/path/file.pcap")

    def test_pcap_stream_yields_events(self, synthetic_pcap):
        from src.ingestion.pcap_reader import PcapReader
        reader = PcapReader(synthetic_pcap)
        events = list(reader.stream())
        assert len(events) > 0

    def test_events_have_timestamps(self, synthetic_pcap):
        from src.ingestion.pcap_reader import PcapReader
        for event in PcapReader(synthetic_pcap).stream():
            assert event.timestamp > 0

    def test_events_have_ip_addresses(self, synthetic_pcap):
        from src.ingestion.pcap_reader import PcapReader
        events = list(PcapReader(synthetic_pcap).stream())
        with_ips = [e for e in events if e.source_ip is not None]
        assert len(with_ips) > 0

    def test_syn_packet_detected(self, synthetic_pcap):
        from src.ingestion.pcap_reader import PcapReader
        events = list(PcapReader(synthetic_pcap).stream())
        syns = [e for e in events if e.is_tcp_syn()]
        assert len(syns) >= 1

    def test_fin_packet_detected(self, synthetic_pcap):
        from src.ingestion.pcap_reader import PcapReader
        events = list(PcapReader(synthetic_pcap).stream())
        fins = [e for e in events if e.tcp_flags is not None and (e.tcp_flags & 0x01)]
        assert len(fins) >= 1

    def test_rst_packet_detected(self, synthetic_pcap):
        from src.ingestion.pcap_reader import PcapReader
        events = list(PcapReader(synthetic_pcap).stream())
        rsts = [e for e in events if e.tcp_flags is not None and (e.tcp_flags & 0x04)]
        assert len(rsts) >= 1

    def test_udp_events_present(self, synthetic_pcap):
        from src.ingestion.pcap_reader import PcapReader
        events = list(PcapReader(synthetic_pcap).stream())
        udps = [e for e in events if e.protocol == 17]
        assert len(udps) >= 1

    def test_tcp_events_present(self, synthetic_pcap):
        from src.ingestion.pcap_reader import PcapReader
        events = list(PcapReader(synthetic_pcap).stream())
        tcps = [e for e in events if e.protocol == 6]
        assert len(tcps) >= 1

    def test_dns_events_present(self, synthetic_pcap):
        from src.ingestion.pcap_reader import PcapReader
        events = list(PcapReader(synthetic_pcap).stream())
        dns_events = [e for e in events if e.dns is not None]
        assert len(dns_events) >= 1

    def test_dns_query_name_extracted(self, synthetic_pcap):
        from src.ingestion.pcap_reader import PcapReader
        events = list(PcapReader(synthetic_pcap).stream())
        dns_events = [e for e in events if e.dns and e.dns.query_name]
        assert any("example.com" in e.dns.query_name for e in dns_events)

    def test_max_packets_limit(self, synthetic_pcap):
        from src.ingestion.pcap_reader import PcapReader
        events = list(PcapReader(synthetic_pcap, max_packets=3).stream())
        assert len(events) <= 3

    def test_stats_populated_after_stream(self, synthetic_pcap):
        from src.ingestion.pcap_reader import PcapReader
        reader = PcapReader(synthetic_pcap)
        list(reader.stream())
        assert reader.stats.packets_processed > 0
        assert reader.stats.events_produced > 0
        assert reader.stats.elapsed_seconds > 0

    def test_no_payload_stored(self, synthetic_pcap):
        """Verify we never store actual payload content."""
        from src.ingestion.pcap_reader import PcapReader
        for event in PcapReader(synthetic_pcap).stream():
            # payload_length is the byte COUNT only — not the bytes themselves
            assert not hasattr(event, "payload_bytes")
            assert not hasattr(event, "raw_payload")
            assert not hasattr(event, "content")

    def test_ingestion_source_is_pcap(self, synthetic_pcap):
        from src.ingestion.pcap_reader import PcapReader
        for event in PcapReader(synthetic_pcap).stream():
            assert event.ingestion_source == "pcap"

    def test_packet_lengths_are_positive(self, synthetic_pcap):
        from src.ingestion.pcap_reader import PcapReader
        for event in PcapReader(synthetic_pcap).stream():
            if event.packet_length is not None:
                assert event.packet_length > 0


# ================================================================
# 4. Zeek Log Reader
# ================================================================

class TestZeekLogReader:
    """Test Zeek log adapter using synthetic TSV log content."""

    def _write_conn_log(self, path: Path) -> Path:
        """Write a minimal synthetic Zeek conn.log for testing."""
        content = (
            "#separator \\x09\n"
            "#fields\tts\tid.orig_h\tid.orig_p\tid.resp_h\tid.resp_p\t"
            "proto\tservice\tduration\torig_bytes\tresp_bytes\t"
            "conn_state\thistory\n"
            "1700000000.000\t192.168.1.1\t54321\t10.0.0.1\t80\t"
            "tcp\thttp\t0.100\t512\t2048\tSF\tShADadfF\n"
            "1700000001.000\t192.168.1.2\t12345\t8.8.8.8\t53\t"
            "udp\tdns\t0.005\t50\t100\tSF\t-\n"
            "1700000002.000\t-\t-\t-\t-\ttcp\t-\t-\t-\t-\t-\t-\n"  # missing fields
        )
        log_path = path / "conn.log"
        log_path.write_text(content)
        return log_path

    def _write_dns_log(self, path: Path) -> Path:
        """Write a minimal synthetic Zeek dns.log for testing."""
        content = (
            "#separator \\x09\n"
            "#fields\tts\tid.orig_h\tid.orig_p\tid.resp_h\tid.resp_p\t"
            "proto\ttrans_id\tquery\tqtype\tqtype_name\t"
            "rcode\trcode_name\tQR\tAA\tTC\tRD\tRA\tZ\tanswers\n"
            "1700000000.200\t192.168.1.101\t12345\t8.8.8.8\t53\t"
            "udp\t43981\texample.com\t1\tA\t0\tNOERROR\tF\tF\tF\tT\tT\t0\texample.com\n"
            "1700000000.205\t8.8.8.8\t53\t192.168.1.101\t12345\t"
            "udp\t43981\texample.com\t1\tA\t0\tNOERROR\tT\tF\tF\tT\tT\t0\t93.184.216.34\n"
        )
        log_path = path / "dns.log"
        log_path.write_text(content)
        return log_path

    def _write_ssl_log(self, path: Path) -> Path:
        """Write a minimal synthetic Zeek ssl.log for testing."""
        content = (
            "#separator \\x09\n"
            "#fields\tts\tid.orig_h\tid.orig_p\tid.resp_h\tid.resp_p\t"
            "version\tcipher\tserver_name\tja3\tja3s\tsubject\tissuer\tresumed\n"
            "1700000003.000\t192.168.1.100\t54322\t10.0.0.1\t443\t"
            "TLSv12\tTLS_AES_128_GCM_SHA256\texample.com\t"
            "aabbcc\tddeeff\tCN=example.com\tCN=DigiCert\tF\n"
        )
        log_path = path / "ssl.log"
        log_path.write_text(content)
        return log_path

    def test_conn_log_yields_events(self, tmp_path):
        from src.ingestion.flow_reader import ZeekLogReader
        log = self._write_conn_log(tmp_path)
        events = list(ZeekLogReader(log, log_type="conn").stream())
        assert len(events) >= 1

    def test_conn_log_source_ip_extracted(self, tmp_path):
        from src.ingestion.flow_reader import ZeekLogReader
        log = self._write_conn_log(tmp_path)
        events = list(ZeekLogReader(log, log_type="conn").stream())
        ips = [e.source_ip for e in events if e.source_ip]
        assert "192.168.1.1" in ips

    def test_conn_log_tcp_flags_from_history(self, tmp_path):
        from src.ingestion.flow_reader import ZeekLogReader
        from src.ingestion.models import TCPFlags
        log = self._write_conn_log(tmp_path)
        events = list(ZeekLogReader(log, log_type="conn").stream())
        tcp_events = [e for e in events if e.tcp_flags is not None]
        assert len(tcp_events) >= 1
        # ShADadfF -> SYN seen
        flags = TCPFlags.from_int(tcp_events[0].tcp_flags)
        assert bool(flags & TCPFlags.SYN)

    def test_conn_log_missing_fields_handled(self, tmp_path):
        """Row with '-' fields should not crash."""
        from src.ingestion.flow_reader import ZeekLogReader
        log = self._write_conn_log(tmp_path)
        events = list(ZeekLogReader(log, log_type="conn").stream())
        # Should not raise — just yield fewer events or None fields
        assert len(events) >= 1

    def test_dns_log_yields_events(self, tmp_path):
        from src.ingestion.flow_reader import ZeekLogReader
        log = self._write_dns_log(tmp_path)
        events = list(ZeekLogReader(log, log_type="dns").stream())
        assert len(events) >= 1

    def test_dns_log_query_name_extracted(self, tmp_path):
        from src.ingestion.flow_reader import ZeekLogReader
        log = self._write_dns_log(tmp_path)
        events = list(ZeekLogReader(log, log_type="dns").stream())
        dns_events = [e for e in events if e.dns and e.dns.query_name]
        assert any("example.com" in e.dns.query_name for e in dns_events)

    def test_dns_log_is_query_flag(self, tmp_path):
        from src.ingestion.flow_reader import ZeekLogReader
        log = self._write_dns_log(tmp_path)
        events = list(ZeekLogReader(log, log_type="dns").stream())
        is_query = [e for e in events if e.dns and e.dns.is_query is True]
        assert len(is_query) >= 1

    def test_ssl_log_yields_events(self, tmp_path):
        from src.ingestion.flow_reader import ZeekLogReader
        log = self._write_ssl_log(tmp_path)
        events = list(ZeekLogReader(log, log_type="ssl").stream())
        assert len(events) >= 1

    def test_ssl_log_sni_extracted(self, tmp_path):
        from src.ingestion.flow_reader import ZeekLogReader
        log = self._write_ssl_log(tmp_path)
        events = list(ZeekLogReader(log, log_type="ssl").stream())
        tls_events = [e for e in events if e.tls and e.tls.sni]
        assert any("example.com" in e.tls.sni for e in tls_events)

    def test_ingestion_source_zeek(self, tmp_path):
        from src.ingestion.flow_reader import ZeekLogReader
        log = self._write_conn_log(tmp_path)
        events = list(ZeekLogReader(log, log_type="conn").stream())
        assert all("zeek" in e.ingestion_source for e in events)

    def test_unsupported_log_type_raises(self, tmp_path):
        from src.ingestion.flow_reader import ZeekLogReader
        log = tmp_path / "http.log"
        log.write_text("#fields\tts\n1700000000.0\n")
        with pytest.raises(ValueError):
            ZeekLogReader(log, log_type="http")

    def test_nonexistent_log_raises(self):
        from src.ingestion.flow_reader import ZeekLogReader
        with pytest.raises(FileNotFoundError):
            ZeekLogReader("/nonexistent/conn.log", log_type="conn")


# ================================================================
# 5. StreamProcessor
# ================================================================

class TestStreamProcessor:
    """Test the event stream fan-out."""

    def _make_events(self, n: int):
        from src.ingestion.models import NetworkEvent
        return [
            NetworkEvent(
                timestamp=float(i),
                source_ip="1.2.3.4",
                destination_ip="5.6.7.8",
                source_port=1000 + i,
                destination_port=80,
                protocol=6,
            )
            for i in range(n)
        ]

    def test_processor_calls_handler(self):
        from src.ingestion.stream import StreamProcessor
        received = []
        events = self._make_events(5)
        proc = StreamProcessor(iter(events), handlers=[received.append])
        count = proc.run()
        assert count == 5
        assert len(received) == 5

    def test_multiple_handlers(self):
        from src.ingestion.stream import StreamProcessor
        bucket1, bucket2 = [], []
        events = self._make_events(3)
        proc = StreamProcessor(iter(events))
        proc.add_handler(bucket1.append)
        proc.add_handler(bucket2.append)
        proc.run()
        assert len(bucket1) == 3
        assert len(bucket2) == 3

    def test_handler_exception_does_not_stop_stream(self):
        from src.ingestion.stream import StreamProcessor

        def bad_handler(event):
            raise RuntimeError("intentional test error")

        received = []
        events = self._make_events(3)
        proc = StreamProcessor(
            iter(events),
            handlers=[bad_handler, received.append],
        )
        count = proc.run()
        assert count == 3
        assert len(received) == 3

    def test_as_generator_yields_events(self):
        from src.ingestion.stream import StreamProcessor
        events = self._make_events(4)
        proc = StreamProcessor(iter(events))
        result = list(proc.as_generator())
        assert len(result) == 4


# ================================================================
# 6. FlowRecord
# ================================================================

class TestFlowRecord:
    """Test FlowRecord creation and incremental updates."""

    def _make_event(
        self,
        src="192.168.1.1", dst="10.0.0.1",
        sport=54321, dport=80, proto=6,
        ts=1_700_000_000.0, pkt_len=100,
        flags=None,
    ):
        from src.ingestion.models import NetworkEvent
        return NetworkEvent(
            timestamp=ts,
            source_ip=src, destination_ip=dst,
            source_port=sport, destination_port=dport,
            protocol=proto,
            packet_length=pkt_len,
            tcp_flags=flags,
        )

    def test_flow_created_from_event(self):
        from src.flows.flow import FlowRecord
        e = self._make_event()
        flow = FlowRecord.from_event(e)
        assert flow.source_ip == "192.168.1.1"
        assert flow.packet_count == 1
        assert flow.byte_count == 100

    def test_flow_id_is_uuid(self):
        from src.flows.flow import FlowRecord
        import uuid
        e = self._make_event()
        flow = FlowRecord.from_event(e)
        uuid.UUID(flow.flow_id)  # should not raise

    def test_flow_update_increments_packets(self):
        from src.flows.flow import FlowRecord
        e1 = self._make_event(ts=1_700_000_000.0)
        e2 = self._make_event(ts=1_700_000_000.1)
        flow = FlowRecord.from_event(e1)
        flow.update(e2)
        assert flow.packet_count == 2

    def test_flow_update_accumulates_bytes(self):
        from src.flows.flow import FlowRecord
        e1 = self._make_event(pkt_len=100)
        e2 = self._make_event(ts=1_700_000_001.0, pkt_len=200)
        flow = FlowRecord.from_event(e1)
        flow.update(e2)
        assert flow.byte_count == 300

    def test_flow_duration_computed(self):
        from src.flows.flow import FlowRecord
        e1 = self._make_event(ts=1_700_000_000.0)
        e2 = self._make_event(ts=1_700_000_010.0)
        flow = FlowRecord.from_event(e1)
        flow.update(e2)
        assert flow.duration == pytest.approx(10.0, abs=0.001)

    def test_flow_iat_computed(self):
        from src.flows.flow import FlowRecord
        e1 = self._make_event(ts=1_700_000_000.0)
        e2 = self._make_event(ts=1_700_000_001.0)
        flow = FlowRecord.from_event(e1)
        flow.update(e2)
        assert len(flow.inter_arrival_times) == 1
        assert flow.inter_arrival_times[0] == pytest.approx(1.0, abs=0.001)

    def test_packet_sizes_stored(self):
        from src.flows.flow import FlowRecord
        e = self._make_event(pkt_len=150)
        flow = FlowRecord.from_event(e)
        assert 150 in flow.packet_sizes

    def test_mean_packet_size(self):
        from src.flows.flow import FlowRecord
        e1 = self._make_event(ts=1.0, pkt_len=100)
        e2 = self._make_event(ts=2.0, pkt_len=200)
        flow = FlowRecord.from_event(e1)
        flow.update(e2)
        assert flow.mean_packet_size == pytest.approx(150.0)

    def test_packets_per_second(self):
        from src.flows.flow import FlowRecord
        e1 = self._make_event(ts=0.0)
        e2 = self._make_event(ts=1.0)
        e3 = self._make_event(ts=2.0)
        flow = FlowRecord.from_event(e1)
        flow.update(e2)
        flow.update(e3)
        # 3 packets over 2 seconds = 1.5 pkt/s
        assert flow.packets_per_second == pytest.approx(1.5, abs=0.01)

    def test_tcp_flag_counts_syn(self):
        from src.flows.flow import FlowRecord
        e = self._make_event(flags=0x02)  # SYN
        flow = FlowRecord.from_event(e)
        assert flow.tcp_flags.syn == 1

    def test_tcp_flag_counts_syn_ack(self):
        from src.flows.flow import FlowRecord
        e = self._make_event(flags=0x12)  # SYN+ACK
        flow = FlowRecord.from_event(e)
        assert flow.tcp_flags.syn_ack == 1

    def test_tcp_fin_marks_completed(self):
        from src.flows.flow import FlowRecord
        e1 = self._make_event(ts=1.0, flags=0x02)
        e2 = self._make_event(ts=2.0, flags=0x01)  # FIN
        flow = FlowRecord.from_event(e1)
        assert not flow.completed
        flow.update(e2)
        assert flow.completed

    def test_tcp_rst_marks_completed(self):
        from src.flows.flow import FlowRecord
        e1 = self._make_event(ts=1.0, flags=0x02)
        e2 = self._make_event(ts=2.0, flags=0x04)  # RST
        flow = FlowRecord.from_event(e1)
        flow.update(e2)
        assert flow.completed

    def test_to_dict_serialisable(self):
        from src.flows.flow import FlowRecord
        import json
        e = self._make_event()
        flow = FlowRecord.from_event(e)
        d = flow.to_dict()
        # Should be JSON-serialisable
        json_str = json.dumps(d)
        assert "flow_id" in json_str

    def test_flow_id_str_contains_ips(self):
        from src.flows.flow import FlowRecord
        e = self._make_event()
        flow = FlowRecord.from_event(e)
        s = flow.flow_id_str
        assert "192.168.1.1" in s
        assert "10.0.0.1" in s


# ================================================================
# 7. FlowManager
# ================================================================

class TestFlowManager:
    """Test flow table operations."""

    def _make_event(self, src="192.168.1.1", dst="10.0.0.1",
                    sport=1234, dport=80, proto=6,
                    ts=1_700_000_000.0, flags=None):
        from src.ingestion.models import NetworkEvent
        return NetworkEvent(
            timestamp=ts,
            source_ip=src, destination_ip=dst,
            source_port=sport, destination_port=dport,
            protocol=proto, packet_length=100,
            tcp_flags=flags,
        )

    def test_new_event_creates_flow(self, flow_manager):
        e = self._make_event()
        flow_manager.process_event(e)
        assert flow_manager.active_count == 1

    def test_same_flow_events_merged(self, flow_manager):
        e1 = self._make_event(ts=1_700_000_000.0)
        e2 = self._make_event(ts=1_700_000_000.1)
        flow_manager.process_event(e1)
        flow_manager.process_event(e2)
        assert flow_manager.active_count == 1
        flow = next(flow_manager.active_flows())
        assert flow.packet_count == 2

    def test_different_flows_tracked_separately(self, flow_manager):
        e1 = self._make_event(sport=1111, dport=80)
        e2 = self._make_event(sport=2222, dport=443)
        flow_manager.process_event(e1)
        flow_manager.process_event(e2)
        assert flow_manager.active_count == 2

    def test_fin_closes_flow(self, flow_manager):
        completed = []
        flow_manager._on_complete = completed.append

        e1 = self._make_event(ts=1.0, flags=0x02)  # SYN
        e2 = self._make_event(ts=2.0, flags=0x01)  # FIN
        flow_manager.process_event(e1)
        flow_manager.process_event(e2)

        assert flow_manager.active_count == 0
        assert len(completed) == 1

    def test_rst_closes_flow(self, flow_manager):
        completed = []
        flow_manager._on_complete = completed.append

        e1 = self._make_event(ts=1.0, flags=0x02)
        e2 = self._make_event(ts=2.0, flags=0x04)  # RST
        flow_manager.process_event(e1)
        flow_manager.process_event(e2)

        assert len(completed) == 1

    def test_timeout_expires_idle_flow(self, flow_manager):
        """Flows idle past timeout should be expired on next sweep."""
        completed = []
        flow_manager._on_complete = completed.append

        e1 = self._make_event(ts=1_700_000_000.0)
        flow_manager.process_event(e1)
        assert flow_manager.active_count == 1

        # Force cleanup with a future timestamp beyond the 5s timeout
        expired = flow_manager._sweep_expired(current_time=1_700_000_000.0 + 10.0)
        assert expired == 1
        assert flow_manager.active_count == 0
        assert len(completed) == 1

    def test_flush_clears_all_flows(self, flow_manager):
        for i in range(5):
            e = self._make_event(sport=10000 + i)
            flow_manager.process_event(e)

        assert flow_manager.active_count == 5
        flushed = flow_manager.flush()
        assert flow_manager.active_count == 0
        assert len(flushed) == 5

    def test_total_flows_created_counter(self, flow_manager):
        for i in range(3):
            e = self._make_event(sport=20000 + i)
            flow_manager.process_event(e)
        assert flow_manager.total_flows_created == 3

    def test_summary_returns_dict(self, flow_manager):
        s = flow_manager.summary()
        assert isinstance(s, dict)
        assert "active_flows" in s
        assert "total_flows_created" in s


# ================================================================
# 8. Sessionizer (end-to-end)
# ================================================================

class TestSessionizer:
    """Test the complete PCAP -> NetworkEvent -> FlowRecord pipeline."""

    def _make_events(self, n=5, base_ts=1_700_000_000.0):
        from src.ingestion.models import NetworkEvent
        events = []
        # Create a single flow with n packets
        for i in range(n):
            events.append(NetworkEvent(
                timestamp=base_ts + i,
                source_ip="192.168.1.1",
                destination_ip="10.0.0.1",
                source_port=54321,
                destination_port=80,
                protocol=6,
                packet_length=100 + i,
                tcp_flags=0x02 if i == 0 else (0x01 if i == n - 1 else 0x10),
            ))
        return events

    def test_sessionizer_produces_flows(self):
        from src.flows.flow_manager import FlowManager
        from src.flows.sessionizer import Sessionizer

        manager = FlowManager(timeout_seconds=60.0, cleanup_interval_seconds=999.0)
        sess = Sessionizer(manager)
        events = self._make_events()
        flows = sess.process_all(events)
        assert len(flows) >= 1

    def test_completed_flow_has_correct_packet_count(self):
        from src.flows.flow_manager import FlowManager
        from src.flows.sessionizer import Sessionizer

        manager = FlowManager(timeout_seconds=60.0, cleanup_interval_seconds=999.0)
        sess = Sessionizer(manager)
        events = self._make_events(n=5)
        flows = sess.process_all(events)

        # The FIN in last packet should close the flow
        assert len(flows) >= 1
        total_packets = sum(f.packet_count for f in flows)
        assert total_packets == 5

    def test_end_to_end_with_pcap(self, synthetic_pcap):
        """Full pipeline: PCAP file -> events -> flows."""
        import warnings
        warnings.filterwarnings("ignore")

        from src.ingestion.pcap_reader import PcapReader
        from src.flows.flow_manager import FlowManager
        from src.flows.sessionizer import Sessionizer

        manager = FlowManager(timeout_seconds=60.0, cleanup_interval_seconds=999.0)
        sess = Sessionizer(manager)
        reader = PcapReader(synthetic_pcap)

        completed_flows = sess.process_all(reader.stream())

        # The synthetic PCAP has multiple flows
        assert len(completed_flows) >= 1

        # All completed flows should have packet counts > 0
        for flow in completed_flows:
            assert flow.packet_count >= 1
            assert flow.byte_count >= 0

    def test_incremental_flow_yields(self):
        """Flows should be yielded incrementally, not all at the end."""
        from src.flows.flow_manager import FlowManager
        from src.flows.sessionizer import Sessionizer
        from src.ingestion.models import NetworkEvent

        manager = FlowManager(timeout_seconds=60.0, cleanup_interval_seconds=999.0)
        sess = Sessionizer(manager)

        # Create two separate flows, each terminated with FIN
        events = [
            # Flow 1: SYN -> FIN
            NetworkEvent(timestamp=1.0, source_ip="1.1.1.1", destination_ip="2.2.2.2",
                         source_port=1000, destination_port=80, protocol=6,
                         packet_length=100, tcp_flags=0x02),
            NetworkEvent(timestamp=2.0, source_ip="1.1.1.1", destination_ip="2.2.2.2",
                         source_port=1000, destination_port=80, protocol=6,
                         packet_length=100, tcp_flags=0x01),  # FIN
            # Flow 2: SYN -> FIN
            NetworkEvent(timestamp=3.0, source_ip="3.3.3.3", destination_ip="4.4.4.4",
                         source_port=2000, destination_port=443, protocol=6,
                         packet_length=200, tcp_flags=0x02),
            NetworkEvent(timestamp=4.0, source_ip="3.3.3.3", destination_ip="4.4.4.4",
                         source_port=2000, destination_port=443, protocol=6,
                         packet_length=200, tcp_flags=0x01),  # FIN
        ]

        flow_gen = sess.process(iter(events), flush_at_end=False)
        received = list(flow_gen)

        # Both flows should be completed by FIN before flush
        assert len(received) == 2


# ================================================================
# 9. Passive-only compliance
# ================================================================

class TestPassiveOnlyCompliance:
    """
    Verify that the ingestion layer satisfies the passive-only constraints
    required by SIH 26145.
    """

    def test_pcap_reader_has_no_send_method(self):
        """PcapReader must not expose any packet-sending capability."""
        from src.ingestion.pcap_reader import PcapReader
        assert not hasattr(PcapReader, "send")
        assert not hasattr(PcapReader, "inject")
        assert not hasattr(PcapReader, "transmit")
        assert not hasattr(PcapReader, "probe")

    def test_network_event_has_no_payload(self):
        """NetworkEvent must not store raw payload bytes."""
        from src.ingestion.models import NetworkEvent
        e = NetworkEvent(timestamp=1.0)
        assert not hasattr(e, "payload_bytes")
        assert not hasattr(e, "raw_data")
        assert not hasattr(e, "content")

    def test_flow_manager_has_no_send_method(self):
        """FlowManager must not have any capability to send packets."""
        from src.flows.flow_manager import FlowManager
        mgr = FlowManager()
        assert not hasattr(mgr, "send")
        assert not hasattr(mgr, "inject")
        assert not hasattr(mgr, "probe")
        assert not hasattr(mgr, "respond")

    def test_flow_record_has_no_payload(self):
        """FlowRecord must not store payload bytes."""
        from src.flows.flow import FlowRecord
        from src.ingestion.models import NetworkEvent
        e = NetworkEvent(timestamp=1.0, source_ip="1.1.1.1",
                         destination_ip="2.2.2.2", source_port=1000,
                         destination_port=80, protocol=6, packet_length=100)
        flow = FlowRecord.from_event(e)
        assert not hasattr(flow, "payload_bytes")
        assert not hasattr(flow, "raw_payload")
        assert not hasattr(flow, "content")

    def test_pcap_reader_is_read_only(self, synthetic_pcap):
        """Reading a PCAP should not modify the file."""
        import os
        mtime_before = os.path.getmtime(synthetic_pcap)
        from src.ingestion.pcap_reader import PcapReader
        list(PcapReader(synthetic_pcap).stream())
        mtime_after = os.path.getmtime(synthetic_pcap)
        assert mtime_before == mtime_after
