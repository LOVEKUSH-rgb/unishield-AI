"""
UniShield AI -- Zeek Ingestion Tests
====================================
Verifies that Zeek JSON logs are parsed correctly, missing fields are handled,
and that the ingestion pipeline gracefully maps into the existing canonical events.
"""

import pytest
import os
import tempfile
import json
from src.ingestion.zeek_reader import ZeekLogReader
from src.ingestion.models import Protocol

@pytest.fixture
def mock_zeek_dir():
    with tempfile.TemporaryDirectory() as d:
        conn_log = os.path.join(d, "conn.log")
        dns_log = os.path.join(d, "dns.log")
        ssl_log = os.path.join(d, "ssl.log")
        
        with open(conn_log, "w") as f:
            f.write(json.dumps({
                "ts": 1610000000.0,
                "uid": "Cu123",
                "id.orig_h": "192.168.1.10",
                "id.orig_p": 44321,
                "id.resp_h": "8.8.8.8",
                "id.resp_p": 443,
                "proto": "tcp",
                "duration": 5.0,
                "orig_bytes": 1000,
                "resp_bytes": 5000,
                "orig_pkts": 10,
                "resp_pkts": 15
            }) + "\n")
            # Malformed JSON
            f.write("{malformed\n")
            
        with open(dns_log, "w") as f:
            f.write(json.dumps({
                "ts": 1610000000.1,
                "uid": "Cu124",
                "id.orig_h": "192.168.1.10",
                "id.orig_p": 5353,
                "id.resp_h": "1.1.1.1",
                "id.resp_p": 53,
                "proto": "udp",
                "query": "malicious.com",
                "qtype_name": "A",
                "rcode_name": "NOERROR"
            }) + "\n")
            
        with open(ssl_log, "w") as f:
            f.write(json.dumps({
                "ts": 1610000000.2,
                "uid": "Cu123", # Matches conn.log
                "id.orig_h": "192.168.1.10",
                "id.orig_p": 44321,
                "id.resp_h": "8.8.8.8",
                "id.resp_p": 443,
                "proto": "tcp",
                "version": "TLSv1.2",
                "cipher": "TLS_AES_128_GCM_SHA256",
                "server_name": "google.com",
                "ja3": "abc123hash"
            }) + "\n")
            
        yield d


def test_conn_log_parsing(mock_zeek_dir):
    reader = ZeekLogReader(mock_zeek_dir)
    events = list(reader.stream_file("conn.log"))
    
    # Should yield 1 valid event, ignoring the malformed line
    assert len(events) == 1
    ev = events[0]
    
    assert ev.is_aggregated is True
    assert ev.source_ip == "192.168.1.10"
    assert ev.protocol == Protocol.TCP
    assert ev.aggregated_duration == 5.0
    assert ev.aggregated_packet_count == 25
    assert ev.aggregated_byte_count == 6000
    assert ev.zeek_uid == "Cu123"
    reader.stop()

def test_dns_log_parsing(mock_zeek_dir):
    reader = ZeekLogReader(mock_zeek_dir)
    events = list(reader.stream_file("dns.log"))
    
    assert len(events) == 1
    ev = events[0]
    
    assert ev.is_aggregated is False # dns is just metadata
    assert ev.dns is not None
    assert ev.dns.query_name == "malicious.com"
    assert ev.dns.response_code == "NOERROR"
    assert ev.zeek_uid == "Cu124"
    reader.stop()

def test_ssl_log_parsing(mock_zeek_dir):
    reader = ZeekLogReader(mock_zeek_dir)
    events = list(reader.stream_file("ssl.log"))
    
    assert len(events) == 1
    ev = events[0]
    
    assert ev.is_aggregated is False
    assert ev.tls is not None
    assert ev.tls.version == "TLSv1.2"
    assert ev.tls.sni == "google.com"
    assert ev.tls.ja3_fingerprint == "abc123hash"
    assert ev.zeek_uid == "Cu123"
    reader.stop()

def test_flow_record_aggregation():
    # Test that FlowRecord natively inherits the Zeek aggregation
    from src.flows.flow import FlowRecord
    from src.ingestion.models import NetworkEvent
    
    ev = NetworkEvent(
        timestamp=100.0,
        source_ip="10.0.0.1",
        destination_ip="8.8.8.8",
        is_aggregated=True,
        aggregated_duration=10.0,
        aggregated_packet_count=50,
        aggregated_byte_count=5000
    )
    
    flow = FlowRecord.from_event(ev)
    
    assert flow.packet_count == 50
    assert flow.byte_count == 5000
    assert flow.completed is True
    assert flow.start_time == 100.0
    assert flow.last_seen == 110.0
    assert flow.duration == 10.0
