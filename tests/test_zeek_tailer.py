import os
import json
import time
import pytest
import threading
from pathlib import Path
from src.ingestion.zeek_reader import ZeekLogReader, ZeekFileTailer
from src.ingestion.models import NetworkEvent

@pytest.fixture
def zeek_log_dir(tmp_path):
    conn_log = tmp_path / "conn.log"
    dns_log = tmp_path / "dns.log"
    ssl_log = tmp_path / "ssl.log"
    
    # Touch files so they exist
    conn_log.touch()
    dns_log.touch()
    ssl_log.touch()
    
    return tmp_path

def test_single_tailer_basic(zeek_log_dir):
    """TEST 1: single conn.log tailing"""
    import queue
    q = queue.Queue()
    stop_event = threading.Event()
    
    conn_log = zeek_log_dir / "conn.log"
    tailer = ZeekFileTailer(conn_log, "conn", q, stop_event)
    tailer.start()
    
    with open(conn_log, "a") as f:
        f.write('{"ts": 100.0, "uid": "C1", "id.orig_h": "1.1.1.1", "id.resp_h": "2.2.2.2", "id.orig_p": 1234, "id.resp_p": 80, "proto": "tcp", "duration": 1.0}\n')
        f.flush()
        
    try:
        event = q.get(timeout=2.0)
        assert event.timestamp == 100.0
        assert event.source_ip == "1.1.1.1"
        assert event.ingestion_source == "zeek_conn"
        assert event.is_aggregated == True
    finally:
        stop_event.set()
        tailer.thread.join(timeout=1.0)

def test_missing_timestamp_and_malformed(zeek_log_dir):
    """TEST 8, 9: missing timestamp, malformed record"""
    import queue
    q = queue.Queue()
    stop_event = threading.Event()
    
    conn_log = zeek_log_dir / "conn.log"
    tailer = ZeekFileTailer(conn_log, "conn", q, stop_event)
    tailer.start()
    
    with open(conn_log, "a") as f:
        # Malformed
        f.write('{"ts": 100.0, "uid": \n')
        # Missing TS (will use time.time() internally, but lets just check it doesn't crash)
        f.write('{"uid": "C2", "id.orig_h": "1.1.1.1", "id.resp_h": "2.2.2.2", "id.orig_p": 1234, "id.resp_p": 80, "proto": "tcp"}\n')
        f.flush()
        
    try:
        event = q.get(timeout=2.0)
        assert event.source_ip == "1.1.1.1"
    finally:
        stop_event.set()
        tailer.thread.join(timeout=1.0)

@pytest.mark.skipif(os.name == 'nt', reason="Windows file locking prevents rename")
def test_file_rotation(zeek_log_dir):
    """TEST 14: log rotation"""
    import queue
    q = queue.Queue()
    stop_event = threading.Event()
    
    conn_log = zeek_log_dir / "conn.log"
    tailer = ZeekFileTailer(conn_log, "conn", q, stop_event)
    tailer.start()
    
    with open(conn_log, "a") as f:
        f.write('{"ts": 100.0, "uid": "C1", "id.orig_h": "1.1.1.1", "id.resp_h": "2.2.2.2", "id.orig_p": 1234, "id.resp_p": 80, "proto": "tcp"}\n')
        f.flush()
        
    event = q.get(timeout=2.0)
    assert event.timestamp == 100.0
    
    # Rotate file
    os.rename(conn_log, zeek_log_dir / "conn.log.old")
    with open(conn_log, "w") as f:
        f.write('{"ts": 101.0, "uid": "C2", "id.orig_h": "3.3.3.3", "id.resp_h": "4.4.4.4", "id.orig_p": 1234, "id.resp_p": 80, "proto": "tcp"}\n')
        f.flush()
        
    try:
        event2 = q.get(timeout=5.0)
        assert event2.timestamp == 101.0
        assert event2.source_ip == "3.3.3.3"
    finally:
        stop_event.set()
        tailer.thread.join(timeout=1.0)

def test_merger_timestamp_ordering(zeek_log_dir):
    """TEST 4, 5, 6, 7: concurrent tailing, timestamp ordering, out-of-order, identical timestamps"""
    # Overwrite max_lateness to a small value for testing
    import src.ingestion.zeek_reader as zr
    
    reader = ZeekLogReader(str(zeek_log_dir))
    reader.max_lateness = 1.0 # 1 second window
    
    def writer_thread():
        time.sleep(0.1) # Let tailers start
        conn = open(zeek_log_dir / "conn.log", "a")
        dns = open(zeek_log_dir / "dns.log", "a")
        ssl = open(zeek_log_dir / "ssl.log", "a")
        
        # Write out of order physically
        # Event 3 (ts 102)
        ssl.write('{"ts": 102.0, "id.orig_h": "1", "id.resp_h": "2", "id.orig_p": 1, "id.resp_p": 2, "proto": "tcp", "version": "TLS 1.2"}\n')
        ssl.flush()
        
        # Event 1 (ts 100)
        conn.write('{"ts": 100.0, "id.orig_h": "1", "id.resp_h": "2", "id.orig_p": 1, "id.resp_p": 2, "proto": "tcp"}\n')
        conn.flush()
        
        # Event 2 (ts 101) - Identical TS for another event
        dns.write('{"ts": 101.0, "id.orig_h": "1", "id.resp_h": "2", "id.orig_p": 1, "id.resp_p": 2, "proto": "udp", "query": "a.com"}\n')
        dns.write('{"ts": 101.0, "id.orig_h": "1", "id.resp_h": "2", "id.orig_p": 1, "id.resp_p": 2, "proto": "udp", "query": "b.com"}\n')
        dns.flush()
        
        # Advance watermark with a highly delayed event (ts 105)
        # 105 - 1.0 = watermark 104. So events 100, 101, 102 should flush.
        conn.write('{"ts": 105.0, "id.orig_h": "1", "id.resp_h": "2", "id.orig_p": 1, "id.resp_p": 2, "proto": "tcp"}\n')
        conn.flush()
        
        # Advance further to flush 105
        time.sleep(0.2)
        conn.write('{"ts": 110.0, "id.orig_h": "1", "id.resp_h": "2", "id.orig_p": 1, "id.resp_p": 2, "proto": "tcp"}\n')
        conn.flush()

    t = threading.Thread(target=writer_thread)
    t.start()
    
    stream = reader.stream()
    
    try:
        e1 = next(stream)
        assert e1.timestamp == 100.0
        
        e2 = next(stream)
        assert e2.timestamp == 101.0
        assert e2.dns.query_name == "a.com"
        
        e3 = next(stream)
        assert e3.timestamp == 101.0
        assert e3.dns.query_name == "b.com"
        
        e4 = next(stream)
        assert e4.timestamp == 102.0
        
        e5 = next(stream)
        assert e5.timestamp == 105.0
        
    finally:
        reader.stop()
        t.join()

def test_late_event_emission(zeek_log_dir):
    """TEST 6: late events are emitted with a metric bump"""
    reader = ZeekLogReader(str(zeek_log_dir))
    reader.max_lateness = 1.0
    
    def writer_thread():
        time.sleep(0.1)
        conn = open(zeek_log_dir / "conn.log", "a")
        # Event at 100
        conn.write('{"ts": 100.0, "id.orig_h": "1", "id.resp_h": "2", "id.orig_p": 1, "id.resp_p": 2, "proto": "tcp"}\n')
        # Advance watermark to 109 (watermark = 108)
        conn.write('{"ts": 109.0, "id.orig_h": "1", "id.resp_h": "2", "id.orig_p": 1, "id.resp_p": 2, "proto": "tcp"}\n')
        conn.flush()
        
        time.sleep(1.0) # Let watermark advance AND overcome the 0.5s startup buffer in stream()
        
        # Late event arriving at ts 99 (watermark is 108)
        conn.write('{"ts": 99.0, "id.orig_h": "1", "id.resp_h": "2", "id.orig_p": 1, "id.resp_p": 2, "proto": "tcp"}\n')
        # Push something to flush the late event out if it was queued (it isn't, it emits immediately)
        conn.write('{"ts": 115.0, "id.orig_h": "1", "id.resp_h": "2", "id.orig_p": 1, "id.resp_p": 2, "proto": "tcp"}\n')
        conn.flush()

    t = threading.Thread(target=writer_thread)
    t.start()
    
    stream = reader.stream()
    try:
        e1 = next(stream)
        assert e1.timestamp == 100.0
        
        e2 = next(stream)
        assert e2.timestamp == 99.0
        
        e3 = next(stream)
        assert e3.timestamp == 109.0
        
        # Check metric
        assert reader.late_events_dropped == 1
    finally:
        reader.stop()
        t.join()
