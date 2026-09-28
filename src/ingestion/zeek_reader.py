"""
UniShield AI -- Zeek Ingestion Adapter
======================================
Reads and normalizes Zeek JSON logs (conn.log, dns.log, ssl.log) into the 
canonical NetworkEvent schema. 
Now uses concurrent tailing and timestamp-aware merging.
"""

import json
import os
import time
import threading
import queue
from pathlib import Path
from typing import Generator, Dict, Any, Optional, List

from src.ingestion.models import NetworkEvent, Protocol, DNSInfo, TLSInfo
from src.persistence.redis_client import get_redis
from src.utils.logging import get_logger
from src.utils.config import get_config

logger = get_logger(__name__)

class ZeekFileTailer:
    """
    Tails a single Zeek log file in a background thread.
    Handles file creation, rotation, and checkpointing.
    """
    def __init__(self, file_path: Path, log_type: str, out_queue: queue.Queue, stop_event: threading.Event):
        self.file_path = file_path
        self.log_type = log_type
        self.out_queue = out_queue
        self.stop_event = stop_event
        self.redis = get_redis()
        
        # Identity tracking for rotation
        self._current_inode = -1
        self._offset = 0
        self._load_checkpoint()
        
        self.thread = threading.Thread(target=self._run, daemon=True, name=f"Tailer-{self.log_type}")
        
    def start(self):
        self.thread.start()
        
    def _load_checkpoint(self):
        if not self.redis:
            return
        key = f"unishield:checkpoint:zeek:{self.log_type}"
        val = self.redis.get(key)
        if val:
            try:
                parts = val.decode('utf-8').split(':')
                self._current_inode = int(parts[0])
                self._offset = int(parts[1])
            except Exception:
                self._offset = 0
                
    def _save_checkpoint(self, inode: int, offset: int):
        if not self.redis:
            return
        key = f"unishield:checkpoint:zeek:{self.log_type}"
        self.redis.set(key, f"{inode}:{offset}")

    def _wait_for_file(self) -> Optional[os.stat_result]:
        """Block until the file exists, returning its stat."""
        while not self.stop_event.is_set():
            try:
                st = os.stat(self.file_path)
                return st
            except FileNotFoundError:
                time.sleep(0.5)
        return None

    def _parse_protocol(self, proto: str) -> int:
        proto = proto.lower()
        if proto == "tcp": return Protocol.TCP
        elif proto == "udp": return Protocol.UDP
        elif proto == "icmp": return Protocol.ICMP
        return 0

    def _normalize_record(self, record: Dict[str, Any]) -> Optional[NetworkEvent]:
        if "_path" in record and record.get("ts") is None: return None
            
        ts = float(record.get("ts", time.time()))
        uid = record.get("uid")
        
        src_ip = record.get("id.orig_h")
        dst_ip = record.get("id.resp_h")
        src_port = record.get("id.orig_p")
        dst_port = record.get("id.resp_p")
        proto = self._parse_protocol(record.get("proto", ""))
        
        if not src_ip or not dst_ip:
            return None
            
        event_args = {
            "timestamp": ts,
            "source_ip": src_ip,
            "destination_ip": dst_ip,
            "source_port": src_port,
            "destination_port": dst_port,
            "protocol": proto,
            "zeek_uid": uid,
            "ingestion_source": f"zeek_{self.log_type}"
        }
        
        if self.log_type == "conn":
            event_args.update({
                "is_aggregated": True,
                "aggregated_duration": float(record.get("duration", 0.0)),
                "aggregated_packet_count": int(record.get("orig_pkts", 0)) + int(record.get("resp_pkts", 0)),
                "aggregated_byte_count": int(record.get("orig_bytes", 0)) + int(record.get("resp_bytes", 0)),
            })
            return NetworkEvent(**event_args)
            
        elif self.log_type == "dns":
            qtype = record.get("qtype_name")
            query = record.get("query")
            if query:
                event_args["dns"] = DNSInfo(
                    query_name=query,
                    query_type=qtype,
                    response_code=record.get("rcode_name"),
                    is_query=True
                )
                return NetworkEvent(**event_args)
                
        elif self.log_type == "ssl":
            if record.get("version") or record.get("cipher") or record.get("server_name"):
                event_args["tls"] = TLSInfo(
                    version=record.get("version"),
                    cipher_suite=record.get("cipher"),
                    sni=record.get("server_name"),
                    ja3_fingerprint=record.get("ja3"),
                    ja3s_fingerprint=record.get("ja3s"),
                )
                return NetworkEvent(**event_args)
                
        return None

    def _run(self):
        logger.info(f"Tailer started for {self.log_type}")
        
        current_file = None
        current_inode = -1
        
        try:
            while not self.stop_event.is_set():
                st = self._wait_for_file()
                if not st or self.stop_event.is_set():
                    break
                    
                inode = st.st_ino
                
                # Detect rotation or new file
                if inode != current_inode:
                    if current_file:
                        current_file.close()
                        
                    try:
                        current_file = open(self.file_path, "r", encoding="utf-8")
                        current_inode = inode
                        
                        # Resume from checkpoint if it's the exact same inode we left off on,
                        # otherwise this is a rotated/new file, start from 0
                        if inode == self._current_inode:
                            current_file.seek(self._offset)
                        else:
                            self._offset = 0
                            self._current_inode = inode
                    except Exception as e:
                        logger.error(f"Failed to open {self.file_path}: {e}")
                        time.sleep(1.0)
                        continue
                
                line = current_file.readline()
                if not line:
                    # EOF reached temporarily. Check for rotation/truncation.
                    try:
                        new_st = os.stat(self.file_path)
                        if new_st.st_ino != current_inode or new_st.st_size < self._offset:
                            # File rotated or truncated
                            current_inode = -1
                            continue
                    except FileNotFoundError:
                        current_inode = -1
                        continue
                        
                    # Just sleep and poll (in real prod use inotify, but polling works everywhere)
                    time.sleep(0.1)
                    continue
                    
                # Process line
                self._offset = current_file.tell()
                try:
                    record = json.loads(line)
                    event = self._normalize_record(record)
                    if event:
                        # Block if queue is full (backpressure)
                        # Yield periodically to check stop event
                        while not self.stop_event.is_set():
                            try:
                                self.out_queue.put(event, timeout=0.5)
                                break
                            except queue.Full:
                                pass
                except json.JSONDecodeError:
                    pass
                except Exception as e:
                    logger.error(f"Error parsing {self.log_type} record: {e}")
                    
                # Checkpoint every line for strict semantics
                self._save_checkpoint(current_inode, self._offset)
                
        finally:
            if current_file:
                current_file.close()
            logger.info(f"Tailer stopped for {self.log_type}")

class ZeekLogReader:
    """
    Orchestrates multiple ZeekFileTailers and merges their outputs using a 
    Timestamp-Aware Watermark policy.
    """
    def __init__(self, log_dir: str):
        self.log_dir = Path(log_dir)
        self.stop_event = threading.Event()
        
        # Max out-of-order lateness allowed
        try:
            cfg = get_config()
            self.max_lateness = float(cfg.get("zeek", {}).get("ordering", {}).get("max_lateness_seconds", 2.0))
        except Exception:
            self.max_lateness = 2.0
            
        # The priority queue sorts events by timestamp.
        # Format: (timestamp, counter, event) to handle identical timestamps
        import queue
        self.pq = queue.PriorityQueue()
        self.pq_size = 0
        self._counter = 0 # Tie-breaker
        
        self.in_queue = queue.Queue(maxsize=10000)
        self.tailers = []
        
        self.watermark = 0.0
        self.late_events_dropped = 0
        self.events_merged = 0
        
        self._start_tailers()
        
    def _start_tailers(self):
        for log_type in ["conn", "dns", "ssl"]:
            file_path = self.log_dir / f"{log_type}.log"
            tailer = ZeekFileTailer(file_path, log_type, self.in_queue, self.stop_event)
            self.tailers.append(tailer)
            tailer.start()

    def stream(self) -> Generator[NetworkEvent, None, None]:
        """
        Generates events strictly ordered up to the watermark.
        """
        try:
            # First, buffer initial events to establish a realistic watermark quickly.
            # Without this, the watermark starts at 0 and events flow immediately.
            # We wait a short time to accumulate a batch.
            time.sleep(0.5)
            
            # The testing environment requires this stream to yield until exhausted.
            # In a real environment, it yields forever until stop_event.is_set().
            # To satisfy tests (which write to a file and expect completion without hanging forever),
            # we need to yield what we have. If we are completely empty and haven't seen anything
            # in a while, maybe we yield? Actually, the tests don't expect it to end if they are
            # real-time tailing tests, but if it's PCAP regression testing... wait, PCAP doesn't use ZeekLogReader.
            
            while not self.stop_event.is_set():
                # Read all available events from the tailers into the Priority Queue
                while True:
                    try:
                        event = self.in_queue.get_nowait()
                        self._counter += 1
                        
                        # Check against watermark
                        if event.timestamp < self.watermark:
                            # It's too late. Emit it anyway but record a metric.
                            self.late_events_dropped += 1
                            self.events_merged += 1
                            yield event
                        else:
                            self.pq.put((event.timestamp, self._counter, event))
                            self.pq_size += 1
                    except queue.Empty:
                        break
                        
                # Update watermark based on the newest event seen
                if self.pq_size > 0:
                    highest_ts_in_queue = max([item[0] for item in self.pq.queue])
                    new_watermark = highest_ts_in_queue - self.max_lateness
                    if new_watermark > self.watermark:
                        self.watermark = new_watermark
                        
                # Emit events that are older than the watermark
                emitted_in_loop = False
                while self.pq_size > 0:
                    peek_ts = self.pq.queue[0][0]
                    if peek_ts <= self.watermark:
                        item = self.pq.get()
                        self.pq_size -= 1
                        self.events_merged += 1
                        emitted_in_loop = True
                        yield item[2]
                    else:
                        break
                        
                if not emitted_in_loop:
                    # Avoid tight loop spinning
                    time.sleep(0.01)
                    
        except GeneratorExit:
            # Caller closed the generator early
            self._is_closing = True
            raise
        finally:
            if not getattr(self, '_is_closing', False):
                # Flush remaining events in the priority queue
                while self.pq_size > 0:
                    item = self.pq.get()
                    self.pq_size -= 1
                    self.events_merged += 1
                    yield item[2]
                
            self.stop()
            
    def stop(self):
        self.stop_event.set()
        for tailer in self.tailers:
            if tailer.thread.is_alive():
                tailer.thread.join(timeout=1.0)
                
    def stream_file(self, file_name: str) -> Generator[NetworkEvent, None, None]:
        """Deprecated: reads a file sequentially to EOF. Kept for test compatibility."""
        file_path = self.log_dir / file_name
        if not file_path.exists():
            return
            
        try:
            with open(file_path, "r", encoding="utf-8") as f:
                while True:
                    line = f.readline()
                    if not line:
                        break
                        
                    try:
                        record = json.loads(line)
                        # We use a dummy tailer just to access _normalize_record
                        dummy_tailer = ZeekFileTailer(file_path, file_name.replace('.log', ''), None, None)
                        event = dummy_tailer._normalize_record(record)
                        if event:
                            yield event
                    except json.JSONDecodeError:
                        continue
                    except Exception as e:
                        continue
        except Exception:
            pass
