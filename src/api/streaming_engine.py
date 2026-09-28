"""
UniShield AI — Streaming Engine
=================================
Orchestrates incremental real-time processing of FeatureVectors.
Features a bounded queue to handle backpressure and simulates
sustained incoming data rates.

Threads:
1. Ingest Thread: Reads JSONL at a specified flows/sec rate, pushes to Queue.
2. Worker Thread: Pulls from Queue, runs detectors/correlation.
"""

from __future__ import annotations

import time
import queue
import threading
from typing import Dict, List, Any

from src.ingestion.jsonl_reader import JsonlReader
from src.features.feature_vector import FeatureVector
from src.detectors.ddos import DDoSDetector
from src.detectors.c2_beacon import C2BeaconDetector
from src.detectors.dga_dns import DGADetector, DNSTunnelDetector
from src.detectors.dns_tracker import DNSTracker
from src.detectors.encrypted import EncryptedSessionDetector
from src.detectors.recon import ReconDetector
from src.detectors.exfiltration import ExfiltrationDetector
from src.correlation.correlation_engine import CorrelationEngine
from src.risk.risk_engine import RiskEngine
from src.utils.logging import get_logger

logger = get_logger(__name__)

class StreamingEngine:
    def __init__(self, queue_size: int = 5000):
        self.queue = queue.Queue(maxsize=queue_size)
        self.is_running = False
        
        self.detectors = [
            DDoSDetector(),
            C2BeaconDetector(),
            DGADetector(),
            DNSTunnelDetector(tracker=DNSTracker()),
            EncryptedSessionDetector(),
            ReconDetector(),
            ExfiltrationDetector()
        ]
        self.correlation_engine = CorrelationEngine()
        self.risk_engine = RiskEngine()
        
        self.metrics = {
            "received": 0,
            "processed": 0,
            "dropped": 0,
            "alerts": 0,
            "incidents": 0,
            "latency_ms_sum": 0.0,
            "latency_samples": 0
        }

    def _ingest_worker(self, file_path: str, flows_per_sec: int, max_records: int = None):
        reader = JsonlReader(file_path, max_records=max_records)
        
        sleep_interval = 1.0 / flows_per_sec if flows_per_sec > 0 else 0
        
        for fv in reader.stream():
            if not self.is_running:
                break
                
            self.metrics["received"] += 1
            
            # Attach an ingest timestamp to measure true system latency
            fv_wrapper = {
                "fv": fv,
                "ingest_time": time.time()
            }
            
            try:
                self.queue.put_nowait(fv_wrapper)
            except queue.Full:
                self.metrics["dropped"] += 1
                
            if sleep_interval > 0:
                time.sleep(sleep_interval)
                
        # Signal completion
        self.queue.put(None)

    def _process_worker(self):
        while self.is_running:
            try:
                item = self.queue.get(timeout=1.0)
            except queue.Empty:
                continue
                
            if item is None:
                self.queue.task_done()
                break
                
            fv: FeatureVector = item["fv"]
            ingest_time: float = item["ingest_time"]
            
            # Detect
            start_detect = time.time()
            for detector in self.detectors:
                result = detector.detect(fv)
                if result and result.is_alert():
                    self.metrics["alerts"] += 1
                    inc = self.correlation_engine.correlate_alert(result)
                    if inc:
                        self.risk_engine.update_risk(inc)
                        self.metrics["incidents"] = len(self.correlation_engine.active_incidents)
                        
            end_detect = time.time()
            
            # End-to-End Latency = current time - ingest time
            latency_ms = (end_detect - ingest_time) * 1000
            self.metrics["latency_ms_sum"] += latency_ms
            self.metrics["latency_samples"] += 1
            self.metrics["processed"] += 1
            
            self.queue.task_done()

    def run(self, file_path: str, flows_per_sec: int, max_records: int = None):
        self.is_running = True
        
        ingest_thread = threading.Thread(
            target=self._ingest_worker, 
            args=(file_path, flows_per_sec, max_records),
            daemon=True
        )
        process_thread = threading.Thread(
            target=self._process_worker,
            daemon=True
        )
        
        start_time = time.time()
        
        process_thread.start()
        ingest_thread.start()
        
        ingest_thread.join()
        
        # Wait up to 5 seconds for queue to drain
        drain_start = time.time()
        while not self.queue.empty() and time.time() - drain_start < 5.0:
            time.sleep(0.1)
            
        self.is_running = False
        process_thread.join(timeout=2.0)
        
        elapsed = time.time() - start_time
        
        return {
            "elapsed_seconds": elapsed,
            "metrics": self.metrics
        }
