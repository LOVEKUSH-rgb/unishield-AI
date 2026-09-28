"""
UniShield AI -- Replay Manager
==============================
Coordinates reading PCAP files, pushing through the ML/heuristic pipeline,
and maintaining a globally accessible state for the API and Dashboard.
"""
import time
import threading
from typing import Dict, List, Any
from pathlib import Path

from src.ingestion.pcap_reader import PcapReader
from src.ingestion.zeek_reader import ZeekLogReader
from src.flows.sessionizer import Sessionizer
from src.flows.flow_manager import FlowManager
from src.features.feature_pipeline import FeaturePipeline
from src.detectors.ddos import DDoSDetector
from src.detectors.c2_beacon import C2BeaconDetector
from src.detectors.dga_dns import DGADetector, DNSTunnelDetector
from src.detectors.dns_tracker import DNSTracker
from src.detectors.encrypted import EncryptedSessionDetector
from src.detectors.recon import ReconDetector
from src.detectors.exfiltration import ExfiltrationDetector

from src.correlation.correlation_engine import CorrelationEngine
from src.risk.risk_engine import RiskEngine

from src.persistence.state_manager import StateManager
from src.persistence.database import SessionLocal
from src.persistence.repositories import AlertRepository, IncidentRepository
from src.utils.logging import get_logger

logger = get_logger(__name__)

class IngestionManager:
    def __init__(self):
        self.state_mgr = StateManager()
        
        self.pipeline_lock = threading.RLock()
        self._play_thread = None
        self._stop_event = threading.Event()
        self._pause_event = threading.Event()
        self._pause_event.set()
        
        self.feature_extractor = FeaturePipeline()
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
        self.latency_history = []

    def load_pcap(self, pcap_path: str):
        with self.pipeline_lock:
            self.reset()
            state = self.state_mgr.get_state()
            state["current_pcap"] = pcap_path
            state["ingestion_mode"] = "pcap"
            self.state_mgr.set_state(state)
            
    def load_zeek(self, log_dir: str):
        with self.pipeline_lock:
            self.reset()
            state = self.state_mgr.get_state()
            state["current_zeek_dir"] = log_dir
            state["ingestion_mode"] = "zeek"
            self.state_mgr.set_state(state)
            
    def play(self):
        state = self.state_mgr.get_state()
        if state["status"] == "PLAYING":
            return
            
        if state["status"] == "PAUSED":
            state["status"] = "PLAYING"
            self.state_mgr.set_state(state)
            self._pause_event.set()
            return
            
        state["status"] = "PLAYING"
        self.state_mgr.set_state(state)
        
        self._stop_event.clear()
        self._pause_event.set()
        
        self._play_thread = threading.Thread(target=self._run_pipeline, daemon=True)
        self._play_thread.start()
        
    def pause(self):
        state = self.state_mgr.get_state()
        if state["status"] == "PLAYING":
            state["status"] = "PAUSED"
            self.state_mgr.set_state(state)
            self._pause_event.clear()
            
    def stop(self):
        state = self.state_mgr.get_state()
        state["status"] = "STOPPED"
        self.state_mgr.set_state(state)
        self._stop_event.set()
        self._pause_event.set()
        if getattr(self, 'zeek_reader', None):
            self.zeek_reader.stop()
        if self._play_thread:
            self._play_thread.join(timeout=1.0)
            
    def reset(self):
        self.stop()
        with self.pipeline_lock:
            self.state_mgr.reset()
            self.latency_history.clear()
                
            self.feature_extractor = FeaturePipeline()
            self.correlation_engine = CorrelationEngine()
            self.risk_engine = RiskEngine()
            
    def set_speed(self, speed: float):
        state = self.state_mgr.get_state()
        state["speed"] = speed
        self.state_mgr.set_state(state)

    def _run_pipeline(self):
        import queue
        state = self.state_mgr.get_state()
        ingestion_mode = state.get("ingestion_mode", "pcap")
        
        zeek = None
        if ingestion_mode == "pcap":
            if not state.get("current_pcap") or not Path(state["current_pcap"]).exists():
                state["status"] = "STOPPED"
                self.state_mgr.set_state(state)
                return
            reader_stream = PcapReader(state["current_pcap"]).stream()
        elif ingestion_mode == "zeek":
            if not state.get("current_zeek_dir") or not Path(state["current_zeek_dir"]).exists():
                state["status"] = "STOPPED"
                self.state_mgr.set_state(state)
                return
            
            # Use the new concurrent tailer and timestamp merger
            self.zeek_reader = ZeekLogReader(state["current_zeek_dir"])
            reader_stream = self.zeek_reader.stream()
        else:
            self.zeek_reader = None
            
        sessionizer = Sessionizer(FlowManager())
        last_packet_time = None
        
        # Bounded queue for backpressure
        event_queue = queue.Queue(maxsize=1000)
        
        def _producer():
            from src.utils.prometheus_metrics import INGESTION_EVENTS_TOTAL, INGESTION_QUEUE_DEPTH, INGESTION_DROPPED_TOTAL
            for ev in reader_stream:
                # Allow the generator to yield its flushed events on stop.
                # If it's an infinite stream, the generator itself should break.
                
                INGESTION_EVENTS_TOTAL.labels(source_type=ingestion_mode).inc()
                
                try:
                    event_queue.put(ev, timeout=0.1) # Blocks if queue is full
                    INGESTION_QUEUE_DEPTH.labels(queue_name="event_queue").set(event_queue.qsize())
                except queue.Full:
                    INGESTION_DROPPED_TOTAL.labels(queue_name="event_queue").inc()
                    logger.warning("Ingestion queue full, dropping event")
                    
            event_queue.put(None) # EOF
            if getattr(self, 'zeek_reader', None):
                self.zeek_reader.stop()
            
        prod_thread = threading.Thread(target=_producer, daemon=True)
        prod_thread.start()
        
        db = SessionLocal() if SessionLocal else None
        if not db:
            logger.error("No database connection available!")
            return
            
        alert_repo = AlertRepository(db)
        incident_repo = IncidentRepository(db, alert_repo)
        
        try:
            start_wall_time = time.time()
            while True:
                # Removed early break on stop_event to allow draining the queue
                self._pause_event.wait()
                
                try:
                    event = event_queue.get(timeout=1.0)
                except queue.Empty:
                    continue
                    
                if event is None:
                    break # EOF
                
                # Fetch fresh state occasionally if needed, but for tight loop we can keep in mem and sync periodically
                # We'll sync every 100 packets to reduce Redis roundtrips
                
                if last_packet_time is not None:
                    delta = event.timestamp - last_packet_time
                    if delta > 0:
                        sleep_time = delta / state["speed"]
                        if sleep_time > 0:
                            time.sleep(sleep_time)
                            
                last_packet_time = event.timestamp
                t0_wall = time.time()
                
                with self.pipeline_lock:
                    state["packets_processed"] += 1
                    if "bytes_processed" not in state:
                        state["bytes_processed"] = 0
                    state["bytes_processed"] += (event.packet_length or 0)
                    
                    elapsed = time.time() - start_wall_time
                    if elapsed > 0:
                        state["mbps"] = (state["bytes_processed"] * 8) / (elapsed * 1_000_000)
                        state["flows_per_second"] = state["flows_processed"] / elapsed
                    
                    for flow in sessionizer.process([event], flush_at_end=False):
                        vector = self.feature_extractor.extract(
                            flow, 
                            dns_event=flow.last_dns_event, 
                            tls_event=flow.last_tls_event
                        )
                        if not vector:
                            continue
                            
                        state["flows_processed"] += 1
                        
                        for detector in self.detectors:
                            det_name = detector.__class__.__name__
                            try:
                                import time as _time
                                from src.utils.prometheus_metrics import DETECTOR_INVOCATIONS_TOTAL, DETECTOR_ALERTS_TOTAL, DETECTOR_ERRORS_TOTAL, DETECTOR_LATENCY_SECONDS
                                DETECTOR_INVOCATIONS_TOTAL.labels(detector=det_name).inc()
                                
                                _t0 = _time.time()
                                result = detector.detect(vector)
                                DETECTOR_LATENCY_SECONDS.labels(detector=det_name).observe(_time.time() - _t0)
                                
                                if result and result.is_alert():
                                    t_class_val = result.threat_class.value if hasattr(result.threat_class, 'value') else str(result.threat_class)
                                    DETECTOR_ALERTS_TOTAL.labels(detector=det_name, threat_class=t_class_val).inc()
                                    
                                    state["alerts_generated"] += 1
                                    
                                    threats = self.state_mgr.get_threats()
                                    if t_class_val in threats:
                                        threats[t_class_val] += 1
                                    self.state_mgr.set_threats(threats)
                                    
                                    # Persist Alert
                                    alert_repo.save(result)
                                    
                                    incident = self.correlation_engine.correlate_alert(result)
                                    if incident:
                                        self.risk_engine.update_risk(incident)
                                        incident_repo.save(incident)
                                        state["incidents_generated"] = len(incident_repo.get_active())
                            except Exception as e:
                                logger.error(f"Detector {det_name} failed: {e}")
                                from src.utils.prometheus_metrics import DETECTOR_ERRORS_TOTAL
                                DETECTOR_ERRORS_TOTAL.labels(detector=det_name).inc()
                                    
                        latency = (time.time() - t0_wall) * 1000
                        if "detection_latency_ms" not in state:
                            state["detection_latency_ms"] = latency
                        else:
                            state["detection_latency_ms"] = (state["detection_latency_ms"] * 0.9) + (latency * 0.1)
                        
                        self.latency_history.append(latency)
                        if len(self.latency_history) > 1000:
                            self.latency_history = self.latency_history[-1000:]
                            
                        if len(self.latency_history) > 10 and state["flows_processed"] % 10 == 0:
                            sorted_lat = sorted(self.latency_history)
                            state["latency_p50"] = sorted_lat[int(len(sorted_lat) * 0.50)]
                            state["latency_p95"] = sorted_lat[int(len(sorted_lat) * 0.95)]
                            state["latency_p99"] = sorted_lat[int(len(sorted_lat) * 0.99)]
                            
                    from src.utils.prometheus_metrics import PIPELINE_EVENTS_PROCESSED_TOTAL, PIPELINE_LATENCY_SECONDS
                    PIPELINE_EVENTS_PROCESSED_TOTAL.labels(stage="feature_extraction_and_detection").inc()
                    PIPELINE_LATENCY_SECONDS.observe((time.time() - t0_wall))
                            
                # Sync state back to Redis periodically to save I/O
                if state["packets_processed"] % 10 == 0 or (time.time() - getattr(self, "_last_sync", 0)) > 1.0:
                    if getattr(self, 'zeek_reader', None):
                        state["zeek_queue_depth"] = self.zeek_reader.pq_size
                        state["zeek_late_events"] = self.zeek_reader.late_events_dropped
                        state["zeek_merged_events"] = self.zeek_reader.events_merged
                    self.state_mgr.set_state(state)
                    self._last_sync = time.time()
                            
            # Flush remaining
            with self.pipeline_lock:
                for flow in sessionizer.process([], flush_at_end=True):
                    vector = self.feature_extractor.extract(
                        flow, 
                        dns_event=flow.last_dns_event, 
                        tls_event=flow.last_tls_event
                    )
                    if not vector:
                        continue
                        
                    state["flows_processed"] += 1
                    
                    for detector in self.detectors:
                        det_name = detector.__class__.__name__
                        try:
                            import time as _time
                            from src.utils.prometheus_metrics import DETECTOR_INVOCATIONS_TOTAL, DETECTOR_ALERTS_TOTAL, DETECTOR_ERRORS_TOTAL, DETECTOR_LATENCY_SECONDS
                            DETECTOR_INVOCATIONS_TOTAL.labels(detector=det_name).inc()
                            
                            _t0 = _time.time()
                            result = detector.detect(vector)
                            DETECTOR_LATENCY_SECONDS.labels(detector=det_name).observe(_time.time() - _t0)
                            
                            if result and result.is_alert():
                                t_class_val = result.threat_class.value if hasattr(result.threat_class, 'value') else str(result.threat_class)
                                DETECTOR_ALERTS_TOTAL.labels(detector=det_name, threat_class=t_class_val).inc()
                                
                                state["alerts_generated"] += 1
                                
                                threats = self.state_mgr.get_threats()
                                if t_class_val in threats:
                                    threats[t_class_val] += 1
                                self.state_mgr.set_threats(threats)
                                
                                alert_repo.save(result)
                                incident = self.correlation_engine.correlate_alert(result)
                                if incident:
                                    self.risk_engine.update_risk(incident)
                                    incident_repo.save(incident)
                                    state["incidents_generated"] = len(incident_repo.get_active())
                        except Exception as e:
                            logger.error(f"Detector {det_name} flush failed: {e}")
                            from src.utils.prometheus_metrics import DETECTOR_ERRORS_TOTAL
                            DETECTOR_ERRORS_TOTAL.labels(detector=det_name).inc()
                self.state_mgr.set_state(state)
                                
        except Exception as e:
            logger.error(f"Replay Error: {e}")
        finally:
            if db:
                db.close()
            state = self.state_mgr.get_state()
            state["status"] = "STOPPED"
            self.state_mgr.set_state(state)

# Global Instance
manager = IngestionManager()
