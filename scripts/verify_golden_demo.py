"""
UniShield AI -- Golden Demo Verifier
"""
import time
from pathlib import Path

from src.ingestion.pcap_reader import PcapReader
from src.flows.flow_manager import FlowManager
from src.flows.sessionizer import Sessionizer
from src.features.feature_pipeline import FeaturePipeline
from src.detectors.base import DetectionResult, ThreatClass, Severity
from src.detectors.ddos import DDoSDetector
from src.detectors.c2_beacon import C2BeaconDetector
from src.detectors.dga_dns import DGADetector
from src.detectors.encrypted import EncryptedSessionDetector
from src.detectors.recon import ReconDetector
from src.detectors.exfiltration import ExfiltrationDetector
from src.correlation.correlation_engine import CorrelationEngine
from src.risk.risk_engine import RiskEngine

def verify():
    pcap_path = Path("data/samples/demo_scenario.pcap")
    if not pcap_path.exists():
        print(f"Error: PCAP not found at {pcap_path}")
        return
        
    reader = PcapReader(str(pcap_path))
    flow_manager = FlowManager()
    sessionizer = Sessionizer(flow_manager)
    feature_extractor = FeaturePipeline()
    
    detectors = [
        DDoSDetector(),
        C2BeaconDetector(),
        DGADetector(),
        EncryptedSessionDetector(),
        ReconDetector(),
        ExfiltrationDetector()
    ]
    
    correlation_engine = CorrelationEngine()
    risk_engine = RiskEngine()
    
    start_time = time.time()
    
    flows_processed = 0
    events_processed = 0
    alerts = []
    active_incidents = {}
    
    for event in reader.stream():
        events_processed += 1
        for flow in sessionizer.process([event]):
            vector = feature_extractor.extract(
                flow,
                dns_event=flow.last_dns_event,
                tls_event=flow.last_tls_event
            )
            if not vector:
                continue
                
            flows_processed += 1
            
            for detector in detectors:
                result = detector.detect(vector)
                if result and result.is_alert():
                    alerts.append(result)
                    incident = correlation_engine.correlate_alert(result)
                    if incident:
                        risk_engine.update_risk(incident)
                        active_incidents[incident.incident_id] = incident

    # Flush sessionizer
    for flow in sessionizer._manager.active_flows():
        vector = feature_extractor.extract(
            flow,
            dns_event=flow.last_dns_event,
            tls_event=flow.last_tls_event
        )
        if not vector:
            continue
        flows_processed += 1
        for detector in detectors:
            result = detector.detect(vector)
            if result and result.is_alert():
                alerts.append(result)
                incident = correlation_engine.correlate_alert(result)
                if incident:
                    risk_engine.update_risk(incident)
                    active_incidents[incident.incident_id] = incident
                    
    end_time = time.time()
    duration = end_time - start_time
    
    print(f"--- PERFORMANCE ---")
    print(f"Duration: {duration:.4f} seconds")
    print(f"Events Processed: {events_processed}")
    print(f"Flows Processed: {flows_processed}")
    print(f"Alerts Generated: {len(alerts)}")
    print(f"Incidents Generated: {len(active_incidents)}")
    print(f"Throughput: {events_processed/duration:.2f} events/sec")
    print("")
    
    print(f"--- DETECTOR SEQUENCE ---")
    for a in alerts:
        print(f"[{a.timestamp}] {a.threat_class.value} (Score: {a.detection_score:.2f}) - {a.source_ip}")
    print("")
    
    print(f"--- INCIDENTS ---")
    for inc_id, inc in active_incidents.items():
        print(f"Incident ID: {inc_id}")
        print(f"Risk Score: {inc.risk_score}")
        print(f"Risk Level: {inc.risk_level.value if hasattr(inc.risk_level, 'value') else inc.risk_level}")
        print(f"Sources: {inc.sources}")
        print(f"Detectors: {inc.detectors}")
        print(f"Progression: {inc.potential_progression}")
        print(f"Explanation: {inc.explanation}")
        print(f"Risk Factors:")
        for rf in inc.risk_factors:
            print(f"  - {rf.factor}: +{rf.contribution:.1f}")
        print("")
        
if __name__ == "__main__":
    verify()
