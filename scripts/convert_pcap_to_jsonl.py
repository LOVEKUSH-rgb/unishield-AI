import argparse
import json
import time
from pathlib import Path

from src.ingestion.pcap_reader import PcapReader
from src.flows.flow_manager import FlowManager
from src.flows.sessionizer import Sessionizer
from src.features.feature_pipeline import FeaturePipeline

def convert_pcap_to_jsonl(pcap_path: str, output_path: str):
    print(f"Converting {pcap_path} to {output_path}...")
    reader = PcapReader(pcap_path)
    manager = FlowManager(timeout_seconds=120.0)
    sess = Sessionizer(manager)
    pipeline = FeaturePipeline()

    start_time = time.time()
    
    with open(output_path, "w") as f:
        for flow in sess.process(reader.stream()):
            fv = pipeline.extract(flow, dns_event=flow.last_dns_event, tls_event=flow.last_tls_event)
            # Output FeatureVector to JSONL
            f.write(fv.model_dump_json() + "\n")

    # Flush any remaining flows
    for flow in manager.flush():
        fv = pipeline.extract(flow, dns_event=flow.last_dns_event, tls_event=flow.last_tls_event)
        f.write(fv.model_dump_json() + "\n")

    elapsed = time.time() - start_time
    print(f"Conversion complete in {elapsed:.2f}s")
    print(f"Total Feature Vectors Generated: {pipeline.vectors_produced}")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Convert PCAP to JSONL Feature Vectors for streaming benchmark.")
    parser.add_argument("--input", default="data/samples/demo_scenario.pcap", help="Path to input PCAP")
    parser.add_argument("--output", default="data/samples/demo_flows.jsonl", help="Path to output JSONL")
    args = parser.parse_args()
    
    convert_pcap_to_jsonl(args.input, args.output)
