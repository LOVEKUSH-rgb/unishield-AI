import json
import uuid
import time
from pathlib import Path

def create_flow(**kwargs):
    base = {
        "flow_id": str(uuid.uuid4()),
        "timestamp": "2024-07-03T10:00:00.000000+00:00",
        "source_ip": "10.0.0.1",
        "destination_ip": "10.0.0.2",
        "source_port": 12345,
        "destination_port": 80,
        "protocol": 6,
        "features": {
            "flow_duration": 10.0,
            "packet_count": 10,
            "byte_count": 1000,
            "packets_per_second": 1.0,
            "bytes_per_second": 100.0,
            "protocol": 6
        }
    }
    for k, v in kwargs.items():
        if k in base:
            base[k] = v
        else:
            base["features"][k] = v
    return base

def main():
    cases = []
    
    # 1. zero-duration flow (DDoS test)
    cases.append(create_flow(flow_duration=0.0, tcp_syn_count=1, packet_count=1, dst_conn_count_60s=60000))
    
    # 2. extremely short flow
    cases.append(create_flow(flow_duration=0.0001, packet_count=2, bytes_per_second=1000000000.0))
    
    # 3. empty packet statistics (missing optional fields)
    cases.append(create_flow(pkt_size_min=None, pkt_size_max=None, splt_sizes=[]))
    
    # 4. malformed numeric fields
    cases.append(create_flow(flow_duration=-5.0, packet_count=-1))
    
    # 5. unusually long DNS name (DGA test)
    cases.append(create_flow(dns_is_query=True, dns_query_name="a"*250 + ".com", dns_query_length=254, dns_entropy=5.0))
    
    # 6. zero byte count
    cases.append(create_flow(byte_count=0, bytes_per_second=0.0))
    
    # 7. periodic connection pattern (C2 test)
    cases.append(create_flow(destination_ip="103.45.67.99", destination_port=443, flow_duration=0.5, packet_count=15, byte_count=1500))
    
    # 8. incomplete TLS metadata
    cases.append(create_flow(tls_client_hello=1, tls_server_hello=0, tls_established=0))

    out_path = Path("data/samples/phase32_edge_cases.jsonl")
    out_path.parent.mkdir(parents=True, exist_ok=True)
    with open(out_path, "w") as f:
        for c in cases:
            f.write(json.dumps(c) + "\n")
            
    print(f"Edge cases written to {out_path}")

if __name__ == "__main__":
    main()
