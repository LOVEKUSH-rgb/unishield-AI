import argparse
import json
import psutil
import os
import threading
import time
from pathlib import Path

from src.api.streaming_engine import StreamingEngine
from src.utils.logging import configure_logging

def get_process_memory_mb():
    process = psutil.Process(os.getpid())
    return process.memory_info().rss / (1024 * 1024)

def run_benchmark(input_file: str, flows_per_sec: int, max_records: int, name: str, output_dir: str):
    print(f"\n{'='*50}")
    print(f"Starting Benchmark: {name}")
    print(f"Target Rate: {flows_per_sec if flows_per_sec > 0 else 'UNLIMITED'} flows/sec")
    print(f"{'='*50}")
    
    engine = StreamingEngine(queue_size=1000)
    
    # Track peak memory
    peak_mem = 0.0
    mem_tracking = True
    def track_mem():
        nonlocal peak_mem
        while mem_tracking:
            mem = get_process_memory_mb()
            if mem > peak_mem:
                peak_mem = mem
            time.sleep(0.1)
            
    mem_thread = threading.Thread(target=track_mem, daemon=True)
    mem_thread.start()
    
    start_mem = get_process_memory_mb()
    
    result = engine.run(input_file, flows_per_sec, max_records)
    
    mem_tracking = False
    mem_thread.join()
    
    end_mem = get_process_memory_mb()
    
    metrics = result["metrics"]
    elapsed = result["elapsed_seconds"]
    
    actual_rate = metrics["processed"] / elapsed if elapsed > 0 else 0
    avg_latency = metrics["latency_ms_sum"] / metrics["latency_samples"] if metrics["latency_samples"] > 0 else 0
    
    print(f"Duration          : {elapsed:.2f} seconds")
    print(f"Records Received  : {metrics['received']}")
    print(f"Records Processed : {metrics['processed']}")
    print(f"Records Dropped   : {metrics['dropped']} ({(metrics['dropped']/max(1, metrics['received']))*100:.1f}%)")
    print(f"Actual Throughput : {actual_rate:.1f} flows/sec")
    print(f"Average Latency   : {avg_latency:.2f} ms")
    print(f"Alerts Generated  : {metrics['alerts']}")
    print(f"Incidents Created : {metrics['incidents']}")
    print(f"Start Memory      : {start_mem:.1f} MB")
    print(f"Peak Memory       : {peak_mem:.1f} MB")
    print(f"End Memory        : {end_mem:.1f} MB")
    
    report = {
        "benchmark_name": name,
        "target_rate": flows_per_sec,
        "duration": elapsed,
        "received": metrics["received"],
        "processed": metrics["processed"],
        "dropped": metrics["dropped"],
        "throughput": actual_rate,
        "average_latency_ms": avg_latency,
        "alerts": metrics["alerts"],
        "incidents": metrics["incidents"],
        "start_memory_mb": start_mem,
        "peak_memory_mb": peak_mem,
        "end_memory_mb": end_mem
    }
    
    os.makedirs(output_dir, exist_ok=True)
    report_path = os.path.join(output_dir, f"{name.replace(' ', '_').lower()}.json")
    with open(report_path, "w") as f:
        json.dump(report, f, indent=2)
        
    return report

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Run streaming benchmarks.")
    parser.add_argument("--input", default="data/samples/demo_flows.jsonl")
    parser.add_argument("--output-dir", default="reports/performance")
    args = parser.parse_args()
    
    configure_logging(level="WARNING")
    
    print("UniShield AI — Streaming Performance Benchmark")
    
    # Generate larger synthetic load by looping over the 451 vectors
    # We will generate a big file so we can run sustained tests
    print("\nGenerating expanded dataset for sustained benchmark...")
    expanded_file = "data/samples/demo_flows_expanded.jsonl"
    with open(args.input, "r") as fin:
        lines = fin.readlines()
        
    if not lines:
        print("Input file is empty. Run convert_pcap_to_jsonl.py first.")
        exit(1)
        
    with open(expanded_file, "w") as fout:
        # 10,000 flows total is enough to see throughput and drops
        target_lines = 10000
        count = 0
        while count < target_lines:
            for line in lines:
                if count >= target_lines:
                    break
                fout.write(line)
                count += 1
                
    run_benchmark(expanded_file, flows_per_sec=100, max_records=500, name="Base Rate (100 fps)", output_dir=args.output_dir)
    run_benchmark(expanded_file, flows_per_sec=1000, max_records=5000, name="High Rate (1000 fps)", output_dir=args.output_dir)
    run_benchmark(expanded_file, flows_per_sec=0, max_records=10000, name="Unlimited Burst", output_dir=args.output_dir)
    
    # A sustained test with limited queue to trigger drops if processing is slow
    run_benchmark(expanded_file, flows_per_sec=5000, max_records=10000, name="Overload Test (5000 fps)", output_dir=args.output_dir)
    
    print("\nBenchmarks complete. Reports saved to:", args.output_dir)
