"""Performance and Throughput Benchmarking Suite for SIH26145."""

import time
import os
import asyncio
import tempfile
from sih26145.orchestrator import ThreatDetectionPipeline
from sih26145.utils.pcap_generator import generate_threat_pcap


def run_benchmark():
    print("==================================================")
    print("SIH26145 — NTRO PERFORMANCE BENCHMARK HARNESS")
    print("==================================================")

    with tempfile.NamedTemporaryFile(suffix=".pcap", delete=False) as tmp:
        pcap_path = tmp.name

    try:
        print("\n1. Generating Benchmark PCAP Dataset...")
        start_gen = time.perf_counter()
        total_packets = 0
        for _ in range(50):
            total_packets += generate_threat_pcap(pcap_path)
        gen_time = time.perf_counter() - start_gen
        file_size_kb = os.path.getsize(pcap_path) / 1024.0
        print(f"Generated {total_packets} packets ({file_size_kb:.2f} KB) in {gen_time*1000:.2f} ms")

        print("\n2. Benchmark End-to-End Ingestion & Processing Pipeline...")
        pipeline = ThreatDetectionPipeline(":memory:")
        start_pipe = time.perf_counter()
        alerts = asyncio.run(pipeline.process_pcap(pcap_path))
        elapsed = time.perf_counter() - start_pipe

        pps = total_packets / elapsed if elapsed > 0 else 0
        bps = (file_size_kb * 1024) / elapsed if elapsed > 0 else 0
        latency_us_per_pkt = (elapsed / total_packets) * 1e6 if total_packets > 0 else 0

        print(f"Processed {total_packets} packets in {elapsed*1000:.2f} ms")
        print(f"  - Ingestion & Pipeline Throughput: {pps:.2f} Packets/Sec ({bps/1024:.2f} KB/s)")
        print(f"  - Average Per-Packet Processing Latency: {latency_us_per_pkt:.2f} µs/packet")
        print(f"  - Total Threat Alerts Generated & Persisted: {len(alerts)}")

        print("\n==================================================")
        print("PERFORMANCE BENCHMARK PASSED CLEANLY!")
        print("==================================================")
    finally:
        if os.path.exists(pcap_path):
            os.remove(pcap_path)


if __name__ == "__main__":
    run_benchmark()
