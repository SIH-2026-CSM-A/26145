"""Command Line Interface for SIH26145 Threat Engine."""

import sys
import argparse
import asyncio
import os
from sih26145.orchestrator import ThreatDetectionPipeline
from sih26145.utils.pcap_generator import generate_threat_pcap


def main():
    parser = argparse.ArgumentParser(
        description="SIH26145 — NTRO: AI-Based Detection of Cyber Threats in Unidirectional IP Traffic"
    )
    subparsers = parser.add_subparsers(dest="command", help="Sub-command to run")

    # Analyze PCAP subcommand
    analyze_parser = subparsers.add_parser("analyze", help="Analyze a PCAP file for cyber threats")
    analyze_parser.add_argument("pcap_file", type=str, help="Path to input PCAP file")
    analyze_parser.add_argument("--db", type=str, default=None, help="SQLite database path")

    # Demo subcommand
    demo_parser = subparsers.add_parser("demo", help="Generate synthetic threats PCAP & execute pipeline")
    demo_parser.add_argument("--output-pcap", type=str, default="demo_threats.pcap", help="Output PCAP file path")

    args = parser.parse_args()

    async def run_cli():
        if args.command == "analyze":
            pipeline = ThreatDetectionPipeline(args.db)
            try:
                alerts = await pipeline.process_pcap(args.pcap_file)
                print(f"Analysis complete. Total alerts generated: {len(alerts)}")
                for a in alerts:
                    print(f"[{a.severity}] {a.threat_class} | Confidence: {a.confidence*100:.1f}% | Flow: {a.flow['src_ip']} -> {a.flow['dst_ip']}:{a.flow['dst_port']}")
            finally:
                await pipeline.storage.close()
        elif args.command == "demo":
            print(f"Generating synthetic PCAP with threat traffic -> {args.output_pcap}")
            count = generate_threat_pcap(args.output_pcap)
            print(f"Generated {count} packets in {args.output_pcap}")
            pipeline = ThreatDetectionPipeline(":memory:")
            try:
                alerts = await pipeline.process_pcap(args.output_pcap)
                print(f"Pipeline Analysis Complete. Total threat alerts detected: {len(alerts)}")
                for a in alerts:
                    print(f"[{a.severity}] {a.threat_class} | Confidence: {a.confidence*100:.1f}% | Rules: {a.detection.get('rule_matches')} | {a.observability_state}")
            finally:
                await pipeline.storage.close()
        else:
            parser.print_help()

    if args.command in ("analyze", "demo"):
        asyncio.run(run_cli())
    else:
        parser.print_help()


if __name__ == "__main__":
    main()
