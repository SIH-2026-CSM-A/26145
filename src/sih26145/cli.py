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

    serve_parser = subparsers.add_parser("serve", help="Replay a PCAP through the pipeline and serve API + SSE")
    serve_parser.add_argument("pcap_file", type=str, help="Capture to replay")
    pace = serve_parser.add_mutually_exclusive_group()
    pace.add_argument("--speed", type=float, default=1.0, help="Replay rate as a multiple of real time (default 1.0)")
    pace.add_argument("--unthrottled", action="store_true", help="Replay as fast as possible")
    serve_parser.add_argument("--host", default="127.0.0.1")
    serve_parser.add_argument("--port", type=int, default=8000)
    serve_parser.add_argument("--db", type=str, default=None, help="SQLite database path (default: in memory)")
    serve_parser.add_argument("--tick", type=float, default=1.0, help="Idle-flush timer period, seconds")
    serve_parser.add_argument("--loop", action="store_true",
                              help="Replay forever; each loop starts from an empty in-memory store (not with --db)")
    serve_parser.add_argument("--pause", type=float, default=30.0, help="Seconds to hold the final picture between loops")

    dump_parser = subparsers.add_parser("dump-features", help="Write one model-input row per scored flow (gzip CSV)")
    dump_parser.add_argument("pcap_file", type=str, help="Capture to replay (unthrottled, lossless)")
    dump_parser.add_argument("--out", required=True, help="Output .csv.gz path")

    verify_parser = subparsers.add_parser("verify-log", help="Recompute the alert log's hash chain")
    verify_parser.add_argument("--db", required=True, help="SQLite alert database")
    export_parser = subparsers.add_parser("export", help="Write a one-way transfer bundle of the alert log")
    export_parser.add_argument("--db", required=True, help="SQLite alert database")
    export_parser.add_argument("--out", required=True, help="Output directory")

    bundle_parser = subparsers.add_parser("bundle", help="Signed offline update bundles (models, ruleset, contract)")
    bsub = bundle_parser.add_subparsers(dest="bundle_cmd", required=True)
    kg = bsub.add_parser("keygen", help="New Ed25519 signing key (private key stays outside the repository)")
    kg.add_argument("--private", required=True, help="Where to write the private key (PEM, mode 0600)")
    kg.add_argument("--public", help="Also write the public key here (e.g. src/sih26145/config/bundle_ed25519.pub)")
    bb = bsub.add_parser("build", help="Pack models/artifacts, the ruleset, lists and contract into a tar")
    bb.add_argument("--out", required=True)
    bb.add_argument("--artifacts", help="Model artefact directory (default: the package's models/artifacts)")
    bs = bsub.add_parser("sign", help="Write BUNDLE.sig with a private key")
    bs.add_argument("bundle")
    bs.add_argument("--key", required=True)
    bv = bsub.add_parser("verify", help="Check a bundle's signature and hashes against the pinned key")
    bv.add_argument("bundle")
    bv.add_argument("--pubkey", help="Public key file (default: the pinned config/bundle_ed25519.pub)")

    args = parser.parse_args()
    if args.command == "bundle":
        from sih26145 import bundle
        try:
            if args.bundle_cmd == "keygen":
                print(f"public key (pin in config/bundle_ed25519.pub): {bundle.keygen(args.private, args.public)}")
            elif args.bundle_cmd == "build":
                m = bundle.build(args.out, args.artifacts)
                print(f"built {args.out}: {len(m['files'])} files, models {m['model_version']}, "
                      f"rules {m['ruleset_version']}, contract {m['contract_version']} (unsigned: run bundle sign)")
            elif args.bundle_cmd == "sign":
                print(f"signed: {bundle.sign(args.bundle, args.key)}")
            else:
                pub = open(args.pubkey).read() if args.pubkey else None
                files = bundle.load_verified(args.bundle, pubkey=pub)
                bundle.check_code_matches(files)
                print(f"verified: {args.bundle}, {len(files) - 1} files, signature and every sha256 match; "
                      "ruleset, contract and lists match this code")
        except (bundle.BundleError, FileExistsError, FileNotFoundError) as e:
            print(f"refused: {e}")
            sys.exit(1)
        return
    if args.command in ("verify-log", "export"):
        from sih26145.storage import chain
        if args.command == "verify-log":
            res = chain.verify(args.db)
            if res["ok"]:
                print(f"verified: {res['n']} records, chain head {res['head']}")
                return
            print(f"BROKEN at index {res['first_bad_index']} of {res['rows']}: {res['reason']}")
            sys.exit(1)
        try:
            m = chain.export(args.db, args.out)
        except ValueError as e:
            print(f"refused: {e}")
            sys.exit(1)
        print(f"exported {m['alerts']} alerts to {args.out}; alerts.jsonl sha256 {m['alerts_jsonl_sha256']}")
        return
    if args.command == "dump-features":
        import json
        from sih26145.features.dump import dump_features
        print(json.dumps(asyncio.run(dump_features(args.pcap_file, args.out))))
        return
    if args.command == "serve":
        import logging
        from sih26145.serve import serve
        logging.basicConfig(level=logging.INFO)
        if args.loop and args.db:
            parser.error("--loop starts every replay from an empty in-memory store; drop --db")
        asyncio.run(serve(args.pcap_file, None if args.unthrottled else args.speed,
                          args.host, args.port, args.db, args.tick, loop=args.loop, pause=args.pause))
        return

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
