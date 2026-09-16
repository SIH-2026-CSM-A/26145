"""Forensic Verification Script for SIH26145 Production Demo Correction."""

import os
import asyncio
import sqlite3
import json
import time
from collections import Counter

from sih26145.utils.pcap_generator import generate_threat_pcap
from sih26145.orchestrator import ThreatDetectionPipeline
from sih26145.detectors import RuleDetectorSuite
from sih26145.features.models import FeatureVector
from sih26145.models.anomaly import IsolationForestAnomalyDetector
from sih26145.models.classifier import RandomForestThreatClassifier


def make_fv(**kwargs) -> FeatureVector:
    """Helper to create a FeatureVector for adversarial testing."""
    defaults = {
        "flow_key_str": "192.168.1.10->10.0.0.1:80/TCP",
        "duration": 2.0,
        "total_packets": 3,
        "total_bytes": 600,
        "pps": 1.5,
        "bps": 300.0,
        "pkt_size_min": 100.0,
        "pkt_size_max": 300.0,
        "pkt_size_mean": 200.0,
        "pkt_size_std": 81.65,
        "pkt_size_q25": 150.0,
        "pkt_size_q50": 200.0,
        "pkt_size_q75": 250.0,
        "iat_mean": 1.0,
        "iat_var": 0.5,
        "iat_min": 0.5,
        "iat_max": 1.5,
        "jitter": 0.2,
        "burstiness_ratio": 0.4,
        "small_pkt_ratio": 0.0,
        "is_tcp": 1.0,
        "is_udp": 0.0,
        "is_icmp": 0.0,
        "dst_port": 80,
        "dns_query_count": 0,
        "dns_max_domain_entropy": 0.0,
        "dns_max_subdomain_depth": 0,
        "tls_client_hello_count": 0,
        "tls_max_sni_entropy": 0.0,
        "tls_max_sni_length": 0,
    }
    defaults.update(kwargs)
    return FeatureVector(**defaults)


def make_single_pkt_fv(**kwargs) -> FeatureVector:
    """Helper to create a consistent single packet FeatureVector for testing."""
    defaults = {
        "flow_key_str": "192.168.1.10:50000->10.0.0.1:80/TCP",
        "duration": 0.0,
        "total_packets": 1,
        "total_bytes": 64,
        "pps": 1.0,
        "bps": 64.0,
        "pkt_size_min": 64.0,
        "pkt_size_max": 64.0,
        "pkt_size_mean": 64.0,
        "pkt_size_std": 0.0,
        "pkt_size_q25": 64.0,
        "pkt_size_q50": 64.0,
        "pkt_size_q75": 64.0,
        "iat_mean": 0.0,
        "iat_var": 0.0,
        "iat_min": 0.0,
        "iat_max": 0.0,
        "jitter": 0.0,
        "burstiness_ratio": 0.0,
        "small_pkt_ratio": 1.0,
        "is_tcp": 1.0,
        "is_udp": 0.0,
        "is_icmp": 0.0,
        "dst_port": 80,
        "dns_query_count": 0,
        "dns_max_domain_entropy": 0.0,
        "dns_max_subdomain_depth": 0,
        "tls_client_hello_count": 0,
        "tls_max_sni_entropy": 0.0,
        "tls_max_sni_length": 0,
    }
    defaults.update(kwargs)
    return FeatureVector(**defaults)


async def run_forensic_verification():
    pcap_path = "/tmp/verify_demo.pcap"
    db_path = "/tmp/verify_demo.db"

    if os.path.exists(db_path):
        os.remove(db_path)
    if os.path.exists(pcap_path):
        os.remove(pcap_path)

    # 1. Clean PCAP Generation
    packet_count = generate_threat_pcap(pcap_path)
    print(f"=== 1. CLEAN REPRODUCTION ===")
    print(f"Generated PCAP: {pcap_path}")
    print(f"Total Packets: {packet_count}")

    # 2. Production Pipeline Execution
    pipeline = ThreatDetectionPipeline(db_path)
    alerts = await pipeline.process_pcap(pcap_path)
    
    # 3. Clean Async Storage Closure
    await pipeline.storage.close()

    print(f"\n=== 2. EXACT ALERT DISTRIBUTION ===")
    print(f"Total Pipeline Alerts: {len(alerts)}")

    # Query SQLite DB directly
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()

    cursor.execute("""
        SELECT threat_class, json_extract(json_data, '$.detector.name') as det_name, COUNT(1)
        FROM alerts
        GROUP BY threat_class, det_name
        ORDER BY threat_class
    """)
    rows = cursor.fetchall()
    
    rule_ml_count = 0
    anomaly_count = 0
    print("\nSQLite Database Query (threat_class x detector_name x count):")
    for tc, det, cnt in rows:
        print(f"  {tc:<28} | {str(det):<38} | {cnt}")
        if tc == "THREAT_UNSUPERVISED_ANOMALY":
            anomaly_count += cnt
        else:
            rule_ml_count += cnt

    print(f"\nReconciliation Summary:")
    print(f"  Rule / Supervised Threat Alerts : {rule_ml_count}")
    print(f"  Unsupervised Anomaly ML Alerts  : {anomaly_count}")
    print(f"  Total Persisted Alerts          : {rule_ml_count + anomaly_count}")
    assert rule_ml_count + anomaly_count == len(alerts)

    # 4. Detailed Inspection of the Unsupervised Anomaly Alerts
    print(f"\n=== 3. FORENSIC INSPECTION OF THE {anomaly_count} UNSUPERVISED ANOMALY ALERTS ===")
    cursor.execute("SELECT alert_id, threat_class, confidence, severity, json_data FROM alerts WHERE threat_class = 'THREAT_UNSUPERVISED_ANOMALY'")
    anomaly_rows = cursor.fetchall()

    for idx, (aid, tc, conf, sev, jdata_str) in enumerate(anomaly_rows, 1):
        jdata = json.loads(jdata_str)
        flow = jdata.get("flow", {})
        feat = jdata.get("feature_summary", {})
        ev = jdata.get("evidence", {})
        print(f"\nAnomaly Alert #{idx}:")
        print(f"  ID         : {aid}")
        print(f"  Src/Dst    : {flow.get('src_ip')}:{flow.get('src_port')} -> {flow.get('dst_ip')}:{flow.get('dst_port')} ({flow.get('protocol')})")
        print(f"  Telemetry  : packets={feat.get('total_packets')}, bytes={feat.get('total_bytes')}, pps={feat.get('pps')}, bps={feat.get('bps')}")
        print(f"  Confidence : {conf} (Severity: {sev})")
        print(f"  Evidence   : {ev}")

    conn.close()

    # 5. Targeted Adversarial Controls Test Suite
    print(f"\n=== 4. TARGETED ADVERSARIAL CONTROLS TEST SUITE ===")
    rule_suite = RuleDetectorSuite()
    rf_classifier = RandomForestThreatClassifier()
    if_detector = IsolationForestAnomalyDetector()

    # Control 1: UDP Port 80 non-DNS traffic
    fv_udp80 = make_fv(is_tcp=0.0, is_udp=1.0, dst_port=80, dns_query_count=0, dns_max_domain_entropy=0.0)
    rf_pred = rf_classifier.predict(fv_udp80)
    rule_hits = rule_suite.evaluate(fv_udp80)
    print(f"Control 1 (UDP Port 80 non-DNS)    : RF Class='{rf_pred.threat_class}' (Rule Hits={len(rule_hits)})")
    assert rf_pred.threat_class == "BENIGN"
    assert len(rule_hits) == 0

    # Control 2: DNS Port 53 low entropy
    fv_dns_low = make_fv(is_tcp=0.0, is_udp=1.0, dst_port=53, dns_query_count=1, dns_max_domain_entropy=2.1, dns_max_subdomain_depth=1)
    rf_pred2 = rf_classifier.predict(fv_dns_low)
    rule_hits2 = rule_suite.evaluate(fv_dns_low)
    print(f"Control 2 (DNS Port 53 low entropy): RF Class='{rf_pred2.threat_class}' (Rule Hits={len(rule_hits2)})")
    assert rf_pred2.threat_class == "BENIGN"
    assert len(rule_hits2) == 0

    # Control 3: High-entropy non-DNS UDP (port 12345)
    fv_udp_ent = make_fv(is_tcp=0.0, is_udp=1.0, dst_port=12345, dns_query_count=0, dns_max_domain_entropy=4.8)
    rf_pred3 = rf_classifier.predict(fv_udp_ent)
    print(f"Control 3 (High-entropy non-DNS UDP): RF Class='{rf_pred3.threat_class}'")
    assert rf_pred3.threat_class == "BENIGN"

    # Control 4: Benign 1-packet TCP
    fv_tcp1 = make_single_pkt_fv(is_tcp=1.0, dst_port=80)
    if_pred1 = if_detector.predict(fv_tcp1)
    print(f"Control 4 (Benign 1-pkt TCP)       : IF is_anomaly={if_pred1.is_anomaly} (decision_score={if_pred1.anomaly_score:.4f})")
    assert not if_pred1.is_anomaly

    # Control 5: Short benign UDP
    fv_udp_short = make_single_pkt_fv(duration=0.05, is_tcp=0.0, is_udp=1.0, dst_port=123)
    if_pred2 = if_detector.predict(fv_udp_short)
    print(f"Control 5 (Short benign UDP)       : IF is_anomaly={if_pred2.is_anomaly} (decision_score={if_pred2.anomaly_score:.4f})")
    assert not if_pred2.is_anomaly

    # Control 6: Periodic benign TCP (low IAT var but only 3 packets and short duration)
    fv_tcp_per = make_fv(total_packets=3, duration=2.0, iat_var=0.0001, pps=1.5, is_tcp=1.0, dst_port=80)
    rule_hits6 = rule_suite.evaluate(fv_tcp_per)
    print(f"Control 6 (Periodic benign TCP)    : Rule Hits={len(rule_hits6)}")
    assert len(rule_hits6) == 0

    # Control 7: Standard TLS 443 normal SNI
    fv_tls_std = make_fv(is_tcp=1.0, dst_port=443, tls_client_hello_count=1, tls_max_sni_entropy=2.8, tls_max_sni_length=15)
    rule_hits7 = rule_suite.evaluate(fv_tls_std)
    print(f"Control 7 (Standard TLS 443)       : Rule Hits={len(rule_hits7)}")
    assert len(rule_hits7) == 0

    # Control 8: Non-standard TLS 8443 high SNI entropy
    fv_tls_ano = make_fv(is_tcp=1.0, dst_port=8443, tls_client_hello_count=1, tls_max_sni_entropy=4.5, tls_max_sni_length=35)
    rule_hits8 = rule_suite.evaluate(fv_tls_ano)
    print(f"Control 8 (Non-std TLS 8443 SNI)   : Rule Hits={len(rule_hits8)} (Threat='{rule_hits8[0].threat_class}')")
    assert len(rule_hits8) == 1 and rule_hits8[0].threat_class == "THREAT_ENCRYPTED_ANOMALY"

    # Control 9: Recon port scan probes
    fv_recon = make_fv(is_tcp=1.0, small_pkt_ratio=0.9, total_packets=2, duration=0.05, dst_port=100)
    rule_hits9 = rule_suite.evaluate(fv_recon)
    print(f"Control 9 (Recon SYN probe)        : Rule Hits={len(rule_hits9)} (Threat='{rule_hits9[0].threat_class}')")
    assert len(rule_hits9) == 1 and rule_hits9[0].threat_class == "THREAT_RECON_PORTSCAN"

    # Control 10: ICMP below exfil threshold (200B, 0.5s)
    fv_icmp_low = make_fv(is_tcp=0.0, is_icmp=1.0, total_bytes=200, total_packets=2, duration=0.5, small_pkt_ratio=0.0)
    rule_hits10 = rule_suite.evaluate(fv_icmp_low)
    print(f"Control 10 (ICMP below threshold)  : Rule Hits={len(rule_hits10)}")
    assert len(rule_hits10) == 0

    # Control 11: ICMP above exfil threshold (1536B, 1.2s)
    fv_icmp_high = make_fv(is_tcp=0.0, is_icmp=1.0, total_bytes=1536, total_packets=6, duration=1.2, small_pkt_ratio=0.0)
    rule_hits11 = rule_suite.evaluate(fv_icmp_high)
    print(f"Control 11 (ICMP above threshold)  : Rule Hits={len(rule_hits11)} (Threat='{rule_hits11[0].threat_class}')")
    assert len(rule_hits11) == 1 and rule_hits11[0].threat_class == "THREAT_EXFILTRATION"

    print("\nALL 11 TARGETED ADVERSARIAL CONTROLS PASSED!")


if __name__ == "__main__":
    asyncio.run(run_forensic_verification())
