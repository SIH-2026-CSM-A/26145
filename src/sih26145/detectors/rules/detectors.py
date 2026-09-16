"""Implementation of the 7 Deterministic Threat Rule Detectors for SIH26145."""

from typing import Optional
from sih26145.features.models import FeatureVector
from sih26145.detectors.models import RuleHit
from sih26145.detectors.rules.base import BaseRuleDetector


class DDoSVolumeDetector(BaseRuleDetector):
    name = "ddos_volume_detector"
    threat_class = "THREAT_DDOS_VOLUME"

    def detect(self, fv: FeatureVector) -> Optional[RuleHit]:
        if fv.pps > 10000.0 or fv.bps > 10000000.0 or fv.burstiness_ratio > 5.0:
            return RuleHit(
                detector_name=self.name,
                threat_class=self.threat_class,
                rule_id="RULE_DDOS_VOLUME_THRESHOLD",
                severity="CRITICAL" if fv.pps > 50000.0 else "HIGH",
                confidence=0.95,
                evidence={
                    "pps": fv.pps,
                    "bps": fv.bps,
                    "burstiness_ratio": fv.burstiness_ratio,
                    "total_packets": fv.total_packets,
                }
            )
        return None


class C2BeaconDetector(BaseRuleDetector):
    name = "c2_beacon_detector"
    threat_class = "THREAT_C2_BEACON"

    def detect(self, fv: FeatureVector) -> Optional[RuleHit]:
        if fv.total_packets >= 5 and fv.duration >= 5.0 and fv.iat_var < 0.01 and fv.pps < 100.0:
            return RuleHit(
                detector_name=self.name,
                threat_class=self.threat_class,
                rule_id="RULE_C2_PERIODIC_IAT",
                severity="HIGH",
                confidence=0.88,
                evidence={
                    "iat_mean": fv.iat_mean,
                    "iat_var": fv.iat_var,
                    "duration": fv.duration,
                    "total_packets": fv.total_packets,
                }
            )
        return None


class DGALexicalDetector(BaseRuleDetector):
    name = "dga_lexical_detector"
    threat_class = "THREAT_DNS_DGA"

    def detect(self, fv: FeatureVector) -> Optional[RuleHit]:
        if fv.is_udp and fv.dst_port == 53 and fv.dns_max_domain_entropy > 4.2:
            return RuleHit(
                detector_name=self.name,
                threat_class=self.threat_class,
                rule_id="RULE_DGA_HIGH_DOMAIN_ENTROPY",
                severity="HIGH",
                confidence=0.90,
                evidence={
                    "dns_max_domain_entropy": fv.dns_max_domain_entropy,
                    "dns_query_count": fv.dns_query_count,
                }
            )
        return None


class DNSTunnelDetector(BaseRuleDetector):
    name = "dns_tunnel_detector"
    threat_class = "THREAT_DNS_TUNNEL"

    def detect(self, fv: FeatureVector) -> Optional[RuleHit]:
        if fv.dst_port == 53 and (fv.dns_max_subdomain_depth >= 4 or (fv.dns_query_count >= 5 and fv.dns_max_domain_entropy > 3.8)):
            return RuleHit(
                detector_name=self.name,
                threat_class=self.threat_class,
                rule_id="RULE_DNS_TUNNEL_PAYLOAD_DEPTH",
                severity="HIGH",
                confidence=0.92,
                evidence={
                    "dns_max_subdomain_depth": fv.dns_max_subdomain_depth,
                    "dns_max_domain_entropy": fv.dns_max_domain_entropy,
                    "dns_query_count": fv.dns_query_count,
                }
            )
        return None


class EncryptedAnomalyDetector(BaseRuleDetector):
    name = "encrypted_anomaly_detector"
    threat_class = "THREAT_ENCRYPTED_ANOMALY"

    def detect(self, fv: FeatureVector) -> Optional[RuleHit]:
        if fv.tls_client_hello_count > 0 and (fv.tls_max_sni_entropy > 4.0 or fv.dst_port not in (443, 8443)):
            return RuleHit(
                detector_name=self.name,
                threat_class=self.threat_class,
                rule_id="RULE_ENCRYPTED_SNI_PORT_ANOMALY",
                severity="MEDIUM",
                confidence=0.82,
                evidence={
                    "tls_max_sni_entropy": fv.tls_max_sni_entropy,
                    "tls_max_sni_length": fv.tls_max_sni_length,
                    "dst_port": fv.dst_port,
                }
            )
        return None


class ReconPortScanDetector(BaseRuleDetector):
    name = "recon_portscan_detector"
    threat_class = "THREAT_RECON_PORTSCAN"

    def detect(self, fv: FeatureVector) -> Optional[RuleHit]:
        if fv.is_tcp and fv.small_pkt_ratio > 0.8 and fv.total_packets <= 5 and fv.duration < 1.0:
            return RuleHit(
                detector_name=self.name,
                threat_class=self.threat_class,
                rule_id="RULE_RECON_SYN_SWEEP",
                severity="MEDIUM",
                confidence=0.85,
                evidence={
                    "small_pkt_ratio": fv.small_pkt_ratio,
                    "total_packets": fv.total_packets,
                    "duration": fv.duration,
                }
            )
        return None


class ExfiltrationDetector(BaseRuleDetector):
    name = "exfiltration_detector"
    threat_class = "THREAT_EXFILTRATION"

    def detect(self, fv: FeatureVector) -> Optional[RuleHit]:
        if (fv.bps > 500000.0 or (fv.is_icmp == 1.0 and fv.total_bytes >= 500)) and fv.duration >= 1.0 and fv.small_pkt_ratio < 0.5:
            return RuleHit(
                detector_name=self.name,
                threat_class=self.threat_class,
                rule_id="RULE_EXFIL_HIGH_BYTE_STREAM",
                severity="HIGH",
                confidence=0.87,
                evidence={
                    "bps": fv.bps,
                    "duration": fv.duration,
                    "total_bytes": fv.total_bytes,
                    "small_pkt_ratio": fv.small_pkt_ratio,
                    "is_icmp": fv.is_icmp,
                }
            )
        return None
