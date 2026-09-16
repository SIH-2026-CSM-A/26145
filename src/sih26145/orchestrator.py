"""Pipeline Orchestrator for SIH26145 Threat Engine."""

import asyncio
from typing import List, Dict, Any, Optional
from sih26145.ingest.reader import PcapReader
from sih26145.flow.tracker import FlowTracker
from sih26145.features.extractor import FeatureExtractor
from sih26145.detectors.rules.suite import RuleDetectorSuite
from sih26145.models.suite import MLModelSuite
from sih26145.alerts.aggregator import EvidenceAggregator
from sih26145.storage.database import AlertStorage
from sih26145.alerts.models import Alert


class ThreatDetectionPipeline:
    """End-to-End Unidirectional Cyber Threat Detection Pipeline."""

    def __init__(self, db_path: Optional[str] = None):
        self.flow_tracker = FlowTracker(max_flows=10000, idle_timeout=15.0, active_timeout=60.0)
        self.feature_extractor = FeatureExtractor()
        self.rule_suite = RuleDetectorSuite()
        self.ml_suite = MLModelSuite()
        self.aggregator = EvidenceAggregator()
        self.storage = AlertStorage(db_path)

    async def init(self):
        """Initialize pipeline storage."""
        await self.storage.init_db()

    async def process_pcap(self, pcap_path: str, alert_queue: Optional[asyncio.Queue] = None) -> List[Alert]:
        """Process a PCAP file end-to-end and persist alerts."""
        await self.init()
        reader = PcapReader(pcap_path)
        generated_alerts: List[Alert] = []

        last_pkt_time = 0.0
        for pkt in reader:
            if pkt is None:
                continue
            last_pkt_time = pkt.timestamp
            flushed_flows = self.flow_tracker.process_packet(pkt)
            for flow in flushed_flows:
                fv = self.feature_extractor.extract(flow)
                rule_hits = self.rule_suite.evaluate(fv)
                ml_preds = self.ml_suite.predict(fv)

                final_alerts = self.aggregator.aggregate(
                    flow=flow,
                    fv=fv,
                    rule_hits=rule_hits,
                    ml_predictions=ml_preds,
                )

                for alert in final_alerts:
                    await self.storage.save_alert(alert)
                    if alert_queue is not None:
                        await alert_queue.put(alert.to_dict())
                    generated_alerts.append(alert)

        # Flush all remaining active flows at the end of PCAP
        remaining_flows = self.flow_tracker.flush_expired(last_pkt_time + 100.0)
        for flow in list(self.flow_tracker._active_flows.values()):
            if flow not in remaining_flows:
                remaining_flows.append(flow)

        for flow in remaining_flows:
            fv = self.feature_extractor.extract(flow)
            rule_hits = self.rule_suite.evaluate(fv)
            ml_preds = self.ml_suite.predict(fv)
            final_alerts = self.aggregator.aggregate(
                flow=flow,
                fv=fv,
                rule_hits=rule_hits,
                ml_predictions=ml_preds,
            )
            for alert in final_alerts:
                await self.storage.save_alert(alert)
                if alert_queue is not None:
                    await alert_queue.put(alert.to_dict())
                generated_alerts.append(alert)

        return generated_alerts
