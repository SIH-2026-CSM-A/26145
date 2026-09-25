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
from sih26145.detectors.context import DetectionContext
from sih26145.features.directional import NetworkPolicy
from sih26145.features.store import FeatureStore
from sih26145.flow.models import FlowRecord


class ThreatDetectionPipeline:
    """End-to-End Unidirectional Cyber Threat Detection Pipeline."""

    def __init__(self, db_path: Optional[str] = None):
        self.flow_tracker = FlowTracker(max_flows=10000, idle_timeout=15.0, active_timeout=60.0)
        self.feature_extractor = FeatureExtractor()
        self.rule_suite = RuleDetectorSuite()
        self.ml_suite = MLModelSuite()
        self.aggregator = EvidenceAggregator()
        self.storage = AlertStorage(db_path)
        self.policy = NetworkPolicy.from_env()
        self.feature_store = FeatureStore(policy=self.policy)

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
            for flow in self.flow_tracker.process_packet(pkt):
                await self._score(flow, alert_queue, generated_alerts)

        # Flush all remaining active flows at the end of PCAP
        remaining_flows = self.flow_tracker.flush_expired(last_pkt_time + 100.0)
        for flow in list(self.flow_tracker._active_flows.values()):
            if flow not in remaining_flows:
                remaining_flows.append(flow)
        for flow in remaining_flows:
            await self._score(flow, alert_queue, generated_alerts)

        return generated_alerts

    async def _score(self, flow: FlowRecord, alert_queue: Optional[asyncio.Queue], out: List[Alert]):
        """Tier-2 update, then rules + ML on the flow, then persist and publish."""
        self.feature_store.update(flow)
        fv = self.feature_extractor.extract(flow)
        ctx = DetectionContext(flow, self.feature_store, self.policy)
        rule_hits = self.rule_suite.evaluate(fv, ctx)
        ml_preds = self.ml_suite.predict(fv)
        for alert in self.aggregator.aggregate(flow=flow, fv=fv, rule_hits=rule_hits, ml_predictions=ml_preds):
            await self.storage.save_alert(alert)
            if alert_queue is not None:
                await alert_queue.put(alert.to_dict())
            out.append(alert)
