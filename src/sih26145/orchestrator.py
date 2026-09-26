"""Pipeline Orchestrator for SIH26145 Threat Engine."""

import asyncio
from typing import Callable, List, Optional

from sih26145.alerts.aggregator import EvidenceAggregator
from sih26145.alerts.models import Alert
from sih26145.detectors.context import DetectionContext
from sih26145.detectors.rules.suite import RuleDetectorSuite
from sih26145.features.directional import NetworkPolicy
from sih26145.features.extractor import FeatureExtractor
from sih26145.features.store import FeatureStore
from sih26145.flow.models import FlowRecord
from sih26145.flow.tracker import FlowTracker
from sih26145.models.features import model_row
from sih26145.models.suite import MLModelSuite
from sih26145.storage.database import AlertStorage
from sih26145.streaming import run_stream


class ThreatDetectionPipeline:
    """End-to-end pipeline: flows -> tier-2 store -> detectors -> alerts -> storage -> publish.

    `storage` and `publish` let the `serve` command share the API's AlertStorage and SSE
    broadcaster; `publish` receives each alert as a dict as soon as it is stored.
    `feature_sink(flow, row)` receives each flow's model input row (the feature dump);
    `ml=False` skips model scoring.
    """

    def __init__(self, db_path: Optional[str] = None, storage: Optional[AlertStorage] = None,
                 publish: Optional[Callable[[dict], None]] = None,
                 feature_sink: Optional[Callable[[FlowRecord, dict], None]] = None, ml: bool = True):
        self.flow_tracker = FlowTracker(max_flows=10000, idle_timeout=15.0, active_timeout=60.0)
        self.feature_extractor = FeatureExtractor()
        self.rule_suite = RuleDetectorSuite()
        self.ml_suite = MLModelSuite() if ml else None
        self.feature_sink = feature_sink
        self.aggregator = EvidenceAggregator()
        self.storage = storage or AlertStorage(db_path)
        self.publish = publish
        self.policy = NetworkPolicy.from_env()
        self.feature_store = FeatureStore(policy=self.policy)
        self.last_metrics = None

    async def init(self):
        """Initialize pipeline storage."""
        await self.storage.init_db()

    async def process_pcap(self, pcap_path: str, alert_queue: Optional[asyncio.Queue] = None) -> List[Alert]:
        """Analyse a capture as fast as possible (lossless) and return its alerts."""
        await self.init()
        out: List[Alert] = []

        def collect(alert: Alert) -> None:
            out.append(alert)
            if alert_queue is not None:
                alert_queue.put_nowait(alert.to_dict())

        self.last_metrics = await run_stream(self, pcap_path, on_alert=collect)
        return out

    async def score(self, flow: FlowRecord) -> List[Alert]:
        """Score one flow (a batch of one)."""
        return (await self.score_batch([flow]))[0]

    async def score_batch(self, flows: List[FlowRecord]) -> List[List[Alert]]:
        """Per flow, in order: tier-2 update, features, rules, model row. Each row is taken at
        its own flow's scoring time, before the next flow's update. Then one predict call per
        model for the whole batch, then each flow's alerts are persisted and published."""
        staged = []
        for flow in flows:
            self.feature_store.update(flow)
            fv = self.feature_extractor.extract(flow)
            ctx = DetectionContext(flow, self.feature_store, self.policy)
            row = model_row(fv, ctx)
            if self.feature_sink is not None:
                self.feature_sink(flow, row)
            staged.append((flow, fv, row, self.rule_suite.evaluate(fv, ctx)))
        preds = (self.ml_suite.predict_batch([s[2] for s in staged]) if self.ml_suite is not None
                 else [[] for _ in staged])
        out = []
        for (flow, fv, _, rule_hits), ml_preds in zip(staged, preds):
            alerts = self.aggregator.aggregate(flow=flow, fv=fv, rule_hits=rule_hits, ml_predictions=ml_preds)
            for alert in alerts:
                await self.storage.save_alert(alert)
                if self.publish is not None:
                    self.publish(alert.to_dict())
            out.append(alerts)
        return out
