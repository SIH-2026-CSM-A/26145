"""Pipeline Orchestrator for SIH26145 Threat Engine."""

import asyncio
from typing import Callable, List, Optional

from sih26145 import bundle
from sih26145.alerts.aggregator import EvidenceAggregator, WindowTopFlows, provisional_alert
from sih26145.alerts.models import Alert
from sih26145.correlate import Correlator, tactic
from sih26145.detectors.context import DetectionContext
from sih26145.detectors.fastlane import FastLane
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

# The flow-lane detector that confirms each fast-lane class (same threat class, same entity).
CONFIRMED_BY = {"THREAT_DDOS_VOLUME": "ddos_volume_detector", "THREAT_RECON_PORTSCAN": "recon_portscan_detector"}
PROVISIONAL_CAP = 4096


class ThreatDetectionPipeline:
    """End-to-end pipeline: flows -> tier-2 store -> detectors -> alerts -> storage -> publish.

    `storage` and `publish` let the `serve` command share the API's AlertStorage and SSE
    broadcaster; `publish` receives each alert as a dict as soon as it is stored.
    `feature_sink(flow, row)` receives each flow's model input row (the feature dump);
    `ml=False` skips model scoring.
    """

    def __init__(self, db_path: Optional[str] = None, storage: Optional[AlertStorage] = None,
                 publish: Optional[Callable[[dict], None]] = None,
                 feature_sink: Optional[Callable[[FlowRecord, dict], None]] = None, ml: bool = True,
                 bundle_path: Optional[str] = None, bundle_pubkey: Optional[str] = None):
        # Signed update bundle (docs/MODELS.md §8): signature and hashes first, then the code's
        # thresholds, contract and lists must equal the signed ones; models load from its bytes.
        files = bundle.load_verified(bundle_path, pubkey=bundle_pubkey)
        bundle.check_code_matches(files)
        self.flow_tracker = FlowTracker(max_flows=10000, idle_timeout=15.0, active_timeout=60.0)
        self.feature_extractor = FeatureExtractor()
        self.rule_suite = RuleDetectorSuite()
        self.ml_suite = MLModelSuite(files) if ml else None
        self.feature_sink = feature_sink
        self.storage = storage or AlertStorage(db_path)
        self.publish = publish
        self.policy = NetworkPolicy.from_env()
        self.feature_store = FeatureStore(policy=self.policy)
        self.aggregator = EvidenceAggregator(top=WindowTopFlows(self.feature_store.cfg.window))
        self.correlator = Correlator()
        self.fast_lane = FastLane()
        self._provisional: dict = {}  # (threat_class, entity) -> (alert_id, event time)
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
            self.aggregator.top.update(flow)
            fv = self.feature_extractor.extract(flow)
            ctx = DetectionContext(flow, self.feature_store, self.policy)
            row = model_row(fv, ctx)
            if self.feature_sink is not None:
                self.feature_sink(flow, row)
            staged.append((flow, fv, row, self.rule_suite.evaluate(fv, ctx), self.correlator.observe(ctx)))
        preds = (self.ml_suite.predict_batch([s[2] for s in staged]) if self.ml_suite is not None
                 else [[] for _ in staged])
        out = []
        for (flow, fv, _, rule_hits, pivots), ml_preds in zip(staged, preds):
            alerts = self.aggregator.aggregate(flow=flow, fv=fv, rule_hits=rule_hits, ml_predictions=ml_preds)
            self.correlator.assign(alerts, pivots)
            for alert in alerts:
                self._confirm(alert, flow.last_time)
                await self._store(alert)
            out.append(alerts)
        return out

    async def _store(self, alert: Alert) -> None:
        await self.storage.save_alert(alert)
        if self.publish is not None:
            self.publish(alert.to_dict())

    def _confirm(self, alert: Alert, t: float) -> None:
        """A flow-lane alert on an entity the fast lane flagged names that provisional alert."""
        entity = alert.detection.get("entity")
        p = self._provisional.get((alert.threat_class, entity)) if entity else None
        if p is not None and abs(t - p[1]) < self.rule_suite.dedupe_seconds:
            alert.confirms = p[0]

    async def raise_provisional(self, closed) -> List[Alert]:
        """Alerts for one closed fast-lane window. One per (class, entity) per dedupe period, and
        none when the flow lane already reported that entity in the period."""
        win, hits = closed
        t, period, out = win.start + 1.0, self.rule_suite.dedupe_seconds, []
        for scope, hit in hits:
            key = (hit.threat_class, hit.entity)
            last = self._provisional.get(key)
            fired = self.rule_suite.last_fired(CONFIRMED_BY[hit.threat_class], hit.entity)
            if (last is not None and t - last[1] < period) or (fired is not None and abs(t - fired) < period):
                continue
            alert = provisional_alert(scope, hit, win)
            tid, tname = tactic(hit.threat_class)
            alert.host_stage = tid
            alert.detection["correlation"] = {
                "campaign_id": None, "host": hit.entity, "tactic": tname, "joined_on": [], "not_merged": [],
                "refused_pivots": [], "note": "provisional: correlated when the flow lane confirms"}
            self._provisional[key] = (alert.alert_id, t)
            if len(self._provisional) > PROVISIONAL_CAP:
                self._provisional.pop(next(iter(self._provisional)))
            await self._store(alert)
            out.append(alert)
        return out
