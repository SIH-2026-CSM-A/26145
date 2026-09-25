"""What a detector may see beyond its FeatureVector: the flow, the tier-2 store, the policy."""

from dataclasses import dataclass
from typing import Any

from sih26145.features.directional import NetworkPolicy, flow_feature
from sih26145.features.store import FeatureStore
from sih26145.flow.models import FlowRecord


@dataclass
class DetectionContext:
    flow: FlowRecord
    store: FeatureStore
    policy: NetworkPolicy

    # Detectors must pass feature names as string literals: tests/contract scans these calls.
    def flow_feature(self, name: str) -> Any:
        return flow_feature(self.flow, name, self.policy)

    def store_feature(self, name: str, key: Any = None) -> Any:
        return self.store.get(name, key)

    def internal_and_external(self):
        """(internal endpoint, external endpoint) of a boundary-crossing flow."""
        key = self.flow.flow_key
        if self.policy.is_internal(key.src_ip):
            return key.src_ip, key.dst_ip
        return key.dst_ip, key.src_ip
