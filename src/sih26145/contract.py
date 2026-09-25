"""Loader and checks for the Unidirectional Feature Contract (feature_contract.toml)."""

import tomllib
from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path
from typing import Dict, List, Optional, Tuple

CONTRACT_PATH = Path(__file__).with_name("feature_contract.toml")

STATES = ("computable", "degraded", "reverse_dependent", "unavailable")
# Order used for consumer tier checks; "unavailable" is never readable.
STATE_RANK = {"computable": 0, "degraded": 1, "reverse_dependent": 2}


class UnavailableFeatureError(LookupError):
    """A feature was requested that this capture, or this flow, cannot provide."""


@dataclass(frozen=True)
class Feature:
    name: str
    state: str
    tier: str
    approx: str
    sources: Tuple[str, ...]
    reason: str
    substitutes: Tuple[str, ...] = ()


@dataclass(frozen=True)
class Consumer:
    name: str
    ps_class: str
    max_state: str
    reads: Tuple[str, ...]


class FeatureContract:
    def __init__(self, version: str, features: Dict[str, Feature], consumers: Dict[str, Consumer]):
        self.version = version
        self.features = features
        self.consumers = consumers

    def feature(self, name: str) -> Feature:
        if name not in self.features:
            raise KeyError(f"feature {name!r} is not declared in the contract")
        return self.features[name]

    def state(self, name: str) -> str:
        return self.feature(name).state

    def require(self, name: str) -> Feature:
        """Return the feature, raising if it can never be computed here."""
        f = self.feature(name)
        if f.state == "unavailable":
            raise UnavailableFeatureError(f"{name}: {f.reason}")
        return f

    def consumer(self, name: str) -> Consumer:
        return self.consumers[name]

    def read_violations(self, consumer: str, reads) -> List[str]:
        """Why `reads` breaks `consumer`'s declaration (empty list = compliant)."""
        c = self.consumers.get(consumer)
        if c is None:
            return [f"{consumer}: not declared as a consumer"]
        errors = []
        for name in sorted(set(reads)):
            f = self.features.get(name)
            if f is None:
                errors.append(f"{consumer}: reads undeclared feature {name!r}")
            elif f.state == "unavailable":
                errors.append(f"{consumer}: reads unavailable feature {name!r}")
            elif STATE_RANK[f.state] > STATE_RANK[c.max_state]:
                errors.append(f"{consumer}: reads {f.state} {name!r} above its tier {c.max_state!r}")
        return errors

    def validate(self) -> List[str]:
        """Internal consistency of the contract file itself."""
        errors = []
        for f in self.features.values():
            if f.state not in STATES:
                errors.append(f"{f.name}: unknown state {f.state!r}")
            for s in f.substitutes:
                if s not in self.features:
                    errors.append(f"{f.name}: substitute {s!r} is not declared")
        for c in self.consumers.values():
            if c.max_state not in STATE_RANK:
                errors.append(f"{c.name}: invalid max_state {c.max_state!r}")
                continue
            errors += self.read_violations(c.name, c.reads)
        return errors


def parse_contract(data: dict) -> FeatureContract:
    features = {}
    for row in data["features"]:
        if row["name"] in features:
            raise ValueError(f"duplicate feature {row['name']!r}")
        features[row["name"]] = Feature(
            name=row["name"], state=row["state"], tier=row["tier"], approx=row["approx"],
            sources=tuple(row["sources"]), reason=row["reason"],
            substitutes=tuple(row.get("substitutes", ())),
        )
    consumers = {
        name: Consumer(name=name, ps_class=c["ps_class"], max_state=c["max_state"], reads=tuple(c["reads"]))
        for name, c in data.get("consumers", {}).items()
    }
    return FeatureContract(data["contract_version"], features, consumers)


@lru_cache(maxsize=None)
def load_contract(path: Optional[str] = None) -> FeatureContract:
    with open(path or CONTRACT_PATH, "rb") as fh:
        return parse_contract(tomllib.load(fh))
