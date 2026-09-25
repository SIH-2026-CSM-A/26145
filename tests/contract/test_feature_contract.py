"""The contract is internally consistent, and every consumer reads only what it declares."""

import ast
import dataclasses
import inspect

import pytest

import sih26145.detectors.rules.detectors as rule_detectors
import sih26145.models.anomaly as anomaly
from sih26145.contract import UnavailableFeatureError, load_contract, parse_contract
from sih26145.features.models import FeatureVector

# Calls through which detectors read context features; the first argument must be a literal.
FEATURE_CALLS = {"flow_feature", "store_feature"}


def scan_reads(node: ast.AST, fv_names=("fv",)) -> set:
    """Collect feature names read by `fv.<attr>` and ctx.flow_feature/store_feature("<name>")."""
    reads = set()
    for n in ast.walk(node):
        if isinstance(n, ast.Attribute) and isinstance(n.value, ast.Name) and n.value.id in fv_names:
            reads.add(n.attr)
        elif isinstance(n, ast.Call) and isinstance(n.func, ast.Attribute) and n.func.attr in FEATURE_CALLS:
            arg = n.args[0] if n.args else None
            if not (isinstance(arg, ast.Constant) and isinstance(arg.value, str)):
                raise AssertionError(
                    f"line {n.lineno}: {n.func.attr}() must take a string literal so the contract scan is complete"
                )
            reads.add(arg.value)
    return reads


def detector_classes():
    tree = ast.parse(inspect.getsource(rule_detectors))
    for cls in tree.body:
        if not isinstance(cls, ast.ClassDef):
            continue
        if not any(isinstance(f, ast.FunctionDef) and f.name == "detect" for f in cls.body):
            continue
        name = next(
            s.value.value for s in cls.body
            if isinstance(s, ast.Assign) and s.targets[0].id == "name"
        )
        yield name, cls


def test_contract_file_is_internally_valid():
    assert load_contract().validate() == []


@pytest.mark.parametrize("name,cls", list(detector_classes()), ids=lambda x: x if isinstance(x, str) else "")
def test_detector_reads_match_declaration_and_tier(name, cls):
    contract = load_contract()
    reads = scan_reads(cls)
    assert contract.read_violations(name, reads) == []
    assert reads == set(contract.consumer(name).reads), "declared reads drifted from the code"


def test_ml_feature_array_reads_match_declaration():
    contract = load_contract()
    fn = ast.parse(inspect.getsource(anomaly.feature_vector_to_array))
    reads = scan_reads(fn)
    assert contract.read_violations("ml_flow_models", reads) == []
    assert reads == set(contract.consumer("ml_flow_models").reads)


def test_every_feature_vector_field_is_declared():
    contract = load_contract()
    fields = {f.name for f in dataclasses.fields(FeatureVector)} - {"flow_key_str"}
    assert fields - set(contract.features) == set()


def test_checker_rejects_over_tier_unavailable_and_undeclared_reads():
    contract = parse_contract({
        "contract_version": "t",
        "features": [
            {"name": "a", "state": "computable", "tier": "flow", "approx": "exact", "sources": [], "reason": ""},
            {"name": "b", "state": "degraded", "tier": "flow", "approx": "exact", "sources": [], "reason": ""},
            {"name": "c", "state": "reverse_dependent", "tier": "flow", "approx": "exact", "sources": [], "reason": ""},
            {"name": "d", "state": "unavailable", "tier": "flow", "approx": "exact", "sources": [], "reason": ""},
        ],
        "consumers": {"det": {"ps_class": "x", "max_state": "degraded", "reads": ["a", "b"]}},
    })
    assert contract.read_violations("det", {"a", "b"}) == []
    assert len(contract.read_violations("det", {"c"})) == 1      # above tier
    assert len(contract.read_violations("det", {"d"})) == 1      # unavailable
    assert len(contract.read_violations("det", {"zzz"})) == 1    # undeclared
    assert len(contract.read_violations("nobody", {"a"})) == 1   # undeclared consumer


def test_scan_rejects_non_literal_feature_names():
    tree = ast.parse("def detect(self, fv, ctx):\n    name = 'x'\n    return ctx.flow_feature(name)\n")
    with pytest.raises(AssertionError, match="string literal"):
        scan_reads(tree)


def test_unavailable_features_cannot_be_required():
    contract = load_contract()
    unavailable = [f.name for f in contract.features.values() if f.state == "unavailable"]
    assert "quic_client_hello" in unavailable
    for name in unavailable:
        with pytest.raises(UnavailableFeatureError):
            contract.require(name)


def test_reverse_dependent_set_matches_the_design():
    contract = load_contract()
    rd = {f.name for f in contract.features.values() if f.state == "reverse_dependent"}
    assert {"outbound_inbound_byte_ratio", "tcp_handshake_completed", "tcp_rtt", "dns_nxdomain_rate"} <= rd
