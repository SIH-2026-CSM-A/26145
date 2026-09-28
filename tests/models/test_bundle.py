"""Signed update bundles (docs/MODELS.md §8): the sensor refuses a tampered, wrongly signed or
unsigned bundle, and verification runs before any model is deserialised."""

import io
import shutil
import tarfile

import pytest

from sih26145 import bundle
from sih26145.bundle import BundleError
from sih26145.orchestrator import ThreatDetectionPipeline


@pytest.fixture(scope="module")
def signed(tmp_path_factory):
    """A bundle built from the package's artefacts and signed with a throwaway test key."""
    d = tmp_path_factory.mktemp("bundle")
    pub = bundle.keygen(str(d / "test.pem"))
    tar = d / "b.tar"
    bundle.build(str(tar))
    bundle.sign(str(tar), str(d / "test.pem"))
    return d, tar, pub


def _copy(signed, tmp_path):
    d, tar, pub = signed
    shutil.copy(tar, tmp_path / "b.tar")
    shutil.copy(str(tar) + ".sig", tmp_path / "b.tar.sig")
    return tmp_path / "b.tar", pub


def _rewrite_member(path, name, change):
    """Rebuild the tar with one member's bytes changed (the manifest is left alone)."""
    src = tarfile.open(path)
    members = [(m, src.extractfile(m).read()) for m in src.getmembers()]
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w", format=tarfile.USTAR_FORMAT) as out:
        for m, data in members:
            data = change(data) if m.name == name else data
            m.size = len(data)
            out.addfile(m, io.BytesIO(data))
    path.write_bytes(buf.getvalue())


@pytest.fixture
def no_deserialise(monkeypatch):
    """Fail the test if any model deserialiser is reached."""
    calls = []
    import skops.io
    import lightgbm
    monkeypatch.setattr(skops.io, "loads", lambda *a, **k: calls.append("skops") or pytest.fail("skops.loads reached"))
    monkeypatch.setattr(lightgbm, "Booster", lambda *a, **k: calls.append("lgbm") or pytest.fail("Booster reached"))
    return calls


def test_valid_bundle_verifies(signed):
    d, tar, pub = signed
    files = bundle.load_verified(str(tar), pubkey=pub)
    assert {"models/lgbm.txt", "models/iforest.skops", "ruleset.json", "feature_contract.toml"} <= set(files)
    bundle.check_code_matches(files)


def test_tampered_model_file_is_refused_before_loading(signed, tmp_path, no_deserialise):
    tar, pub = _copy(signed, tmp_path)
    _rewrite_member(tar, "models/iforest.skops", lambda b: b[:-1] + bytes([b[-1] ^ 1]))
    with pytest.raises(BundleError, match="signature does not verify"):
        ThreatDetectionPipeline(":memory:", bundle_path=str(tar), bundle_pubkey=pub)
    assert no_deserialise == []


def test_re_signed_tampered_file_fails_its_hash(signed, tmp_path, no_deserialise):
    """Even a correctly signed tar is refused when a member differs from MANIFEST.json."""
    d, _, pub = signed
    tar, _ = _copy(signed, tmp_path)
    _rewrite_member(tar, "models/lgbm.txt", lambda b: b + b"\n")
    bundle.sign(str(tar), str(d / "test.pem"))
    with pytest.raises(BundleError, match="lgbm.txt sha256"):
        bundle.load_verified(str(tar), pubkey=pub)
    assert no_deserialise == []


def test_wrong_key_is_refused(signed, tmp_path, no_deserialise):
    tar, _ = _copy(signed, tmp_path)
    other = bundle.keygen(str(tmp_path / "other.pem"))
    with pytest.raises(BundleError, match="signature does not verify"):
        ThreatDetectionPipeline(":memory:", bundle_path=str(tar), bundle_pubkey=other)
    assert no_deserialise == []


def test_unsigned_bundle_is_refused(signed, tmp_path, no_deserialise):
    tar, pub = _copy(signed, tmp_path)
    (tmp_path / "b.tar.sig").unlink()
    with pytest.raises(BundleError, match="unsigned"):
        ThreatDetectionPipeline(":memory:", bundle_path=str(tar), bundle_pubkey=pub)
    assert no_deserialise == []


def test_threshold_changed_in_code_is_refused(signed, monkeypatch):
    from sih26145.detectors.rules.detectors import DDoSVolumeDetector
    d, tar, pub = signed
    files = bundle.load_verified(str(tar), pubkey=pub)
    monkeypatch.setattr(DDoSVolumeDetector, "MIN_SRCS", 150)
    with pytest.raises(BundleError, match="ddos_volume_detector.MIN_SRCS: code 150, bundle 200"):
        bundle.check_code_matches(files)


def test_committed_bundle_verifies_with_the_pinned_key():
    files = bundle.load_verified()  # committed tar + .sig, config/bundle_ed25519.pub
    bundle.check_code_matches(files)


def test_bundle_build_is_deterministic(tmp_path):
    bundle.build(str(tmp_path / "a.tar"))
    bundle.build(str(tmp_path / "b.tar"))
    assert (tmp_path / "a.tar").read_bytes() == (tmp_path / "b.tar").read_bytes() == bundle.BUNDLE_PATH.read_bytes()


def test_private_key_is_not_in_the_repository():
    """No tracked or staged file holds a PEM private key."""
    import subprocess
    marker = "BEGIN " + "PRIVATE KEY"
    res = subprocess.run(["git", "grep", "--cached", "-l", marker], cwd=bundle.PKG.parents[1],
                         capture_output=True, text=True)
    assert res.returncode == 1 and res.stdout == "", res.stdout


@pytest.mark.asyncio
async def test_valid_bundle_gives_the_demo_its_same_ten_alerts(monkeypatch):
    monkeypatch.setenv("SIH26145_INTERNAL_CIDRS", "147.32.0.0/16,10.0.0.0/8,192.168.0.0/16,172.16.0.0/12")
    pipeline = ThreatDetectionPipeline(":memory:", bundle_path=str(bundle.BUNDLE_PATH),
                                       bundle_pubkey=bundle.PUBKEY_PATH.read_text())
    try:
        alerts = await pipeline.process_pcap(str(bundle.PKG.parents[1] / "demo" / "demo.pcap"))
    finally:
        await pipeline.storage.close()
    flow_lane = sorted(a.detection["rule_matches"][0] for a in alerts if not a.provisional)
    assert flow_lane == sorted(["RULE_DDOS_SYN_FLOOD", "RULE_EXFIL_OUTBOUND_RATIO", "RULE_DNS_TUNNEL_VOLUME_LENGTH",
                                "RULE_C2_PERIODIC_FLOWS", "RULE_C2_PERIODIC_FLOWS", "RULE_C2_PERIODIC_FLOWS",
                                "RULE_C2_PERIODIC_FLOWS", "RULE_DGA_NXDOMAIN_HIGH_ENTROPY",
                                "RULE_TLS_RARE_JA4_REPEATED", "RULE_RECON_FANOUT_SYN_ONLY"])
