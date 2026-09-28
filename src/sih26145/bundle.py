"""Signed offline update bundles (docs/MODELS.md §8).

A bundle is an uncompressed, deterministic tar holding everything that decides what the sensor
flags:

    MANIFEST.json          format, versions, and the sha256 of every other member
    models/manifest.json   the model manifest written by scripts/train_models.py
    models/lgbm.txt        LightGBM text model
    models/iforest.skops   IsolationForest (skops format, loaded with an explicit type list)
    ruleset.json           every rule and fast-lane threshold, generated from the code
    lists/*.txt            the default poller allowlist and known-bad JA4 list
    feature_contract.toml

and a detached `<bundle>.sig`: the base64 Ed25519 signature over the tar's bytes. The public key is
pinned in `config/bundle_ed25519.pub`; the private key never enters the repository.

`load_verified` checks, in this order, before anything in the bundle is parsed: the signature is
present, the signature verifies over the exact bytes, then (tar parsed in memory) the member set
equals MANIFEST.json's and every sha256 matches. Only then are the files handed out, as bytes.
"""

import base64
import hashlib
import inspect
import io
import json
import os
import stat
import tarfile
from pathlib import Path
from typing import Dict, Optional

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey

PKG = Path(__file__).resolve().parent
PUBKEY_PATH = PKG / "config" / "bundle_ed25519.pub"
BUNDLE_PATH = PKG / "models" / "bundle" / "saakshi-models.tar"
ARTIFACTS = PKG / "models" / "artifacts"
FORMAT = "saakshi-bundle/1"
LISTS = ("poller_allowlist.txt", "ja4_known_bad.txt")


class BundleError(Exception):
    """The bundle is unsigned, signed by another key, altered, or does not match this code."""


# ---- keys and signatures -------------------------------------------------------------------
def keygen(private_path: str, public_path: Optional[str] = None) -> str:
    """Write a new Ed25519 private key (PKCS8 PEM, mode 0600; refuses to overwrite) and return the
    public key as base64 of its 32 raw bytes (also written to public_path if given)."""
    key = Ed25519PrivateKey.generate()
    pem = key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                            serialization.NoEncryption())
    Path(private_path).parent.mkdir(parents=True, exist_ok=True)
    fd = os.open(private_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, stat.S_IRUSR | stat.S_IWUSR)
    with os.fdopen(fd, "wb") as fh:
        fh.write(pem)
    pub = base64.b64encode(key.public_key().public_bytes(serialization.Encoding.Raw,
                                                         serialization.PublicFormat.Raw)).decode()
    if public_path:
        Path(public_path).write_text(pub + "\n")
    return pub


def sign(bundle_path: str, private_path: str) -> str:
    key = serialization.load_pem_private_key(Path(private_path).read_bytes(), password=None)
    if not isinstance(key, Ed25519PrivateKey):
        raise BundleError(f"{private_path}: not an Ed25519 private key")
    sig_path = str(bundle_path) + ".sig"
    Path(sig_path).write_text(base64.b64encode(key.sign(Path(bundle_path).read_bytes())).decode() + "\n")
    return sig_path


def _public_key(pubkey: Optional[str]) -> Ed25519PublicKey:
    raw = base64.b64decode((pubkey if pubkey is not None else PUBKEY_PATH.read_text()).strip(), validate=True)
    return Ed25519PublicKey.from_public_bytes(raw)


# ---- the ruleset as data -------------------------------------------------------------------
def ruleset_from_code() -> dict:
    """Every upper-case numeric/string constant of every rule detector and of the fast lane,
    plus the ruleset version and the dedupe period: what ruleset.json must equal."""
    from sih26145.detectors import fastlane
    from sih26145.detectors.models import RULESET_VERSION
    from sih26145.detectors.rules import detectors
    from sih26145.detectors.rules.suite import RuleDetectorSuite

    classes = [c for _, c in inspect.getmembers(detectors, inspect.isclass)
               if c.__module__ == detectors.__name__ and hasattr(c, "detect")] + [fastlane.FastLaneDetector]
    rules = {}
    for cls in sorted(classes, key=lambda c: c.__name__):
        consts = {k: v for k, v in vars(cls).items()
                  if k.isupper() and isinstance(v, (int, float, str)) and not isinstance(v, bool)}
        rules[cls.name] = dict(sorted(consts.items()))
    return {"ruleset_version": RULESET_VERSION,
            "dedupe_seconds": inspect.signature(RuleDetectorSuite.__init__).parameters["dedupe_seconds"].default,
            "fastlane_window_s": fastlane.WINDOW_S, "detectors": rules}


# ---- build ---------------------------------------------------------------------------------
def _canonical(obj) -> bytes:
    return (json.dumps(obj, indent=2, sort_keys=True) + "\n").encode()


def build(out_path: str, artifacts: Optional[str] = None) -> dict:
    """Pack the trained artefacts, the generated ruleset, the default lists and the contract."""
    from sih26145.contract import load_contract
    src = Path(artifacts) if artifacts else ARTIFACTS
    model_manifest = json.loads((src / "manifest.json").read_text())
    files: Dict[str, bytes] = {"models/manifest.json": (src / "manifest.json").read_bytes()}
    for key in ("lgbm", "iforest"):
        name = model_manifest[key]["file"]
        data = (src / name).read_bytes()
        if hashlib.sha256(data).hexdigest() != model_manifest[key]["sha256"]:
            raise BundleError(f"{name}: sha256 does not match models/manifest.json")
        files[f"models/{name}"] = data
    ruleset = ruleset_from_code()
    files["ruleset.json"] = _canonical(ruleset)
    for name in LISTS:
        files[f"lists/{name}"] = (PKG / "config" / name).read_bytes()
    files["feature_contract.toml"] = (PKG / "feature_contract.toml").read_bytes()
    manifest = {"format": FORMAT, "model_version": model_manifest["version"],
                "ruleset_version": ruleset["ruleset_version"], "contract_version": load_contract().version,
                "files": {p: hashlib.sha256(d).hexdigest() for p, d in sorted(files.items())}}
    files["MANIFEST.json"] = _canonical(manifest)
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w", format=tarfile.USTAR_FORMAT) as tar:
        for path in ["MANIFEST.json"] + sorted(p for p in files if p != "MANIFEST.json"):
            info = tarfile.TarInfo(path)
            info.size, info.mtime, info.mode, info.uid, info.gid = len(files[path]), 0, 0o644, 0, 0
            tar.addfile(info, io.BytesIO(files[path]))
    Path(out_path).parent.mkdir(parents=True, exist_ok=True)
    Path(out_path).write_bytes(buf.getvalue())
    return manifest


# ---- verify and load -----------------------------------------------------------------------
def load_verified(bundle_path: Optional[str] = None, sig_path: Optional[str] = None,
                  pubkey: Optional[str] = None) -> Dict[str, bytes]:
    """{member path: bytes} of a bundle whose signature and every hash verify. Raises BundleError
    otherwise. Nothing in the bundle is parsed before the signature check passes."""
    path = str(bundle_path or BUNDLE_PATH)
    sig_file = Path(sig_path or path + ".sig")
    data = Path(path).read_bytes()
    if not sig_file.exists():
        raise BundleError(f"{path}: unsigned (no {sig_file.name}); refusing to load")
    try:
        sig = base64.b64decode(sig_file.read_text().strip(), validate=True)
        _public_key(pubkey).verify(sig, data)
    except (InvalidSignature, ValueError) as e:
        raise BundleError(f"{path}: signature does not verify with the pinned public key") from e
    # signed by the pinned key: only now is the tar structure read (in memory, nothing extracted)
    with tarfile.open(fileobj=io.BytesIO(data), mode="r:") as tar:
        members: Dict[str, bytes] = {}
        for m in tar.getmembers():
            if not m.isfile() or m.name in members:
                raise BundleError(f"{path}: unexpected member {m.name!r}")
            members[m.name] = tar.extractfile(m).read()
    manifest = json.loads(members.pop("MANIFEST.json", b"null") or b"null")
    if not isinstance(manifest, dict) or manifest.get("format") != FORMAT:
        raise BundleError(f"{path}: not a {FORMAT} bundle")
    if set(manifest["files"]) != set(members):
        raise BundleError(f"{path}: members differ from MANIFEST.json")
    for name, digest in manifest["files"].items():
        if hashlib.sha256(members[name]).hexdigest() != digest:
            raise BundleError(f"{path}: {name} sha256 does not match MANIFEST.json")
    members["MANIFEST.json"] = _canonical(manifest)
    return members


def check_code_matches(files: Dict[str, bytes]) -> None:
    """The thresholds, contract and default lists this code runs with must equal the signed ones."""
    signed, code = json.loads(files["ruleset.json"]), ruleset_from_code()
    if signed != code:
        sd = signed.get("detectors", {})
        diffs = [f"{d}.{k}: code {v!r}, bundle {sd.get(d, {}).get(k)!r}"
                 for d, consts in code["detectors"].items() for k, v in consts.items() if sd.get(d, {}).get(k) != v]
        raise BundleError("rule thresholds differ from the signed ruleset: " + ("; ".join(diffs) or "versions differ"))
    if files["feature_contract.toml"] != (PKG / "feature_contract.toml").read_bytes():
        raise BundleError("feature_contract.toml differs from the signed copy")
    for name in LISTS:
        if files[f"lists/{name}"] != (PKG / "config" / name).read_bytes():
            raise BundleError(f"config/{name} differs from the signed copy")
