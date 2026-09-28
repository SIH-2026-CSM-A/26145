"""Trained IsolationForest: novelty against benign flows (docs/MODELS.md)."""

import io
import json
import zipfile

import numpy as np
import skops.io

NAN_SENTINEL = -1.0  # undefined store features (warm-up, < 2 gaps); every real value is >= 0
# The only type in the artefact outside skops' default-trusted set (checked with
# skops.io.get_untrusted_types when the artefact was converted; docs/MODELS.md §8).
TRUSTED_TYPES = ["sklearn.tree._tree.Tree"]


def impute(X: np.ndarray) -> np.ndarray:
    """IsolationForest cannot split on NaN; undefined values get a value no real one takes."""
    return np.where(np.isnan(X), NAN_SENTINEL, X)


def dump_skops(model) -> bytes:
    """skops bytes that are the same for the same model every time. skops names members and
    `__id__`s after Python object ids (memory addresses); they are renumbered in order of first
    appearance in schema.json. sklearn's tree node arrays carry a 7-byte padding field of
    uninitialised memory; it is zeroed. Zip timestamps are fixed."""
    src = zipfile.ZipFile(io.BytesIO(skops.io.dumps(model)))
    schema, ids, names = json.loads(src.read("schema.json")), {}, {}

    def walk(node):
        if isinstance(node, dict):
            for k, v in node.items():
                if k == "__id__":
                    node[k] = ids.setdefault(v, len(ids) + 1)
                elif k == "file" and isinstance(v, str) and v.endswith(".npy"):
                    node[k] = names.setdefault(v, f"{len(names) + 1}.npy")
                else:
                    walk(v)
        elif isinstance(node, list):
            for v in node:
                walk(v)

    walk(schema)
    out = io.BytesIO()
    with zipfile.ZipFile(out, "w", zipfile.ZIP_DEFLATED) as dst:
        dst.writestr(zipfile.ZipInfo("schema.json", (1980, 1, 1, 0, 0, 0)), json.dumps(schema, indent=2))
        for old, new in sorted(names.items(), key=lambda kv: int(kv[1][:-4])):
            dst.writestr(zipfile.ZipInfo(new, (1980, 1, 1, 0, 0, 0)), _zero_padding(src.read(old)))
    return out.getvalue()


def _zero_padding(npy: bytes) -> bytes:
    """Zero the bytes of a structured array that no field covers (alignment padding)."""
    arr = np.load(io.BytesIO(npy), allow_pickle=False)
    if not arr.dtype.names:
        return npy
    covered = np.zeros(arr.dtype.itemsize, dtype=bool)
    for dt, off, *_ in arr.dtype.fields.values():
        covered[off:off + dt.itemsize] = True
    if covered.all():
        return npy
    raw = np.ascontiguousarray(arr).view(np.uint8).reshape(-1, arr.dtype.itemsize).copy()
    raw[:, ~covered] = 0
    buf = io.BytesIO()
    np.save(buf, raw.view(arr.dtype).reshape(arr.shape), allow_pickle=False)
    return buf.getvalue()


class IsolationForestFlowModel:
    model_name = "isolation_forest_flow_model"
    threat_class = "THREAT_UNSUPERVISED_ANOMALY"

    def __init__(self, data: bytes, threshold: float, benign_quantiles):
        """`data`: skops bytes from a verified bundle (bundle.load_verified). No pickle is used:
        skops refuses any type outside its defaults and TRUSTED_TYPES."""
        self.model = skops.io.loads(data, trusted=TRUSTED_TYPES)
        self.model.set_params(n_jobs=1)
        self.threshold = threshold
        self.benign_quantiles = np.asarray(benign_quantiles, dtype=np.float64)

    def scores(self, X: np.ndarray) -> np.ndarray:
        """Higher = more anomalous (negated score_samples)."""
        return -self.model.score_samples(impute(X))

    def confidence(self, scores: np.ndarray) -> np.ndarray:
        """Share of out-of-fold benign flows scoring lower: a percentile, not a probability."""
        q = self.benign_quantiles
        return np.searchsorted(q, scores, side="right") / len(q)
