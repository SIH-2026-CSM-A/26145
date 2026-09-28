"""The trained flow models, loaded offline from versioned artefacts and scored in batches."""

import json
from typing import Dict, List, Optional

import numpy as np

from sih26145 import bundle
from sih26145.models.anomaly import IsolationForestFlowModel
from sih26145.models.classifier import LightGBMFlowClassifier
from sih26145.models.features import ML_FEATURES, ml_matrix
from sih26145.models.schemas import ML_MODEL_VERSION, MLPrediction

IF_EVIDENCE_NOTE = "evidence is LightGBM pred_contrib: it explains the supervised model's view, not the IsolationForest"


class MLModelSuite:
    """LightGBM + IsolationForest over the ML_FEATURES of each flow's model row."""

    def __init__(self, files: Optional[Dict[str, bytes]] = None):
        """`files`: the members of a verified bundle (bundle.load_verified). Default: the
        committed bundle, verified against the pinned key. Models load from those bytes only."""
        files = files if files is not None else bundle.load_verified()
        m = json.loads(files["models/manifest.json"])
        if m["version"] != ML_MODEL_VERSION or m["features"] != ML_FEATURES:
            raise ValueError("model artefacts do not match ML_MODEL_VERSION / ML_FEATURES; retrain")
        self.classifier = LightGBMFlowClassifier(files[f"models/{m['lgbm']['file']}"].decode(),
                                                 m["lgbm"]["threshold"], m["features"])
        self.anomaly = IsolationForestFlowModel(files[f"models/{m['iforest']['file']}"], m["iforest"]["threshold"],
                                                m["iforest"]["benign_score_quantiles"])
        # whether a model's flag may raise an alert with no rule hit (docs/MODELS.md)
        self.alone = {"lgbm": m["lgbm"]["alerts_alone"], "iforest": m["iforest"]["alerts_alone"]}

    def predict_batch(self, rows: List[Dict[str, float]]) -> List[List[MLPrediction]]:
        """One predict call per model for the whole batch; contributions only for flagged rows."""
        X = ml_matrix(rows)
        prob = self.classifier.probabilities(X)
        score = self.anomaly.scores(X)
        conf = self.anomaly.confidence(score)
        hit_c, hit_i = prob > self.classifier.threshold, score > self.anomaly.threshold
        flagged = np.flatnonzero(hit_c | hit_i)
        evidence = dict(zip(flagged, self.classifier.top_contributions(X[flagged])))
        out = []
        for i in range(len(rows)):
            ev = evidence.get(i, ())
            out.append([
                MLPrediction(self.classifier.model_name, self.classifier.threat_class, float(prob[i]), float(prob[i]),
                             bool(hit_c[i]), {"threshold": self.classifier.threshold,
                                              "alerts_alone": self.alone["lgbm"]}, ev),
                MLPrediction(self.anomaly.model_name, self.anomaly.threat_class, float(score[i]), float(conf[i]),
                             bool(hit_i[i]), {"threshold": self.anomaly.threshold, "note": IF_EVIDENCE_NOTE,
                                              "alerts_alone": self.alone["iforest"]}, ev),
            ])
        return out

    def predict(self, row: Dict[str, float]) -> List[MLPrediction]:
        return self.predict_batch([row])[0]
