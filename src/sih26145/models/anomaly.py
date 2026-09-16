"""Isolation Forest Unsupervised Anomaly Detector for SIH26145."""

from typing import List, Optional
import numpy as np
from sklearn.ensemble import IsolationForest

from sih26145.features.models import FeatureVector
from sih26145.models.schemas import MLPrediction


def feature_vector_to_array(fv: FeatureVector) -> np.ndarray:
    """Extract numerical feature vector array for ML model input.
    
    Extracts all 32 numerical fields from FeatureVector in deterministic order.
    Sanitizes any non-finite values (NaN, Inf) to 0.0.
    """
    arr = np.array([
        fv.duration,
        float(fv.total_packets),
        float(fv.total_bytes),
        fv.pps,
        fv.bps,
        fv.pkt_size_min,
        fv.pkt_size_max,
        fv.pkt_size_mean,
        fv.pkt_size_std,
        fv.pkt_size_q25,
        fv.pkt_size_q50,
        fv.pkt_size_q75,
        fv.iat_mean,
        fv.iat_var,
        fv.iat_min,
        fv.iat_max,
        fv.jitter,
        fv.burstiness_ratio,
        fv.small_pkt_ratio,
        fv.is_tcp,
        fv.is_udp,
        fv.is_icmp,
        float(fv.dst_port),
        float(fv.dns_query_count),
        fv.dns_max_domain_entropy,
        float(fv.dns_max_subdomain_depth),
        float(fv.tls_client_hello_count),
        fv.tls_max_sni_entropy,
        float(fv.tls_max_sni_length),
        fv.has_syn,
        fv.has_fin,
        fv.has_rst,
    ], dtype=np.float64)
    return np.nan_to_num(arr, nan=0.0, posinf=0.0, neginf=0.0)


class IsolationForestAnomalyDetector:
    """Unsupervised Isolation Forest detector for network flow volume and pattern anomalies.
    
    Score Semantics:
    - anomaly_score: Raw scikit-learn decision_function output (< 0.0 indicates an anomalous outlier).
    - probability: Sigmoid-transformed uncalibrated anomaly score in [0.0, 1.0] derived from decision_function.
    - is_anomaly: True if decision_score < 0.0, else False.
    """

    def __init__(self, contamination: float = 0.05, random_state: int = 42):
        self.model_name = "isolation_forest_anomaly_detector"
        self.contamination = contamination
        self.model = IsolationForest(contamination=self.contamination, random_state=random_state)
        self._is_fitted = False

    def fit_baseline(self, benign_vectors: List[FeatureVector]):
        """Fit Isolation Forest on baseline benign FeatureVectors."""
        if not benign_vectors:
            return
        X = np.vstack([feature_vector_to_array(fv) for fv in benign_vectors])
        self.model.fit(X)
        self._is_fitted = True

    def predict(self, fv: FeatureVector) -> MLPrediction:
        """Run Isolation Forest anomaly prediction on a FeatureVector."""
        X = feature_vector_to_array(fv).reshape(1, -1)
        
        if not self._is_fitted:
            # Synthetic baseline fit for uninitialized inference across normal network traffic profiles
            rng = np.random.RandomState(42)
            X_list = []

            # 1. Standard multi-packet HTTP/HTTPS background traffic
            for _ in range(30):
                dummy = rng.normal(loc=0.0, scale=0.1, size=X.shape[1])
                dummy[0] = 2.0 + rng.uniform(0.1, 2.0)     # duration ~2-4s
                dummy[1] = 10.0 + rng.uniform(1.0, 10.0)   # total_packets ~10-20
                dummy[2] = 1000.0 + rng.uniform(100, 500)  # total_bytes ~1000-1500
                dummy[3] = 5.0 + rng.uniform(0.5, 2.0)     # pps ~5-7
                dummy[4] = 500.0 + rng.uniform(50, 200)    # bps ~500-700
                dummy[18] = 0.5                            # small_pkt_ratio
                dummy[19] = 1.0                            # is_tcp
                dummy[22] = 443.0                          # dst_port
                X_list.append(dummy)

            # 2. Short / single-packet background traffic (DNS, HTTP SYNs, ping, UDP)
            for _ in range(30):
                dummy = rng.normal(loc=0.0, scale=0.1, size=X.shape[1])
                dummy[0] = rng.uniform(0.0, 0.2)           # duration 0..0.2s
                dummy[1] = 1.0 + rng.uniform(0.0, 1.0)     # total_packets 1..2
                dummy[2] = 60.0 + rng.uniform(10, 100)     # total_bytes 60..160
                dummy[3] = 1.0 + rng.uniform(0.0, 1.0)     # pps 1..2
                dummy[4] = 100.0 + rng.uniform(10, 100)    # bps
                dummy[5] = 64.0                            # pkt_size_min
                dummy[6] = 100.0                           # pkt_size_max
                dummy[7] = 80.0                            # pkt_size_mean
                dummy[8] = 10.0                            # pkt_size_std
                dummy[9] = 64.0                            # pkt_size_q25
                dummy[10] = 80.0                           # pkt_size_q50
                dummy[11] = 100.0                          # pkt_size_q75
                dummy[18] = 0.8 + rng.uniform(0.0, 0.2)    # small_pkt_ratio ~1.0
                dummy[19] = float(rng.choice([0, 1]))
                dummy[20] = 1.0 - dummy[19]
                dummy[22] = float(rng.choice([53, 80, 443, 123]))
                X_list.append(dummy)

            self.model.fit(np.vstack(X_list))
            self._is_fitted = True

        decision_score = float(self.model.decision_function(X)[0])
        raw_pred = self.model.predict(X)[0]
        
        # In scikit-learn IsolationForest, decision_function < 0 indicates an anomaly (outlier)
        is_anomaly = bool(decision_score < 0.0)

        # Uncalibrated sigmoid score mapping decision score into [0.0, 1.0] range
        uncalibrated_score = float(1.0 / (1.0 + np.exp(decision_score * 5.0)))

        return MLPrediction(
            model_name=self.model_name,
            threat_class="THREAT_UNSUPERVISED_ANOMALY",
            anomaly_score=decision_score,
            probability=uncalibrated_score,
            is_anomaly=is_anomaly,
            metadata={
                "contamination": self.contamination,
                "raw_prediction": int(raw_pred),
                "decision_threshold": 0.0,
                "score_type": "derived_uncalibrated_sigmoid_anomaly_score",
            }
        )
