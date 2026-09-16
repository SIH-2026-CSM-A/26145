"""Random Forest Supervised Threat Classifier for SIH26145."""

from typing import List, Optional
import numpy as np
from sklearn.ensemble import RandomForestClassifier

from sih26145.features.models import FeatureVector
from sih26145.models.schemas import MLPrediction
from sih26145.models.anomaly import feature_vector_to_array


CLASSES = ["BENIGN", "THREAT_C2_BEACON", "THREAT_DNS_DGA", "THREAT_EXFILTRATION"]


class RandomForestThreatClassifier:
    """Supervised Random Forest classifier for multi-class threat recognition.
    
    Provides a structurally valid multiclass ML inference path initialized from a
    deterministic synthetic baseline.
    """

    def __init__(self, n_estimators: int = 50, random_state: int = 42):
        self.model_name = "random_forest_threat_classifier"
        self.model = RandomForestClassifier(n_estimators=n_estimators, random_state=random_state)
        self.classes_ = CLASSES
        self._is_fitted = False

    def fit_synthetic_baseline(self):
        """Fit model with deterministic baseline dataset across all declared classes."""
        rng = np.random.RandomState(42)
        X_list = []
        y_list = []

        # 1. Benign baseline (standard HTTP/HTTPS & non-DNS UDP traffic)
        for _ in range(20):
            dummy = rng.normal(loc=0.0, scale=0.1, size=32)
            dummy[0] = 2.0 + rng.uniform(0.1, 1.0)    # duration ~2.5s
            dummy[1] = 5.0 + rng.uniform(1.0, 5.0)    # total_packets ~7
            dummy[2] = 500.0 + rng.uniform(50, 200)   # total_bytes ~600
            dummy[3] = 3.0 + rng.uniform(0.1, 1.0)    # pps
            dummy[4] = 300.0 + rng.uniform(10, 50)    # bps
            dummy[12] = 0.5 + rng.uniform(0.01, 0.1)  # iat_mean
            dummy[13] = 0.05 + rng.uniform(0.01, 0.05) # iat_var
            dummy[19] = 1.0                           # is_tcp
            dummy[22] = 80.0                          # dst_port
            dummy[29] = 1.0                           # has_syn
            X_list.append(dummy)
            y_list.append("BENIGN")

        # 1b. Benign UDP baseline (non-DNS UDP traffic, e.g., RTP/STUN/HTTP3)
        for _ in range(20):
            dummy = rng.normal(loc=0.0, scale=0.1, size=32)
            dummy[0] = 0.5 + rng.uniform(0.01, 0.5)
            dummy[1] = 1.0 + rng.uniform(0.0, 2.0)
            dummy[2] = 100.0 + rng.uniform(10, 100)
            dummy[20] = 1.0                           # is_udp
            dummy[22] = 80.0                          # dst_port (non-DNS port)
            dummy[23] = 0.0                           # dns_query_count = 0
            dummy[24] = 0.0                           # dns_max_domain_entropy = 0
            X_list.append(dummy)
            y_list.append("BENIGN")

        # 2. C2 Beacon (high packet count, long duration, extremely low IAT variance)
        for _ in range(20):
            dummy = rng.normal(loc=0.0, scale=0.1, size=32)
            dummy[0] = 30.0 + rng.uniform(1.0, 5.0)   # duration ~32s
            dummy[1] = 30.0 + rng.uniform(1.0, 5.0)   # total_packets ~32
            dummy[2] = 1500.0 + rng.uniform(50, 100)  # total_bytes ~1500
            dummy[3] = 1.0 + rng.uniform(0.01, 0.05)  # pps ~1.0
            dummy[4] = 50.0 + rng.uniform(1.0, 5.0)   # bps
            dummy[12] = 1.0                           # iat_mean ~1.0s
            dummy[13] = 0.00001                       # iat_var (extremely low jitter)
            dummy[19] = 1.0                           # is_tcp
            dummy[22] = 443.0                         # dst_port
            X_list.append(dummy)
            y_list.append("THREAT_C2_BEACON")

        # 3. DGA (UDP DNS traffic with high domain entropy)
        for _ in range(20):
            dummy = rng.normal(loc=0.0, scale=0.1, size=32)
            dummy[0] = 0.5 + rng.uniform(0.01, 0.1)   # duration ~0.5s
            dummy[1] = 2.0                            # total_packets
            dummy[2] = 200.0                          # total_bytes
            dummy[20] = 1.0                           # is_udp
            dummy[22] = 53.0                          # dst_port
            dummy[23] = 1.0                           # dns_query_count
            dummy[24] = 4.5 + rng.uniform(0.1, 0.5)   # dns_max_domain_entropy > 4.2
            dummy[25] = 2.0                           # dns_max_subdomain_depth
            X_list.append(dummy)
            y_list.append("THREAT_DNS_DGA")

        # 4. Exfiltration (long duration, massive outbound byte rate, low small packet ratio)
        for _ in range(20):
            dummy = rng.normal(loc=0.0, scale=0.1, size=32)
            dummy[0] = 10.0 + rng.uniform(1.0, 5.0)   # duration ~12s
            dummy[1] = 500.0 + rng.uniform(10, 50)    # total_packets
            dummy[2] = 5000000.0 + rng.uniform(1e5, 5e5) # total_bytes ~5MB
            dummy[3] = 50.0                           # pps
            dummy[4] = 4000000.0 + rng.uniform(1e5, 5e5) # bps > 500,000
            dummy[18] = 0.01                          # small_pkt_ratio ~0
            dummy[19] = 1.0                           # is_tcp
            dummy[22] = 8080.0                        # dst_port
            X_list.append(dummy)
            y_list.append("THREAT_EXFILTRATION")

        X = np.vstack(X_list)
        y = np.array(y_list)
        self.model.fit(X, y)
        self._is_fitted = True

    def fit(self, vectors: List[FeatureVector], labels: List[str]):
        """Fit Random Forest classifier on labeled FeatureVectors."""
        if not vectors or not labels:
            return
        X = np.vstack([feature_vector_to_array(fv) for fv in vectors])
        y = np.array(labels)
        self.model.fit(X, y)
        self._is_fitted = True

    def predict(self, fv: FeatureVector) -> MLPrediction:
        """Predict threat class probabilities for a FeatureVector."""
        if not self._is_fitted:
            self.fit_synthetic_baseline()

        X = feature_vector_to_array(fv).reshape(1, -1)
        probs = self.model.predict_proba(X)[0]
        max_idx = int(np.argmax(probs))
        predicted_class = str(self.model.classes_[max_idx])
        max_prob = float(probs[max_idx])

        # Semantic domain check: THREAT_DNS_DGA requires DNS destination port or non-zero DNS query count
        if predicted_class == "THREAT_DNS_DGA" and fv.dst_port != 53 and fv.dns_query_count == 0:
            predicted_class = "BENIGN"
            max_prob = float(probs[list(self.model.classes_).index("BENIGN")]) if "BENIGN" in self.model.classes_ else 0.0

        is_anomaly = bool(predicted_class != "BENIGN" and max_prob > 0.5)

        class_prob_dict = {str(c): float(p) for c, p in zip(self.model.classes_, probs)}

        return MLPrediction(
            model_name=self.model_name,
            threat_class=predicted_class if is_anomaly else "BENIGN",
            anomaly_score=max_prob if is_anomaly else 0.0,
            probability=max_prob,
            is_anomaly=is_anomaly,
            metadata={
                "class_probabilities": class_prob_dict,
                "dataset_source": "synthetic_baseline_classifier",
            }
        )
