"""
Topological drift calculation and anomaly detection for TopoChain.
Measures latent geometric shift of persistent homology invariants against project manifold baseline.
Separates scalar drift statistics from vector embedding centroid tracking.
"""

from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple, Any
import numpy as np


@dataclass
class DriftResult:
    drift_score: float  # Scalar L2 distance between consecutive embeddings: ||z_t - z_{t-1}||_2
    z_score: float  # Normalized anomaly z-score: (drift - mu_drift) / sigma_drift
    is_anomaly: bool
    threshold: float
    baseline_mean: float  # Running mean of scalar drift values
    baseline_std: float  # Running std dev of scalar drift values
    quantiles: Dict[str, float] = field(default_factory=dict)  # p50, p90, p99 of historical drift
    centroid_distance: float = 0.0  # Vector distance to historical embedding centroid (separate from step drift)
    severity: str = "CLEAN"
    diagnostics: Dict[str, Any] = field(default_factory=dict)


class TopologicalDriftDetector:
    """
    Evaluates topological drift between successive code commits.
    Maintains strict mathematical separation between:
    1. Scalar drift statistics: delta = ||z_t - z_{t-1}||_2, mean(delta), var(delta), quantiles(delta)
    2. Vector embedding statistics: centroid c = mean(z_i), dispersion = ||z_t - c||_2
    """

    def __init__(
        self,
        default_threshold: float = 3.0,
        min_samples_for_zscore: int = 3,
        epsilon: float = 1e-8
    ):
        self.default_threshold = default_threshold
        self.min_samples_for_zscore = min_samples_for_zscore
        self.epsilon = epsilon

    def compute_drift(
        self,
        current_embedding: np.ndarray,
        previous_embedding: Optional[np.ndarray],
        baseline_mean: float = 0.15,
        baseline_variance: float = 0.005,
        historical_drifts: Optional[List[float]] = None,
        baseline_centroid: Optional[np.ndarray] = None,
        custom_threshold: Optional[float] = None
    ) -> DriftResult:
        threshold = custom_threshold if custom_threshold is not None else self.default_threshold
        current_emb = np.asarray(current_embedding, dtype=np.float32)

        # Sanitize NaN/Inf in embedding
        if not np.all(np.isfinite(current_emb)):
            current_emb = np.nan_to_num(current_emb, nan=0.0, posinf=1.0, neginf=-1.0)
            norm = np.linalg.norm(current_emb)
            if norm > 1e-6:
                current_emb = current_emb / norm

        # 1. Scalar step drift calculation: delta = ||z_t - z_{t-1}||_2
        if previous_embedding is not None:
            prev_emb = np.asarray(previous_embedding, dtype=np.float32)
            if not np.all(np.isfinite(prev_emb)):
                prev_emb = np.nan_to_num(prev_emb, nan=0.0, posinf=1.0, neginf=-1.0)
                p_norm = np.linalg.norm(prev_emb)
                if p_norm > 1e-6:
                    prev_emb = prev_emb / p_norm
            step_drift = float(np.linalg.norm(current_emb - prev_emb))
        else:
            step_drift = 0.0

        # Guarantee non-negative finite drift
        step_drift = max(0.0, float(step_drift))
        if not np.isfinite(step_drift):
            step_drift = 0.0

        # 2. Vector centroid distance (kept strictly separate from scalar drift)
        if baseline_centroid is not None:
            cent = np.asarray(baseline_centroid, dtype=np.float32)
            centroid_dist = float(np.linalg.norm(current_emb - cent))
        else:
            centroid_dist = step_drift

        # 3. Z-score calculation using historical scalar drift distribution: z = (delta - mu_delta) / sqrt(var_delta + eps)
        safe_variance = max(0.0, float(baseline_variance))
        safe_std = float(np.sqrt(safe_variance + self.epsilon))

        if previous_embedding is None:
            # First commit anchor: anchor has 0 drift, negative z-score against positive mean
            z_score = float((0.0 - baseline_mean) / safe_std)
        else:
            z_score = float((step_drift - baseline_mean) / safe_std)

        # Clamp extreme numerical artifacts
        if not np.isfinite(z_score):
            z_score = 0.0

        # 4. Quantile computation over scalar historical drift
        quantiles = {}
        if historical_drifts and len(historical_drifts) >= 2:
            arr_drifts = np.array(historical_drifts, dtype=np.float32)
            quantiles["p50"] = float(np.percentile(arr_drifts, 50))
            quantiles["p90"] = float(np.percentile(arr_drifts, 90))
            quantiles["p99"] = float(np.percentile(arr_drifts, 99))
        else:
            quantiles["p50"] = baseline_mean
            quantiles["p90"] = baseline_mean + 1.28 * safe_std
            quantiles["p99"] = baseline_mean + 2.33 * safe_std

        # 5. Anomaly decision
        is_anomaly = bool(z_score > threshold)

        # 6. Severity classification
        if z_score < 1.0:
            severity = "CLEAN"
        elif z_score < 2.0:
            severity = "NORMAL_EVOLUTION"
        elif z_score < threshold:
            severity = "ELEVATED_VARIATION"
        elif z_score < threshold * 1.5:
            severity = "ANOMALY_HIGH"
        else:
            severity = "CRITICAL_ATTACK"

        return DriftResult(
            drift_score=step_drift,
            z_score=z_score,
            is_anomaly=is_anomaly,
            threshold=threshold,
            baseline_mean=baseline_mean,
            baseline_std=safe_std,
            quantiles=quantiles,
            centroid_distance=centroid_dist,
            severity=severity,
            diagnostics={}
        )

    @staticmethod
    def update_baseline_statistics(
        drifts: List[float],
        existing_mean: float = 0.0,
        existing_var: float = 0.0,
        existing_count: int = 0
    ) -> Tuple[float, float, int]:
        """
        Welford's algorithm for streaming update of scalar drift distribution statistics.
        """
        if not drifts:
            return existing_mean, existing_var, existing_count

        valid_drifts = [float(d) for d in drifts if np.isfinite(d) and d >= 0.0]
        if not valid_drifts:
            return existing_mean, existing_var, existing_count

        if existing_count == 0:
            new_mean = float(np.mean(valid_drifts))
            new_var = float(np.var(valid_drifts)) if len(valid_drifts) > 1 else 0.005
            return new_mean, max(1e-6, new_var), len(valid_drifts)

        count = existing_count
        mean = existing_mean
        M2 = existing_var * (count - 1) if count > 1 else 0.0

        for x in valid_drifts:
            count += 1
            delta = x - mean
            mean += delta / count
            delta2 = x - mean
            M2 += delta * delta2

        new_variance = M2 / (count - 1) if count > 1 else 0.005
        return float(mean), max(1e-6, float(new_variance)), count
