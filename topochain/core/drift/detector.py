"""
Topological drift calculation and anomaly detection for TopoChain.
Measures latent geometric shift of persistent homology invariants against project manifold baseline.
"""

from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple, Any
import numpy as np


@dataclass
class DriftResult:
    drift_score: float  # raw L2 distance
    z_score: float  # normalized anomaly score
    is_anomaly: bool
    threshold: float
    baseline_mean: float
    baseline_std: float
    centroid_distance: float
    severity: str
    diagnostics: Dict[str, Any] = field(default_factory=dict)


class TopologicalDriftDetector:
    """
    Evaluates topological drift between successive code commits.
    """

    def __init__(
        self,
        default_threshold: float = 3.0,
        min_samples_for_zscore: int = 3,
        epsilon: float = 1e-5
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
        baseline_centroid: Optional[np.ndarray] = None,
        custom_threshold: Optional[float] = None
    ) -> DriftResult:
        threshold = custom_threshold if custom_threshold is not None else self.default_threshold
        current_emb = np.asarray(current_embedding, dtype=np.float32)

        # 1. Step drift (L2 distance from previous commit)
        if previous_embedding is not None:
            prev_emb = np.asarray(previous_embedding, dtype=np.float32)
            step_drift = float(np.linalg.norm(current_emb - prev_emb))
        else:
            step_drift = 0.0

        # 2. Centroid drift (distance to historical project center)
        if baseline_centroid is not None:
            cent = np.asarray(baseline_centroid, dtype=np.float32)
            centroid_dist = float(np.linalg.norm(current_emb - cent))
        else:
            centroid_dist = step_drift

        # 3. Z-score calculation
        baseline_std = float(np.sqrt(max(0.0, baseline_variance) + self.epsilon))
        z_score = float((step_drift - baseline_mean) / baseline_std)

        # 4. Anomaly decision
        is_anomaly = bool(z_score > threshold)

        # 5. Severity classification
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
            baseline_std=baseline_std,
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
        Welford's algorithm / streaming update for running drift mean and variance.
        """
        if not drifts:
            return existing_mean, existing_var, existing_count

        all_drifts = np.array(drifts, dtype=np.float32)
        if existing_count == 0:
            new_mean = float(np.mean(all_drifts))
            new_var = float(np.var(all_drifts)) if len(all_drifts) > 1 else 0.005
            return new_mean, max(0.001, new_var), len(all_drifts)

        # Incremental update
        count = existing_count
        mean = existing_mean
        M2 = existing_var * (count - 1) if count > 1 else 0.0

        for x in all_drifts:
            count += 1
            delta = x - mean
            mean += delta / count
            delta2 = x - mean
            M2 += delta * delta2

        new_variance = M2 / (count - 1) if count > 1 else 0.005
        return float(mean), max(0.001, float(new_variance)), count
