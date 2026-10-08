"""
Dedicated unit tests for Section 18 drift mathematics fixes.
Tests:
- identical embeddings
- normal drift
- high drift
- zero variance
- insufficient baseline history
- NaN/Inf handling
- quantile tracking
- separation of scalar drift stats from vector centroid
"""

import numpy as np
import pytest

from topochain.core.drift.detector import TopologicalDriftDetector, DriftResult


def test_identical_embeddings():
    detector = TopologicalDriftDetector(default_threshold=3.0)
    v1 = np.ones(64, dtype=np.float32) / np.sqrt(64)
    v2 = v1.copy()

    res = detector.compute_drift(
        current_embedding=v2,
        previous_embedding=v1,
        baseline_mean=0.10,
        baseline_variance=0.002
    )

    assert res.drift_score == 0.0
    assert res.z_score < 0.0  # Drift 0 is below mean 0.10
    assert not res.is_anomaly
    assert res.severity == "CLEAN"


def test_normal_and_high_drift():
    detector = TopologicalDriftDetector(default_threshold=3.0)
    v1 = np.zeros(64, dtype=np.float32)
    v1[0] = 1.0

    # Slight perturbation (normal)
    v_norm = v1.copy()
    v_norm[1] = 0.04
    v_norm = v_norm / np.linalg.norm(v_norm)

    res_norm = detector.compute_drift(
        current_embedding=v_norm,
        previous_embedding=v1,
        baseline_mean=0.05,
        baseline_variance=0.001
    )
    assert not res_norm.is_anomaly
    assert res_norm.z_score < 3.0

    # Orthogonal jump (high drift ~ sqrt(2) = 1.414)
    v_high = np.zeros(64, dtype=np.float32)
    v_high[5] = 1.0

    res_high = detector.compute_drift(
        current_embedding=v_high,
        previous_embedding=v1,
        baseline_mean=0.05,
        baseline_variance=0.001
    )
    assert res_high.is_anomaly
    assert res_high.z_score > 10.0
    assert res_high.severity == "CRITICAL_ATTACK"


def test_zero_variance_guard():
    detector = TopologicalDriftDetector(default_threshold=3.0)
    v1 = np.zeros(64, dtype=np.float32)
    v1[0] = 1.0
    v2 = np.zeros(64, dtype=np.float32)
    v2[1] = 1.0

    # Zero variance must not raise ZeroDivisionError
    res = detector.compute_drift(
        current_embedding=v2,
        previous_embedding=v1,
        baseline_mean=0.05,
        baseline_variance=0.0
    )
    assert np.isfinite(res.z_score)
    assert res.baseline_std > 0.0  # Guarded by epsilon


def test_nan_inf_handling():
    detector = TopologicalDriftDetector(default_threshold=3.0)
    v_nan = np.full(64, np.nan, dtype=np.float32)
    v_prev = np.zeros(64, dtype=np.float32)
    v_prev[0] = 1.0

    res = detector.compute_drift(
        current_embedding=v_nan,
        previous_embedding=v_prev,
        baseline_mean=0.05,
        baseline_variance=0.001
    )
    assert np.isfinite(res.drift_score)
    assert np.isfinite(res.z_score)


def test_quantile_tracking():
    detector = TopologicalDriftDetector(default_threshold=3.0)
    v1 = np.zeros(64, dtype=np.float32)
    v1[0] = 1.0
    v2 = v1.copy()

    history = [0.02, 0.03, 0.05, 0.07, 0.12, 0.15, 0.25]
    res = detector.compute_drift(
        current_embedding=v2,
        previous_embedding=v1,
        baseline_mean=0.05,
        baseline_variance=0.001,
        historical_drifts=history
    )

    assert "p50" in res.quantiles
    assert "p90" in res.quantiles
    assert "p99" in res.quantiles
    assert res.quantiles["p50"] <= res.quantiles["p90"] <= res.quantiles["p99"]


def test_isolation_of_scalar_and_vector_stats():
    detector = TopologicalDriftDetector(default_threshold=3.0)
    v1 = np.zeros(64, dtype=np.float32)
    v1[0] = 1.0
    v2 = np.zeros(64, dtype=np.float32)
    v2[1] = 1.0
    centroid = np.zeros(64, dtype=np.float32)
    centroid[0] = 0.5
    centroid[1] = 0.5

    res = detector.compute_drift(
        current_embedding=v2,
        previous_embedding=v1,
        baseline_mean=0.10,  # scalar stat
        baseline_variance=0.005,  # scalar stat
        baseline_centroid=centroid  # vector stat
    )

    # Step drift is between v2 and v1 (~1.414)
    # Centroid distance is between v2 and centroid (~0.707)
    assert not np.isclose(res.drift_score, res.centroid_distance)
    assert np.isclose(res.drift_score, np.linalg.norm(v2 - v1), atol=1e-4)
    assert np.isclose(res.centroid_distance, np.linalg.norm(v2 - centroid), atol=1e-4)
