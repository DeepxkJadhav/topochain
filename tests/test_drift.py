"""
Unit tests for drift detection, defect diagnostics, and SQLite storage.
"""

import tempfile
from pathlib import Path
import numpy as np

from topochain.core.drift import (
    TopologicalDriftDetector,
    TopologicalDiagnosticsEngine,
)
from topochain.core.topology import PersistenceDiagramSet
from topochain.core.db import StorageEngine


def test_drift_detector_scoring():
    detector = TopologicalDriftDetector(default_threshold=3.0)

    # Unit vector 1 and 2 with small drift
    v1 = np.zeros(64, dtype=np.float32)
    v1[0] = 1.0

    v2 = v1.copy()
    v2[1] = 0.05
    v2 = v2 / np.linalg.norm(v2)

    # Benign small drift
    res_benign = detector.compute_drift(
        current_embedding=v2,
        previous_embedding=v1,
        baseline_mean=0.04,
        baseline_variance=0.001
    )
    assert not res_benign.is_anomaly
    assert res_benign.z_score < 3.0

    # Large anomalous drift
    v_attack = np.zeros(64, dtype=np.float32)
    v_attack[10] = 1.0  # Orthogonal vector (drift = sqrt(2) ~ 1.414)
    res_attack = detector.compute_drift(
        current_embedding=v_attack,
        previous_embedding=v1,
        baseline_mean=0.04,
        baseline_variance=0.001
    )
    assert res_attack.is_anomaly
    assert res_attack.z_score > 3.0
    assert res_attack.severity in {"ANOMALY_HIGH", "CRITICAL_ATTACK"}


def test_diagnostics_rca():
    cur = PersistenceDiagramSet(
        h0=np.array([[0, 1]]),
        h1=np.array([[0.2, 0.8], [0.3, 0.9]]),  # 2 loops
        h2=np.empty((0, 2))
    )
    prev = PersistenceDiagramSet(
        h0=np.array([[0, 1]]),
        h1=np.empty((0, 2)),  # 0 loops
        h2=np.empty((0, 2))
    )

    diag = TopologicalDiagnosticsEngine.analyze_defects(cur, prev)
    assert "LOOP_BIRTH_ANOMALY" in diag["defects"]


def test_storage_engine():
    with tempfile.TemporaryDirectory() as tmpdir:
        db_path = str(Path(tmpdir) / "test.db")
        storage = StorageEngine(db_path=db_path)

        p = storage.get_or_create_project("test_proj")
        assert p["id"] == "test_proj"

        img = np.random.rand(3, 32, 32).astype(np.float32)
        emb = np.random.rand(64).astype(np.float32)
        ok = storage.record_commit(
            commit_hash="commit_1",
            project_id="test_proj",
            persistence_image=img,
            latent_embedding=emb,
            drift_score=0.12,
            is_anomaly=False,
            diagnostics={"info": "clean"}
        )
        assert ok

        retrieved = storage.get_commit("commit_1")
        assert retrieved is not None
        assert retrieved["drift_score"] == 0.12
        assert retrieved["persistence_image"].shape == (3, 32, 32)
        assert retrieved["latent_embedding"].shape == (64,)
