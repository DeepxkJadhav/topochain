"""
Unit tests for Persistent Homology computation, Persistence Image conversion, and Visualization.
"""

import tempfile
from pathlib import Path
import numpy as np

from topochain.core.topology import (
    PersistentHomologyEngine,
    PersistenceImageConverter,
    TopologicalVisualizer,
)


def test_persistent_homology_computation():
    # Construct a cycle graph distance matrix (should produce H_1 loop feature)
    n = 6
    dist = np.full((n, n), 1.0, dtype=np.float32)
    np.fill_diagonal(dist, 0.0)
    for i in range(n):
        nxt = (i + 1) % n
        dist[i, nxt] = 0.2
        dist[nxt, i] = 0.2

    engine = PersistentHomologyEngine(max_dim=1, threshold=1.0)
    diagrams = engine.compute(dist)

    assert len(diagrams.h0) > 0
    assert len(diagrams.h1) >= 1  # Cycle detected
    assert "b0" in diagrams.betti_numbers
    assert "h1" in diagrams.total_persistence


def test_persistence_image_converter():
    engine = PersistentHomologyEngine(max_dim=1)
    dist = np.array([
        [0.0, 0.2, 0.5],
        [0.2, 0.0, 0.2],
        [0.5, 0.2, 0.0]
    ], dtype=np.float32)
    diagrams = engine.compute(dist)

    converter = PersistenceImageConverter(resolution=32)
    img = converter.convert(diagrams)

    assert img.shape == (3, 32, 32)
    assert not np.isnan(img).any()
    assert np.all(img >= 0.0)


def test_visualizer_ascii_and_plot():
    engine = PersistentHomologyEngine(max_dim=1)
    dist = np.random.rand(5, 5).astype(np.float32)
    dist = (dist + dist.T) / 2.0
    np.fill_diagonal(dist, 0.0)

    diagrams = engine.compute(dist)
    converter = PersistenceImageConverter(resolution=32)
    img = converter.convert(diagrams)

    ascii_rep = TopologicalVisualizer.format_ascii_summary(diagrams)
    assert "Persistent Homology Invariants" in ascii_rep

    with tempfile.TemporaryDirectory() as tmpdir:
        plot_p = str(Path(tmpdir) / "diag.png")
        saved = TopologicalVisualizer.save_plot(diagrams, img, plot_p)
        assert Path(saved).exists()
