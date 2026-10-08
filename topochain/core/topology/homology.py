"""
Persistent homology computation engine using Ripser for TopoChain.
Computes H_0 (connected components), H_1 (loops/cycles), and H_2 (voids/cavities) over metric graph complexes.
"""

from dataclasses import dataclass, field
from typing import Dict, List, Tuple, Any, Optional
import numpy as np
import ripser


@dataclass
class PersistenceDiagramSet:
    h0: np.ndarray  # Shape: (N0, 2) [birth, death]
    h1: np.ndarray  # Shape: (N1, 2) [birth, death]
    h2: np.ndarray  # Shape: (N2, 2) [birth, death]
    betti_numbers: Dict[str, int] = field(default_factory=dict)
    total_persistence: Dict[str, float] = field(default_factory=dict)
    persistent_entropy: Dict[str, float] = field(default_factory=dict)

    def summary(self) -> Dict[str, Any]:
        return {
            "h0_count": len(self.h0),
            "h1_count": len(self.h1),
            "h2_count": len(self.h2),
            "betti_numbers": self.betti_numbers,
            "total_persistence": self.total_persistence,
            "persistent_entropy": self.persistent_entropy,
        }


class PersistentHomologyEngine:
    """
    Computes simplicial complex filtration and persistent homology.
    """

    def __init__(self, max_dim: int = 2, threshold: float = 1.0):
        self.max_dim = max_dim
        self.threshold = threshold

    def compute(self, distance_matrix: np.ndarray) -> PersistenceDiagramSet:
        n = distance_matrix.shape[0]

        # Handle trivial / empty graphs
        if n <= 1:
            dummy_h0 = np.array([[0.0, np.inf]], dtype=np.float32)
            dummy_h1 = np.empty((0, 2), dtype=np.float32)
            dummy_h2 = np.empty((0, 2), dtype=np.float32)
            return PersistenceDiagramSet(
                h0=dummy_h0,
                h1=dummy_h1,
                h2=dummy_h2,
                betti_numbers={"b0": 1, "b1": 0, "b2": 0},
                total_persistence={"h0": 1.0, "h1": 0.0, "h2": 0.0},
                persistent_entropy={"h0": 0.0, "h1": 0.0, "h2": 0.0}
            )

        # Ensure symmetric & non-negative
        sym_dist = np.maximum(distance_matrix, distance_matrix.T)
        np.fill_diagonal(sym_dist, 0.0)

        # Call Ripser
        try:
            res = ripser.ripser(
                sym_dist,
                distance_matrix=True,
                maxdim=self.max_dim,
                thresh=self.threshold
            )
            dgms = res["dgms"]
        except Exception:
            # Fallback if ripser encounters numerical edge case
            dgms = [
                np.array([[0.0, 1.0]]),
                np.empty((0, 2)),
                np.empty((0, 2))
            ]

        h0 = dgms[0] if len(dgms) > 0 else np.empty((0, 2))
        h1 = dgms[1] if len(dgms) > 1 else np.empty((0, 2))
        h2 = dgms[2] if len(dgms) > 2 else np.empty((0, 2))

        # Filter out infinite death for total persistence computation
        betti_numbers = {
            "b0": int(np.sum(h0[:, 1] >= self.threshold)) if len(h0) > 0 else 1,
            "b1": len(h1),
            "b2": len(h2)
        }

        total_pers = {
            "h0": float(self._compute_total_persistence(h0, self.threshold)),
            "h1": float(self._compute_total_persistence(h1, self.threshold)),
            "h2": float(self._compute_total_persistence(h2, self.threshold)),
        }

        pers_entropy = {
            "h0": float(self._compute_persistence_entropy(h0, self.threshold)),
            "h1": float(self._compute_persistence_entropy(h1, self.threshold)),
            "h2": float(self._compute_persistence_entropy(h2, self.threshold)),
        }

        return PersistenceDiagramSet(
            h0=h0,
            h1=h1,
            h2=h2,
            betti_numbers=betti_numbers,
            total_persistence=total_pers,
            persistent_entropy=pers_entropy
        )

    def _compute_total_persistence(self, dgm: np.ndarray, max_val: float) -> float:
        if len(dgm) == 0:
            return 0.0
        finite_pts = dgm.copy()
        finite_pts[np.isinf(finite_pts[:, 1]), 1] = max_val
        lifetimes = finite_pts[:, 1] - finite_pts[:, 0]
        return np.sum(np.maximum(0.0, lifetimes))

    def _compute_persistence_entropy(self, dgm: np.ndarray, max_val: float) -> float:
        if len(dgm) == 0:
            return 0.0
        finite_pts = dgm.copy()
        finite_pts[np.isinf(finite_pts[:, 1]), 1] = max_val
        lifetimes = np.maximum(1e-6, finite_pts[:, 1] - finite_pts[:, 0])
        total = np.sum(lifetimes)
        if total <= 0:
            return 0.0
        probs = lifetimes / total
        return -np.sum(probs * np.log2(probs + 1e-12))
