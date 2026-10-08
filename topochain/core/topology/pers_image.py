"""
Persistence image generation for TopoChain.
Maps persistence diagrams (H_0, H_1, H_2) into a fixed-resolution multi-channel tensor.
"""

from typing import Tuple, List, Optional
import numpy as np

from topochain.core.topology.homology import PersistenceDiagramSet


class PersistenceImageConverter:
    """
    Converts variable-sized persistence diagrams into fixed-shape (3, resolution, resolution) tensors.
    Channel 0: H_0 (connected components)
    Channel 1: H_1 (loops / cycles)
    Channel 2: H_2 (voids / cavities)
    """

    def __init__(
        self,
        resolution: int = 32,
        max_birth: float = 1.0,
        max_persistence: float = 1.0,
        sigma: float = 0.08,
        weight_power: float = 1.0
    ):
        self.resolution = resolution
        self.max_birth = max_birth
        self.max_persistence = max_persistence
        self.sigma = sigma
        self.weight_power = weight_power

        # Precompute coordinate grid in birth-persistence plane
        b_coords = np.linspace(0.0, max_birth, resolution)
        p_coords = np.linspace(0.0, max_persistence, resolution)
        self.grid_b, self.grid_p = np.meshgrid(b_coords, p_coords)

    def convert(self, diagrams: PersistenceDiagramSet) -> np.ndarray:
        """
        Transforms PersistenceDiagramSet into a numpy array of shape (3, resolution, resolution).
        """
        img_h0 = self._diagram_to_image(diagrams.h0)
        img_h1 = self._diagram_to_image(diagrams.h1)
        img_h2 = self._diagram_to_image(diagrams.h2)

        return np.stack([img_h0, img_h1, img_h2], axis=0).astype(np.float32)

    def _diagram_to_image(self, dgm: np.ndarray) -> np.ndarray:
        image = np.zeros((self.resolution, self.resolution), dtype=np.float32)
        if len(dgm) == 0:
            return image

        # Filter out invalid / NaN points
        valid_mask = ~np.isnan(dgm[:, 0]) & ~np.isnan(dgm[:, 1])
        pts = dgm[valid_mask].copy()
        if len(pts) == 0:
            return image

        # Handle infinite death
        pts[np.isinf(pts[:, 1]), 1] = self.max_birth

        # Coordinates in birth-persistence space: (birth, lifetime = death - birth)
        births = pts[:, 0]
        lifetimes = np.maximum(0.0, pts[:, 1] - births)

        # Discard zero-lifetime points
        nz = lifetimes > 1e-5
        if not np.any(nz):
            return image

        births = births[nz]
        lifetimes = lifetimes[nz]

        # Weight function: w(b, p) = (p / max_p)^power
        weights = np.clip(lifetimes / (self.max_persistence + 1e-6), 0.0, 1.0) ** self.weight_power

        # Gaussian kernel evaluation over grid
        sigma_sq = 2.0 * (self.sigma ** 2)

        for b, p, w in zip(births, lifetimes, weights):
            # Distance squared to grid points
            dist_sq = (self.grid_b - b) ** 2 + (self.grid_p - p) ** 2
            kernel = np.exp(-dist_sq / sigma_sq)
            image += (w * kernel).astype(np.float32)

        # Normalize channel to [0, 1] if not all zeros
        max_val = np.max(image)
        if max_val > 1e-6:
            image = image / max_val

        return image
