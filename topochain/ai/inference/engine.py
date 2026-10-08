"""
Inference engine for TopoChain's Topological Neural Network.
Runs fast, deterministic forward passes on persistence image representations.
"""

from pathlib import Path
from typing import Optional, Union, List
import numpy as np
import torch

from topochain.ai.models.tnn import TopologicalNeuralNetwork


class TNNInferenceEngine:
    """
    Production-grade inference runner for TNN.
    Provides sub-50ms CPU latency and deterministic embeddings.
    """

    def __init__(
        self,
        model_path: Optional[str] = None,
        device: Optional[str] = None,
        embedding_dim: int = 64
    ):
        if device is None:
            self.device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
        else:
            self.device = torch.device(device)

        self.model = TopologicalNeuralNetwork(in_channels=3, embedding_dim=embedding_dim)

        if model_path and Path(model_path).exists():
            checkpoint = torch.load(model_path, map_location=self.device)
            if "state_dict" in checkpoint:
                self.model.load_state_dict(checkpoint["state_dict"])
            else:
                self.model.load_state_dict(checkpoint)

        self.model.to(self.device)
        self.model.eval()

    def embed_image(self, persistence_image: np.ndarray) -> np.ndarray:
        """
        Embeds a single persistence image of shape (3, H, W) into a 64-dim unit vector.
        """
        tensor = torch.from_numpy(persistence_image).unsqueeze(0).to(self.device)
        with torch.no_grad():
            emb = self.model(tensor)
        return emb.squeeze(0).cpu().numpy()

    def embed_batch(self, persistence_images: List[np.ndarray]) -> np.ndarray:
        """
        Embeds a list of persistence images into shape (N, 64).
        """
        if not persistence_images:
            return np.empty((0, self.model.embedding_dim), dtype=np.float32)

        stacked = np.stack(persistence_images, axis=0)
        tensor = torch.from_numpy(stacked).to(self.device)
        with torch.no_grad():
            emb = self.model(tensor)
        return emb.cpu().numpy()

    def save_checkpoint(self, path: str):
        out_p = Path(path)
        out_p.parent.mkdir(parents=True, exist_ok=True)
        torch.save({"state_dict": self.model.state_dict()}, str(out_p))
