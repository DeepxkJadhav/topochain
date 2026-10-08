"""
Self-supervised contrastive training pipeline for TopoChain's TNN.
Learns the manifold of natural software evolution and separates topological defects.
"""

from typing import List, Tuple, Optional, Dict, Any
import numpy as np
import torch
import torch.nn as nn
import torch.optim as optim

from topochain.ai.models.tnn import TopologicalNeuralNetwork


class ContrastiveHomologyLoss(nn.Module):
    """
    Contrastive loss pulling consecutive benign commits together on the hypersphere,
    while pushing topologically defected (backdoored) commits apart by at least `margin`.
    """

    def __init__(self, margin: float = 0.5):
        super().__init__()
        self.margin = margin

    def forward(self, anchor: torch.Tensor, positive: torch.Tensor, negative: torch.Tensor) -> torch.Tensor:
        # Cosine distance = 1 - dot product (vectors are already L2-normalized)
        d_pos = 1.0 - torch.sum(anchor * positive, dim=-1)
        d_neg = 1.0 - torch.sum(anchor * negative, dim=-1)
        loss = torch.mean(torch.clamp(d_pos - d_neg + self.margin, min=0.0))
        return loss


class TopologicalTrainer:
    """
    Trains or fine-tunes TNN using contrastive pairs/triplets of commit persistence images.
    """

    def __init__(self, model: Optional[TopologicalNeuralNetwork] = None, lr: float = 1e-3, margin: float = 0.5):
        self.model = model or TopologicalNeuralNetwork()
        self.criterion = ContrastiveHomologyLoss(margin=margin)
        self.optimizer = optim.AdamW(self.model.parameters(), lr=lr, weight_decay=1e-4)

    def train_step(
        self,
        anchors: np.ndarray,
        positives: np.ndarray,
        negatives: np.ndarray
    ) -> float:
        self.model.train()
        self.optimizer.zero_grad()

        a_t = torch.from_numpy(anchors)
        p_t = torch.from_numpy(positives)
        n_t = torch.from_numpy(negatives)

        emb_a = self.model(a_t)
        emb_p = self.model(p_t)
        emb_n = self.model(n_t)

        loss = self.criterion(emb_a, emb_p, emb_n)
        loss.backward()
        self.optimizer.step()

        return float(loss.item())

    def train_epochs(
        self,
        triplets: List[Tuple[np.ndarray, np.ndarray, np.ndarray]],
        epochs: int = 5,
        batch_size: int = 16
    ) -> List[float]:
        history = []
        if not triplets:
            return history

        for epoch in range(epochs):
            epoch_loss = 0.0
            np.random.shuffle(triplets)
            num_batches = int(np.ceil(len(triplets) / batch_size))

            for b in range(num_batches):
                batch = triplets[b * batch_size : (b + 1) * batch_size]
                anchors = np.stack([item[0] for item in batch])
                positives = np.stack([item[1] for item in batch])
                negatives = np.stack([item[2] for item in batch])

                loss_val = self.train_step(anchors, positives, negatives)
                epoch_loss += loss_val

            avg_loss = epoch_loss / max(1, num_batches)
            history.append(avg_loss)

        return history
