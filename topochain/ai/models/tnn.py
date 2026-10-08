"""
Topological Neural Network (TNN) model architecture for TopoChain.
Maps multi-channel persistence images into a normalized 64-dimensional topological manifold embedding.
"""

import torch
import torch.nn as nn
import torch.nn.functional as F
from typing import Optional


class ResidualBlock(nn.Module):
    """
    Residual convolution block for topological feature extraction.
    """
    def __init__(self, channels: int):
        super().__init__()
        self.conv1 = nn.Conv2d(channels, channels, kernel_size=3, padding=1, bias=False)
        self.bn1 = nn.BatchNorm2d(channels)
        self.act = nn.SiLU()
        self.conv2 = nn.Conv2d(channels, channels, kernel_size=3, padding=1, bias=False)
        self.bn2 = nn.BatchNorm2d(channels)

    def forward(self, x: torch.Tensor) -> torch.Tensor:
        residual = x
        out = self.act(self.bn1(self.conv1(x)))
        out = self.bn2(self.conv2(out))
        return self.act(out + residual)


class TopologicalNeuralNetwork(nn.Module):
    """
    TNN architecture designed for persistent homology embeddings.
    Extracts multi-scale topological patterns (birth-death features, cycle persistence, cavity counts)
    and maps them to an invariant 64-dimensional hypersphere latent space.
    """

    def __init__(self, in_channels: int = 3, embedding_dim: int = 64):
        super().__init__()
        self.in_channels = in_channels
        self.embedding_dim = embedding_dim

        # Backbone
        self.stem = nn.Sequential(
            nn.Conv2d(in_channels, 32, kernel_size=3, padding=1, bias=False),
            nn.BatchNorm2d(32),
            nn.SiLU(),
        )

        self.layer1 = nn.Sequential(
            nn.Conv2d(32, 64, kernel_size=3, stride=2, padding=1, bias=False),
            nn.BatchNorm2d(64),
            nn.SiLU(),
            ResidualBlock(64),
        )

        self.layer2 = nn.Sequential(
            nn.Conv2d(64, 128, kernel_size=3, stride=2, padding=1, bias=False),
            nn.BatchNorm2d(128),
            nn.SiLU(),
            ResidualBlock(128),
        )

        # Global spatial aggregation (both average and peak persistence)
        self.avg_pool = nn.AdaptiveAvgPool2d((1, 1))
        self.max_pool = nn.AdaptiveMaxPool2d((1, 1))

        # Projection head to latent sphere
        self.projector = nn.Sequential(
            nn.Linear(256, 128),
            nn.LayerNorm(128),
            nn.SiLU(),
            nn.Dropout(0.1),
            nn.Linear(128, embedding_dim),
        )

        self._initialize_weights()

    def _initialize_weights(self):
        for m in self.modules():
            if isinstance(m, nn.Conv2d):
                nn.init.kaiming_normal_(m.weight, mode="fan_out", nonlinearity="relu")
            elif isinstance(m, nn.BatchNorm2d):
                nn.init.constant_(m.weight, 1.0)
                nn.init.constant_(m.bias, 0.0)
            elif isinstance(m, nn.Linear):
                nn.init.orthogonal_(m.weight, gain=1.0)
                if m.bias is not None:
                    nn.init.constant_(m.bias, 0.0)

    def forward(self, x: torch.Tensor) -> torch.Tensor:
        """
        Input: Tensor of shape (B, in_channels, H, W)
        Output: L2-normalized embedding tensor of shape (B, embedding_dim)
        """
        # Ensure 4D tensor
        if x.dim() == 3:
            x = x.unsqueeze(0)

        feat = self.stem(x)
        feat = self.layer1(feat)
        feat = self.layer2(feat)

        avg_p = self.avg_pool(feat).flatten(1)
        max_p = self.max_pool(feat).flatten(1)
        pooled = torch.cat([avg_p, max_p], dim=1)

        embedding = self.projector(pooled)
        normalized = F.normalize(embedding, p=2, dim=-1)
        return normalized
