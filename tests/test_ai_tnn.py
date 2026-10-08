"""
Unit tests for Topological Neural Network (TNN) architecture, inference engine, and trainer.
"""

import numpy as np
import torch

from topochain.ai.models import TopologicalNeuralNetwork
from topochain.ai.inference import TNNInferenceEngine
from topochain.ai.training import ContrastiveHomologyLoss, TopologicalTrainer


def test_tnn_architecture():
    model = TopologicalNeuralNetwork(in_channels=3, embedding_dim=64)
    x = torch.randn(4, 3, 32, 32)
    out = model(x)

    assert out.shape == (4, 64)
    # Check L2 normalization
    norms = torch.norm(out, p=2, dim=-1)
    assert torch.allclose(norms, torch.ones(4), atol=1e-5)


def test_tnn_inference_engine():
    engine = TNNInferenceEngine(embedding_dim=64)
    single_img = np.random.rand(3, 32, 32).astype(np.float32)
    emb = engine.embed_image(single_img)

    assert emb.shape == (64,)
    assert np.isclose(np.linalg.norm(emb), 1.0, atol=1e-5)

    batch_imgs = [single_img, np.random.rand(3, 32, 32).astype(np.float32)]
    batch_embs = engine.embed_batch(batch_imgs)
    assert batch_embs.shape == (2, 64)


def test_trainer_contrastive_step():
    model = TopologicalNeuralNetwork(in_channels=3, embedding_dim=64)
    trainer = TopologicalTrainer(model=model, lr=1e-3, margin=0.5)

    a = np.random.rand(2, 3, 32, 32).astype(np.float32)
    p = a + np.random.normal(0, 0.01, size=a.shape).astype(np.float32)
    n = np.random.rand(2, 3, 32, 32).astype(np.float32)

    loss = trainer.train_step(a, p, n)
    assert isinstance(loss, float)
    assert loss >= 0.0
