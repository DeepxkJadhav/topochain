"""
Unit tests for GraphBuilder, weighting, and metric distance matrix.
"""

import numpy as np
from topochain.core.extractor import ExtractionResult, CodeEntity, EntityType
from topochain.core.graph import GraphBuilder, TopologicalMetricWeighting


def test_metric_weighting():
    dist_intra = TopologicalMetricWeighting.compute_edge_distance("mod.a", "mod.b", {"type": "call"})
    dist_inter = TopologicalMetricWeighting.compute_edge_distance("mod_a.fn", "mod_b.fn", {"type": "call"})
    dist_dep = TopologicalMetricWeighting.compute_edge_distance("mod_a.fn", "dep:requests", {"type": "dependency_use"})

    assert dist_intra < dist_inter
    assert dist_inter < dist_dep
    assert 0.0 < dist_intra <= 1.0


def test_graph_builder_distance_matrix():
    extraction = ExtractionResult()
    extraction.entities = {
        "fn:a": CodeEntity(id="fn:a", name="a", entity_type=EntityType.FUNCTION, file_path="main.py"),
        "fn:b": CodeEntity(id="fn:b", name="b", entity_type=EntityType.FUNCTION, file_path="main.py"),
        "fn:c": CodeEntity(id="fn:c", name="c", entity_type=EntityType.FUNCTION, file_path="main.py"),
    }
    extraction.call_edges = [
        ("fn:a", "fn:b", {"type": "call"}),
        ("fn:b", "fn:c", {"type": "call"}),
    ]

    builder = GraphBuilder()
    res = builder.build_graph(extraction)

    assert res.graph.number_of_nodes() == 3
    assert res.distance_matrix.shape == (3, 3)
    # Diagonal should be 0.0
    for i in range(3):
        assert res.distance_matrix[i, i] == 0.0
    # Symmetric
    assert np.allclose(res.distance_matrix, res.distance_matrix.T)
