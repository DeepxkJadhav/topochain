"""
Graph construction and geodesic metric space generation for TopoChain.
Transforms extracted code entities and dependencies into a weighted metric graph.
"""

from dataclasses import dataclass
from typing import Dict, List, Tuple, Any, Optional
import networkx as nx
import numpy as np

from topochain.core.extractor.base import ExtractionResult, EntityType, CodeEntity
from topochain.core.graph.weighting import TopologicalMetricWeighting


@dataclass
class CodeGraphResult:
    graph: nx.DiGraph
    undirected_graph: nx.Graph
    node_index: Dict[str, int]
    index_to_node: Dict[int, str]
    distance_matrix: np.ndarray
    clique_count_est: int
    betti_summary_rough: Dict[str, int]


class GraphBuilder:
    """
    Constructs software architecture graphs and computes the geodesic metric distance matrix.
    """

    def __init__(self, max_nodes: int = 400, max_unconnected_dist: float = 1.0):
        self.max_nodes = max_nodes
        self.max_unconnected_dist = max_unconnected_dist

    def build_graph(self, extraction: ExtractionResult) -> CodeGraphResult:
        g = nx.DiGraph()

        # 1. Add all extracted entities as nodes
        for ent_id, ent in extraction.entities.items():
            g.add_node(
                ent_id,
                name=ent.name,
                type=ent.entity_type.value,
                complexity=ent.complexity,
                sensitive_ops=len(ent.sensitive_operations),
                file_path=ent.file_path,
            )

        # 2. Add edges with metric distance
        for src, tgt, data in extraction.call_edges:
            # Ensure target exists
            if not g.has_node(tgt):
                g.add_node(
                    tgt,
                    name=tgt.split(":")[-1],
                    type=EntityType.EXTERNAL_DEPENDENCY.value if tgt.startswith("dep:") or tgt.startswith("ext:") else EntityType.FUNCTION.value,
                    complexity=1,
                    sensitive_ops=0,
                    file_path="external"
                )
            if not g.has_node(src):
                g.add_node(
                    src,
                    name=src.split(":")[-1],
                    type=EntityType.FUNCTION.value,
                    complexity=1,
                    sensitive_ops=0,
                    file_path="unknown"
                )

            src_ent = extraction.entities.get(src)
            tgt_ent = extraction.entities.get(tgt)
            src_c = src_ent.complexity if src_ent else 1
            tgt_c = tgt_ent.complexity if tgt_ent else 1
            has_sens = bool((src_ent and src_ent.sensitive_operations) or (tgt_ent and tgt_ent.sensitive_operations))

            dist = TopologicalMetricWeighting.compute_edge_distance(
                src, tgt, data, src_c, tgt_c, has_sens
            )
            g.add_edge(src, tgt, weight=dist, edge_type=data.get("type", "call"))

        # If graph is empty, add a dummy root node
        if g.number_of_nodes() == 0:
            g.add_node("root:empty", name="empty", type=EntityType.MODULE.value, complexity=1, sensitive_ops=0, file_path="")

        # 3. Create undirected version for simplicial complex filtration
        undirected_g = g.to_undirected()

        # Prune if graph exceeds max_nodes to keep TDA computation ultra-fast
        if undirected_g.number_of_nodes() > self.max_nodes:
            # Keep nodes with highest degree & centrality
            degrees = dict(undirected_g.degree())
            top_nodes = sorted(degrees.keys(), key=lambda n: degrees[n], reverse=True)[:self.max_nodes]
            undirected_g = undirected_g.subgraph(top_nodes).copy()
            g = g.subgraph(top_nodes).copy()

        # 4. Compute index mapping
        nodes = list(undirected_g.nodes())
        node_index = {n: i for i, n in enumerate(nodes)}
        index_to_node = {i: n for i, n in enumerate(nodes)}
        n_count = len(nodes)

        # 5. Compute all-pairs shortest path distance matrix
        dist_matrix = np.full((n_count, n_count), self.max_unconnected_dist, dtype=np.float32)
        np.fill_diagonal(dist_matrix, 0.0)

        # Calculate shortest path lengths using Dijkstra on edge 'weight'
        path_lengths = dict(nx.all_pairs_dijkstra_path_length(undirected_g, weight="weight"))
        for u, targets in path_lengths.items():
            u_idx = node_index[u]
            for v, d in targets.items():
                v_idx = node_index[v]
                dist_matrix[u_idx, v_idx] = min(float(d), self.max_unconnected_dist)

        # Quick clique estimation & connected components
        num_components = nx.number_connected_components(undirected_g)
        num_cycles = len(nx.cycle_basis(undirected_g)) if n_count < 200 else 0

        return CodeGraphResult(
            graph=g,
            undirected_graph=undirected_g,
            node_index=node_index,
            index_to_node=index_to_node,
            distance_matrix=dist_matrix,
            clique_count_est=undirected_g.number_of_edges(),
            betti_summary_rough={"betti_0": num_components, "betti_1_cycles": num_cycles}
        )
