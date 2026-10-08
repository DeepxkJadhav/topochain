"""
Edge weighting models and metric space distance transforms for TopoChain.
Maps semantic and structural relationships into a metric space suitable for simplicial filtration.
"""

import math
from typing import Dict, Any, Optional


class TopologicalMetricWeighting:
    """
    Computes metric distances for edges in the code & dependency graph.
    In Vietoris-Rips filtration:
    - Smaller distance => simplex appears early in filtration (tight coupling).
    - Larger distance => simplex appears late in filtration (loose coupling).
    """

    DEFAULT_INTRA_MODULE = 0.20
    DEFAULT_INTER_MODULE = 0.50
    DEFAULT_DEPENDENCY = 0.75
    DEFAULT_CONTAINS = 0.15
    DEFAULT_SENSITIVE = 0.35

    @classmethod
    def compute_edge_distance(
        cls,
        source_id: str,
        target_id: str,
        edge_data: Dict[str, Any],
        source_complexity: int = 1,
        target_complexity: int = 1,
        has_sensitive_ops: bool = False
    ) -> float:
        edge_type = edge_data.get("type", "call")
        base_weight = edge_data.get("weight", 0.5)

        if edge_type == "contains" or edge_type == "member":
            base_dist = cls.DEFAULT_CONTAINS
        elif edge_type == "dependency_use":
            base_dist = cls.DEFAULT_DEPENDENCY
        else:
            # Check if source and target belong to same module
            src_mod = source_id.split(".")[0] if "." in source_id else source_id
            tgt_mod = target_id.split(".")[0] if "." in target_id else target_id
            if src_mod == tgt_mod:
                base_dist = cls.DEFAULT_INTRA_MODULE
            else:
                base_dist = cls.DEFAULT_INTER_MODULE

        # Modulation by complexity: complex logic creates richer simplicial geometry
        complexity_factor = 1.0 + 0.1 * math.log1p(max(source_complexity, target_complexity))
        dist = base_dist * complexity_factor

        # Sensitive operations alter topological connectivity
        if has_sensitive_ops:
            dist *= 0.85  # Tighter coupling to highlight stealth hooks

        # Ensure metric distance is strictly positive and bounded
        return max(0.05, min(1.0, float(dist)))
