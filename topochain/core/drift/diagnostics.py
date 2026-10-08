"""
Topological defect localization and diagnostic reasoning for TopoChain.
Maps abstract persistence anomalies back to source AST entities and supply chain hooks.
"""

from typing import Dict, List, Optional, Any, Set
import numpy as np

from topochain.core.topology.homology import PersistenceDiagramSet
from topochain.core.graph.builder import CodeGraphResult


class TopologicalDiagnosticsEngine:
    """
    Performs Root Cause Analysis (RCA) on topological drift anomalies.
    """

    @staticmethod
    def analyze_defects(
        current_diagrams: PersistenceDiagramSet,
        previous_diagrams: Optional[PersistenceDiagramSet],
        current_graph_result: Optional[CodeGraphResult] = None,
        previous_graph_result: Optional[CodeGraphResult] = None,
        previous_nodes: Optional[Set[str]] = None
    ) -> Dict[str, Any]:
        defects = []
        details = {}

        cur_h0_count = len(current_diagrams.h0)
        cur_h1_count = len(current_diagrams.h1)
        cur_h2_count = len(current_diagrams.h2)

        prev_h0_count = len(previous_diagrams.h0) if previous_diagrams else cur_h0_count
        prev_h1_count = len(previous_diagrams.h1) if previous_diagrams else cur_h1_count
        prev_h2_count = len(previous_diagrams.h2) if previous_diagrams else cur_h2_count

        delta_h0 = cur_h0_count - prev_h0_count
        delta_h1 = cur_h1_count - prev_h1_count
        delta_h2 = cur_h2_count - prev_h2_count

        details["delta_h0"] = delta_h0
        details["delta_h1"] = delta_h1
        details["delta_h2"] = delta_h2

        # AST node culprit localization
        suspect_nodes = []
        if current_graph_result:
            cur_nodes = set(current_graph_result.graph.nodes())
            if previous_graph_result:
                prev_n = set(previous_graph_result.graph.nodes())
            elif previous_nodes:
                prev_n = set(previous_nodes)
            else:
                prev_n = set()

            new_nodes = cur_nodes - prev_n if prev_n else set()
            for node in new_nodes:
                data = current_graph_result.graph.nodes[node]
                if data.get("sensitive_ops", 0) > 0 or "dep:" in node or "ext:" in node:
                    suspect_nodes.append({
                        "node_id": node,
                        "type": data.get("type", "unknown"),
                        "reason": "New node with sensitive API access or external dependency"
                    })
                elif not prev_n:
                    # Initial scan baseline, not suspect
                    pass
                else:
                    # Normal new entity
                    pass

        # 1. Check for sudden Loop Birth Anomaly (H1)
        # Supply chain hooks create cyclical call loops between internal core routines and payload handlers
        if delta_h1 > 0:
            defects.append("LOOP_BIRTH_ANOMALY")
            details["h1_defect_desc"] = (
                f"Detected {delta_h1} unexpected 1D topological cycle(s) in call graph. "
                "Indicates new closed feedback paths or stealth inter-module bridging."
            )

        # 2. Check for Component Severing or Island Injection with sensitive capabilities
        has_sensitive_suspects = any("sensitive" in s.get("reason", "") for s in suspect_nodes)
        if delta_h0 >= 3 and has_sensitive_suspects:
            defects.append("UNCONNECTED_ISLAND_INJECTION")
            details["h0_defect_desc"] = (
                f"Detected {delta_h0} isolated module island(s) introduced with sensitive API access."
            )
        elif delta_h0 <= -6:
            defects.append("STRUCTURAL_TOPOLOGY_COLLAPSE")
            details["h0_defect_desc"] = (
                f"Previously distinct subgraphs collapsed by {-delta_h0} connections."
            )

        # 3. Check for Void / Higher-order Cavity Emergence (H2)
        if delta_h2 > 0:
            defects.append("HIGH_DIMENSIONAL_VOID_EMERGENCE")
            details["h2_defect_desc"] = (
                f"Detected {delta_h2} 2D simplicial void(s) indicating complex circular clique dependencies."
            )

        # 4. Sensitive hook injection defect
        if has_sensitive_suspects and "SUSPICIOUS_SENSITIVE_HOOK_INJECTION" not in defects:
            defects.append("SUSPICIOUS_SENSITIVE_HOOK_INJECTION")

        details["defects"] = defects
        details["suspect_nodes"] = suspect_nodes[:8]

        # Formulate actionable security recommendation
        if defects or suspect_nodes:
            details["recommendation"] = (
                "CRITICAL: Structural shape deviation detected. Inspect recent diffs for indirect call hooks, "
                "unpinned external packages, or conditional execution in authentication/networking paths."
            )
        else:
            details["recommendation"] = "Topological evolution matches standard project manifold bounds."

        return details
