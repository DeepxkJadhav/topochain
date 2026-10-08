"""
End-to-end TopoChain pipeline orchestrator.
Coordinates AST extraction, simplicial filtration, persistent homology, TNN inference, and drift detection.
"""

import os
from pathlib import Path
from typing import Dict, Any, Optional, Tuple, List
import numpy as np

from topochain.core.extractor import CodebaseExtractor, ExtractionResult
from topochain.core.graph import GraphBuilder, CodeGraphResult
from topochain.core.topology import (
    PersistentHomologyEngine,
    PersistenceDiagramSet,
    PersistenceImageConverter,
    TopologicalVisualizer,
)
from topochain.ai.inference import TNNInferenceEngine
from topochain.core.drift import (
    TopologicalDriftDetector,
    DriftResult,
    TopologicalDiagnosticsEngine,
)
from topochain.core.db import StorageEngine


class TopoChainOrchestrator:
    """
    Main processing engine for software supply chain topological verification.
    """

    def __init__(
        self,
        db_path: str = ".topochain/topochain.db",
        model_path: Optional[str] = None,
        default_threshold: float = 3.0
    ):
        self.extractor = CodebaseExtractor()
        self.graph_builder = GraphBuilder()
        self.homology_engine = PersistentHomologyEngine(max_dim=2, threshold=1.0)
        self.image_converter = PersistenceImageConverter(resolution=32)
        self.inference_engine = TNNInferenceEngine(model_path=model_path)
        self.drift_detector = TopologicalDriftDetector(default_threshold=default_threshold)
        self.storage = StorageEngine(db_path=db_path)
        self.default_threshold = default_threshold

    def scan_codebase(
        self,
        repo_dir: str,
        commit_hash: Optional[str] = None,
        project_id: Optional[str] = None,
        threshold: Optional[float] = None,
        save_plot_path: Optional[str] = None,
        update_baseline: bool = True
    ) -> Dict[str, Any]:
        """
        Executes complete verification pipeline for a repository snapshot.
        """
        p_dir = Path(repo_dir).resolve()
        proj_id = project_id or p_dir.name
        c_hash = commit_hash or f"commit_{os.urandom(4).hex()}"
        thresh = threshold or self.default_threshold

        # 1. Initialize project in database
        self.storage.get_or_create_project(proj_id, name=p_dir.name)

        # 2. Extract AST and dependencies
        extraction = self.extractor.extract_directory(str(p_dir))

        # 3. Build metric graph and distance matrix
        graph_result = self.graph_builder.build_graph(extraction)

        # 4. Compute persistent homology (H0, H1, H2)
        diagrams = self.homology_engine.compute(graph_result.distance_matrix)

        # 5. Convert to 2D persistence image
        pers_image = self.image_converter.convert(diagrams)

        # 6. TNN forward pass -> 64-dim unit vector
        embedding = self.inference_engine.embed_image(pers_image)

        # 7. Retrieve previous commit & baseline statistics
        previous_commit = self.storage.get_latest_commit(proj_id)
        prev_emb = previous_commit["latent_embedding"] if previous_commit else None
        base_mean, base_var, sample_count = self.storage.get_baseline_stats(proj_id)

        # 8. Calculate topological drift & z-score anomaly
        drift_res = self.drift_detector.compute_drift(
            current_embedding=embedding,
            previous_embedding=prev_emb,
            baseline_mean=base_mean,
            baseline_variance=base_var,
            custom_threshold=thresh
        )

        # 9. Perform Root Cause Analysis & defect localization
        prev_diagrams = None
        prev_nodes = None
        if previous_commit and "diagnostics" in previous_commit:
            p_diag = previous_commit["diagnostics"]
            if "diagrams_raw" in p_diag:
                raw_d = p_diag["diagrams_raw"]
                h0_arr = np.array(raw_d.get("h0", []), dtype=np.float32).reshape(-1, 2) if raw_d.get("h0") else np.empty((0, 2), dtype=np.float32)
                h1_arr = np.array(raw_d.get("h1", []), dtype=np.float32).reshape(-1, 2) if raw_d.get("h1") else np.empty((0, 2), dtype=np.float32)
                h2_arr = np.array(raw_d.get("h2", []), dtype=np.float32).reshape(-1, 2) if raw_d.get("h2") else np.empty((0, 2), dtype=np.float32)
                prev_diagrams = PersistenceDiagramSet(h0=h0_arr, h1=h1_arr, h2=h2_arr)
            if "nodes" in p_diag:
                prev_nodes = set(p_diag["nodes"])

        diagnostics = TopologicalDiagnosticsEngine.analyze_defects(
            current_diagrams=diagrams,
            previous_diagrams=prev_diagrams,
            current_graph_result=graph_result,
            previous_nodes=prev_nodes
        )
        # Store serialized topological invariants for subsequent commit comparisons
        diagnostics["diagrams_raw"] = {
            "h0": diagrams.h0.tolist(),
            "h1": diagrams.h1.tolist(),
            "h2": diagrams.h2.tolist()
        }
        diagnostics["nodes"] = list(graph_result.graph.nodes())
        if diagnostics.get("defects"):
            drift_res.is_anomaly = True
            if drift_res.severity in {"CLEAN", "NORMAL_EVOLUTION", "ELEVATED_VARIATION"}:
                drift_res.severity = "CRITICAL_ATTACK"
        drift_res.diagnostics = diagnostics

        # 10. Update baseline statistics if benign and enabled
        if update_baseline and not drift_res.is_anomaly and prev_emb is not None:
            new_mean, new_var, new_count = TopologicalDriftDetector.update_baseline_statistics(
                drifts=[drift_res.drift_score],
                existing_mean=base_mean,
                existing_var=base_var,
                existing_count=sample_count
            )
            self.storage.update_baseline_stats(proj_id, new_mean, new_var, new_count)

        # 11. Record commit to SQLite
        self.storage.record_commit(
            commit_hash=c_hash,
            project_id=proj_id,
            persistence_image=pers_image,
            latent_embedding=embedding,
            drift_score=drift_res.drift_score,
            is_anomaly=drift_res.is_anomaly,
            diagnostics=diagnostics
        )

        # 12. Optional plot generation
        plot_saved = None
        if save_plot_path:
            plot_saved = TopologicalVisualizer.save_plot(
                diagrams=diagrams,
                image_tensor=pers_image,
                output_path=save_plot_path,
                title=f"TopoChain: {proj_id} ({c_hash[:8]})"
            )

        # 13. Format return result
        return {
            "project_id": proj_id,
            "commit_hash": c_hash,
            "status": "ANOMALY_DETECTED" if drift_res.is_anomaly else "PASSED",
            "is_anomaly": drift_res.is_anomaly,
            "drift_score": round(drift_res.drift_score, 4),
            "z_score": round(drift_res.z_score, 3),
            "threshold": thresh,
            "severity": drift_res.severity,
            "baseline": {
                "mean": round(base_mean, 4),
                "std": round(drift_res.baseline_std, 4),
                "samples": sample_count
            },
            "topological_summary": diagrams.summary(),
            "graph_metrics": {
                "nodes": graph_result.graph.number_of_nodes(),
                "edges": graph_result.graph.number_of_edges(),
                "components": graph_result.betti_summary_rough.get("betti_0", 1),
                "clique_simplices": graph_result.clique_count_est
            },
            "defects": diagnostics.get("defects", []),
            "suspect_nodes": diagnostics.get("suspect_nodes", []),
            "recommendation": diagnostics.get("recommendation", ""),
            "plot_path": plot_saved
        }
