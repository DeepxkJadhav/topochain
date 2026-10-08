"""
End-to-end TopoChain pipeline orchestrator.
Coordinates Multimodal Software Supply Chain Integrity Verification:
- AST / Code Structure Analysis
- Multi-ecosystem Dependency Intelligence
- Algebraic Topology & Persistent Homology Drift
- Semantic & Capability Analysis
- Git Evolution Dynamics
- Isolated Behavioral Observation (Zero-host execution)
- Calibrated Multimodal Risk Fusion
- 3-State Defensible Decision Engine (SAFE / REVIEW / BLOCK)
- Baseline Protection & Anti-Poisoning Architecture
"""

import os
from pathlib import Path
from typing import Dict, Any, Optional, Tuple, List
import numpy as np

from topochain.core.extractor import CodebaseExtractor, ExtractionResult
from topochain.core.extractor.dependency_extractor import DependencyExtractor
from topochain.core.semantic.analyzer import SemanticAnalyzer
from topochain.core.git.analyzer import GitEvolutionAnalyzer
from topochain.core.sandbox.runner import BehavioralSandboxRunner, SandboxConfig
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
from topochain.core.fusion.risk_engine import RiskFusionEngine, ChannelSignal, FusedRiskResult
from topochain.core.fusion.decision_engine import DecisionEngine, DecisionState, DecisionResult
from topochain.core.db import StorageEngine


class TopoChainOrchestrator:
    """
    Multimodal processing orchestrator for software supply chain security verification.
    """

    def __init__(
        self,
        db_path: str = ".topochain/topochain.db",
        model_path: Optional[str] = None,
        default_threshold: float = 3.0,
        custom_channel_weights: Optional[Dict[str, float]] = None
    ):
        self.extractor = CodebaseExtractor()
        self.dep_extractor = DependencyExtractor()
        self.semantic_analyzer = SemanticAnalyzer()
        self.git_analyzer = GitEvolutionAnalyzer()
        self.sandbox_runner = BehavioralSandboxRunner(SandboxConfig(mode="emulation"))
        self.graph_builder = GraphBuilder()
        self.homology_engine = PersistentHomologyEngine(max_dim=2, threshold=1.0)
        self.image_converter = PersistenceImageConverter(resolution=32)
        self.inference_engine = TNNInferenceEngine(model_path=model_path)
        self.drift_detector = TopologicalDriftDetector(default_threshold=default_threshold)
        self.risk_fusion = RiskFusionEngine(custom_weights=custom_channel_weights)
        self.decision_engine = DecisionEngine()
        self.storage = StorageEngine(db_path=db_path)
        self.default_threshold = default_threshold

    def scan_codebase(
        self,
        repo_dir: str,
        commit_hash: Optional[str] = None,
        project_id: Optional[str] = None,
        threshold: Optional[float] = None,
        save_plot_path: Optional[str] = None,
        update_baseline: bool = True,
        run_sandbox: bool = False,
        sandbox_mock_trace: Optional[Dict[str, Any]] = None,
        custom_weights: Optional[Dict[str, float]] = None,
    ) -> Dict[str, Any]:
        """
        Executes complete multimodal verification pipeline for a repository snapshot.
        """
        p_dir = Path(repo_dir).resolve()
        proj_id = project_id or p_dir.name
        c_hash = commit_hash or f"commit_{os.urandom(4).hex()}"
        thresh = threshold or self.default_threshold

        # 1. Initialize project in database
        self.storage.get_or_create_project(proj_id, name=p_dir.name)

        # 2. Extract AST and code structure
        extraction = self.extractor.extract_directory(str(p_dir))

        # 3. Multi-ecosystem Dependency Intelligence
        dep_result = self.dep_extractor.analyze_directory(str(p_dir))
        dep_signal = ChannelSignal(
            name="dependency",
            score=dep_result.risk_score,
            confidence=0.92,
            evidence=list(dep_result.findings),
            raw_details=dep_result.summary()
        )

        # 4. Semantic & Capability Analysis
        sem_result = self.semantic_analyzer.analyze_directory(str(p_dir))
        sem_signal = ChannelSignal(
            name="semantic",
            score=sem_result.risk_score,
            confidence=0.90,
            evidence=list(sem_result.findings),
            raw_details=sem_result.summary()
        )

        # 5. Git Evolution Dynamics
        git_result = self.git_analyzer.analyze_repository(str(p_dir))
        git_signal = ChannelSignal(
            name="git_evolution",
            score=git_result.risk_score,
            confidence=0.75,
            evidence=list(git_result.findings),
            raw_details=git_result.summary()
        )

        # 6. Build metric graph and compute persistent homology
        graph_result = self.graph_builder.build_graph(extraction)
        diagrams = self.homology_engine.compute(graph_result.distance_matrix)
        pers_image = self.image_converter.convert(diagrams)
        embedding = self.inference_engine.embed_image(pers_image)

        # 7. AST / Structural Graph delta
        previous_commit = self.storage.get_latest_commit(proj_id)
        prev_emb = previous_commit["latent_embedding"] if previous_commit else None
        base_mean, base_var, sample_count = self.storage.get_baseline_stats(proj_id)

        prev_node_count = 0
        prev_edge_count = 0
        if previous_commit and "diagnostics" in previous_commit:
            p_nodes = previous_commit["diagnostics"].get("nodes", [])
            prev_node_count = len(p_nodes)

        curr_nodes = graph_result.graph.number_of_nodes()
        curr_edges = graph_result.graph.number_of_edges()
        node_delta = abs(curr_nodes - prev_node_count) if prev_node_count > 0 else 0
        ast_risk = min(1.0, node_delta * 0.08)
        ast_signal = ChannelSignal(
            name="ast_structural",
            score=ast_risk,
            confidence=0.80,
            evidence=[f"AST entity delta: {node_delta} nodes shifted"] if node_delta > 3 else [],
            raw_details={"nodes": curr_nodes, "edges": curr_edges, "node_delta": node_delta}
        )

        # 8. Calculate topological drift & diagnostics
        drift_res = self.drift_detector.compute_drift(
            current_embedding=embedding,
            previous_embedding=prev_emb,
            baseline_mean=base_mean,
            baseline_variance=base_var,
            custom_threshold=thresh
        )

        # Root Cause Analysis & defect localization
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
        diagnostics["diagrams_raw"] = {
            "h0": diagrams.h0.tolist(),
            "h1": diagrams.h1.tolist(),
            "h2": diagrams.h2.tolist()
        }
        diagnostics["nodes"] = list(graph_result.graph.nodes())
        drift_res.diagnostics = diagnostics

        # Calibrated Topological Signal
        topo_score = min(1.0, max(0.0, drift_res.drift_score * 1.5))
        topo_signal = ChannelSignal(
            name="topology",
            score=topo_score,
            confidence=0.85,
            evidence=[f"Topological drift: {drift_res.drift_score:.4f} (z-score: {drift_res.z_score:.2f})"],
            raw_details={
                "drift_score": drift_res.drift_score,
                "z_score": drift_res.z_score,
                "is_anomaly": drift_res.is_anomaly,
                "severity": drift_res.severity,
            }
        )

        # 9. Optional Behavioral Sandbox Observation
        runtime_signal = None
        sandbox_obs = None
        if run_sandbox or sandbox_mock_trace:
            sandbox_obs = self.sandbox_runner.run_observation(
                repo_dir=str(p_dir),
                mock_events=sandbox_mock_trace
            )
            runtime_signal = sandbox_obs.to_channel_signal()

        # 10. Multimodal Risk Fusion
        active_signals = {
            "dependency": dep_signal,
            "semantic": sem_signal,
            "topology": topo_signal,
            "ast_structural": ast_signal,
            "git_evolution": git_signal,
        }
        if runtime_signal:
            active_signals["runtime"] = runtime_signal

        fusion_engine = self.risk_fusion
        if custom_weights:
            fusion_engine = RiskFusionEngine(custom_weights=custom_weights)

        fused = fusion_engine.fuse_signals(active_signals)

        # 11. Defensible Decision Engine (SAFE, REVIEW, BLOCK)
        decision = self.decision_engine.evaluate(fused)

        # 12. Baseline Protection & Gradual Poisoning Check
        is_poisoning, poison_dist, anchor_commit = self.storage.is_drift_poisoning(
            proj_id,
            embedding,
            poisoning_threshold=0.55
        )
        poisoning_alert = None
        if is_poisoning:
            poisoning_alert = (
                f"POTENTIAL DRIFT POISONING: Cumulative distance from trusted anchor '{anchor_commit}' "
                f"is {poison_dist:.3f} (exceeds threshold 0.55)."
            )
            decision.evidence.append(poisoning_alert)
            if decision.state == DecisionState.SAFE:
                decision.state = DecisionState.REVIEW

        # Update baseline statistics only if verified SAFE and no poisoning
        if update_baseline and decision.state == DecisionState.SAFE and not is_poisoning and prev_emb is not None:
            new_mean, new_var, new_count = TopologicalDriftDetector.update_baseline_statistics(
                drifts=[drift_res.drift_score],
                existing_mean=base_mean,
                existing_var=base_var,
                existing_count=sample_count
            )
            self.storage.update_baseline_stats(proj_id, new_mean, new_var, new_count)

        # Record commit to SQLite
        self.storage.record_commit(
            commit_hash=c_hash,
            project_id=proj_id,
            persistence_image=pers_image,
            latent_embedding=embedding,
            drift_score=drift_res.drift_score,
            is_anomaly=(decision.state == DecisionState.BLOCK or drift_res.is_anomaly),
            diagnostics=diagnostics
        )

        # Optional visualization
        plot_saved = None
        if save_plot_path:
            plot_saved = TopologicalVisualizer.save_plot(
                diagrams=diagrams,
                image_tensor=pers_image,
                output_path=save_plot_path,
                title=f"TopoChain: {proj_id} ({c_hash[:8]})"
            )

        # 13. Comprehensive Unified Response
        if decision.state == DecisionState.BLOCK:
            legacy_status = "BLOCK"
            is_anomaly = True
        elif decision.state == DecisionState.REVIEW:
            if fused.is_refactor_pattern:
                legacy_status = "PASSED"
                is_anomaly = False
            else:
                legacy_status = "REVIEW"
                is_anomaly = False
        else:
            legacy_status = "PASSED"
            is_anomaly = False

        return {
            "project_id": proj_id,
            "commit_hash": c_hash,
            "status": legacy_status,
            "decision_state": decision.state,
            "is_anomaly": is_anomaly,
            "composite_risk": round(fused.composite_risk, 4),
            "confidence": round(decision.confidence, 3),
            "exit_code": decision.exit_code,
            "drift_score": round(drift_res.drift_score, 4),
            "z_score": round(drift_res.z_score, 3),
            "threshold": thresh,
            "severity": drift_res.severity,
            "summary": decision.summary,
            "recommendation": decision.recommendation,
            "is_refactor": fused.is_refactor_pattern,
            "channel_scores": {k: round(v, 4) for k, v in fused.channel_scores.items()},
            "corroborating_channels": fused.corroborating_channels,
            "all_evidence": decision.evidence,
            "defects": diagnostics.get("defects", []),
            "suspect_nodes": diagnostics.get("suspect_nodes", []),
            "topological_summary": diagrams.summary(),
            "graph_metrics": {
                "nodes": curr_nodes,
                "edges": curr_edges,
                "components": graph_result.betti_summary_rough.get("betti_0", 1),
                "clique_simplices": graph_result.clique_count_est
            },
            "baseline": {
                "mean": round(base_mean, 4),
                "std": round(drift_res.baseline_std, 4),
                "samples": sample_count
            },
            "poisoning_alert": poisoning_alert,
            "plot_path": plot_saved
        }
