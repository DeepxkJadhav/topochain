"""
FastAPI REST server for TopoChain supply chain verification.
Enables SOAR, CI/CD webhooks, SIEM integration, and web dashboard control.
"""

from typing import Optional, List, Dict, Any
from fastapi import FastAPI, HTTPException, status
from pydantic import BaseModel, Field

from topochain.core.orchestrator import TopoChainOrchestrator
from topochain.data.benchmark.ablation_runner import AblationRunner

app = FastAPI(
    title="TopoChain Integrity API",
    description="Multimodal Software Supply Chain Integrity Verification API combining AST, Dependency Intelligence, Algebraic Topology, and Semantic Analysis",
    version="0.2.0"
)

# Global orchestrator instance
orchestrator = TopoChainOrchestrator()


class ScanRequest(BaseModel):
    repo_dir: str = Field(..., description="Path to codebase repository directory")
    commit_hash: Optional[str] = Field(None, description="Commit hash or unique snapshot ID")
    project_id: Optional[str] = Field(None, description="Project ID override")
    threshold: Optional[float] = Field(3.0, description="Anomaly z-score threshold")
    run_sandbox: Optional[bool] = Field(False, description="Run isolated behavioral sandbox observation")


class ScanResponse(BaseModel):
    project_id: str
    commit_hash: str
    status: str
    decision_state: str = "SAFE"
    composite_risk: float = 0.0
    confidence: float = 0.85
    exit_code: int = 0
    is_anomaly: bool
    drift_score: float
    z_score: float
    threshold: float
    severity: str
    channel_scores: Dict[str, float] = Field(default_factory=dict)
    all_evidence: List[str] = Field(default_factory=list)
    defects: List[str]
    suspect_nodes: List[Dict[str, Any]]
    recommendation: str
    topological_summary: Dict[str, Any]


class BaselineApproveRequest(BaseModel):
    commit_hash: str = Field(..., description="Commit hash to approve as trusted anchor")
    approver: str = Field("security-lead", description="Identity or service approving the baseline")
    reason: str = Field("Verified benign evolution", description="Business/technical rationale for update")


@app.get("/health", tags=["System"])
def health_check():
    return {
        "status": "online",
        "system": "TopoChain Core",
        "engine": "Multimodal Persistent Homology & Risk Fusion",
        "version": "0.2.0"
    }


@app.post("/api/v1/scan", response_model=ScanResponse, tags=["Verification"])
def scan_repository(req: ScanRequest):
    try:
        res = orchestrator.scan_codebase(
            repo_dir=req.repo_dir,
            commit_hash=req.commit_hash,
            project_id=req.project_id,
            threshold=req.threshold,
            run_sandbox=bool(req.run_sandbox)
        )
        return ScanResponse(
            project_id=res["project_id"],
            commit_hash=res["commit_hash"],
            status=res["status"],
            decision_state=res.get("decision_state", "SAFE"),
            composite_risk=res.get("composite_risk", 0.0),
            confidence=res.get("confidence", 0.85),
            exit_code=res.get("exit_code", 0),
            is_anomaly=res["is_anomaly"],
            drift_score=res["drift_score"],
            z_score=res["z_score"],
            threshold=res["threshold"],
            severity=res["severity"],
            channel_scores=res.get("channel_scores", {}),
            all_evidence=res.get("all_evidence", []),
            defects=res["defects"],
            suspect_nodes=res["suspect_nodes"],
            recommendation=res["recommendation"],
            topological_summary=res["topological_summary"]
        )
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/api/v1/projects/{project_id}/history", tags=["Projects"])
def get_project_history(project_id: str, limit: int = 20):
    history = orchestrator.storage.get_history(project_id, limit=limit)
    serialized = []
    for h in history:
        serialized.append({
            "commit_hash": h["commit_hash"],
            "drift_score": h["drift_score"],
            "is_anomaly": h["is_anomaly"],
            "timestamp": h["timestamp"],
            "diagnostics": h["diagnostics"]
        })
    return {"project_id": project_id, "history": serialized}


def _sanitize_for_json(obj: Any) -> Any:
    import numpy as np
    import math
    if isinstance(obj, dict):
        return {str(k): _sanitize_for_json(v) for k, v in obj.items()}
    elif isinstance(obj, (list, tuple, set)):
        return [_sanitize_for_json(v) for v in obj]
    elif isinstance(obj, np.ndarray):
        return _sanitize_for_json(obj.tolist())
    elif isinstance(obj, (np.floating, float)):
        if math.isnan(obj) or math.isinf(obj):
            return 0.0
        return float(obj)
    elif isinstance(obj, (np.integer, int)):
        return int(obj)
    return obj


@app.get("/api/v1/projects/{project_id}/baseline", tags=["Projects"])
def get_project_baseline(project_id: str):
    mean, var, count = orchestrator.storage.get_baseline_stats(project_id)
    anchor = orchestrator.storage.get_trusted_anchor(project_id)
    if anchor and "anchor_embedding" in anchor:
        anchor = dict(anchor)
        anchor.pop("anchor_embedding", None)
    return {
        "project_id": project_id,
        "drift_mean": mean,
        "drift_variance": var,
        "sample_count": count,
        "trusted_anchor": anchor
    }


@app.post("/api/v1/projects/{project_id}/baseline/approve", tags=["Governance"])
def approve_project_baseline(project_id: str, req: BaselineApproveRequest):
    rec = orchestrator.storage.get_commit(req.commit_hash)
    if not rec:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Commit '{req.commit_hash}' not found in TopoChain records."
        )

    mean, var, count = orchestrator.storage.get_baseline_stats(project_id)
    orchestrator.storage.approve_baseline_update(
        project_id=project_id,
        commit_hash=req.commit_hash,
        new_mean=mean,
        new_variance=var,
        sample_count=count,
        approved_by=req.approver,
        reason=req.reason
    )
    orchestrator.storage.set_trusted_anchor(
        project_id=project_id,
        anchor_commit=req.commit_hash,
        anchor_embedding=rec["latent_embedding"],
        approved_by=req.approver
    )

    return {
        "status": "APPROVED",
        "project_id": project_id,
        "anchor_commit": req.commit_hash,
        "approved_by": req.approver,
        "reason": req.reason
    }


@app.get("/api/v1/projects/{project_id}/explain/{commit_hash}", tags=["Explainability"])
def explain_commit(project_id: str, commit_hash: str):
    rec = orchestrator.storage.get_commit(commit_hash)
    if not rec:
        raise HTTPException(status_code=404, detail=f"Commit '{commit_hash}' not found.")

    return _sanitize_for_json({
        "project_id": project_id,
        "commit_hash": commit_hash,
        "drift_score": rec["drift_score"],
        "is_anomaly": rec["is_anomaly"],
        "timestamp": rec["timestamp"],
        "diagnostics": rec.get("diagnostics", {})
    })


@app.post("/api/v1/benchmark/run", tags=["Scientific Benchmark"])
def run_benchmark():
    runner = AblationRunner()
    results = runner.run_ablation_study()
    serialized = {k: v.__dict__ for k, v in results.items()}
    return {
        "status": "COMPLETED",
        "configurations": serialized,
        "markdown_report": runner.generate_markdown_report(results)
    }
