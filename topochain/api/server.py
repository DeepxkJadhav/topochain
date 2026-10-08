"""
FastAPI REST server for TopoChain supply chain verification.
Enables SOAR, CI/CD webhooks, and dashboard integration.
"""

from typing import Optional, List, Dict, Any
from fastapi import FastAPI, HTTPException, status
from pydantic import BaseModel, Field

from topochain.core.orchestrator import TopoChainOrchestrator

app = FastAPI(
    title="TopoChain Integrity API",
    description="Algebraic Topology & Topological Neural Network Verification API for Software Supply Chains",
    version="0.1.0"
)

# Global orchestrator instance
orchestrator = TopoChainOrchestrator()


class ScanRequest(BaseModel):
    repo_dir: str = Field(..., description="Path to codebase repository directory")
    commit_hash: Optional[str] = Field(None, description="Commit hash or unique snapshot ID")
    project_id: Optional[str] = Field(None, description="Project ID override")
    threshold: Optional[float] = Field(3.0, description="Anomaly z-score threshold")


class ScanResponse(BaseModel):
    project_id: str
    commit_hash: str
    status: str
    is_anomaly: bool
    drift_score: float
    z_score: float
    threshold: float
    severity: str
    defects: List[str]
    suspect_nodes: List[Dict[str, Any]]
    recommendation: str
    topological_summary: Dict[str, Any]


@app.get("/health", tags=["System"])
def health_check():
    return {
        "status": "online",
        "system": "TopoChain Core",
        "engine": "Persistent Homology & TNN",
        "version": "0.1.0"
    }


@app.post("/api/v1/scan", response_model=ScanResponse, tags=["Verification"])
def scan_repository(req: ScanRequest):
    try:
        res = orchestrator.scan_codebase(
            repo_dir=req.repo_dir,
            commit_hash=req.commit_hash,
            project_id=req.project_id,
            threshold=req.threshold
        )
        return ScanResponse(
            project_id=res["project_id"],
            commit_hash=res["commit_hash"],
            status=res["status"],
            is_anomaly=res["is_anomaly"],
            drift_score=res["drift_score"],
            z_score=res["z_score"],
            threshold=res["threshold"],
            severity=res["severity"],
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
    # Exclude raw numpy arrays for JSON serialization
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


@app.get("/api/v1/projects/{project_id}/baseline", tags=["Projects"])
def get_project_baseline(project_id: str):
    mean, var, count = orchestrator.storage.get_baseline_stats(project_id)
    return {
        "project_id": project_id,
        "drift_mean": mean,
        "drift_variance": var,
        "sample_count": count
    }
