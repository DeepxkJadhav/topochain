"""
Decision Engine for TopoChain.
Maps fused risk results to three primary operational security states:
SAFE, REVIEW, BLOCK.
Ensures legitimate major refactors produce REVIEW, not BLOCK.
"""

from dataclasses import dataclass, field
from typing import Dict, List, Optional, Any

from topochain.core.fusion.risk_engine import FusedRiskResult


class DecisionState:
    SAFE = "SAFE"
    REVIEW = "REVIEW"
    BLOCK = "BLOCK"


@dataclass
class DecisionResult:
    state: str  # SAFE, REVIEW, BLOCK
    composite_risk: float
    confidence: float
    summary: str
    recommendation: str
    evidence: List[str] = field(default_factory=list)
    channel_breakdown: Dict[str, float] = field(default_factory=dict)
    exit_code: int = 0  # 0 for SAFE/REVIEW, 1 for BLOCK


class DecisionEngine:
    """
    Evaluates fused multimodal evidence and issues defensible security verdicts.
    """

    def __init__(
        self,
        block_threshold: float = 0.68,
        review_threshold: float = 0.32
    ):
        self.block_threshold = block_threshold
        self.review_threshold = review_threshold

    def evaluate(self, fused: FusedRiskResult) -> DecisionResult:
        risk = fused.composite_risk
        confidence = fused.composite_confidence
        corroborating = fused.corroborating_channels

        # Critical single-channel triggers (e.g. arbitrary postinstall execution or hardcoded credential leak)
        sem_score = fused.channel_scores.get("semantic", 0.0)
        dep_score = fused.channel_scores.get("dependency", 0.0)
        critical_evidence_present = any(
            ("CRITICAL" in ev) or ("postinstall" in ev.lower()) or ("AUTHENTICATION_BYPASS" in ev)
            for ev in fused.all_evidence
        )

        # 1. Refactor Protection:
        # A legitimate large refactor produces high topology drift, but clean dependencies and clean semantics.
        # It must produce REVIEW, never BLOCK.
        if fused.is_refactor_pattern:
            state = DecisionState.REVIEW
            summary = (
                f"Legitimate architectural evolution detected. High structural/topological drift "
                f"({fused.channel_scores.get('topology', 0.0):.2f}) without malicious dependency or semantic signals."
            )
            recommendation = (
                "Review architectural refactor with author before merge. "
                "Update baseline anchor via 'topochain baseline approve' once verified."
            )
            exit_code = 0

        # 2. BLOCK criteria:
        # High composite risk supported by multiple independent channels OR unequivocal critical exploit evidence
        elif (risk >= self.block_threshold and (len(corroborating) >= 2 or critical_evidence_present)) or (sem_score >= 0.90 and dep_score >= 0.60):
            state = DecisionState.BLOCK
            summary = (
                f"Multiple independent security channels indicate supply chain compromise "
                f"(Risk: {risk:.2f}, Corroborating: {', '.join(corroborating) or 'Critical Vector'})."
            )
            recommendation = (
                "CRITICAL: Block CI/CD pipeline and quarantine commit immediately. "
                "Inspect newly introduced dependencies, lifecycle hooks, and privileged API calls."
            )
            exit_code = 1

        # 3. REVIEW criteria:
        # Elevated variation or single suspicious channel requiring human-in-the-loop inspection
        elif risk >= self.review_threshold or len(corroborating) >= 1 or critical_evidence_present:
            state = DecisionState.REVIEW
            summary = (
                f"Elevated risk signals detected ({risk:.2f}). Evidence is unusual but insufficient "
                f"to warrant automated blocking."
            )
            recommendation = (
                "Manual peer-review recommended. Examine flagged changes in dependencies or structural geometry."
            )
            exit_code = 0

        # 4. SAFE criteria:
        else:
            state = DecisionState.SAFE
            summary = "Evidence is consistent with normal, benign project evolution."
            recommendation = "Commit passed automated supply chain integrity verification."
            exit_code = 0

        return DecisionResult(
            state=state,
            composite_risk=risk,
            confidence=confidence,
            summary=summary,
            recommendation=recommendation,
            evidence=fused.all_evidence,
            channel_breakdown=fused.channel_scores,
            exit_code=exit_code
        )
