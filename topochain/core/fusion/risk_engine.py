"""
Multimodal Risk Fusion Engine for TopoChain.
Integrates independent security signals into a unified, calibrated risk assessment.
Does NOT assume topology is the sole or dominant detector.
"""

from dataclasses import dataclass, field
from typing import Dict, List, Optional, Any


@dataclass
class ChannelSignal:
    name: str
    score: float  # Normalized 0.0 to 1.0
    confidence: float  # Normalized 0.0 to 1.0
    evidence: List[str] = field(default_factory=list)
    raw_details: Dict[str, Any] = field(default_factory=dict)


@dataclass
class FusedRiskResult:
    composite_risk: float  # 0.0 to 1.0
    composite_confidence: float  # 0.0 to 1.0
    channel_scores: Dict[str, float] = field(default_factory=dict)
    channel_confidences: Dict[str, float] = field(default_factory=dict)
    all_evidence: List[str] = field(default_factory=list)
    corroborating_channels: List[str] = field(default_factory=list)
    is_refactor_pattern: bool = False
    details: Dict[str, Any] = field(default_factory=dict)


class RiskFusionEngine:
    """
    Transparent, configurable multi-signal risk fusion engine.
    Weights each independent dimension without treating any single signal as absolute authority.
    """

    DEFAULT_WEIGHTS = {
        "dependency": 0.30,
        "semantic": 0.30,
        "topology": 0.20,
        "ast_structural": 0.10,
        "git_evolution": 0.10,
        "runtime": 0.0,
    }

    def __init__(self, custom_weights: Optional[Dict[str, float]] = None):
        weights = dict(self.DEFAULT_WEIGHTS)
        if custom_weights:
            weights.update(custom_weights)
        self.weights = weights

    def fuse_signals(
        self,
        signals: Dict[str, ChannelSignal]
    ) -> FusedRiskResult:
        channel_scores = {}
        channel_confidences = {}
        all_evidence = []
        corroborating = []

        total_weight = 0.0
        weighted_risk_sum = 0.0
        weighted_conf_sum = 0.0

        for channel_name, signal in signals.items():
            s_score = max(0.0, min(1.0, float(signal.score)))
            s_conf = max(0.0, min(1.0, float(signal.confidence)))

            channel_scores[channel_name] = s_score
            channel_confidences[channel_name] = s_conf

            if signal.evidence:
                for ev in signal.evidence:
                    all_evidence.append(f"[{channel_name.upper()}] {ev}")

            # Track high-risk corroborating channels
            if s_score >= 0.55:
                corroborating.append(channel_name)

            weight = self.weights.get(channel_name, 0.10)
            total_weight += weight
            weighted_risk_sum += s_score * weight * s_conf
            weighted_conf_sum += s_conf * weight

        # Normalize composite scores
        if total_weight > 0:
            raw_composite = weighted_risk_sum / total_weight
            composite_confidence = weighted_conf_sum / total_weight
        else:
            raw_composite = 0.0
            composite_confidence = 0.50

        # Pattern analysis: Major Refactor vs Multi-vector Attack
        top_score = channel_scores.get("topology", 0.0)
        dep_score = channel_scores.get("dependency", 0.0)
        sem_score = channel_scores.get("semantic", 0.0)
        run_score = channel_scores.get("runtime", 0.0)

        # Refactor pattern: High structural/topological drift, but zero malicious dependency or semantic patterns
        is_refactor_pattern = bool(
            top_score >= 0.50 and
            dep_score < 0.25 and
            sem_score < 0.25 and
            run_score < 0.25
        )

        # Multi-signal synergy boost: if 2+ independent channels confirm anomalies, boost risk
        if len(corroborating) >= 2 and not is_refactor_pattern:
            boost = 0.15 * (len(corroborating) - 1)
            raw_composite = min(1.0, raw_composite + boost)

        return FusedRiskResult(
            composite_risk=round(raw_composite, 4),
            composite_confidence=round(composite_confidence, 4),
            channel_scores=channel_scores,
            channel_confidences=channel_confidences,
            all_evidence=all_evidence,
            corroborating_channels=corroborating,
            is_refactor_pattern=is_refactor_pattern,
            details={
                "raw_weighted_risk": round(raw_composite, 4),
                "active_weights": self.weights,
                "channels_count": len(signals)
            }
        )
