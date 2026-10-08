"""
Unit tests for Multimodal Risk Fusion and 3-State Decision Engine.
Tests:
- SAFE: normal clean commits
- REVIEW: major architectural refactor produces REVIEW, never BLOCK
- BLOCK: multi-vector supply chain attacks produce BLOCK
- Topology-preserving attack: correctly blocked even when topology drift is 0.0
"""

import pytest

from topochain.core.fusion import (
    ChannelSignal,
    RiskFusionEngine,
    DecisionEngine,
    DecisionState,
)


def test_safe_normal_commit():
    fusion = RiskFusionEngine()
    decision = DecisionEngine()

    signals = {
        "dependency": ChannelSignal(name="dependency", score=0.05, confidence=0.9),
        "semantic": ChannelSignal(name="semantic", score=0.0, confidence=0.95),
        "topology": ChannelSignal(name="topology", score=0.08, confidence=0.85),
        "git_evolution": ChannelSignal(name="git_evolution", score=0.05, confidence=0.7),
    }

    fused = fusion.fuse_signals(signals)
    dec = decision.evaluate(fused)

    assert dec.state == DecisionState.SAFE
    assert dec.exit_code == 0
    assert dec.composite_risk < 0.25


def test_major_refactor_produces_review_not_block():
    fusion = RiskFusionEngine()
    decision = DecisionEngine()

    # Major refactor has high topology drift (e.g. 0.85), but clean dependencies and semantics
    signals = {
        "dependency": ChannelSignal(name="dependency", score=0.0, confidence=0.95),
        "semantic": ChannelSignal(name="semantic", score=0.05, confidence=0.9),
        "topology": ChannelSignal(name="topology", score=0.85, confidence=0.85, evidence=["Significant structural restructuring"]),
        "git_evolution": ChannelSignal(name="git_evolution", score=0.20, confidence=0.7),
    }

    fused = fusion.fuse_signals(signals)
    dec = decision.evaluate(fused)

    assert fused.is_refactor_pattern is True
    assert dec.state == DecisionState.REVIEW  # Must NEVER be BLOCK!
    assert dec.exit_code == 0
    assert "Legitimate architectural evolution" in dec.summary


def test_multi_vector_attack_produces_block():
    fusion = RiskFusionEngine()
    decision = DecisionEngine()

    signals = {
        "dependency": ChannelSignal(name="dependency", score=0.85, confidence=0.9, evidence=["Typosquatted package: crypt0graphy"]),
        "semantic": ChannelSignal(name="semantic", score=0.90, confidence=0.95, evidence=["CRITICAL: Network exfiltration + credentials"]),
        "topology": ChannelSignal(name="topology", score=0.75, confidence=0.85, evidence=["Loop birth anomaly in auth flow"]),
        "git_evolution": ChannelSignal(name="git_evolution", score=0.40, confidence=0.7),
    }

    fused = fusion.fuse_signals(signals)
    dec = decision.evaluate(fused)

    assert dec.state == DecisionState.BLOCK
    assert dec.exit_code == 1
    assert dec.composite_risk >= 0.70


def test_topology_preserving_attack_produces_block():
    fusion = RiskFusionEngine()
    decision = DecisionEngine()

    # Attack modifies code in-place: topology drift is zero (0.0)!
    signals = {
        "dependency": ChannelSignal(name="dependency", score=0.80, confidence=0.9, evidence=["Dependency confusion: corp-internal-auth"]),
        "semantic": ChannelSignal(name="semantic", score=0.95, confidence=0.95, evidence=["CRITICAL: Hardcoded authentication bypass detected"]),
        "topology": ChannelSignal(name="topology", score=0.0, confidence=0.85),  # INCONCLUSIVE / ZERO DRIFT!
        "git_evolution": ChannelSignal(name="git_evolution", score=0.30, confidence=0.7),
    }

    fused = fusion.fuse_signals(signals)
    dec = decision.evaluate(fused)

    # System must successfully BLOCK based on semantic and dependency intelligence even though topology is 0!
    assert dec.state == DecisionState.BLOCK
    assert dec.exit_code == 1
    assert "supply chain compromise" in dec.summary.lower()
