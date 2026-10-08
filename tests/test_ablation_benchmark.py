"""
Unit tests for TopoChain empirical ablation study runner.
"""

from topochain.data.benchmark.ablation_runner import (
    AblationRunner,
    AblationResult,
    BenchmarkScenario,
)


def test_ablation_corpus_construction():
    runner = AblationRunner()
    corpus = runner.build_benchmark_corpus()
    assert len(corpus) >= 8

    # Verify diversity
    refactors = [c for c in corpus if c.is_refactor]
    topo_preserving = [c for c in corpus if c.ground_truth and not c.is_topology_changing]
    topo_changing = [c for c in corpus if c.ground_truth and c.is_topology_changing]

    assert len(refactors) >= 2
    assert len(topo_preserving) >= 2
    assert len(topo_changing) >= 4


def test_ablation_study_execution():
    runner = AblationRunner()
    results = runner.run_ablation_study()

    # Must contain all configurations A through H
    for cid in ["A", "B", "C", "D", "E", "F", "G", "H"]:
        assert cid in results
        res = results[cid]
        assert isinstance(res, AblationResult)
        assert 0.0 <= res.precision <= 1.0
        assert 0.0 <= res.recall <= 1.0
        assert 0.0 <= res.f1 <= 1.0
        assert 0.0 <= res.roc_auc <= 1.0
        assert 0.0 <= res.pr_auc <= 1.0

    # Config D (Topology-only) must suffer from in-place attacks (higher FNR)
    # Config H (Full Multimodal) must achieve strong overall F1 score
    res_d = results["D"]
    res_h = results["H"]

    assert res_d.fnr_topology_preserving > 0.0  # Topology alone misses in-place tampering
    assert res_h.f1 >= res_d.f1  # Multimodal matches or exceeds topology alone


def test_ablation_markdown_report():
    runner = AblationRunner()
    results = runner.run_ablation_study()
    report = runner.generate_markdown_report(results)

    assert "# TopoChain Empirical Ablation Study Results" in report
    assert "| **A** |" in report
    assert "| **H** |" in report
    assert "Empirical Findings & Scientific Conclusions" in report
