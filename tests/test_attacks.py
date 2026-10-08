"""
Unit and integration tests for attack generators and topological defect detection.
"""

import tempfile
from pathlib import Path

from topochain.data.datasets.loader import BenchmarkRepoGenerator
from topochain.data.synthetic.attack_generator import SyntheticAttackGenerator
from topochain.core.orchestrator import TopoChainOrchestrator
from topochain.core.extractor import CodebaseExtractor


def test_benign_refactor_vs_backdoor_injection():
    with tempfile.TemporaryDirectory() as tmpdir:
        BenchmarkRepoGenerator.create_sample_service(tmpdir)
        db_path = str(Path(tmpdir) / "topochain.db")
        orchestrator = TopoChainOrchestrator(db_path=db_path)

        # Baseline commit (clean)
        res_0 = orchestrator.scan_codebase(tmpdir, commit_hash="c0_init")
        assert res_0["status"] == "PASSED"

        # Benign refactor
        SyntheticAttackGenerator.apply_benign_refactor(str(Path(tmpdir) / "auth.py"))
        res_refactor = orchestrator.scan_codebase(tmpdir, commit_hash="c1_refactor")
        # Benign refactoring should maintain low drift and PASS
        assert res_refactor["status"] == "PASSED"
        assert not res_refactor["is_anomaly"]

        # Malicious backdoor injection
        SyntheticAttackGenerator.inject_subtle_logic_backdoor(str(Path(tmpdir) / "api.py"))
        res_attack = orchestrator.scan_codebase(tmpdir, commit_hash="c2_backdoor", threshold=2.0)
        
        # Verify backdoor was detected or produced elevated topological defect
        assert res_attack["drift_score"] > res_refactor["drift_score"] or len(res_attack["defects"]) > 0


def test_typosquatting_detection():
    with tempfile.TemporaryDirectory() as tmpdir:
        BenchmarkRepoGenerator.create_sample_service(tmpdir)
        SyntheticAttackGenerator.inject_typosquatting_dependency(tmpdir)

        extractor = CodebaseExtractor()
        ext_res = extractor.extract_directory(tmpdir)

        suspicious = [d for d in ext_res.dependencies if d.suspicious_flags]
        assert len(suspicious) > 0
        assert any("typosquat" in f for f in suspicious[0].suspicious_flags)
