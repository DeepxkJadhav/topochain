"""
Security hardening and adversarial resilience tests for TopoChain.
Verifies defense-in-depth:
- Path traversal escape protection
- Algorithmic DoS / graph explosion capping (N <= 400)
- Graceful handling of malformed / corrupted source code
- Safe handling of corrupted package manifests
"""

import os
import tempfile
from pathlib import Path
import networkx as nx
import numpy as np

from topochain.core.extractor import CodebaseExtractor, ExtractionResult, CodeEntity, EntityType
from topochain.core.extractor.dependency_extractor import DependencyExtractor
from topochain.core.graph.builder import GraphBuilder
from topochain.core.orchestrator import TopoChainOrchestrator
from topochain.data.datasets.loader import BenchmarkRepoGenerator


def test_path_traversal_confinement():
    with tempfile.TemporaryDirectory() as tmpdir:
        base = Path(tmpdir)
        repo_dir = base / "repo"
        secret_dir = base / "secret"
        repo_dir.mkdir()
        secret_dir.mkdir()

        # Secret file outside repository
        secret_file = secret_dir / "passwords.txt"
        secret_file.write_text("SUPER_SECRET_KEY=12345", encoding="utf-8")

        # Create valid codebase in repo
        (repo_dir / "main.py").write_text("def hello(): pass\n", encoding="utf-8")

        # Attempt path traversal via relative symlink or nested traversal if OS allows
        try:
            link = repo_dir / "external_link.py"
            link.symlink_to(secret_file)
        except (OSError, NotImplementedError):
            pass

        extractor = CodebaseExtractor()
        res = extractor.extract_directory(str(repo_dir))

        # Ensure no entities or files were extracted from secret_dir
        for f in res.files_scanned:
            assert "secret" not in f
            assert "passwords" not in f


def test_graph_node_capping_prevents_dos():
    builder = GraphBuilder(max_nodes=50)
    ext = ExtractionResult()

    # Synthesize 200 nodes
    for i in range(200):
        e_id = f"func:f_{i}"
        ext.entities[e_id] = CodeEntity(
            id=e_id,
            name=f"f_{i}",
            entity_type=EntityType.FUNCTION,
            file_path="huge.py"
        )
        if i > 0:
            ext.call_edges.append((f"func:f_{i-1}", e_id, {"type": "call"}))

    # Add a high-degree hub
    for i in range(10, 50):
        ext.call_edges.append(("func:f_0", f"func:f_{i}", {"type": "call"}))

    graph_res = builder.build_graph(ext)
    assert graph_res.undirected_graph.number_of_nodes() <= 50
    assert graph_res.distance_matrix.shape == (50, 50)


def test_corrupted_syntax_handling():
    with tempfile.TemporaryDirectory() as tmpdir:
        p = Path(tmpdir)
        # Corrupted Python with syntax error
        (p / "bad.py").write_text("def broken(x: \n    if for while syntax error!!!", encoding="utf-8")
        # Valid Python
        (p / "good.py").write_text("def valid_func():\n    return 42\n", encoding="utf-8")

        extractor = CodebaseExtractor()
        res = extractor.extract_directory(tmpdir)

        # Extraction must succeed for good.py without crashing
        assert "good.py" in res.files_scanned
        assert any("valid_func" in e.name for e in res.entities.values())


def test_corrupted_manifest_handling():
    with tempfile.TemporaryDirectory() as tmpdir:
        p = Path(tmpdir)
        # Binary null bytes in requirements.txt
        (p / "requirements.txt").write_bytes(b"\x00\xff\xfe\x00requests==2.28.0\n\x00\x00")
        # Malformed package.json
        (p / "package.json").write_text("{ unclosed json: [123", encoding="utf-8")

        dep_extractor = DependencyExtractor()
        res = dep_extractor.analyze_directory(tmpdir)

        # Must return valid DependencyIntelligenceResult without raising
        assert isinstance(res.risk_score, float)
        assert isinstance(res.findings, list)


def test_orchestrator_end_to_end_resilience():
    with tempfile.TemporaryDirectory() as tmpdir:
        p = Path(tmpdir)
        BenchmarkRepoGenerator.create_sample_service(str(p))

        # Add weird files
        (p / "empty.py").write_text("", encoding="utf-8")
        (p / "weird_chars.py").write_text("# encoding test\nπ = 3.14159\ndef calc(): return π\n", encoding="utf-8")

        orchestrator = TopoChainOrchestrator(db_path=str(p / "test.db"))
        res = orchestrator.scan_codebase(str(p), commit_hash="resilience_commit")

        assert res["project_id"] == p.name
        assert res["decision_state"] in ["SAFE", "REVIEW"]
        assert "composite_risk" in res
