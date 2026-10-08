"""
Unit tests for TopoChain extractors (Python AST, JS, and Dependencies).
"""

import tempfile
from pathlib import Path
import pytest

from topochain.core.extractor import (
    PythonASTExtractor,
    JavaScriptExtractor,
    DependencyExtractor,
    CodebaseExtractor,
    EntityType,
)


def test_python_ast_extractor():
    code = '''
import os
import requests

def fetch_data(url):
    if not url:
        return None
    return requests.get(url)

class DataProcessor:
    def process(self, raw):
        for item in raw:
            os.system(f"echo {item}")
'''
    extractor = PythonASTExtractor()
    entities, edges = extractor.extract_file("test_service.py", source_code=code)

    assert "mod:test_service" in entities
    assert "fn:test_service.fetch_data" in entities
    assert "cls:test_service.DataProcessor" in entities
    assert "fn:test_service.DataProcessor.process" in entities

    fetch_ent = entities["fn:test_service.fetch_data"]
    assert fetch_ent.complexity >= 2
    assert "requests.get" in fetch_ent.calls

    proc_ent = entities["fn:test_service.DataProcessor.process"]
    assert "os.system" in proc_ent.sensitive_operations

    assert len(edges) > 0


def test_dependency_extractor_and_typosquatting():
    with tempfile.TemporaryDirectory() as tmpdir:
        req_file = Path(tmpdir) / "requirements.txt"
        req_file.write_text(
            "requests==2.31.0\n"
            "crypt0graphy>=40.0.0\n"  # typosquat
            "numpy>=1.24.0\n"
        )

        extractor = DependencyExtractor()
        deps = extractor.extract_from_directory(tmpdir)

        names = {d.name: d for d in deps}
        assert "requests" in names
        assert "crypt0graphy" in names
        assert any("typosquat" in f for f in names["crypt0graphy"].suspicious_flags)


def test_codebase_extractor_full():
    with tempfile.TemporaryDirectory() as tmpdir:
        td = Path(tmpdir)
        (td / "requirements.txt").write_text("requests>=2.28.0\n")
        (td / "main.py").write_text('''
import requests
def run():
    requests.get("https://example.com")
''')

        extractor = CodebaseExtractor()
        result = extractor.extract_directory(tmpdir)

        assert len(result.entities) >= 2
        assert len(result.dependencies) == 1
        assert "main.py" in result.files_scanned
