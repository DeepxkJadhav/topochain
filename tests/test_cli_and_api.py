"""
Integration tests for TopoChain CLI commands and FastAPI REST server.
"""

import tempfile
from pathlib import Path
from click.testing import CliRunner
from fastapi.testclient import TestClient

from topochain.cli.main import cli
from topochain.api.server import app
from topochain.data.datasets.loader import BenchmarkRepoGenerator


def test_cli_init_and_scan():
    runner = CliRunner()
    with tempfile.TemporaryDirectory() as tmpdir:
        BenchmarkRepoGenerator.create_sample_service(tmpdir)

        # 1. Run init
        init_res = runner.invoke(cli, ["init", "--repo", tmpdir])
        assert init_res.exit_code == 0
        assert "TopoChain Initialized Successfully" in init_res.output

        # 2. Run scan
        scan_res = runner.invoke(cli, ["scan", "--repo", tmpdir, "--json-output"])
        assert scan_res.exit_code == 0
        assert '"status": "PASSED"' in scan_res.output


def test_fastapi_endpoints():
    client = TestClient(app)

    # Health check
    res_health = client.get("/health")
    assert res_health.status_code == 200
    assert res_health.json()["status"] == "online"

    # Scan endpoint
    with tempfile.TemporaryDirectory() as tmpdir:
        BenchmarkRepoGenerator.create_sample_service(tmpdir)
        payload = {
            "repo_dir": tmpdir,
            "commit_hash": "test_api_commit",
            "threshold": 3.0
        }
        res_scan = client.post("/api/v1/scan", json=payload)
        assert res_scan.status_code == 200
        data = res_scan.json()
        assert data["commit_hash"] == "test_api_commit"
        assert "drift_score" in data
        assert "is_anomaly" in data
