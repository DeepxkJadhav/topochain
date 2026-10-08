"""
Integration tests for TopoChain CLI commands and FastAPI REST server.
"""

import tempfile
import json
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


def test_cli_extended_workflows():
    runner = CliRunner()
    with tempfile.TemporaryDirectory() as tmpdir:
        BenchmarkRepoGenerator.create_sample_service(tmpdir)

        # 1. Init & Scan commit 1
        runner.invoke(cli, ["init", "--repo", tmpdir])
        scan_res = runner.invoke(cli, ["scan", "--repo", tmpdir, "--commit", "commit_c1"])
        assert scan_res.exit_code == 0

        # 2. History
        hist_res = runner.invoke(cli, ["history", "--repo", tmpdir])
        assert hist_res.exit_code == 0
        assert "commit_c1" in hist_res.output

        # 3. Explain
        explain_res = runner.invoke(cli, ["explain", "commit_c1", "--repo", tmpdir])
        assert explain_res.exit_code == 0
        assert "Commit Explanation" in explain_res.output

        # 4. Baseline status
        base_res = runner.invoke(cli, ["baseline", "status", "--repo", tmpdir])
        assert base_res.exit_code == 0
        assert "Drift Mean" in base_res.output

        # 5. Baseline approve gate
        appr_res = runner.invoke(cli, ["baseline", "approve", "commit_c1", "--repo", tmpdir, "--approver", "lead_dev"])
        assert appr_res.exit_code == 0
        assert "Approved as Trusted Anchor" in appr_res.output

        # 6. Report generation
        rep_file = str(Path(tmpdir) / "audit.json")
        rep_res = runner.invoke(cli, ["report", "--repo", tmpdir, "--output", rep_file])
        assert rep_res.exit_code == 0
        assert Path(rep_file).is_file()


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
        assert "decision_state" in data
        assert "composite_risk" in data

        project_id = data["project_id"]

        # Baseline endpoint
        res_base = client.get(f"/api/v1/projects/{project_id}/baseline")
        assert res_base.status_code == 200

        # Baseline approve endpoint
        approve_payload = {
            "commit_hash": "test_api_commit",
            "approver": "security_admin",
            "reason": "Test signoff"
        }
        res_approve = client.post(f"/api/v1/projects/{project_id}/baseline/approve", json=approve_payload)
        assert res_approve.status_code == 200
        assert res_approve.json()["status"] == "APPROVED"

        # Explain endpoint
        res_explain = client.get(f"/api/v1/projects/{project_id}/explain/test_api_commit")
        assert res_explain.status_code == 200
        assert res_explain.json()["commit_hash"] == "test_api_commit"
