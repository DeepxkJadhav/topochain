"""
TopoChain Command-Line Interface (CLI).
Provides developer workflows and CI/CD gates for multimodal software supply chain verification.
"""

import sys
import json
import shutil
import tempfile
from pathlib import Path
from typing import Optional, List, Dict, Any
import click
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.text import Text

from topochain.core.orchestrator import TopoChainOrchestrator
from topochain.data.datasets.loader import BenchmarkRepoGenerator
from topochain.data.synthetic.attack_generator import SyntheticAttackGenerator
from topochain.data.benchmark.ablation_runner import AblationRunner

console = Console()


@click.group()
@click.version_option(version="0.2.0", prog_name="TopoChain")
def cli():
    """
    TopoChain: Multimodal Software Supply Chain Integrity Verification Platform.
    Combines AST, Dependency Intelligence, Topological Invariant Drift, and Semantic Analysis.
    """
    pass


@cli.command("init")
@click.option("--repo", default=".", help="Path to repository root.")
@click.option("--name", default=None, help="Project name identifier.")
def init(repo: str, name: Optional[str]):
    """
    Initializes TopoChain baseline and local storage for a repository.
    """
    repo_path = Path(repo).resolve()
    db_path = repo_path / ".topochain" / "topochain.db"
    orchestrator = TopoChainOrchestrator(db_path=str(db_path))

    proj_name = name or repo_path.name
    orchestrator.storage.get_or_create_project(proj_name, name=proj_name)

    console.print(Panel(
        f"[bold green]✓ TopoChain Initialized Successfully[/bold green]\n\n"
        f"• Project Name : [cyan]{proj_name}[/cyan]\n"
        f"• Repository   : [yellow]{repo_path}[/yellow]\n"
        f"• Storage DB   : [magenta]{db_path}[/magenta]\n\n"
        "Ready to scan commits with: [bold white]topochain scan[/bold white]",
        title="TopoChain Init",
        border_style="green"
    ))


@cli.command("scan")
@click.option("--repo", default=".", help="Path to repository root.")
@click.option("--commit", default=None, help="Commit hash or tag.")
@click.option("--threshold", default=3.0, type=float, help="Z-score anomaly threshold (default 3.0).")
@click.option("--visualize", is_flag=True, help="Generate and save persistence diagram plots.")
@click.option("--json-output", is_flag=True, help="Print machine-readable JSON output for CI/CD.")
def scan(repo: str, commit: Optional[str], threshold: float, visualize: bool, json_output: bool):
    """
    Scans a commit for supply chain risks using multimodal fusion.
    Exits with code 0 for SAFE/REVIEW, or code 1 for BLOCK.
    """
    repo_path = Path(repo).resolve()
    db_path = repo_path / ".topochain" / "topochain.db"
    orchestrator = TopoChainOrchestrator(db_path=str(db_path), default_threshold=threshold)

    plot_path = str(repo_path / ".topochain" / f"topology_{commit or 'latest'}.png") if visualize else None

    result = orchestrator.scan_codebase(
        repo_dir=str(repo_path),
        commit_hash=commit,
        threshold=threshold,
        save_plot_path=plot_path
    )

    if json_output:
        click.echo(json.dumps(result, indent=2))
        sys.exit(result["exit_code"])

    # Render Rich Visual Report
    state = result.get("decision_state", "SAFE")
    if state == "BLOCK":
        status_style = "bold red"
        status_icon = "🛑 BLOCK: SUPPLY CHAIN COMPROMISE DETECTED"
        border_style = "red"
    elif state == "REVIEW":
        status_style = "bold yellow"
        status_icon = "⚠️  REVIEW: SUSPICIOUS VARIATION / REFACTOR"
        border_style = "yellow"
    else:
        status_style = "bold green"
        status_icon = "✔ SAFE: CODEBASE INTEGRITY VERIFIED"
        border_style = "green"

    table = Table(title="TopoChain Multimodal Verification Summary", border_style=border_style)
    table.add_column("Security Metric", style="cyan", no_wrap=True)
    table.add_column("Assessment", style="white")

    table.add_row("Decision State", f"[{status_style}]{state}[/{status_style}]")
    table.add_row("Composite Risk", f"{result['composite_risk']:.3f} (Confidence: {result['confidence']:.2f})")
    table.add_row("Topological Drift (L2)", f"{result['drift_score']:.4f} (Z-score: {result['z_score']:.2f})")
    table.add_row("Channel Scores", ", ".join([f"{k}: {v:.2f}" for k, v in result["channel_scores"].items()]))
    table.add_row("Refactor Pattern", "Yes (Legitimate structural change)" if result.get("is_refactor") else "No")
    table.add_row("AST Nodes / Edges", f"{result['graph_metrics']['nodes']} / {result['graph_metrics']['edges']}")
    table.add_row("Homology Betti Counts", f"H0={result['topological_summary']['h0_count']}, H1={result['topological_summary']['h1_count']}, H2={result['topological_summary']['h2_count']}")

    console.print()
    console.print(Panel(f"[{status_style}]{status_icon}[/{status_style}]\n\n{result.get('summary', '')}", border_style=border_style))
    console.print(table)

    if result.get("all_evidence"):
        ev_text = "\n".join([f"• {ev}" for ev in result["all_evidence"][:8]])
        console.print(Panel(ev_text, title="Evidence Breakdown", border_style="cyan"))

    if result.get("recommendation"):
        console.print(Panel(f"[bold]{result['recommendation']}[/bold]", title="Actionable Recommendation", border_style=border_style))

    if plot_path:
        console.print(f"[dim]Topological diagram plot saved to: {plot_path}[/dim]")

    sys.exit(result["exit_code"])


@cli.command("history")
@click.option("--repo", default=".", help="Path to repository root.")
@click.option("--limit", default=20, type=int, help="Number of commits to display.")
@click.option("--json-output", is_flag=True, help="Print JSON output.")
def history(repo: str, limit: int, json_output: bool):
    """
    Displays historical commit verification log and topological trajectory.
    """
    repo_path = Path(repo).resolve()
    db_path = repo_path / ".topochain" / "topochain.db"
    orchestrator = TopoChainOrchestrator(db_path=str(db_path))

    commits = orchestrator.storage.get_history(repo_path.name, limit=limit)
    if json_output:
        serialized = []
        for c in commits:
            serialized.append({
                "commit_hash": c["commit_hash"],
                "drift_score": c["drift_score"],
                "is_anomaly": c["is_anomaly"],
                "timestamp": c["timestamp"],
            })
        click.echo(json.dumps(serialized, indent=2))
        return

    table = Table(title=f"TopoChain Audit History ({repo_path.name})", border_style="cyan")
    table.add_column("Commit", style="cyan")
    table.add_column("Timestamp", style="dim")
    table.add_column("Drift (L2)", style="magenta")
    table.add_column("Status", style="white")

    for c in commits:
        status_text = "[red]ANOMALY[/red]" if c["is_anomaly"] else "[green]CLEAN[/green]"
        table.add_row(
            c["commit_hash"][:12],
            str(c["timestamp"])[:19],
            f"{c['drift_score']:.4f}",
            status_text
        )

    console.print(table)


@cli.command("explain")
@click.argument("commit")
@click.option("--repo", default=".", help="Path to repository root.")
@click.option("--json-output", is_flag=True, help="Print JSON output.")
def explain(commit: str, repo: str, json_output: bool):
    """
    Explains the security determination for a specific commit.
    """
    repo_path = Path(repo).resolve()
    db_path = repo_path / ".topochain" / "topochain.db"
    orchestrator = TopoChainOrchestrator(db_path=str(db_path))

    record = orchestrator.storage.get_commit(commit)
    if not record:
        console.print(f"[red]Commit '{commit}' not found in TopoChain storage.[/red]")
        sys.exit(1)

    diag = record.get("diagnostics", {})
    if json_output:
        click.echo(json.dumps(diag, indent=2))
        return

    console.print(Panel(
        f"[bold]Commit Explanation: {commit}[/bold]\n\n"
        f"• Topological Drift: {record['drift_score']:.4f}\n"
        f"• Status: {'ANOMALY' if record['is_anomaly'] else 'PASSED'}\n"
        f"• Timestamp: {record['timestamp']}\n\n"
        f"Root Cause Summary:\n"
        f"{diag.get('recommendation', 'No anomalous defects flagged for this commit.')}",
        title="TopoChain Explainability Engine",
        border_style="magenta"
    ))

    defects = diag.get("defects", [])
    if defects:
        t = Table(title="Detected Structural Defects")
        t.add_column("Defect Reason", style="red")
        for d in defects:
            t.add_row(d)
        console.print(t)


@cli.group("baseline")
def baseline():
    """
    Manage baseline statistics, trusted anchors, and governance.
    """
    pass


@baseline.command("status")
@click.option("--repo", default=".", help="Path to repository root.")
def baseline_status(repo: str):
    """
    Displays current project baseline statistics and trusted anchor status.
    """
    repo_path = Path(repo).resolve()
    db_path = repo_path / ".topochain" / "topochain.db"
    orchestrator = TopoChainOrchestrator(db_path=str(db_path))

    mean, var, count = orchestrator.storage.get_baseline_stats(repo_path.name)
    anchor = orchestrator.storage.get_trusted_anchor(repo_path.name)

    table = Table(title=f"Baseline & Anchor Status: {repo_path.name}", border_style="green")
    table.add_column("Parameter", style="cyan")
    table.add_column("Value", style="white")

    table.add_row("Drift Mean (μ)", f"{mean:.4f}")
    table.add_row("Drift Variance (σ²)", f"{var:.6f}")
    table.add_row("Sample Count", str(count))
    table.add_row("Trusted Anchor Commit", anchor["anchor_commit"] if anchor else "[dim]None established[/dim]")
    table.add_row("Anchor Approved By", anchor["approved_by"] if anchor else "N/A")

    console.print(table)


@baseline.command("approve")
@click.argument("commit")
@click.option("--repo", default=".", help="Path to repository root.")
@click.option("--approver", default="security-lead", help="Signoff identity.")
@click.option("--reason", default="Manual review verified safe", help="Approval rationale.")
def baseline_approve(commit: str, repo: str, approver: str, reason: str):
    """
    Explicit Trust Approval Gate: promotes a commit as the new trusted anchor.
    """
    repo_path = Path(repo).resolve()
    db_path = repo_path / ".topochain" / "topochain.db"
    orchestrator = TopoChainOrchestrator(db_path=str(db_path))

    rec = orchestrator.storage.get_commit(commit)
    if not rec:
        console.print(f"[red]Error: Commit '{commit}' does not exist in local storage.[/red]")
        sys.exit(1)

    mean, var, count = orchestrator.storage.get_baseline_stats(repo_path.name)
    orchestrator.storage.approve_baseline_update(
        project_id=repo_path.name,
        commit_hash=commit,
        new_mean=mean,
        new_variance=var,
        sample_count=count,
        approved_by=approver,
        reason=reason
    )
    orchestrator.storage.set_trusted_anchor(
        project_id=repo_path.name,
        anchor_commit=commit,
        anchor_embedding=rec["latent_embedding"],
        approved_by=approver
    )

    console.print(Panel(
        f"[bold green]✓ Commit '{commit[:12]}' Approved as Trusted Anchor[/bold green]\n\n"
        f"• Approved by: [cyan]{approver}[/cyan]\n"
        f"• Rationale  : {reason}\n"
        f"• Anti-poisoning reference anchor successfully updated.",
        title="Baseline Governance Gate",
        border_style="green"
    ))


@cli.command("attack-test")
@click.option("--repo", default=None, help="Target codebase directory.")
@click.option("--vector", default="ALL", help="Attack vector to simulate.")
def attack_test(repo: Optional[str], vector: str):
    """
    Simulates real supply chain attack vectors against a testbed.
    """
    with tempfile.TemporaryDirectory() as tmpdir:
        target = Path(repo) if repo else Path(tmpdir)
        if not repo:
            BenchmarkRepoGenerator.create_sample_service(str(target))

        orchestrator = TopoChainOrchestrator(db_path=str(target / "topochain.db"))
        orchestrator.scan_codebase(str(target), commit_hash="c_baseline")

        vectors = [
            "TOPOLOGY_CHANGING_BACKDOOR",
            "TOPOLOGY_PRESERVING_BACKDOOR",
            "TYPOSQUATTING",
            "DEPENDENCY_CONFUSION",
            "POSTINSTALL_ATTACK",
            "CREDENTIAL_THEFT",
            "BENIGN_REFACTOR"
        ] if vector == "ALL" else [vector]

        table = Table(title="Attack Simulation Testbed Results", border_style="red")
        table.add_column("Attack Vector", style="yellow")
        table.add_column("Topology Changing?", style="cyan")
        table.add_column("Decision", style="bold")
        table.add_column("Risk Score", style="magenta")
        table.add_column("Primary Detection Signal", style="dim")

        for v in vectors:
            with tempfile.TemporaryDirectory() as sub_tmp:
                sub_p = Path(sub_tmp)
                BenchmarkRepoGenerator.create_sample_service(str(sub_p))
                atk = SyntheticAttackGenerator.generate_attack(v, str(sub_p))
                if not atk:
                    continue
                res = orchestrator.scan_codebase(str(sub_p), commit_hash=f"c_{v.lower()}")

                d_color = "red" if res["decision_state"] == "BLOCK" else ("yellow" if res["decision_state"] == "REVIEW" else "green")
                top_signal = max(res["channel_scores"].items(), key=lambda x: x[1])[0]

                table.add_row(
                    v,
                    "Yes" if atk.is_topology_changing else "No (In-Place)",
                    f"[{d_color}]{res['decision_state']}[/{d_color}]",
                    f"{res['composite_risk']:.3f}",
                    top_signal
                )

        console.print(table)


@cli.command("benchmark")
@click.option("--output-json", default=None, help="File path to write JSON results.")
def benchmark(output_json: Optional[str]):
    """
    Executes the empirical ablation benchmark comparing Configurations A through H.
    """
    console.print("[bold cyan]Running Scientific Ablation Study (Configurations A - H)...[/bold cyan]")
    runner = AblationRunner()
    results = runner.run_ablation_study()
    report = runner.generate_markdown_report(results)

    console.print(report)

    if output_json:
        data = {cid: res.__dict__ for cid, res in results.items()}
        Path(output_json).write_text(json.dumps(data, indent=2), encoding="utf-8")
        console.print(f"[green]✓ Saved ablation benchmark results to {output_json}[/green]")


@cli.command("report")
@click.option("--repo", default=".", help="Path to repository root.")
@click.option("--output", default="topochain_audit.json", help="Path to output file.")
def report(repo: str, output: str):
    """
    Generates a full compliance audit report for the repository.
    """
    repo_path = Path(repo).resolve()
    db_path = repo_path / ".topochain" / "topochain.db"
    orchestrator = TopoChainOrchestrator(db_path=str(db_path))

    history_records = orchestrator.storage.get_history(repo_path.name, limit=50)
    anchor = orchestrator.storage.get_trusted_anchor(repo_path.name)
    if anchor and "anchor_embedding" in anchor:
        anchor = dict(anchor)
        anchor.pop("anchor_embedding", None)
    mean, var, count = orchestrator.storage.get_baseline_stats(repo_path.name)

    audit_data = {
        "project": repo_path.name,
        "total_audited_commits": len(history_records),
        "baseline_parameters": {"mean": mean, "variance": var, "samples": count},
        "trusted_anchor": anchor,
        "recent_commits": [
            {
                "commit": c["commit_hash"],
                "drift_score": c["drift_score"],
                "is_anomaly": c["is_anomaly"],
                "timestamp": str(c["timestamp"])
            }
            for c in history_records
        ]
    }
    Path(output).write_text(json.dumps(audit_data, indent=2), encoding="utf-8")
    console.print(f"[bold green]✓ Audit report generated: {output}[/bold green]")


@cli.command("demo")
@click.option("--output-dir", default=".topochain_demo", help="Working directory for interactive demo.")
def demo(output_dir: str):
    """
    Runs a live end-to-end benchmark demonstration of TopoChain against simulated attacks.
    """
    demo_path = Path(output_dir).resolve()
    if demo_path.exists():
        shutil.rmtree(demo_path)
    demo_path.mkdir(parents=True, exist_ok=True)

    console.print(Panel(
        "[bold cyan]TOPOCHAIN LIVE DEMONSTRATION & BENCHMARK[/bold cyan]\n"
        "Validating Multimodal Security Fusion on Software Supply Chain Integrity",
        border_style="cyan"
    ))

    BenchmarkRepoGenerator.create_sample_service(str(demo_path))
    db_path = str(demo_path / "topochain.db")
    orchestrator = TopoChainOrchestrator(db_path=db_path)

    res_t0 = orchestrator.scan_codebase(str(demo_path), commit_hash="c0_init_clean", threshold=3.0)
    console.print(f"• Baseline Init: [{res_t0['decision_state']}] Drift: {res_t0['drift_score']:.4f}")

    SyntheticAttackGenerator.apply_benign_refactor(str(demo_path / "auth.py"))
    res_t1 = orchestrator.scan_codebase(str(demo_path), commit_hash="c1_benign_refactor", threshold=3.0)
    console.print(f"• Benign Refactor: [{res_t1['decision_state']}] (is_refactor={res_t1['is_refactor']})")

    SyntheticAttackGenerator.inject_subtle_logic_backdoor(str(demo_path / "api.py"))
    res_t2 = orchestrator.scan_codebase(str(demo_path), commit_hash="c2_malicious_backdoor", threshold=3.0)
    console.print(f"• Backdoor Attack: [{res_t2['decision_state']}] Risk: {res_t2['composite_risk']:.3f}")


@cli.command("serve")
@click.option("--host", default="127.0.0.1", help="API host.")
@click.option("--port", default=8000, type=int, help="API port.")
def serve(host: str, port: int):
    """
    Launches the TopoChain REST API server.
    """
    import uvicorn
    from topochain.api.server import app
    console.print(f"[bold green]Starting TopoChain REST API server on http://{host}:{port}...[/bold green]")
    uvicorn.run(app, host=host, port=port)


if __name__ == "__main__":
    cli()
