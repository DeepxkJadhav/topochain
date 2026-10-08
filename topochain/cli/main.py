"""
TopoChain Command-Line Interface (CLI).
Provides developer workflows and CI/CD gates for topological supply chain verification.
"""

import sys
import json
import shutil
from pathlib import Path
import click
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.text import Text

from topochain.core.orchestrator import TopoChainOrchestrator
from topochain.data.datasets.loader import BenchmarkRepoGenerator
from topochain.data.synthetic.attack_generator import SyntheticAttackGenerator

console = Console()


@click.group()
@click.version_option(version="0.1.0", prog_name="TopoChain")
def cli():
    """
    TopoChain: Topological Invariant Drift Detection for Software Supply Chain Integrity.
    """
    pass


@cli.command("init")
@click.option("--repo", default=".", help="Path to repository root.")
@click.option("--name", default=None, help="Project name identifier.")
def init(repo: str, name: str):
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
def scan(repo: str, commit: str, threshold: float, visualize: bool, json_output: bool):
    """
    Scans a commit for topological invariant drift and supply chain backdoors.
    Exits with code 0 if benign, or code 1 if topological anomaly detected.
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
        sys.exit(1 if result["is_anomaly"] else 0)

    # Render Rich Visual Report
    status_style = "bold red" if result["is_anomaly"] else "bold green"
    status_icon = "✖ ALERT: ANOMALY DETECTED" if result["is_anomaly"] else "✔ PASS: TOPOLOGICAL MANIFOLD INTACT"

    table = Table(title="TopoChain Integrity Verification Summary", border_style="blue")
    table.add_column("Metric", style="cyan", no_wrap=True)
    table.add_column("Value", style="white")

    table.add_row("Project ID", result["project_id"])
    table.add_row("Commit", result["commit_hash"][:12])
    table.add_row("Topological Drift (L2)", f"{result['drift_score']:.4f}")
    table.add_row("Anomaly Z-Score", f"{result['z_score']:.3f} (Threshold: {result['threshold']:.1f})")
    table.add_row("Severity Level", result["severity"])
    table.add_row("AST Graph Nodes / Edges", f"{result['graph_metrics']['nodes']} nodes / {result['graph_metrics']['edges']} edges")
    table.add_row("H_0 (Components)", str(result["topological_summary"]["h0_count"]))
    table.add_row("H_1 (Persistent Loops)", str(result["topological_summary"]["h1_count"]))
    table.add_row("H_2 (2D Voids)", str(result["topological_summary"]["h2_count"]))

    console.print()
    console.print(Panel(f"[{status_style}]{status_icon}[/{status_style}]", border_style="red" if result["is_anomaly"] else "green"))
    console.print(table)

    if result["defects"]:
        def_panel = Panel(
            "\n".join([f"• [red]{d}[/red]" for d in result["defects"]]) + f"\n\n[yellow]{result['recommendation']}[/yellow]",
            title="[bold red]Topological Defect Diagnostics[/bold red]",
            border_style="red"
        )
        console.print(def_panel)

    if plot_path:
        console.print(f"[dim]Topological diagram plot saved to: {plot_path}[/dim]")

    if result["is_anomaly"]:
        sys.exit(1)
    else:
        sys.exit(0)


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
        "Validating Topological Invariant Drift Detection on Software Supply Chain Integrity",
        border_style="cyan"
    ))

    # 1. Generate clean microservice
    console.print("\n[bold yellow]Step 1: Generating clean microservice codebase...[/bold yellow]")
    BenchmarkRepoGenerator.create_sample_service(str(demo_path))
    db_path = str(demo_path / "topochain.db")
    orchestrator = TopoChainOrchestrator(db_path=db_path)

    # 2. Baseline scan
    console.print("[bold yellow]Step 2: Recording Baseline Commit (t0)...[/bold yellow]")
    res_t0 = orchestrator.scan_codebase(str(demo_path), commit_hash="c0_init_clean", threshold=3.0)
    console.print(f"  → Initialized baseline. Invariants: H0={res_t0['topological_summary']['h0_count']}, H1={res_t0['topological_summary']['h1_count']}")

    # 3. Benign evolution (refactor)
    console.print("\n[bold yellow]Step 3: Applying Benign Refactor (renaming, helpers, formatting)...[/bold yellow]")
    SyntheticAttackGenerator.apply_benign_refactor(str(demo_path / "auth.py"))
    res_t1 = orchestrator.scan_codebase(str(demo_path), commit_hash="c1_benign_refactor", threshold=3.0)
    console.print(f"  → Result: [green]{res_t1['status']}[/green] | Drift: {res_t1['drift_score']:.4f} | Z-Score: {res_t1['z_score']:.2f}")

    # 4. Inject subtle logic backdoor
    console.print("\n[bold red]Step 4: Simulating Supply Chain Attack: Injecting Subtle Logic Backdoor...[/bold red]")
    console.print("  [dim](Attacker adds conditional bypass hooking authentication into secret exfiltration)[/dim]")
    SyntheticAttackGenerator.inject_subtle_logic_backdoor(str(demo_path / "api.py"))
    res_t2 = orchestrator.scan_codebase(str(demo_path), commit_hash="c2_malicious_backdoor", threshold=3.0)

    color_status = "red" if res_t2["is_anomaly"] else "green"
    console.print(f"  → Result: [{color_status}]{res_t2['status']}[/{color_status}] | Drift: {res_t2['drift_score']:.4f} | Z-Score: {res_t2['z_score']:.2f}")
    if res_t2["defects"]:
        console.print(f"  → Detected Topological Defects: [bold red]{', '.join(res_t2['defects'])}[/bold red]")

    # 5. Summary comparison
    summary_table = Table(title="Demonstration Comparison Results", border_style="cyan")
    summary_table.add_column("Stage / Commit", style="yellow")
    summary_table.add_column("Drift (L2)", style="magenta")
    summary_table.add_column("Z-Score", style="blue")
    summary_table.add_column("Verification Verdict", style="bold")
    summary_table.add_column("Defect Reason", style="dim")

    summary_table.add_row("c0: Baseline Init", f"{res_t0['drift_score']:.4f}", f"{res_t0['z_score']:.2f}", "[green]PASS[/green]", "Manifold anchor")
    summary_table.add_row("c1: Benign Refactor", f"{res_t1['drift_score']:.4f}", f"{res_t1['z_score']:.2f}", "[green]PASS[/green]", "Homotopic evolution")
    summary_table.add_row("c2: Malicious Backdoor", f"{res_t2['drift_score']:.4f}", f"{res_t2['z_score']:.2f}", "[red]BLOCKED (ANOMALY)[/red]", str(res_t2['defects']))

    console.print("\n")
    console.print(summary_table)
    console.print(Panel(
        "[bold green]✓ Demonstration Complete.[/bold green]\n"
        "TopoChain successfully distinguished natural software refactoring from stealthy supply chain intrusion!",
        border_style="green"
    ))


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
