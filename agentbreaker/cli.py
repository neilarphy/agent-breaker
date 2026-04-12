import os
import sys
import time
from typing import Optional

import typer
from dotenv import load_dotenv
from rich.console import Console
from rich.panel import Panel
from rich.progress import Progress, SpinnerColumn, TextColumn, TimeElapsedColumn
from rich.table import Table
from rich import print as rprint

from agentbreaker.observability import setup_logging

load_dotenv()

app = typer.Typer(help="AgentBreaker — automated red-teaming for LLM agents")
console = Console()

STEP_LABELS = {
    "init": "Initializing",
    "repo_cloner": "Cloning repository",
    "analyzer": "Analyzing agent architecture",
    "threat_planner": "Building threat model",
    "attack_generator": "Generating attacks",
    "sandbox_runner": "Running attacks",
    "judge": "Evaluating results",
    "report_agent": "Generating report",
}


def _print_banner():
    console.print(Panel.fit(
        "[bold red]AgentBreaker[/bold red] [dim]— LLM Agent Red-Teaming[/dim]",
        border_style="red",
    ))


def _print_findings_table(judgements: list, attack_plans: list):
    plan_map = {a["id"]: a for a in attack_plans}
    findings = [j for j in judgements if j.get("verdict") in ("success", "partial")]

    if not findings:
        console.print("[green]No successful attacks found.[/green]")
        return

    table = Table(title="Findings", show_lines=True)
    table.add_column("ID", style="dim")
    table.add_column("Class")
    table.add_column("Severity")
    table.add_column("Verdict")
    table.add_column("Confidence")
    table.add_column("Evidence", max_width=50)

    severity_colors = {"critical": "red", "high": "yellow", "medium": "cyan", "low": "green"}

    for j in findings:
        plan = plan_map.get(j["attack_id"], {})
        sev = j.get("severity", "medium")
        verdict = j.get("verdict", "")
        color = severity_colors.get(sev, "white")
        table.add_row(
            j["attack_id"],
            plan.get("class", ""),
            f"[{color}]{sev}[/{color}]",
            f"[bold]{verdict}[/bold]",
            f"{j.get('confidence', 0):.2f}",
            j.get("evidence", "")[:80],
        )

    console.print(table)


def _print_stats(state: dict):
    judgements = state.get("judgements", [])
    cost = state.get("cost_tracker", {})

    verdicts = {"success": 0, "failure": 0, "partial": 0, "inconclusive": 0}
    for j in judgements:
        v = j.get("verdict", "inconclusive")
        verdicts[v] = verdicts.get(v, 0) + 1

    table = Table(title="Audit Summary", show_header=False)
    table.add_column("Metric", style="bold")
    table.add_column("Value")

    table.add_row("Total attacks", str(len(judgements)))
    table.add_row("[red]Successful[/red]", str(verdicts["success"]))
    table.add_row("[yellow]Partial[/yellow]", str(verdicts["partial"]))
    table.add_row("[green]Failed[/green]", str(verdicts["failure"]))
    table.add_row("[dim]Inconclusive[/dim]", str(verdicts["inconclusive"]))
    table.add_row("Total cost", f"${cost.get('total_cost_usd', 0):.4f}")
    table.add_row("Total tokens", str(cost.get("total_tokens", 0)))
    table.add_row("Report", state.get("report_path", "N/A"))

    console.print(table)


@app.command()
def audit(
    repo: str = typer.Argument(..., help="GitHub repository URL"),
    endpoint: str = typer.Option(
        "http://localhost:8001", "--endpoint", "-e",
        help="Target agent endpoint (must be localhost or whitelisted)",
    ),
    config: str = typer.Option("config.yaml", "--config", "-c", help="Config file path"),
    log_level: str = typer.Option("INFO", "--log-level", help="Logging level"),
):
    _print_banner()
    setup_logging(level=log_level)

    console.print(f"[bold]Repository:[/bold] {repo}")
    console.print(f"[bold]Endpoint:[/bold]   {endpoint}")
    console.print()

    if not os.getenv("GEMINI_API_KEY"):
        console.print("[red]Error: GEMINI_API_KEY not set. Copy .env.example to .env and fill it in.[/red]")
        raise typer.Exit(1)

    from agentbreaker.graph import run_audit

    start = time.time()

    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        TimeElapsedColumn(),
        console=console,
        transient=False,
    ) as progress:
        task = progress.add_task("Starting...", total=None)

        original_node = None

        class StateWatcher:
            def __init__(self):
                self.last_step = ""

            def update(self, step: str):
                if step != self.last_step:
                    label = STEP_LABELS.get(step, step)
                    progress.update(task, description=f"[cyan]{label}[/cyan]")
                    self.last_step = step

        watcher = StateWatcher()

        import agentbreaker.graph as graph_module
        orig_run = graph_module.run_audit

        def patched_run(repo_url, target_endpoint, config_path="config.yaml"):
            result = orig_run(repo_url, target_endpoint, config_path)
            return result

        final_state = patched_run(repo, endpoint, config)

    elapsed = time.time() - start
    console.print(f"\n[dim]Completed in {elapsed:.1f}s[/dim]\n")

    status = final_state.get("pipeline_status", "unknown")
    if status == "completed":
        console.print("[bold green]Audit completed.[/bold green]\n")
    elif status == "partial":
        console.print("[bold yellow]Audit completed with partial results.[/bold yellow]\n")
    else:
        console.print(f"[bold red]Pipeline ended with status: {status}[/bold red]\n")
        errors = final_state.get("errors", [])
        for e in errors[-3:]:
            console.print(f"  [red]{e.get('step')}: {e.get('error')}[/red]")

    _print_findings_table(
        final_state.get("judgements", []),
        final_state.get("attack_plans", []),
    )
    console.print()
    _print_stats(final_state)

    issues = final_state.get("judgements", [])
    findings = [j for j in issues if j.get("verdict") in ("success", "partial") and j.get("confidence", 0) >= 0.7]
    if findings and os.getenv("GITHUB_TOKEN"):
        console.print(f"\n[yellow]{len(findings)} finding(s) eligible for GitHub Issues.[/yellow]")
        create = typer.confirm("Create GitHub Issues?", default=False)
        if create:
            _create_github_issues(final_state, findings)


def _create_github_issues(state: dict, findings: list):
    from github import Github

    token = os.getenv("GITHUB_TOKEN")
    repo_url = state.get("repo_url", "")
    repo_name = "/".join(repo_url.rstrip("/").split("/")[-2:])

    try:
        g = Github(token)
        repo = g.get_repo(repo_name)
        plan_map = {a["id"]: a for a in state.get("attack_plans", [])}

        created = []
        for j in findings[:10]:
            plan = plan_map.get(j["attack_id"], {})
            title = f"[AgentBreaker] {plan.get('name', j['attack_id'])} — {j.get('severity', 'medium').upper()}"
            body = (
                f"## Security Finding\n\n"
                f"**Class:** {plan.get('class', '')}\n"
                f"**Severity:** {j.get('severity', '')}\n"
                f"**Confidence:** {j.get('confidence', 0):.2f}\n\n"
                f"### Description\n{j.get('explanation', '')}\n\n"
                f"### Evidence\n{j.get('evidence', '')}\n\n"
                f"### Payload\n```\n{plan.get('payload', '')}\n```\n\n"
                f"*Generated by AgentBreaker*"
            )
            issue = repo.create_issue(title=title, body=body, labels=["security"])
            created.append(issue.html_url)
            console.print(f"  [green]Created:[/green] {issue.html_url}")

        console.print(f"\n[green]Created {len(created)} issue(s).[/green]")
    except Exception as e:
        console.print(f"[red]Failed to create issues: {e}[/red]")


@app.command()
def index_owasp(
    config: str = typer.Option("config.yaml", "--config", "-c"),
):
    console.print("Indexing OWASP LLM Top 10 into ChromaDB...")
    import subprocess
    result = subprocess.run([sys.executable, "scripts/index_owasp.py"], capture_output=True, text=True)
    if result.returncode == 0:
        console.print(f"[green]{result.stdout.strip()}[/green]")
    else:
        console.print(f"[red]{result.stderr.strip()}[/red]")


if __name__ == "__main__":
    app()
