from __future__ import annotations

import json
from pathlib import Path

import typer
import yaml
from rich.console import Console
from rich.table import Table

from snowimpact.collectors.demo import DemoCollector
from snowimpact.collectors.snowflake import SnowflakeCollector
from snowimpact.core.models import AnalysisRequest
from snowimpact.core.settings import get_settings
from snowimpact.engines.analyzer import Analyzer
from snowimpact.integrations.terraform import parse_terraform_plan

app = typer.Typer(help="SnowImpact. Snowflake change intelligence and policy firewall.", no_args_is_help=True)
console = Console()


def _analyzer() -> Analyzer:
    settings = get_settings()
    collector = DemoCollector() if settings.demo_mode else SnowflakeCollector(settings)
    return Analyzer(collector)


def _render(result, output_format: str = "text") -> None:
    if output_format == "json":
        typer.echo(result.model_dump_json(indent=2))
        return
    if output_format == "sarif":
        sarif = {
            "version": "2.1.0",
            "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
            "runs": [{
                "tool": {"driver": {"name": "SnowImpact", "version": "1.0.0", "rules": []}},
                "results": [{
                    "ruleId": f.rule,
                    "level": "error" if f.severity.value in {"critical", "high"} else "warning",
                    "message": {"text": f.title + ". " + f.description},
                    "locations": [{"physicalLocation": {"artifactLocation": {"uri": f.source.get("file") or "inline.sql"}}}],
                } for f in result.findings],
            }],
        }
        typer.echo(json.dumps(sarif, indent=2))
        return

    console.print(f"\n[bold]SnowImpact[/bold]  risk=[bold]{result.risk.overall}/100[/bold]  decision=[bold]{result.decision.value.upper()}[/bold]")
    console.print(f"Coverage: {result.coverage_percent}% | Changes: {len(result.changes)} | Findings: {len(result.findings)}")
    if result.missing_capabilities:
        console.print(f"[yellow]Missing capabilities:[/yellow] {', '.join(result.missing_capabilities)}")
    table = Table("Severity", "Category", "Rule", "Finding", "Risk")
    for finding in result.findings:
        table.add_row(finding.severity.value.upper(), finding.category, finding.rule, finding.title, str(finding.risk_score))
    console.print(table)
    if result.affected_objects:
        console.print("\nAffected objects:")
        for obj in result.affected_objects[:50]:
            console.print(f"  • {obj}")


@app.command("init")
def init_project(force: bool = False) -> None:
    """Create repository-local SnowImpact configuration and starter policies."""
    root = Path.cwd() / ".snowimpact"
    policies = root / "policies"
    root.mkdir(parents=True, exist_ok=True)
    policies.mkdir(parents=True, exist_ok=True)
    config = root / "snowimpact.yaml"
    policy = policies / "repository.yaml"
    if config.exists() and not force:
        console.print(f"[yellow]{config} already exists. Use --force to overwrite.[/yellow]")
        raise typer.Exit(code=1)
    config.write_text("""version: 1
analysis:
  lineage: true
  security: true
  governance: true
  finops: true
  performance: true
  ai_governance: true
risk:
  warn_at: 31
  approval_at: 61
  block_at: 81
ci:
  fail_closed: false
  min_coverage_percent: 70
privacy:
  store_raw_queries: false
""", encoding="utf-8")
    if not policy.exists() or force:
        policy.write_text("""policies:
  - name: repository-critical-security
    category: security
    severities: [critical]
    action: block
""", encoding="utf-8")
    console.print(f"Initialized SnowImpact in {root}")


@app.command()
def doctor() -> None:
    """Validate Snowflake connectivity and feature coverage."""
    rows = _analyzer().collector.doctor()
    table = Table("Capability", "Available", "Reason")
    for row in rows:
        table.add_row(str(row["name"]), "✓" if row["available"] else "✗", str(row.get("reason") or ""))
    console.print(table)


@app.command()
def impact(path: Path, format: str = typer.Option("text", "--format", "-f", help="text|json|sarif"), fail_closed: bool = False) -> None:
    """Analyze a Snowflake SQL migration without executing it."""
    result = _analyzer().analyze(AnalysisRequest(sql=path.read_text(encoding="utf-8"), filename=str(path), fail_closed=fail_closed))
    _render(result, format)
    raise typer.Exit(code=1 if result.decision.value == "block" else 0)


@app.command()
def demo(format: str = typer.Option("text", "--format", "-f")) -> None:
    """Run an end-to-end demonstration."""
    sql = """
ALTER TABLE PROD.CUSTOMER.CUSTOMERS DROP COLUMN REGION;
GRANT SELECT ON ALL TABLES PROD.CUSTOMER.CUSTOMERS TO ROLE MARKETING;
ALTER WAREHOUSE ANALYTICS_WH SET WAREHOUSE_SIZE='2XLARGE';
"""
    analyzer = Analyzer(DemoCollector())
    _render(analyzer.analyze(AnalysisRequest(sql=sql, filename="demo.sql")), format)


@app.command("policy-check")
def policy_check(path: Path = Path("policies/default")) -> None:
    """Validate policy YAML syntax."""
    count = 0
    for f in path.glob("*.y*ml"):
        yaml.safe_load(f.read_text(encoding="utf-8"))
        count += 1
    console.print(f"Validated {count} policy file(s).")


@app.command("terraform")
def terraform_cmd(plan: Path, format: str = typer.Option("text", "--format", "-f")) -> None:
    """Parse a Terraform JSON plan and display normalized Snowflake changes."""
    changes = parse_terraform_plan(plan)
    if format == "json":
        console.print_json(json.dumps([c.model_dump(mode="json") for c in changes]))
    else:
        table = Table("Operation", "Type", "Object")
        for c in changes:
            table.add_row(c.operation.value, c.object.object_type, c.object.fqn)
        console.print(table)


@app.command()
def scan(format: str = typer.Option("text", "--format", "-f")) -> None:
    """Collect a read-only Snowflake environment snapshot."""
    snapshot = _analyzer().collector.collect("development" if get_settings().demo_mode else "production")
    payload = {
        "account": snapshot.account,
        "environment": snapshot.environment,
        "nodes": len(snapshot.nodes),
        "edges": len(snapshot.edges),
        "privileges": len(snapshot.privileges),
        "query_metrics": len(snapshot.query_metrics),
        "warehouses": len(snapshot.warehouse_metrics),
        "classifications": len(snapshot.classifications),
        "capabilities": [c.model_dump(mode="json") for c in snapshot.capabilities],
    }
    if format == "json":
        console.print_json(json.dumps(payload))
        return
    table = Table("Metric", "Value")
    for key, value in payload.items():
        if key != "capabilities":
            table.add_row(key, str(value))
    console.print(table)


@app.command()
def graph(format: str = typer.Option("text", "--format", "-f")) -> None:
    """Show the collected dependency/access graph."""
    snapshot = _analyzer().collector.collect("development" if get_settings().demo_mode else "production")
    if format == "json":
        console.print_json(json.dumps({"nodes": [n.model_dump(mode="json") for n in snapshot.nodes], "edges": [e.model_dump(mode="json") for e in snapshot.edges]}))
        return
    table = Table("Source", "Edge", "Target", "Confidence")
    by_id = {n.id: n.fqn for n in snapshot.nodes}
    for edge in snapshot.edges[:200]:
        table.add_row(by_id.get(edge.source, edge.source), edge.edge_type, by_id.get(edge.target, edge.target), f"{edge.confidence:.2f}")
    console.print(table)


@app.command()
def security(format: str = typer.Option("text", "--format", "-f")) -> None:
    """Inspect observed Snowflake privileges and sensitive classifications."""
    snapshot = _analyzer().collector.collect("development" if get_settings().demo_mode else "production")
    payload = {"privileges": snapshot.privileges, "classifications": snapshot.classifications}
    if format == "json":
        console.print_json(json.dumps(payload, default=str))
        return
    console.print(f"Privileges: {len(snapshot.privileges)} | Classifications: {len(snapshot.classifications)}")
    table = Table("Object", "Classification", "Masked")
    for item in snapshot.classifications[:200]:
        table.add_row(str(item.get("object", "")), str(item.get("classification", "")), str(item.get("masked", "unknown")))
    console.print(table)


@app.command()
def cost(format: str = typer.Option("text", "--format", "-f")) -> None:
    """Show warehouse/query cost inputs used by FinOps analysis."""
    snapshot = _analyzer().collector.collect("development" if get_settings().demo_mode else "production")
    if format == "json":
        console.print_json(json.dumps({"warehouses": snapshot.warehouse_metrics, "queries": snapshot.query_metrics}, default=str))
        return
    table = Table("Warehouse", "Credits", "Size", "Idle %")
    for item in snapshot.warehouse_metrics:
        table.add_row(str(item.get("warehouse") or item.get("WAREHOUSE_NAME") or ""), str(item.get("monthly_credits") or item.get("COMPUTE_CREDITS") or ""), str(item.get("size") or ""), str(item.get("idle_percent") or ""))
    console.print(table)


@app.command("dbt")
def dbt_cmd(manifest: Path, format: str = typer.Option("text", "--format", "-f")) -> None:
    """Import dbt manifest lineage."""
    from snowimpact.integrations.dbt import parse_dbt_manifest
    nodes, edges = parse_dbt_manifest(manifest)
    if format == "json":
        console.print_json(json.dumps({"nodes": [n.model_dump(mode="json") for n in nodes], "edges": [e.model_dump(mode="json") for e in edges]}))
        return
    console.print(f"Imported {len(nodes)} dbt nodes and {len(edges)} dependency edges.")


@app.command("ci")
def ci_cmd(base: str = "HEAD~1", head: str = "HEAD", fail_closed: bool = False) -> None:
    """Analyze changed SQL files from a Git diff and return CI-safe exit status."""
    import subprocess
    proc = subprocess.run(["git", "diff", "--name-only", base, head, "--", "*.sql"], capture_output=True, text=True, check=False)
    if proc.returncode != 0:
        console.print(proc.stderr)
        raise typer.Exit(code=2)
    files = [Path(line) for line in proc.stdout.splitlines() if line.strip() and Path(line).exists()]
    if not files:
        console.print("No changed SQL files.")
        return
    combined = "\n;\n".join(f.read_text(encoding="utf-8") for f in files)
    result = _analyzer().analyze(AnalysisRequest(sql=combined, filename=f"git:{base}..{head}", fail_closed=fail_closed))
    _render(result, "text")
    raise typer.Exit(code=1 if result.decision.value == "block" else 0)


if __name__ == "__main__":
    app()
