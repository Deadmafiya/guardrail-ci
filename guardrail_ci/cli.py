from __future__ import annotations

from pathlib import Path
import typer

from guardrail_ci.config import load_policy
from guardrail_ci.detectors import run_all_detectors
from guardrail_ci.models import ScanReport
from guardrail_ci.policy import evaluate_policy
from guardrail_ci.reporters import write_json_report, write_markdown_report

app = typer.Typer(help="guardrail-ci: secure-by-design CI policy guardrail")


@app.callback()
def main() -> None:
    """guardrail-ci command group."""


@app.command()
def scan(
    path: str = typer.Option(".", help="Path to repository/workspace to scan"),
    policy: str | None = typer.Option(None, help="Policy YAML path"),
    json_out: str = typer.Option("guardrail-report.json", help="JSON report output path"),
    md_out: str = typer.Option("guardrail-report.md", help="Markdown report output path"),
) -> None:
    root = Path(path).resolve()
    if not root.exists():
        typer.secho(f"Path does not exist: {root}", fg=typer.colors.RED)
        raise typer.Exit(code=2)

    findings = run_all_detectors(root)
    report = ScanReport(scanned_path=str(root), findings=findings)

    cfg = load_policy(policy)
    passed, reasons = evaluate_policy(report, cfg)

    write_json_report(report, Path(json_out))
    write_markdown_report(report, Path(md_out), passed, reasons)

    summary = report.summary()
    typer.echo(
        f"Findings total={summary['total']} critical={summary['critical']} high={summary['high']} medium={summary['medium']} low={summary['low']}"
    )
    typer.echo(f"Wrote: {json_out}, {md_out}")

    if not passed:
        typer.secho("Policy check failed", fg=typer.colors.RED)
        for reason in reasons:
            typer.echo(f"- {reason}")
        raise typer.Exit(code=1)

    typer.secho("Policy check passed", fg=typer.colors.GREEN)


if __name__ == "__main__":
    app()
