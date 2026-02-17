from __future__ import annotations

from pathlib import Path
import typer

from guardrail_ci.ai_triage import apply_ai_triage
from guardrail_ci.baseline import apply_baseline, load_baseline, write_baseline
from guardrail_ci.config import load_ai_settings, load_env_file, load_policy
from guardrail_ci.detectors import discover_files, run_all_detectors
from guardrail_ci.git_scope import GitScopeError, get_changed_files
from guardrail_ci.models import ScanReport
from guardrail_ci.policy import evaluate_policy
from guardrail_ci.reporters import (
    write_json_report,
    write_markdown_report,
    write_sarif_report,
)

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
    sarif_out: str | None = typer.Option(None, help="Optional SARIF output path"),
    ai_mode: str = typer.Option("auto", help="AI triage mode: auto|on|off"),
    baseline: str | None = typer.Option(None, help="Baseline YAML path for suppressions"),
    write_baseline_file: bool = typer.Option(False, "--write-baseline", help="Write baseline YAML from current findings"),
    baseline_strict_expiry: bool = typer.Option(False, help="Fail run if expired suppressions are encountered"),
    diff_base: str | None = typer.Option(None, help="Scan only files changed since <diff-base>...HEAD"),
) -> None:
    root = Path(path).resolve()
    if not root.exists():
        typer.secho(f"Path does not exist: {root}", fg=typer.colors.RED)
        raise typer.Exit(code=2)

    # Load .env from current working directory first, then scanned root
    # (helps when scanning nested paths such as fixtures/subdirs).
    load_env_file(Path.cwd() / ".env")
    load_env_file(root / ".env")

    cfg = load_policy(policy)

    include_files: set[str] | None = None
    files_in_diff_scope: int | None = None
    if diff_base:
        try:
            include_files = get_changed_files(root, diff_base)
        except GitScopeError as exc:
            typer.secho(str(exc), fg=typer.colors.RED)
            raise typer.Exit(code=2)
        files_in_diff_scope = len(include_files)

    findings = run_all_detectors(root, exclude_patterns=cfg.exclude_paths, include_files=include_files)

    ai_settings = load_ai_settings(ai_mode_override=ai_mode)
    findings, ai_meta = apply_ai_triage(root, findings, ai_settings)

    baseline_path: Path | None = None
    if baseline:
        baseline_path = Path(baseline)
    elif (root / ".guardrail-baseline.yml").exists():
        baseline_path = root / ".guardrail-baseline.yml"

    baseline_data = None
    if baseline_path:
        try:
            baseline_data = load_baseline(baseline_path)
        except Exception as exc:
            typer.secho(f"Invalid baseline file: {exc}", fg=typer.colors.RED)
            raise typer.Exit(code=2)

    findings, suppressed_total, expired_total = apply_baseline(findings, baseline_data)

    files_scanned = len(list(discover_files(root, cfg.exclude_paths, include_files=include_files)))

    report = ScanReport(
        scanned_path=str(root),
        findings=findings,
        ai=ai_meta,
        files_scanned=files_scanned,
        files_in_diff_scope=files_in_diff_scope,
        suppressed_total=suppressed_total,
        expired_suppressions_total=expired_total,
    )
    passed, reasons = evaluate_policy(report, cfg, baseline_strict_expiry=baseline_strict_expiry)

    write_json_report(report, Path(json_out))
    write_markdown_report(report, Path(md_out), passed, reasons)
    if sarif_out:
        write_sarif_report(report, Path(sarif_out))

    if write_baseline_file:
        out_base = baseline_path or (root / ".guardrail-baseline.yml")
        write_baseline(out_base, findings)
        typer.echo(f"Wrote baseline: {out_base}")

    summary = report.summary()
    effective = report.effective_summary()
    typer.echo(
        f"Findings total={summary['total']} effective={effective['total']} critical={summary['critical']} high={summary['high']} medium={summary['medium']} low={summary['low']} suppressed={report.suppressed_total} expired_suppressions={report.expired_suppressions_total} files_scanned={report.files_scanned} files_in_diff_scope={report.files_in_diff_scope if report.files_in_diff_scope is not None else 'n/a'}"
    )
    typer.echo(f"Wrote: {json_out}, {md_out}{', ' + sarif_out if sarif_out else ''}")

    if report.ai:
        typer.echo(
            f"AI triage status={report.ai.get('status')} mode={report.ai.get('mode')} model={report.ai.get('model', 'n/a')}"
        )

    if not passed:
        typer.secho("Policy check failed", fg=typer.colors.RED)
        for reason in reasons:
            typer.echo(f"- {reason}")
        raise typer.Exit(code=1)

    typer.secho("Policy check passed", fg=typer.colors.GREEN)


if __name__ == "__main__":
    app()
