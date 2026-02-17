from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from guardrail_ci import __version__
from guardrail_ci.models import ScanReport


SARIF_LEVEL_MAP = {
    "critical": "error",
    "high": "error",
    "medium": "warning",
    "low": "note",
    "info": "note",
}


def write_json_report(report: ScanReport, path: Path) -> None:
    path.write_text(json.dumps(report.to_dict(), indent=2))


def build_markdown_report(report: ScanReport, policy_passed: bool, reasons: list[str]) -> str:
    s = report.summary()
    eff = report.effective_summary()
    lines = [
        "# guardrail-ci scan report",
        "",
        f"- **Scanned Path:** `{report.scanned_path}`",
        f"- **Policy Result:** {'PASS ✅' if policy_passed else 'FAIL ❌'}",
        f"- **Files Scanned:** {report.files_scanned}",
        f"- **Files in Diff Scope:** {report.files_in_diff_scope if report.files_in_diff_scope is not None else 'n/a'}",
        f"- **Total Findings:** {s['total']}",
        f"- **Effective Findings (unsuppressed):** {eff['total']}",
        f"- **Suppressed/Expired Suppressions:** {report.suppressed_total}/{report.expired_suppressions_total}",
        f"- **Critical/High/Medium/Low:** {s['critical']}/{s['high']}/{s['medium']}/{s['low']}",
        f"- **Effective Critical/High/Medium/Low:** {eff['critical']}/{eff['high']}/{eff['medium']}/{eff['low']}",
        "",
    ]

    if report.ai:
        lines.extend(["## AI triage", ""])
        for k, v in report.ai.items():
            lines.append(f"- **{k}**: `{v}`")
        lines.append("")

    if reasons:
        lines.extend(["## Policy failure reasons", ""])
        lines.extend([f"- {r}" for r in reasons])
        lines.append("")

    lines.extend(["## Findings", ""])
    if not report.findings:
        lines.append("No findings. 🎉")
    else:
        for finding in report.findings:
            sup = ""
            if finding.suppression_status != "none":
                sup = (
                    f"\n- Suppression: **{finding.suppression_status.upper()}**"
                    f" ({finding.suppression_reason or 'n/a'}, expires {finding.suppression_expires_at or 'n/a'})"
                )
            lines.extend(
                [
                    f"### [{finding.id}] {finding.title}",
                    f"- Severity: **{finding.severity.upper()}**",
                    f"- Category: `{finding.category}`",
                    f"- Location: `{finding.file}`{':' + str(finding.line) if finding.line else ''}",
                    f"- Why it matters: {finding.message}",
                    f"- Remediation: {finding.remediation}",
                    f"- Evidence: `{finding.evidence}`{sup}",
                    "",
                ]
            )

    return "\n".join(lines)


def write_markdown_report(report: ScanReport, path: Path, policy_passed: bool, reasons: list[str]) -> None:
    path.write_text(build_markdown_report(report, policy_passed, reasons))


def _sarif_rule_map(report: ScanReport) -> list[dict[str, Any]]:
    rules: dict[str, dict[str, Any]] = {}
    for f in report.findings:
        if f.id in rules:
            continue
        rules[f.id] = {
            "id": f.id,
            "name": f.title,
            "shortDescription": {"text": f.title},
            "fullDescription": {"text": f.message},
            "help": {"text": f.remediation},
            "properties": {"category": f.category},
        }
    return list(rules.values())


def build_sarif_report(report: ScanReport) -> dict[str, Any]:
    results = []
    for f in report.findings:
        result: dict[str, Any] = {
            "ruleId": f.id,
            "level": SARIF_LEVEL_MAP.get(f.severity, "warning"),
            "message": {"text": f.message},
            "properties": {
                "severity": f.severity,
                "category": f.category,
                "suppressed": f.suppressed,
                "suppression_status": f.suppression_status,
                "suppression_reason": f.suppression_reason,
                "suppression_expires_at": f.suppression_expires_at,
                "fingerprint": f.fingerprint,
            },
            "locations": [
                {
                    "physicalLocation": {
                        "artifactLocation": {"uri": f.file},
                        "region": {"startLine": f.line or 1},
                    }
                }
            ],
        }
        results.append(result)

    return {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "guardrail-ci",
                        "version": __version__,
                        "rules": _sarif_rule_map(report),
                    }
                },
                "results": results,
            }
        ],
    }


def write_sarif_report(report: ScanReport, path: Path) -> None:
    path.write_text(json.dumps(build_sarif_report(report), indent=2))
