from __future__ import annotations

import json
from pathlib import Path

from guardrail_ci.models import ScanReport


def write_json_report(report: ScanReport, path: Path) -> None:
    path.write_text(json.dumps(report.to_dict(), indent=2))


def build_markdown_report(report: ScanReport, policy_passed: bool, reasons: list[str]) -> str:
    s = report.summary()
    lines = [
        "# guardrail-ci scan report",
        "",
        f"- **Scanned Path:** `{report.scanned_path}`",
        f"- **Policy Result:** {'PASS ✅' if policy_passed else 'FAIL ❌'}",
        f"- **Total Findings:** {s['total']}",
        f"- **Critical/High/Medium/Low:** {s['critical']}/{s['high']}/{s['medium']}/{s['low']}",
        "",
    ]

    if reasons:
        lines.extend(["## Policy failure reasons", ""])
        lines.extend([f"- {r}" for r in reasons])
        lines.append("")

    lines.extend(["## Findings", ""])
    if not report.findings:
        lines.append("No findings. 🎉")
    else:
        for finding in report.findings:
            lines.extend(
                [
                    f"### [{finding.id}] {finding.title}",
                    f"- Severity: **{finding.severity.upper()}**",
                    f"- Category: `{finding.category}`",
                    f"- Location: `{finding.file}`{':' + str(finding.line) if finding.line else ''}",
                    f"- Why it matters: {finding.message}",
                    f"- Remediation: {finding.remediation}",
                    f"- Evidence: `{finding.evidence}`",
                    "",
                ]
            )

    return "\n".join(lines)


def write_markdown_report(report: ScanReport, path: Path, policy_passed: bool, reasons: list[str]) -> None:
    path.write_text(build_markdown_report(report, policy_passed, reasons))
