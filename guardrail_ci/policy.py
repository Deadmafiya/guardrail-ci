from __future__ import annotations

from guardrail_ci.config import PolicyConfig
from guardrail_ci.models import ScanReport


def evaluate_policy(report: ScanReport, config: PolicyConfig) -> tuple[bool, list[str]]:
    summary = report.summary()
    reasons: list[str] = []

    for sev, threshold in config.fail_on.items():
        actual = summary.get(sev, 0)
        if actual >= threshold:
            reasons.append(f"{sev} findings: {actual} (threshold: {threshold})")

    return (len(reasons) == 0, reasons)
