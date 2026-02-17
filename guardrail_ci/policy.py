from __future__ import annotations

from guardrail_ci.config import PolicyConfig
from guardrail_ci.models import ScanReport


def evaluate_policy(
    report: ScanReport,
    config: PolicyConfig,
    baseline_strict_expiry: bool = False,
) -> tuple[bool, list[str]]:
    summary = report.effective_summary()
    reasons: list[str] = []

    for sev, threshold in config.fail_on.items():
        actual = summary.get(sev, 0)
        if actual >= threshold:
            reasons.append(f"{sev} findings: {actual} (threshold: {threshold})")

    if baseline_strict_expiry and report.expired_suppressions_total > 0:
        reasons.append(
            f"expired suppressions encountered: {report.expired_suppressions_total} (strict expiry enabled)"
        )

    return (len(reasons) == 0, reasons)
