from guardrail_ci.config import PolicyConfig
from guardrail_ci.models import Finding, ScanReport
from guardrail_ci.policy import evaluate_policy


def _finding(severity: str) -> Finding:
    return Finding(
        id="X",
        title="t",
        category="secrets",
        severity=severity,
        file="a.py",
        line=1,
        message="m",
        remediation="r",
        evidence="e",
    )


def test_policy_fails_when_threshold_hit():
    report = ScanReport(scanned_path=".", findings=[_finding("critical")])
    cfg = PolicyConfig(fail_on={"critical": 1, "high": 999, "medium": 999, "low": 999})
    ok, reasons = evaluate_policy(report, cfg)
    assert not ok
    assert reasons


def test_policy_passes_when_under_threshold():
    report = ScanReport(scanned_path=".", findings=[_finding("high")])
    cfg = PolicyConfig(fail_on={"critical": 1, "high": 2, "medium": 999, "low": 999})
    ok, reasons = evaluate_policy(report, cfg)
    assert ok
    assert reasons == []
