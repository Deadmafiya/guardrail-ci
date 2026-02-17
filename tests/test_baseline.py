from datetime import date
from pathlib import Path

import pytest

from guardrail_ci.baseline import apply_baseline, finding_fingerprint, load_baseline
from guardrail_ci.config import PolicyConfig
from guardrail_ci.models import Finding, ScanReport
from guardrail_ci.policy import evaluate_policy


def _finding() -> Finding:
    return Finding(
        id="GR-SEC-003",
        title="Possible hardcoded secret",
        category="secrets",
        severity="high",
        file="src/config.py",
        line=42,
        message="Potential secret material found in source text.",
        remediation="Move to secret manager",
        evidence="token = 'abcdabcdabcdabcd'",
    )


def test_load_baseline_valid(tmp_path: Path):
    f = _finding()
    baseline = tmp_path / ".guardrail-baseline.yml"
    baseline.write_text(
        "\n".join(
            [
                "version: 1",
                "suppressions:",
                "  - id: GR-SEC-003",
                "    file: src/config.py",
                "    line: 42",
                f"    fingerprint: {finding_fingerprint(f)}",
                "    reason: temporary exception",
                "    expires_at: '2099-01-01'",
            ]
        )
    )

    out = load_baseline(baseline)
    assert out.version == 1
    assert len(out.suppressions) == 1


def test_apply_baseline_marks_suppressed_with_fingerprint(tmp_path: Path):
    finding = _finding()
    baseline = tmp_path / "b.yml"
    baseline.write_text(
        "\n".join(
            [
                "version: 1",
                "suppressions:",
                "  - id: GR-SEC-003",
                f"    fingerprint: {finding_fingerprint(finding)}",
                "    reason: accepted risk",
                "    expires_at: '2099-01-01'",
            ]
        )
    )

    bl = load_baseline(baseline)
    out, suppressed_total, expired_total = apply_baseline([finding], bl, today=date(2026, 2, 17))

    assert suppressed_total == 1
    assert expired_total == 0
    assert out[0].suppressed is True
    assert out[0].suppression_status == "active"


def test_apply_baseline_expired_not_suppressed(tmp_path: Path):
    finding = _finding()
    baseline = tmp_path / "b.yml"
    baseline.write_text(
        "\n".join(
            [
                "version: 1",
                "suppressions:",
                "  - id: GR-SEC-003",
                "    file: src/config.py",
                "    line: 42",
                "    reason: accepted risk",
                "    expires_at: '2020-01-01'",
            ]
        )
    )

    bl = load_baseline(baseline)
    out, suppressed_total, expired_total = apply_baseline([finding], bl, today=date(2026, 2, 17))

    assert suppressed_total == 0
    assert expired_total == 1
    assert out[0].suppressed is False
    assert out[0].suppression_status == "expired"


def test_policy_uses_effective_summary_not_total():
    report = ScanReport(
        scanned_path=".",
        findings=[_finding().with_updates(suppressed=True, suppression_status="active")],
        suppressed_total=1,
    )
    cfg = PolicyConfig(fail_on={"critical": 1, "high": 1, "medium": 999, "low": 999})
    ok, reasons = evaluate_policy(report, cfg)
    assert ok
    assert reasons == []


def test_invalid_baseline_rejects_missing_reason(tmp_path: Path):
    baseline = tmp_path / "bad.yml"
    baseline.write_text(
        "\n".join(
            [
                "version: 1",
                "suppressions:",
                "  - id: GR-SEC-003",
                "    file: src/config.py",
                "    expires_at: '2099-01-01'",
            ]
        )
    )

    with pytest.raises(ValueError):
        load_baseline(baseline)
