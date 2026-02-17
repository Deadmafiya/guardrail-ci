from guardrail_ci.models import Finding, ScanReport
from guardrail_ci.reporters import build_markdown_report, build_sarif_report


def _finding() -> Finding:
    return Finding(
        id="GR-SEC-003",
        title="Possible hardcoded secret",
        category="secrets",
        severity="high",
        file="src/app.py",
        line=10,
        message="Potential secret material found in source text.",
        remediation="Move to secret manager",
        evidence="token = 'abcdabcdabcdabcd'",
        suppressed=True,
        suppression_status="active",
        suppression_reason="temp",
        suppression_expires_at="2099-01-01",
        fingerprint="abc",
    )


def test_markdown_includes_suppression_and_scope_metrics():
    report = ScanReport(
        scanned_path=".",
        findings=[_finding()],
        files_scanned=5,
        files_in_diff_scope=2,
        suppressed_total=1,
        expired_suppressions_total=0,
    )
    out = build_markdown_report(report, True, [])
    assert "Files Scanned" in out
    assert "Suppressed/Expired Suppressions" in out
    assert "Suppression: **ACTIVE**" in out


def test_sarif_properties_include_suppression_metadata():
    report = ScanReport(scanned_path=".", findings=[_finding()])
    sarif = build_sarif_report(report)
    props = sarif["runs"][0]["results"][0]["properties"]
    assert props["suppressed"] is True
    assert props["suppression_status"] == "active"
    assert props["fingerprint"] == "abc"
