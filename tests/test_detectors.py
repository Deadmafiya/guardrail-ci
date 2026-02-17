from pathlib import Path

from guardrail_ci.detectors import scan_dependencies, scan_iac, scan_secrets, run_all_detectors


def test_secrets_detector_finds_aws_key():
    root = Path("tests/fixtures/vulnerable_repo")
    findings = scan_secrets(root)
    ids = {f.id for f in findings}
    assert "GR-SEC-001" in ids


def test_iac_detector_finds_public_admin_port():
    root = Path("tests/fixtures/vulnerable_repo")
    findings = scan_iac(root)
    ids = {f.id for f in findings}
    assert "GR-IAC-001" in ids


def test_dependency_detector_flags_missing_lockfile():
    root = Path("tests/fixtures/vulnerable_repo")
    findings = scan_dependencies(root)
    ids = {f.id for f in findings}
    assert "GR-DEP-001" in ids


def test_clean_fixture_has_no_findings_for_mvp_rules():
    root = Path("tests/fixtures/clean_repo")
    findings = run_all_detectors(root)
    assert findings == []
