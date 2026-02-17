from pathlib import Path

from guardrail_ci.ai_triage import apply_ai_triage
from guardrail_ci.config import AiSettings
from guardrail_ci.models import Finding


def _sample_finding() -> Finding:
    return Finding(
        id="GR-SEC-001",
        title="Possible hardcoded secret",
        category="secrets",
        severity="high",
        file="main.py",
        line=1,
        message="Potential secret material found in source text.",
        remediation="Rotate credential",
        evidence="AKIA1234567890ABCDE",
    )


def test_ai_triage_falls_back_when_config_missing():
    settings = AiSettings(
        mode="auto",
        enabled=True,
        base_url=None,
        api_key=None,
        model=None,
        timeout_seconds=5,
        max_findings=10,
    )
    findings = [_sample_finding()]
    out, meta = apply_ai_triage(Path("."), findings, settings)

    assert out == findings
    assert meta["status"] == "fallback"
    assert meta["reason"] == "missing_openai_config"
