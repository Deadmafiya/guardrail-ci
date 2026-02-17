from __future__ import annotations

import re
from pathlib import Path
from typing import Iterable

from guardrail_ci.models import Finding, SEVERITY_ORDER


TEXT_EXTENSIONS = {
    ".py", ".js", ".ts", ".tsx", ".jsx", ".json", ".yml", ".yaml", ".tf", ".tfvars", ".env", ".txt", ".md",
}

SECRET_PATTERNS: list[tuple[str, re.Pattern[str], str]] = [
    (
        "GR-SEC-001",
        re.compile(r"AKIA[0-9A-Z]{16}"),
        "Rotate the AWS key and move secrets to a vault or CI secret store.",
    ),
    (
        "GR-SEC-002",
        re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----"),
        "Remove private keys from source control and rotate compromised keys.",
    ),
    (
        "GR-SEC-003",
        re.compile(r"(?i)(api[_-]?key|token|secret)\s*[:=]\s*['\"][A-Za-z0-9_\-]{16,}['\"]"),
        "Store tokens/secrets in environment variables and secret managers.",
    ),
]


def discover_files(root: Path) -> Iterable[Path]:
    for path in root.rglob("*"):
        if not path.is_file():
            continue
        if ".git" in path.parts or "node_modules" in path.parts or "venv" in path.parts:
            continue
        if path.suffix.lower() in TEXT_EXTENSIONS or path.name in {"Dockerfile", "requirements.txt", "package-lock.json", "poetry.lock"}:
            yield path


def scan_secrets(root: Path) -> list[Finding]:
    findings: list[Finding] = []
    for path in discover_files(root):
        try:
            lines = path.read_text(errors="ignore").splitlines()
        except Exception:
            continue
        for idx, line in enumerate(lines, start=1):
            for finding_id, pattern, remediation in SECRET_PATTERNS:
                if pattern.search(line):
                    findings.append(
                        Finding(
                            id=finding_id,
                            title="Possible hardcoded secret",
                            category="secrets",
                            severity="high",
                            file=str(path.relative_to(root)),
                            line=idx,
                            message="Potential secret material found in source text.",
                            remediation=remediation,
                            evidence=line.strip()[:200],
                        )
                    )
    return findings


def scan_iac(root: Path) -> list[Finding]:
    findings: list[Finding] = []
    for path in root.rglob("*.tf"):
        lines = path.read_text(errors="ignore").splitlines()
        for idx, line in enumerate(lines, start=1):
            if "0.0.0.0/0" in line and any(port in "\n".join(lines[max(0, idx - 5): idx + 5]) for port in ["22", "3389"]):
                findings.append(
                    Finding(
                        id="GR-IAC-001",
                        title="Sensitive port exposed to the internet",
                        category="iac",
                        severity="critical",
                        file=str(path.relative_to(root)),
                        line=idx,
                        message="Security group allows 0.0.0.0/0 access to sensitive port.",
                        remediation="Restrict CIDR ranges and limit public ingress for admin ports.",
                        evidence=line.strip(),
                    )
                )

    for path in list(root.rglob("*.yml")) + list(root.rglob("*.yaml")):
        lines = path.read_text(errors="ignore").splitlines()
        for idx, line in enumerate(lines, start=1):
            if "privileged: true" in line:
                findings.append(
                    Finding(
                        id="GR-IAC-002",
                        title="Privileged container enabled",
                        category="iac",
                        severity="high",
                        file=str(path.relative_to(root)),
                        line=idx,
                        message="Container is configured with privileged=true.",
                        remediation="Run containers as non-privileged and drop unnecessary capabilities.",
                        evidence=line.strip(),
                    )
                )
    return findings


def scan_dependencies(root: Path) -> list[Finding]:
    findings: list[Finding] = []

    package_json = root / "package.json"
    if package_json.exists() and not (root / "package-lock.json").exists() and not (root / "pnpm-lock.yaml").exists() and not (root / "yarn.lock").exists():
        findings.append(
            Finding(
                id="GR-DEP-001",
                title="Missing JavaScript lockfile",
                category="dependency",
                severity="medium",
                file="package.json",
                line=None,
                message="Dependency lockfile missing; builds may be non-deterministic.",
                remediation="Commit package-lock.json / pnpm-lock.yaml / yarn.lock to version control.",
                evidence="package.json present without recognized lockfile",
            )
        )

    pyproject = root / "pyproject.toml"
    requirements = root / "requirements.txt"
    if (pyproject.exists() or requirements.exists()) and not (root / "poetry.lock").exists() and not (root / "uv.lock").exists() and not (root / "Pipfile.lock").exists():
        findings.append(
            Finding(
                id="GR-DEP-002",
                title="Missing Python lockfile",
                category="dependency",
                severity="medium",
                file="pyproject.toml" if pyproject.exists() else "requirements.txt",
                line=None,
                message="No Python lockfile detected; supply chain risk increases with floating versions.",
                remediation="Use poetry/uv/pipenv lockfile and commit it.",
                evidence="Python manifest found without lockfile",
            )
        )

    # Placeholder for future advisory-db integration
    return findings


def run_all_detectors(root: Path) -> list[Finding]:
    findings = []
    findings.extend(scan_secrets(root))
    findings.extend(scan_iac(root))
    findings.extend(scan_dependencies(root))
    findings.sort(key=lambda f: (SEVERITY_ORDER.get(f.severity, 0), f.file, f.line or 0, f.id), reverse=True)
    return findings
