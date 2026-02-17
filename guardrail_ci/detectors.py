from __future__ import annotations

import fnmatch
import re
from pathlib import Path
from typing import Iterable

from guardrail_ci.models import Finding, sort_findings


TEXT_EXTENSIONS = {
    ".py", ".js", ".ts", ".tsx", ".jsx", ".json", ".yml", ".yaml", ".tf", ".tfvars", ".env", ".txt", ".md", ".toml",
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


def _is_excluded(path: Path, root: Path, exclude_patterns: list[str] | None) -> bool:
    if not exclude_patterns:
        return False

    rel = path.relative_to(root).as_posix()
    for pattern in exclude_patterns:
        p = pattern.strip()
        if not p:
            continue
        if fnmatch.fnmatch(rel, p):
            return True
    return False


def discover_files(
    root: Path,
    exclude_patterns: list[str] | None = None,
    include_files: set[str] | None = None,
) -> Iterable[Path]:
    allow = {p.replace("\\", "/") for p in include_files} if include_files is not None else None

    for path in root.rglob("*"):
        if not path.is_file():
            continue
        rel = path.relative_to(root).as_posix()
        if allow is not None and rel not in allow:
            continue
        if _is_excluded(path, root, exclude_patterns):
            continue
        if path.suffix.lower() in TEXT_EXTENSIONS or path.name in {"Dockerfile", "requirements.txt", "package-lock.json", "poetry.lock"}:
            yield path


def scan_secrets(
    root: Path,
    exclude_patterns: list[str] | None = None,
    include_files: set[str] | None = None,
) -> list[Finding]:
    findings: list[Finding] = []
    for path in discover_files(root, exclude_patterns, include_files=include_files):
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


def scan_iac(
    root: Path,
    exclude_patterns: list[str] | None = None,
    include_files: set[str] | None = None,
) -> list[Finding]:
    findings: list[Finding] = []
    for path in discover_files(root, exclude_patterns, include_files=include_files):
        suffix = path.suffix.lower()

        if suffix == ".tf":
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

        if suffix in {".yml", ".yaml"}:
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


def scan_dependencies(root: Path, exclude_patterns: list[str] | None = None) -> list[Finding]:
    findings: list[Finding] = []

    package_json = root / "package.json"
    if package_json.exists() and not _is_excluded(package_json, root, exclude_patterns):
        if not (root / "package-lock.json").exists() and not (root / "pnpm-lock.yaml").exists() and not (root / "yarn.lock").exists():
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
    py_manifest = pyproject if pyproject.exists() else (requirements if requirements.exists() else None)
    if py_manifest and not _is_excluded(py_manifest, root, exclude_patterns):
        if not (root / "poetry.lock").exists() and not (root / "uv.lock").exists() and not (root / "Pipfile.lock").exists():
            findings.append(
                Finding(
                    id="GR-DEP-002",
                    title="Missing Python lockfile",
                    category="dependency",
                    severity="medium",
                    file=str(py_manifest.relative_to(root)),
                    line=None,
                    message="No Python lockfile detected; supply chain risk increases with floating versions.",
                    remediation="Use poetry/uv/pipenv lockfile and commit it.",
                    evidence="Python manifest found without lockfile",
                )
            )

    return findings


def run_all_detectors(
    root: Path,
    exclude_patterns: list[str] | None = None,
    include_files: set[str] | None = None,
) -> list[Finding]:
    findings: list[Finding] = []
    findings.extend(scan_secrets(root, exclude_patterns=exclude_patterns, include_files=include_files))
    findings.extend(scan_iac(root, exclude_patterns=exclude_patterns, include_files=include_files))
    findings.extend(scan_dependencies(root, exclude_patterns=exclude_patterns))
    return sort_findings(findings)
