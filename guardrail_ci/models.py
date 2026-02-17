from __future__ import annotations

from dataclasses import dataclass, asdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


SEVERITY_ORDER = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}


@dataclass(frozen=True)
class Finding:
    id: str
    title: str
    category: str
    severity: str
    file: str
    line: int | None
    message: str
    remediation: str
    evidence: str

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(frozen=True)
class ScanReport:
    scanned_path: str
    findings: list[Finding]
    ai: dict[str, Any] | None = None

    def summary(self) -> dict[str, int]:
        counts = {k: 0 for k in SEVERITY_ORDER.keys()}
        for finding in self.findings:
            counts[finding.severity] = counts.get(finding.severity, 0) + 1
        counts["total"] = len(self.findings)
        return counts

    def to_dict(self) -> dict[str, Any]:
        out = {
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "scanned_path": str(Path(self.scanned_path).resolve()),
            "summary": self.summary(),
            "findings": [f.to_dict() for f in self.findings],
        }
        if self.ai is not None:
            out["ai"] = self.ai
        return out


def sort_findings(findings: list[Finding]) -> list[Finding]:
    return sorted(
        findings,
        key=lambda f: (
            -SEVERITY_ORDER.get(f.severity, 0),
            f.category,
            f.file,
            f.line or 0,
            f.id,
        ),
    )
