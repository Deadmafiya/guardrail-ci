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

    def summary(self) -> dict[str, int]:
        counts = {k: 0 for k in SEVERITY_ORDER.keys()}
        for finding in self.findings:
            counts[finding.severity] = counts.get(finding.severity, 0) + 1
        counts["total"] = len(self.findings)
        return counts

    def to_dict(self) -> dict[str, Any]:
        return {
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "scanned_path": str(Path(self.scanned_path).resolve()),
            "summary": self.summary(),
            "findings": [f.to_dict() for f in self.findings],
        }
