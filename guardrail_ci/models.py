from __future__ import annotations

from dataclasses import dataclass, asdict, replace
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
    fingerprint: str | None = None
    suppressed: bool = False
    suppression_reason: str | None = None
    suppression_expires_at: str | None = None
    suppression_status: str = "none"

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    def with_updates(self, **kwargs: Any) -> "Finding":
        return replace(self, **kwargs)


@dataclass(frozen=True)
class ScanReport:
    scanned_path: str
    findings: list[Finding]
    ai: dict[str, Any] | None = None
    files_scanned: int = 0
    files_in_diff_scope: int | None = None
    suppressed_total: int = 0
    expired_suppressions_total: int = 0

    def summary(self, include_suppressed: bool = True) -> dict[str, int]:
        counts = {k: 0 for k in SEVERITY_ORDER.keys()}
        pool = self.findings
        if not include_suppressed:
            pool = [f for f in self.findings if not f.suppressed]
        for finding in pool:
            counts[finding.severity] = counts.get(finding.severity, 0) + 1
        counts["total"] = len(pool)
        return counts

    def effective_summary(self) -> dict[str, int]:
        return self.summary(include_suppressed=False)

    def to_dict(self) -> dict[str, Any]:
        out = {
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "scanned_path": str(Path(self.scanned_path).resolve()),
            "summary": self.summary(),
            "effective_summary": self.effective_summary(),
            "suppressed_total": self.suppressed_total,
            "expired_suppressions_total": self.expired_suppressions_total,
            "files_scanned": self.files_scanned,
            "files_in_diff_scope": self.files_in_diff_scope,
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
